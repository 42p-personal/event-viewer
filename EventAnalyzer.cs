using System.Diagnostics.Eventing.Reader;

namespace EventLogAnalyzer;

/// <summary>An input to analyze: an .evtx file or a live channel on this PC.</summary>
public sealed record LogSource(string Path, PathType Type, TimeSpan? MaxAge = null)
{
    public string Display => Type == PathType.LogName ? $"{Path} (this PC)" : System.IO.Path.GetFileName(Path);
}

public static class EventAnalyzer
{
    const int MaxSamples = 3;            // distinct rendered messages kept per issue
    const int MaxSampleAttempts = 10;    // rendering is slow - don't chase distinct samples forever
    const int MaxBreakdownKeys = 200;    // distinct culprit values tracked per issue
    const int TimelineCap = 500_000;     // timestamps kept for the histogram
    const int ContextMaxEntries = 400;   // rolling pre-crash buffer per source
    static readonly TimeSpan ContextMaxAge = TimeSpan.FromMinutes(10);
    static readonly TimeSpan ContextWindow = TimeSpan.FromMinutes(3);
    const int ContextShown = 25;         // max events per crash card
    static readonly TimeSpan CrashMerge = TimeSpan.FromMinutes(5);
    // Markers are logged at the boot AFTER the crash; events closer than this
    // to the marker belong to the new boot, not the crash.
    static readonly TimeSpan CrashGap = TimeSpan.FromSeconds(20);

    static readonly (string Provider, int Id, string Cause)[] CrashMarkers =
    {
        ("microsoft-windows-kernel-power", 41, "Unexpected loss of power or hard reset (Kernel-Power 41)"),
        ("eventlog", 6008, "Unexpected shutdown (EventLog 6008)"),
        ("microsoft-windows-wer-systemerrorreporting", 1001, "Blue screen / bugcheck (Event 1001)"),
        ("bugcheck", 1001, "Blue screen / bugcheck (Event 1001)"),
    };

    public static AnalysisResult Analyze(string evtxPath, IReadOnlyList<Rule> rules)
    {
        if (!File.Exists(evtxPath))
            throw new FileNotFoundException($"File not found: {evtxPath}");
        return Analyze(new[] { new LogSource(evtxPath, PathType.FilePath) }, rules);
    }

    public static AnalysisResult Analyze(IReadOnlyList<LogSource> sources, IReadOnlyList<Rule> rules)
    {
        var state = new State(rules);

        foreach (var src in sources)
        {
            try
            {
                string? xpath = src.MaxAge is { } age
                    ? $"*[System[TimeCreated[timediff(@SystemTime) <= {(long)age.TotalMilliseconds}]]]"
                    : null;
                var query = new EventLogQuery(src.Path, src.Type, xpath);
                using var reader = new EventLogReader(query);
                for (EventRecord? rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                {
                    using (rec) state.OnRecord(rec, src);
                }
            }
            catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException)
            {
                state.Result.SourceErrors.Add($"{src.Display}: {ex.Message}");
            }
        }

        return state.Finish();
    }

    sealed class State
    {
        public readonly AnalysisResult Result = new();
        readonly IReadOnlyList<Rule> _rules;
        readonly Dictionary<int, List<int>> _rulesById = new();
        readonly Dictionary<(string Provider, int Id, int RuleIdx), Agg> _groups = new();
        readonly List<(long Ms, byte Level)> _timeline = new();
        readonly Dictionary<string, List<CrashContextEvent>> _buffers = new();
        long _total, _problems;
        int _timelineDropped;

        public State(IReadOnlyList<Rule> rules)
        {
            _rules = rules;
            for (int i = 0; i < rules.Count; i++)
            {
                if (!_rulesById.TryGetValue(rules[i].EventId, out var list))
                    _rulesById[rules[i].EventId] = list = new List<int>();
                list.Add(i);
            }
        }

        public void OnRecord(EventRecord rec, LogSource src)
        {
            _total++;
            var provider = rec.ProviderName ?? "(unknown provider)";
            var time = rec.TimeCreated;

            // Boot session boundary: "The Event log service was started."
            if (rec.Id == 6005 && provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase))
                Result.BootSessions++;

            if (time.HasValue && rec.Id is 41 or 6008 or 1001)
            {
                foreach (var m in CrashMarkers)
                {
                    if (m.Id == rec.Id && provider.Equals(m.Provider, StringComparison.OrdinalIgnoreCase))
                    {
                        RecordCrash(m.Cause, m.Id, rec, src, time.Value.ToLocalTime());
                        break;
                    }
                }
            }

            // Level: 1=Critical, 2=Error, 3=Warning, 4=Info, 0=LogAlways
            byte level = rec.Level ?? 4;
            if (level is 0 or > 3) return; // info-level records: markers only
            _problems++;

            var props = SafeProps(rec);

            if (time.HasValue)
            {
                var local = time.Value.ToLocalTime();
                if (_timeline.Count < TimelineCap)
                    _timeline.Add((new DateTimeOffset(local).ToUnixTimeMilliseconds(), level));
                else
                    _timelineDropped++;

                var buf = BufferFor(src.Path);
                buf.Add(new CrashContextEvent
                {
                    Time = local, Level = level, Provider = provider, EventId = rec.Id,
                    Summary = ShortSummary(props),
                });
                if (buf.Count > ContextMaxEntries) buf.RemoveRange(0, buf.Count - ContextMaxEntries);
                while (buf.Count > 0 && buf[0].Time < local - ContextMaxAge) buf.RemoveAt(0);
            }

            int ruleIdx = -1;
            if (_rulesById.TryGetValue(rec.Id, out var candidates))
            {
                foreach (var i in candidates)
                {
                    if (_rules[i].Matches(provider, rec.Id, props)) { ruleIdx = i; break; }
                }
            }

            var key = (provider, rec.Id, ruleIdx);
            if (!_groups.TryGetValue(key, out var agg))
            {
                agg = new Agg { Level = level, Rule = ruleIdx >= 0 ? _rules[ruleIdx] : null };
                _groups[key] = agg;
            }
            agg.Count++;
            if (level < agg.Level) agg.Level = level;
            agg.Channels.Add(SafeChannel(rec) ?? src.Display);

            if (time.HasValue)
            {
                var t = time.Value;
                if (agg.First == null || t < agg.First) agg.First = t;
                if (agg.Last == null || t > agg.Last) agg.Last = t;
            }

            CollectSample(rec, agg);
            CollectBreakdown(props, agg);
        }

        void RecordCrash(string cause, int markerId, EventRecord rec, LogSource src, DateTime t)
        {
            var bugcheck = "";
            if (markerId == 1001)
            {
                var p = SafeProps(rec);
                if (p.Count > 0) bugcheck = (p[0] ?? "").Trim();
            }

            var existing = Result.Crashes.FirstOrDefault(c =>
                (c.Time - t).Duration() < CrashMerge && c.Channel == (SafeChannel(rec) ?? src.Display));
            if (existing != null)
            {
                if (!existing.Causes.Contains(cause)) existing.Causes.Add(cause);
                if (bugcheck.Length > 0 && existing.Bugcheck.Length == 0) existing.Bugcheck = bugcheck;
                return;
            }

            var crash = new CrashReport { Time = t, Bugcheck = bugcheck, Channel = SafeChannel(rec) ?? src.Display };
            crash.Causes.Add(cause);

            var buf = BufferFor(src.Path);
            var eligible = buf.Where(e => e.Time <= t - CrashGap).ToList();
            if (eligible.Count > 0)
            {
                var tail = eligible[^1].Time;
                crash.Events.AddRange(eligible.Where(e => e.Time >= tail - ContextWindow).TakeLast(ContextShown));
            }
            Result.Crashes.Add(crash);
        }

        List<CrashContextEvent> BufferFor(string source)
        {
            if (!_buffers.TryGetValue(source, out var b)) _buffers[source] = b = new List<CrashContextEvent>();
            return b;
        }

        public AnalysisResult Finish()
        {
            foreach (var ((provider, id, _), agg) in _groups)
            {
                Finding finding;
                if (agg.Rule != null)
                {
                    finding = new Finding
                    {
                        Recognised = true,
                        Severity = agg.Rule.Severity,
                        Provider = provider,
                        EventId = id,
                        Count = agg.Count,
                        FirstSeen = agg.First?.ToLocalTime(),
                        LastSeen = agg.Last?.ToLocalTime(),
                        Title = agg.Rule.Title,
                        Cause = agg.Rule.Cause,
                        Impact = agg.Rule.Impact,
                        Solutions = agg.Rule.Solutions,
                        Breakdown = agg.SortedBreakdown(),
                        BreakdownLabel = agg.Rule.BreakdownProps != null
                            ? string.Join(" / ", agg.Rule.BreakdownProps.Select(p => p.Name))
                            : "",
                        BreakdownOverflow = agg.BreakdownOverflow,
                        Samples = agg.Samples,
                    };
                    Personalize(finding);
                }
                else
                {
                    finding = MakeUnknownFinding(provider, id, agg);
                }
                finding.Channels = agg.Channels.OrderBy(c => c).ToList();
                Result.Findings.Add(finding);
            }

            Result.Findings.Sort((a, b) =>
            {
                int c = a.SeverityRank.CompareTo(b.SeverityRank);
                return c != 0 ? c : b.Count.CompareTo(a.Count);
            });

            Result.Crashes.Sort((a, b) => b.Time.CompareTo(a.Time));
            Result.TotalEvents = _total;
            Result.ProblemEvents = _problems;
            Result.Timeline = BuildTimeline();
            return Result;
        }

        TimelineData? BuildTimeline()
        {
            if (_timeline.Count == 0) return null;
            long min = long.MaxValue, max = long.MinValue;
            foreach (var (ms, _) in _timeline)
            {
                if (ms < min) min = ms;
                if (ms > max) max = ms;
            }
            long range = Math.Max(max - min, 1);
            long bucketMs = Math.Max(60_000, (long)Math.Ceiling(range / 100.0));
            int nBuckets = (int)(range / bucketMs) + 1;

            var tl = new TimelineData
            {
                Start = DateTimeOffset.FromUnixTimeMilliseconds(min).LocalDateTime,
                Bucket = TimeSpan.FromMilliseconds(bucketMs),
                Dropped = _timelineDropped,
            };
            for (int i = 0; i < nBuckets; i++) tl.Buckets.Add(new TimelinePoint());
            foreach (var (ms, level) in _timeline)
            {
                var b = tl.Buckets[(int)Math.Min((ms - min) / bucketMs, nBuckets - 1)];
                if (level == 1) b.Critical++;
                else if (level == 2) b.Error++;
                else b.Warning++;
            }
            return tl;
        }

        void CollectSample(EventRecord rec, Agg agg)
        {
            if (agg.Samples.Count >= MaxSamples || agg.SampleAttempts >= MaxSampleAttempts) return;
            agg.SampleAttempts++;
            var msg = SafeMessage(rec);
            if (!string.IsNullOrWhiteSpace(msg) && !agg.Samples.Contains(msg))
                agg.Samples.Add(msg);
        }

        void CollectBreakdown(IReadOnlyList<string?> props, Agg agg)
        {
            var bd = agg.Rule?.BreakdownProps;
            if (bd == null || bd.Length == 0) return;

            var key = string.Join(" / ", bd.Select(p => p.Index < props.Count ? props[p.Index] ?? "?" : "?"));
            if (agg.Breakdown.TryGetValue(key, out var count))
                agg.Breakdown[key] = count + 1;
            else if (agg.Breakdown.Count < MaxBreakdownKeys)
                agg.Breakdown[key] = 1;
            else
                agg.BreakdownOverflow++;
        }
    }

    // Fill {top}/{topCount}/{count}/{provider}/{eventId}/{breakdownLabel}
    // placeholders in rule text with the finding's own data, so advice names
    // the actual culprit. Solution lines with unavailable data are dropped;
    // cause/impact fall back to a generic phrase instead.
    static void Personalize(Finding f)
    {
        string? top = f.Breakdown.Count > 0 ? f.Breakdown[0].Value : null;
        string genericTop = "the affected " + (f.BreakdownLabel.Length > 0 ? f.BreakdownLabel.ToLowerInvariant() : "item");

        string? Fill(string text, bool lenient)
        {
            bool unresolved = false;
            string Sub(string placeholder, string? value)
            {
                if (!text.Contains(placeholder)) return text;
                if (value == null) { unresolved = true; return text; }
                return text.Replace(placeholder, value);
            }
            text = Sub("{top}", top ?? (lenient ? genericTop : null));
            text = Sub("{topCount}", f.Breakdown.Count > 0 ? f.Breakdown[0].Count.ToString("N0") : null);
            text = Sub("{count}", f.Count.ToString("N0"));
            text = Sub("{provider}", f.Provider);
            text = Sub("{eventId}", f.EventId.ToString());
            text = Sub("{breakdownLabel}", f.BreakdownLabel.Length > 0 ? f.BreakdownLabel : null);
            return unresolved ? null : text;
        }

        f.Cause = Fill(f.Cause, true) ?? f.Cause;
        if (f.Impact.Length > 0) f.Impact = Fill(f.Impact, true) ?? f.Impact;
        var solutions = f.Solutions.Select(s => Fill(s, false)).Where(s => s != null).Cast<string>().ToList();
        if (top != null && top != "?" && f.Count > f.Breakdown[0].Count)
        {
            solutions.Insert(0,
                $"Start with {top} - it accounts for {f.Breakdown[0].Count:N0} of the {f.Count:N0} occurrences ({f.BreakdownLabel}).");
        }
        f.Solutions = solutions.ToArray();
    }

    // Provider-name heuristics: even without a specific rule, the provider
    // usually reveals which subsystem an event belongs to.
    static readonly (string Pattern, string Label, string Cause, string[] Steps)[] ProviderHints =
    {
        ("disk|stor|nvme|ahci|raid|volsnap|ntfs|volume|partmgr|volmgr|iastor", "storage",
         "The provider name suggests this is a storage (disk/SSD/controller) event.",
         new[]
         {
             "Check the drive health with CrystalDiskInfo (SMART attributes: Reallocated Sectors, Pending Sectors).",
             "Back up important data before troubleshooting further - storage errors can escalate.",
             "Run 'chkdsk /r' on the affected volume from an elevated prompt.",
         }),
        ("display|nvlddmkm|amdkmdag|igfx|dxgkrnl|graphics|nvhda", "graphics",
         "The provider name suggests this involves the graphics card or display driver.",
         new[]
         {
             "Update the GPU driver from NVIDIA/AMD/Intel directly (not Windows Update).",
             "If it started after a driver update, roll back via Device Manager > Display adapters.",
             "Check GPU temperatures under load (HWiNFO) - overheating causes driver resets.",
         }),
        ("tcpip|dhcp|dns|netbt|wlan|netwtw|e1dexpress|rtl8|winhttp|network|lldp|smbclient|smbserver", "network",
         "The provider name suggests this is a networking event.",
         new[]
         {
             "Update the network adapter driver from the PC or motherboard vendor.",
             "Try 'ipconfig /flushdns' and 'netsh winsock reset' from an elevated prompt, then reboot.",
             "If it correlates with drops/disconnects, test with a cable instead of Wi-Fi (or vice versa) to isolate.",
         }),
        ("usb|hidclass|bthusb|bluetooth|kernel-pnp|pnp", "USB/device",
         "The provider name suggests a USB or plug-and-play device issue.",
         new[]
         {
             "Note which device the event data names, then update or reinstall its driver.",
             "Try a different USB port (rear motherboard ports are more reliable than front-panel or hubs).",
             "If it repeats for the same device, test the device on another PC to rule out the device itself.",
         }),
        ("print|spool", "printing",
         "The provider name suggests this is a printing subsystem event.",
         new[]
         {
             "Clear the print queue: stop the Print Spooler service, delete C:\\Windows\\System32\\spool\\PRINTERS\\*, start it again.",
             "Reinstall the printer with the newest driver from the manufacturer.",
         }),
        ("defender|antimalware|security", "security",
         "The provider name suggests this comes from security or antivirus software.",
         new[]
         {
             "Open Windows Security > Protection history and review what happened.",
             "Run a Full scan if anything looks suspicious.",
         }),
        ("update|wuau|servicing|installer|msi", "updates/installer",
         "The provider name suggests this relates to Windows Update or a software installer.",
         new[]
         {
             "Run Settings > Windows Update > Retry, then the built-in Windows Update troubleshooter.",
             "If updates fail repeatedly: 'dism /online /cleanup-image /restorehealth' then 'sfc /scannow' from an elevated prompt.",
         }),
        ("power|acpi|battery|thermal", "power/thermal",
         "The provider name suggests a power management or thermal event.",
         new[]
         {
             "Check Power Options - aggressive power saving causes many device dropouts.",
             "On desktops: verify the PSU is adequate; on laptops: check the battery report (powercfg /batteryreport).",
         }),
        (@"\.net|clr|runtime", "application runtime",
         "The provider name suggests an application runtime error (a program, not Windows itself).",
         new[]
         {
             "The sample data usually names the application - update or reinstall it.",
             "Install the latest .NET runtime from Microsoft if several apps are affected.",
         }),
    };

    static Finding MakeUnknownFinding(string provider, int id, Agg agg)
    {
        var (severity, levelName) = agg.Level switch
        {
            1 => ("high", "critical"),
            2 => ("medium", "error"),
            _ => ("low", "warning"),
        };

        var hint = ProviderHints.FirstOrDefault(h =>
            System.Text.RegularExpressions.Regex.IsMatch(provider, h.Pattern,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase));

        var cause = hint.Pattern != null
            ? $"This {levelName} event isn't in the rules database, but it can still be narrowed down: {hint.Cause}"
            : $"This {levelName} event isn't in the rules database, so there's no specific explanation - but the details below still narrow it down.";

        var steps = new List<string>
        {
            "Read the sample messages below - they often state the problem directly (file paths, device names, error codes).",
        };
        if (hint.Pattern != null) steps.AddRange(hint.Steps);
        steps.Add($"Search the web for: {provider} event {id}");
        steps.Add("If it lines up with a symptom you're seeing, note when it occurs (see First/Last seen and the timeline) and what changed on the machine around that time.");

        return new Finding
        {
            Recognised = false,
            Severity = severity,
            Provider = provider,
            EventId = id,
            Count = agg.Count,
            FirstSeen = agg.First?.ToLocalTime(),
            LastSeen = agg.Last?.ToLocalTime(),
            Title = $"Unrecognised {levelName} event from {provider}" +
                (hint.Pattern != null ? $" (looks {hint.Label}-related)" : ""),
            Cause = cause,
            Solutions = steps.ToArray(),
            Samples = agg.Samples,
        };
    }

    static string ShortSummary(IReadOnlyList<string?> props)
    {
        var s = string.Join(" | ", props.Where(v => !string.IsNullOrWhiteSpace(v)));
        return s.Length > 140 ? s[..137] + "..." : s;
    }

    static IReadOnlyList<string?> SafeProps(EventRecord rec)
    {
        try
        {
            return rec.Properties.Select(p => p.Value?.ToString()).ToList();
        }
        catch
        {
            return Array.Empty<string?>();
        }
    }

    static string? SafeChannel(EventRecord rec)
    {
        try { return string.IsNullOrWhiteSpace(rec.LogName) ? null : rec.LogName; }
        catch { return null; }
    }

    static string SafeMessage(EventRecord rec)
    {
        // FormatDescription needs the provider's message DLLs, which may not exist
        // on the machine analyzing the file - fall back to the raw property values.
        try
        {
            var msg = rec.FormatDescription();
            if (!string.IsNullOrWhiteSpace(msg)) return msg;
        }
        catch (EventLogException) { }

        try
        {
            var props = rec.Properties.Select(p => p.Value?.ToString()).Where(v => !string.IsNullOrWhiteSpace(v));
            return "(message template unavailable; event data: " + string.Join(" | ", props) + ")";
        }
        catch
        {
            return "(message unavailable)";
        }
    }

    class Agg
    {
        public int Count;
        public byte Level;
        public DateTime? First, Last;
        public Rule? Rule;
        public List<string> Samples = new();
        public int SampleAttempts;
        public Dictionary<string, int> Breakdown = new();
        public int BreakdownOverflow;
        public HashSet<string> Channels = new(StringComparer.OrdinalIgnoreCase);

        public List<(string, int)> SortedBreakdown() =>
            Breakdown.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value)).ToList();
    }
}
