using System.Diagnostics.Eventing.Reader;

namespace EventLogAnalyzer;

public static class EventAnalyzer
{
    public static AnalysisResult Analyze(string evtxPath, IReadOnlyList<Rule> rules)
    {
        if (!File.Exists(evtxPath))
            throw new FileNotFoundException($"File not found: {evtxPath}");

        var groups = new Dictionary<(string Provider, int Id), Agg>();
        long total = 0, problems = 0;

        var query = new EventLogQuery(evtxPath, PathType.FilePath);
        using (var reader = new EventLogReader(query))
        {
            for (EventRecord? rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    total++;
                    // Level: 1=Critical, 2=Error, 3=Warning, 4=Info, 0=LogAlways
                    byte level = rec.Level ?? 4;
                    if (level is 0 or > 3) continue;
                    problems++;

                    var key = (rec.ProviderName ?? "(unknown provider)", rec.Id);
                    if (!groups.TryGetValue(key, out var agg))
                    {
                        agg = new Agg { Level = level, SampleMessage = SafeMessage(rec) };
                        groups[key] = agg;
                    }
                    agg.Count++;
                    if (level < agg.Level) agg.Level = level;

                    var t = rec.TimeCreated;
                    if (t.HasValue)
                    {
                        if (agg.First == null || t < agg.First) agg.First = t;
                        if (agg.Last == null || t > agg.Last) agg.Last = t;
                    }
                }
            }
        }

        var findings = new List<Finding>();
        foreach (var ((provider, id), agg) in groups)
        {
            var rule = rules.FirstOrDefault(r => r.Matches(provider, id));
            findings.Add(rule != null
                ? new Finding
                {
                    Recognised = true,
                    Severity = rule.Severity,
                    Provider = provider,
                    EventId = id,
                    Count = agg.Count,
                    FirstSeen = agg.First?.ToLocalTime(),
                    LastSeen = agg.Last?.ToLocalTime(),
                    Title = rule.Title,
                    Cause = rule.Cause,
                    Solutions = rule.Solutions,
                    SampleMessage = agg.SampleMessage,
                }
                : MakeUnknownFinding(provider, id, agg));
        }

        findings.Sort((a, b) =>
        {
            int c = a.SeverityRank.CompareTo(b.SeverityRank);
            return c != 0 ? c : b.Count.CompareTo(a.Count);
        });

        return new AnalysisResult { TotalEvents = total, ProblemEvents = problems, Findings = findings };
    }

    static Finding MakeUnknownFinding(string provider, int id, Agg agg)
    {
        var (severity, levelName) = agg.Level switch
        {
            1 => ("high", "critical"),
            2 => ("medium", "error"),
            _ => ("low", "warning"),
        };
        return new Finding
        {
            Recognised = false,
            Severity = severity,
            Provider = provider,
            EventId = id,
            Count = agg.Count,
            FirstSeen = agg.First?.ToLocalTime(),
            LastSeen = agg.Last?.ToLocalTime(),
            Title = $"Unrecognised {levelName} event from {provider}",
            Cause = "This event is not in the built-in rules database, so no specific advice is available.",
            Solutions = new[]
            {
                $"Read the sample message below - it often states the problem directly.",
                $"Search the web for: {provider} event {id}",
                "If it occurs frequently or lines up with a symptom you're seeing, investigate the software or device that owns this provider.",
                "Consider adding a rule for it to rules.json once you know what it means.",
            },
            SampleMessage = agg.SampleMessage,
        };
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
        public string SampleMessage = "";
    }
}
