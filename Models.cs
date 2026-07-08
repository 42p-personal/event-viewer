using System.Text;
using System.Text.Json;

namespace EventLogAnalyzer;

public class DetailProp
{
    public int Index { get; set; }
    public string Name { get; set; } = "";
}

public class Rule
{
    public string Provider { get; set; } = "";
    public string[]? AltProviders { get; set; }
    public int EventId { get; set; }
    public string Severity { get; set; } = "medium";
    public string Title { get; set; } = "";
    public string Cause { get; set; } = "";
    public string[] Solutions { get; set; } = Array.Empty<string>();

    // Which event data properties identify the culprit (e.g. faulting app,
    // service name). Used to build a per-value occurrence breakdown.
    public DetailProp[]? BreakdownProps { get; set; }

    // Optional keywords: the rule only matches when any event data property
    // contains one of these (case-insensitive). Rules are matched in file
    // order, so keyword rules must appear before generic ones.
    public string[]? DataContains { get; set; }

    public bool Matches(string provider, int eventId, IReadOnlyList<string?> properties)
    {
        if (eventId != EventId) return false;
        bool providerOk = string.Equals(provider, Provider, StringComparison.OrdinalIgnoreCase) ||
            (AltProviders != null &&
             AltProviders.Any(p => string.Equals(provider, p, StringComparison.OrdinalIgnoreCase)));
        if (!providerOk) return false;
        if (DataContains is { Length: > 0 })
            return DataContains.Any(kw => properties.Any(v =>
                v != null && v.Contains(kw, StringComparison.OrdinalIgnoreCase)));
        return true;
    }
}

public static class RuleSet
{
    public static List<Rule> Load(string path)
    {
        if (!File.Exists(path)) return new List<Rule>();
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        return JsonSerializer.Deserialize<List<Rule>>(File.ReadAllText(path), options) ?? new List<Rule>();
    }
}

public class Finding
{
    public string Severity { get; set; } = "medium";
    public string Provider { get; set; } = "";
    public int EventId { get; set; }
    public int Count { get; set; }
    public DateTime? FirstSeen { get; set; }
    public DateTime? LastSeen { get; set; }
    public string Title { get; set; } = "";
    public string Cause { get; set; } = "";
    public string[] Solutions { get; set; } = Array.Empty<string>();
    public bool Recognised { get; set; }

    /// <summary>"180 x GameManagerService3.exe / KERNELBASE.dll" style culprit counts, most frequent first.</summary>
    public List<(string Value, int Count)> Breakdown { get; set; } = new();
    public string BreakdownLabel { get; set; } = "";
    public int BreakdownOverflow { get; set; }

    /// <summary>Up to a few distinct rendered event messages.</summary>
    public List<string> Samples { get; set; } = new();

    public int SeverityRank => Severity.ToLowerInvariant() switch
    {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        "noise" => 5,
        _ => 2,
    };
}

public class AnalysisResult
{
    public long TotalEvents { get; set; }
    public long ProblemEvents { get; set; }
    public List<Finding> Findings { get; set; } = new();
}

public static class ReportFormatter
{
    public static string Format(Finding f)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[{f.Severity.ToUpperInvariant()}] {f.Title}");
        sb.AppendLine($"Provider: {f.Provider}    Event ID: {f.EventId}    Occurrences: {f.Count:N0}");
        if (f.FirstSeen.HasValue || f.LastSeen.HasValue)
            sb.AppendLine($"First seen: {f.FirstSeen:yyyy-MM-dd HH:mm:ss}    Last seen: {f.LastSeen:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();
        sb.AppendLine("What it means:");
        sb.AppendLine("  " + f.Cause);

        if (f.Breakdown.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Breakdown by {f.BreakdownLabel}:");
            foreach (var (value, count) in f.Breakdown.Take(10))
                sb.AppendLine($"  {count,6:N0} x  {value}");
            int more = f.Breakdown.Count - 10;
            if (more > 0) sb.AppendLine($"          ... and {more:N0} more distinct value(s)");
            if (f.BreakdownOverflow > 0) sb.AppendLine($"          ... plus {f.BreakdownOverflow:N0} occurrence(s) not itemised");
        }

        sb.AppendLine();
        sb.AppendLine("What to do:");
        for (int i = 0; i < f.Solutions.Length; i++)
            sb.AppendLine($"  {i + 1}. {f.Solutions[i]}");

        if (f.Samples.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(f.Samples.Count == 1 ? "Sample event message:" : $"Sample event messages ({f.Samples.Count} distinct):");
            for (int i = 0; i < f.Samples.Count; i++)
            {
                if (f.Samples.Count > 1)
                    sb.AppendLine($"  --- sample {i + 1} ---");
                foreach (var line in f.Samples[i].Trim().Split('\n'))
                    sb.AppendLine("  " + line.TrimEnd());
            }
        }
        return sb.ToString();
    }
}
