using System.Text;
using System.Text.Json;

namespace EventLogAnalyzer;

public class Rule
{
    public string Provider { get; set; } = "";
    public string[]? AltProviders { get; set; }
    public int EventId { get; set; }
    public string Severity { get; set; } = "medium";
    public string Title { get; set; } = "";
    public string Cause { get; set; } = "";
    public string[] Solutions { get; set; } = Array.Empty<string>();

    public bool Matches(string provider, int eventId)
    {
        if (eventId != EventId) return false;
        if (string.Equals(provider, Provider, StringComparison.OrdinalIgnoreCase)) return true;
        return AltProviders != null &&
               AltProviders.Any(p => string.Equals(provider, p, StringComparison.OrdinalIgnoreCase));
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
    public string SampleMessage { get; set; } = "";
    public bool Recognised { get; set; }

    public int SeverityRank => Severity.ToLowerInvariant() switch
    {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
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
        sb.AppendLine();
        sb.AppendLine("What to do:");
        for (int i = 0; i < f.Solutions.Length; i++)
            sb.AppendLine($"  {i + 1}. {f.Solutions[i]}");
        if (!string.IsNullOrWhiteSpace(f.SampleMessage))
        {
            sb.AppendLine();
            sb.AppendLine("Sample event message:");
            foreach (var line in f.SampleMessage.Trim().Split('\n'))
                sb.AppendLine("  " + line.TrimEnd());
        }
        return sb.ToString();
    }
}
