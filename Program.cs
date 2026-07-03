using System.Text;

namespace EventLogAnalyzer;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        // Headless mode: EventLogAnalyzer.exe --report <file.evtx> [report.txt]
        // Analyzes the file and writes a text report instead of opening the UI.
        if (args.Length > 1 && args[0].Equals("--report", StringComparison.OrdinalIgnoreCase))
            return RunHeadless(args.Skip(1).ToArray());

        // A bare .evtx argument opens the UI with the file analyzed,
        // so "Open with" / drag-onto-exe work.
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(args.Length > 0 ? args[0] : null));
        return 0;
    }

    static int RunHeadless(string[] args)
    {
        var evtxPath = args[0];
        var outPath = args.Length > 1 ? args[1] : evtxPath + ".report.txt";
        try
        {
            var rules = RuleSet.Load(Path.Combine(AppContext.BaseDirectory, "rules.json"));
            var result = EventAnalyzer.Analyze(evtxPath, rules);

            var sb = new StringBuilder();
            sb.AppendLine($"Event Log Analyzer report for: {evtxPath}");
            sb.AppendLine($"Total events: {result.TotalEvents:N0}   Errors/warnings: {result.ProblemEvents:N0}   Distinct issues: {result.Findings.Count}");
            sb.AppendLine(new string('=', 78));
            foreach (var f in result.Findings)
            {
                sb.AppendLine(ReportFormatter.Format(f));
                sb.AppendLine(new string('-', 78));
            }
            File.WriteAllText(outPath, sb.ToString());
            return 0;
        }
        catch (Exception ex)
        {
            File.WriteAllText(outPath, "ERROR: " + ex);
            return 1;
        }
    }
}
