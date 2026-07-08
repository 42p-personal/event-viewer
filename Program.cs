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

    // --report <file.evtx> [more.evtx ...] [output.txt]
    static int RunHeadless(string[] args)
    {
        var inputs = args.Where(a => a.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToList();
        var outPath = args.FirstOrDefault(a => !a.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase))
                      ?? inputs[0] + ".report.txt";
        try
        {
            var rules = RuleSet.Load(Path.Combine(AppContext.BaseDirectory, "rules.json"));
            var sources = inputs
                .Select(f => new LogSource(f, System.Diagnostics.Eventing.Reader.PathType.FilePath))
                .ToList();
            var result = EventAnalyzer.Analyze(sources, rules);
            File.WriteAllText(outPath, ReportFormatter.FormatFullReport(string.Join(", ", inputs), result));
            return 0;
        }
        catch (Exception ex)
        {
            File.WriteAllText(outPath, "ERROR: " + ex);
            return 1;
        }
    }
}
