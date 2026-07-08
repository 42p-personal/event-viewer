using System.Diagnostics.Eventing.Reader;

namespace EventLogAnalyzer;

public class MainForm : Form
{
    readonly TextBox _pathBox = new() { Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(4, 6, 4, 4) };
    readonly Button _browseBtn = new() { Text = "Browse...", AutoSize = true, Margin = new Padding(4, 4, 4, 4) };
    readonly Button _analyzeBtn = new() { Text = "Analyze", AutoSize = true, Margin = new Padding(4, 4, 4, 4) };
    readonly Button _scanBtn = new() { Text = "Scan this PC", AutoSize = true, Margin = new Padding(12, 4, 4, 4) };
    readonly ComboBox _rangeBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120, Margin = new Padding(4, 5, 8, 4) };
    readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    readonly TabPage _tabFindings = new("Findings");
    readonly TabPage _tabCrashes = new("Crashes");
    readonly TabPage _tabTimeline = new("Timeline");
    readonly DataGridView _grid = new();
    readonly TextBox _detailBox = new();
    readonly TextBox _crashBox = new();
    readonly TimelinePanel _timeline = new() { Dock = DockStyle.Fill };
    readonly ToolStripStatusLabel _status = new() { Text = "Pick .evtx files, drag and drop them here, or press 'Scan this PC' to analyze this machine's logs." };
    List<Rule> _rules = new();

    static readonly (string Label, TimeSpan? Age)[] Ranges =
    {
        ("Last 24 hours", TimeSpan.FromDays(1)),
        ("Last 7 days", TimeSpan.FromDays(7)),
        ("Last 30 days", TimeSpan.FromDays(30)),
        ("Everything", null),
    };

    readonly string? _initialFile;
    List<LogSource> _pendingSources = new();

    public MainForm(string? initialFile = null)
    {
        _initialFile = initialFile;
        Text = "Event Log Analyzer";
        Width = 1150;
        Height = 780;
        StartPosition = FormStartPosition.CenterScreen;

        // --- findings tab: grid on top, detail/solutions pane below ---
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 380,
        };

        _grid.Dock = DockStyle.Fill;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.RowHeadersVisible = false;
        _grid.MultiSelect = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        _grid.Columns.Add(NewCol("Severity", 80));
        _grid.Columns.Add(NewCol("Count", 60));
        _grid.Columns.Add(NewCol("Provider", 230));
        _grid.Columns.Add(NewCol("Event ID", 70));
        var issueCol = NewCol("Issue", 280);
        issueCol.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        _grid.Columns.Add(issueCol);
        _grid.Columns.Add(NewCol("Log", 90));
        _grid.Columns.Add(NewCol("First seen", 120));
        _grid.Columns.Add(NewCol("Last seen", 120));
        _grid.SelectionChanged += (_, _) => ShowDetail();
        split.Panel1.Controls.Add(_grid);

        _detailBox.Dock = DockStyle.Fill;
        _detailBox.Multiline = true;
        _detailBox.ReadOnly = true;
        _detailBox.ScrollBars = ScrollBars.Vertical;
        _detailBox.Font = new Font("Consolas", 9.75f);
        _detailBox.BackColor = SystemColors.Window;
        split.Panel2.Controls.Add(_detailBox);
        _tabFindings.Controls.Add(split);

        // --- crashes tab ---
        _crashBox.Dock = DockStyle.Fill;
        _crashBox.Multiline = true;
        _crashBox.ReadOnly = true;
        _crashBox.ScrollBars = ScrollBars.Vertical;
        _crashBox.Font = new Font("Consolas", 9.75f);
        _crashBox.BackColor = SystemColors.Window;
        _tabCrashes.Controls.Add(_crashBox);

        // --- timeline tab ---
        _tabTimeline.Controls.Add(_timeline);

        _tabs.TabPages.Add(_tabFindings);
        _tabs.TabPages.Add(_tabCrashes);
        _tabs.TabPages.Add(_tabTimeline);

        // --- top bar: file path + buttons + live-scan range ---
        var topBar = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 6,
            Padding = new Padding(6, 4, 6, 2),
        };
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.Controls.Add(new Label { Text = "Event log file(s) (.evtx):", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(4, 9, 4, 4) }, 0, 0);
        topBar.Controls.Add(_pathBox, 1, 0);
        topBar.Controls.Add(_browseBtn, 2, 0);
        topBar.Controls.Add(_analyzeBtn, 3, 0);
        topBar.Controls.Add(_scanBtn, 4, 0);
        topBar.Controls.Add(_rangeBox, 5, 0);

        foreach (var (label, _) in Ranges) _rangeBox.Items.Add(label);
        _rangeBox.SelectedIndex = 1; // last 7 days

        var statusStrip = new StatusStrip();
        statusStrip.Items.Add(_status);

        // Dock order: Fill control must be added first so it takes the remaining space.
        Controls.Add(_tabs);
        Controls.Add(topBar);
        Controls.Add(statusStrip);

        _browseBtn.Click += (_, _) => BrowseForFiles();
        _analyzeBtn.Click += async (_, _) => await AnalyzeFromPathBoxAsync();
        _scanBtn.Click += async (_, _) => await ScanThisPcAsync();
        _pathBox.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await AnalyzeFromPathBoxAsync(); } };

        AllowDrop = true;
        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
            {
                SetFiles(files);
                await RunAnalysisAsync(_pendingSources);
            }
        };

        Load += async (_, _) =>
        {
            LoadRules();
            if (_initialFile != null)
            {
                SetFiles(new[] { _initialFile });
                await RunAnalysisAsync(_pendingSources);
            }
        };
    }

    static DataGridViewTextBoxColumn NewCol(string name, int width) =>
        new() { HeaderText = name, Width = width, SortMode = DataGridViewColumnSortMode.NotSortable };

    void LoadRules()
    {
        var rulesPath = Path.Combine(AppContext.BaseDirectory, "rules.json");
        try
        {
            _rules = RuleSet.Load(rulesPath);
            if (_rules.Count == 0)
                _status.Text = $"Warning: no rules loaded from {rulesPath} - events will still be listed, but without specific advice.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not load rules.json:\n\n{ex.Message}", "Rules error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    void SetFiles(IReadOnlyList<string> files)
    {
        _pendingSources = files.Select(f => new LogSource(f, PathType.FilePath)).ToList();
        _pathBox.Text = string.Join("; ", files);
    }

    void BrowseForFiles()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Select event log file(s)",
            Filter = "Event log files (*.evtx)|*.evtx|All files (*.*)|*.*",
            Multiselect = true,
            InitialDirectory = Directory.Exists(@"C:\Windows\System32\winevt\Logs")
                ? @"C:\Windows\System32\winevt\Logs"
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
        {
            SetFiles(dlg.FileNames);
            _ = RunAnalysisAsync(_pendingSources);
        }
    }

    async Task AnalyzeFromPathBoxAsync()
    {
        var text = _pathBox.Text.Trim();
        if (text.Length == 0) { BrowseForFiles(); return; }

        var files = text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(f => f.Trim('"')).ToList();
        var missing = files.Where(f => !File.Exists(f)).ToList();
        if (missing.Count > 0)
        {
            MessageBox.Show(this, "File not found:\n" + string.Join("\n", missing), "Event Log Analyzer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        SetFiles(files);
        await RunAnalysisAsync(_pendingSources);
    }

    async Task ScanThisPcAsync()
    {
        var age = Ranges[Math.Max(_rangeBox.SelectedIndex, 0)].Age;
        var sources = new List<LogSource>
        {
            new("System", PathType.LogName, age),
            new("Application", PathType.LogName, age),
        };
        _pathBox.Text = $"(live) System; Application - {Ranges[Math.Max(_rangeBox.SelectedIndex, 0)].Label}";
        await RunAnalysisAsync(sources);
    }

    async Task RunAnalysisAsync(List<LogSource> sources)
    {
        if (sources.Count == 0) { BrowseForFiles(); return; }

        _browseBtn.Enabled = _analyzeBtn.Enabled = _scanBtn.Enabled = false;
        _status.Text = "Analyzing... (large logs can take a minute)";
        _grid.Rows.Clear();
        _detailBox.Clear();
        _crashBox.Clear();
        _timeline.SetData(null);
        UseWaitCursor = true;

        try
        {
            var rules = _rules;
            var result = await Task.Run(() => EventAnalyzer.Analyze(sources, rules));

            foreach (var f in result.Findings)
            {
                int i = _grid.Rows.Add(
                    f.Severity.ToUpperInvariant(),
                    f.Count.ToString("N0"),
                    f.Provider,
                    f.EventId.ToString(),
                    f.Title,
                    string.Join(", ", f.Channels),
                    f.FirstSeen?.ToString("yyyy-MM-dd HH:mm") ?? "",
                    f.LastSeen?.ToString("yyyy-MM-dd HH:mm") ?? "");
                var row = _grid.Rows[i];
                row.Tag = f;
                row.DefaultCellStyle.BackColor = SeverityColor(f.Severity);
            }

            RenderCrashes(result);
            _timeline.SetData(result.Timeline);
            _tabTimeline.Text = "Timeline";

            int recognised = result.Findings.Count(f => f.Recognised);
            var sessionInfo = result.BootSessions > 0
                ? $" {result.BootSessions:N0} boot session(s), {result.Crashes.Count} unexpected shutdown(s)."
                : "";
            var sourceErrors = result.SourceErrors.Count > 0
                ? $" {result.SourceErrors.Count} source(s) could not be read."
                : "";
            _status.Text = result.Findings.Count > 0
                ? $"{result.TotalEvents:N0} events scanned - {result.ProblemEvents:N0} errors/warnings in {result.Findings.Count} distinct issues ({recognised} with specific advice).{sessionInfo}{sourceErrors} Select a row for details."
                : $"{result.TotalEvents:N0} events scanned - no errors or warnings found. This log looks healthy.{sourceErrors}";

            if (_grid.Rows.Count > 0)
            {
                _grid.Rows[0].Selected = true;
                // The grid auto-selects the first row during Rows.Add, before its
                // Tag is assigned - refresh the detail pane now that Tags exist.
                ShowDetail();
            }
        }
        catch (Exception ex)
        {
            _status.Text = "Analysis failed.";
            MessageBox.Show(this, $"Could not analyze:\n\n{ex.Message}", "Event Log Analyzer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            UseWaitCursor = false;
            _browseBtn.Enabled = _analyzeBtn.Enabled = _scanBtn.Enabled = true;
        }
    }

    void RenderCrashes(AnalysisResult result)
    {
        _tabCrashes.Text = result.Crashes.Count > 0 ? $"Crashes ({result.Crashes.Count})" : "Crashes";
        if (result.Crashes.Count == 0)
        {
            _crashBox.Text = result.BootSessions > 0
                ? $"No unexpected shutdowns detected across {result.BootSessions:N0} boot session(s)."
                : "No unexpected shutdowns detected.";
            return;
        }
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{result.Crashes.Count} unexpected shutdown(s) across {result.BootSessions:N0} boot session(s).");
        sb.AppendLine("What was happening in the minutes before each one:");
        sb.AppendLine(new string('=', 78));
        foreach (var c in result.Crashes)
        {
            sb.AppendLine(ReportFormatter.FormatCrash(c));
            sb.AppendLine(new string('-', 78));
        }
        _crashBox.Text = sb.ToString();
        _crashBox.SelectionStart = 0;
    }

    void ShowDetail()
    {
        if (_grid.SelectedRows.Count > 0 && _grid.SelectedRows[0].Tag is Finding f)
        {
            _detailBox.Text = ReportFormatter.Format(f);
            _detailBox.SelectionStart = 0;
            _detailBox.ScrollToCaret();
        }
    }

    static Color SeverityColor(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => Color.FromArgb(255, 205, 205),
        "high" => Color.FromArgb(255, 228, 200),
        "medium" => Color.FromArgb(255, 249, 196),
        "low" => Color.FromArgb(226, 240, 255),
        "noise" => Color.FromArgb(241, 241, 240),
        _ => Color.FromArgb(235, 235, 235),
    };
}
