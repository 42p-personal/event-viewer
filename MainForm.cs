namespace EventLogAnalyzer;

public class MainForm : Form
{
    readonly TextBox _pathBox = new() { Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(4, 6, 4, 4) };
    readonly Button _browseBtn = new() { Text = "Browse...", AutoSize = true, Margin = new Padding(4, 4, 4, 4) };
    readonly Button _analyzeBtn = new() { Text = "Analyze", AutoSize = true, Margin = new Padding(4, 4, 8, 4) };
    readonly DataGridView _grid = new();
    readonly TextBox _detailBox = new();
    readonly ToolStripStatusLabel _status = new() { Text = "Pick an .evtx file to analyze. Tip: you can also drag and drop one onto this window." };
    List<Rule> _rules = new();

    readonly string? _initialFile;

    public MainForm(string? initialFile = null)
    {
        _initialFile = initialFile;
        Text = "Event Log Analyzer";
        Width = 1150;
        Height = 780;
        StartPosition = FormStartPosition.CenterScreen;

        // --- main layout: findings grid on top, detail/solutions pane below ---
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
        _grid.Columns.Add(NewCol("Provider", 250));
        _grid.Columns.Add(NewCol("Event ID", 70));
        var issueCol = NewCol("Issue", 300);
        issueCol.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        _grid.Columns.Add(issueCol);
        _grid.Columns.Add(NewCol("First seen", 130));
        _grid.Columns.Add(NewCol("Last seen", 130));
        _grid.SelectionChanged += (_, _) => ShowDetail();
        split.Panel1.Controls.Add(_grid);

        _detailBox.Dock = DockStyle.Fill;
        _detailBox.Multiline = true;
        _detailBox.ReadOnly = true;
        _detailBox.ScrollBars = ScrollBars.Vertical;
        _detailBox.Font = new Font("Consolas", 9.75f);
        _detailBox.BackColor = SystemColors.Window;
        split.Panel2.Controls.Add(_detailBox);

        // --- top bar: file path + browse + analyze ---
        var topBar = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 4,
            Padding = new Padding(6, 4, 6, 2),
        };
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topBar.Controls.Add(new Label { Text = "Event log file (.evtx):", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(4, 9, 4, 4) }, 0, 0);
        topBar.Controls.Add(_pathBox, 1, 0);
        topBar.Controls.Add(_browseBtn, 2, 0);
        topBar.Controls.Add(_analyzeBtn, 3, 0);

        var statusStrip = new StatusStrip();
        statusStrip.Items.Add(_status);

        // Dock order: Fill control must be added first so it takes the remaining space.
        Controls.Add(split);
        Controls.Add(topBar);
        Controls.Add(statusStrip);

        _browseBtn.Click += (_, _) => BrowseForFile();
        _analyzeBtn.Click += async (_, _) => await RunAnalysisAsync();
        _pathBox.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await RunAnalysisAsync(); } };

        AllowDrop = true;
        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
            {
                _pathBox.Text = files[0];
                await RunAnalysisAsync();
            }
        };

        Load += async (_, _) =>
        {
            LoadRules();
            if (_initialFile != null)
            {
                _pathBox.Text = _initialFile;
                await RunAnalysisAsync();
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

    void BrowseForFile()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Select an event log file",
            Filter = "Event log files (*.evtx)|*.evtx|All files (*.*)|*.*",
            InitialDirectory = Directory.Exists(@"C:\Windows\System32\winevt\Logs")
                ? @"C:\Windows\System32\winevt\Logs"
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
        {
            _pathBox.Text = dlg.FileName;
            _ = RunAnalysisAsync();
        }
    }

    async Task RunAnalysisAsync()
    {
        var path = _pathBox.Text.Trim().Trim('"');
        if (path.Length == 0) { BrowseForFile(); return; }
        if (!File.Exists(path))
        {
            MessageBox.Show(this, $"File not found:\n{path}", "Event Log Analyzer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _browseBtn.Enabled = _analyzeBtn.Enabled = false;
        _status.Text = "Analyzing... (large logs can take a minute)";
        _grid.Rows.Clear();
        _detailBox.Clear();
        UseWaitCursor = true;

        try
        {
            var rules = _rules;
            var result = await Task.Run(() => EventAnalyzer.Analyze(path, rules));

            foreach (var f in result.Findings)
            {
                int i = _grid.Rows.Add(
                    f.Severity.ToUpperInvariant(),
                    f.Count.ToString("N0"),
                    f.Provider,
                    f.EventId.ToString(),
                    f.Title,
                    f.FirstSeen?.ToString("yyyy-MM-dd HH:mm") ?? "",
                    f.LastSeen?.ToString("yyyy-MM-dd HH:mm") ?? "");
                var row = _grid.Rows[i];
                row.Tag = f;
                row.DefaultCellStyle.BackColor = SeverityColor(f.Severity);
            }

            int recognised = result.Findings.Count(f => f.Recognised);
            _status.Text = $"{result.TotalEvents:N0} events scanned - {result.ProblemEvents:N0} errors/warnings in {result.Findings.Count} distinct issues ({recognised} with specific advice). Select a row for details.";
            if (_grid.Rows.Count > 0)
            {
                _grid.Rows[0].Selected = true;
                // The grid auto-selects the first row during Rows.Add, before its
                // Tag is assigned - refresh the detail pane now that Tags exist.
                ShowDetail();
            }
            else _status.Text = $"{result.TotalEvents:N0} events scanned - no errors or warnings found. This log looks healthy.";
        }
        catch (Exception ex)
        {
            _status.Text = "Analysis failed.";
            MessageBox.Show(this, $"Could not analyze this file:\n\n{ex.Message}", "Event Log Analyzer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            UseWaitCursor = false;
            _browseBtn.Enabled = _analyzeBtn.Enabled = true;
        }
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
        _ => Color.FromArgb(235, 235, 235),
    };
}
