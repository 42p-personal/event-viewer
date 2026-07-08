namespace EventLogAnalyzer;

/// <summary>Stacked histogram of errors/warnings over time (same design as the
/// web version: single-hue severity ramp, critical anchored to the baseline).</summary>
public class TimelinePanel : Panel
{
    static readonly Color CriticalColor = Color.FromArgb(0x7f, 0x1d, 0x1d);
    static readonly Color ErrorColor = Color.FromArgb(0xdc, 0x26, 0x26);
    static readonly Color WarningColor = Color.FromArgb(0xf8, 0x71, 0x71);
    static readonly Color GridColor = Color.FromArgb(0xe1, 0xe0, 0xd9);
    static readonly Color BaselineColor = Color.FromArgb(0xc3, 0xc2, 0xb7);
    static readonly Color TickColor = Color.FromArgb(0x89, 0x87, 0x81);

    const int PadL = 56, PadR = 12, PadT = 30, PadB = 34;

    TimelineData? _data;
    readonly ToolTip _tip = new();
    int _tipBucket = -1;

    public TimelinePanel()
    {
        DoubleBuffered = true;
        BackColor = Color.White;
        ResizeRedraw = true;
    }

    public void SetData(TimelineData? data)
    {
        _data = data;
        _tipBucket = -1;
        Invalidate();
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_data == null || _data.Buckets.Count == 0) return;
        float slot = (Width - PadL - PadR) / (float)_data.Buckets.Count;
        int idx = slot > 0 ? (int)((e.X - PadL) / slot) : -1;
        if (idx < 0 || idx >= _data.Buckets.Count || e.X < PadL)
        {
            if (_tipBucket != -1) { _tip.Hide(this); _tipBucket = -1; }
            return;
        }
        if (idx == _tipBucket) return;
        _tipBucket = idx;
        var b = _data.Buckets[idx];
        var from = _data.Start + TimeSpan.FromTicks(_data.Bucket.Ticks * idx);
        var to = from + _data.Bucket;
        _tip.Show(
            $"{from:yyyy-MM-dd HH:mm} - {to:HH:mm}\nCritical: {b.Critical:N0}   Errors: {b.Error:N0}   Warnings: {b.Warning:N0}",
            this, e.X + 14, e.Y + 14, 4000);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _tip.Hide(this);
        _tipBucket = -1;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        using var tickFont = new Font(Font.FontFamily, 8f);

        if (_data == null || _data.Buckets.Count < 2)
        {
            TextRenderer.DrawText(g, "No dated errors or warnings to chart.", Font,
                ClientRectangle, TickColor, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            return;
        }

        int plotW = Width - PadL - PadR;
        int plotH = Height - PadT - PadB;
        if (plotW < 40 || plotH < 40) return;

        int maxTotal = NiceMax(_data.Buckets.Max(b => b.Total));
        float Y(float v) => PadT + plotH - v / maxTotal * plotH;

        // legend (top-left)
        int lx = PadL;
        int totalC = _data.Buckets.Sum(b => b.Critical);
        int totalE = _data.Buckets.Sum(b => b.Error);
        int totalW = _data.Buckets.Sum(b => b.Warning);
        foreach (var (color, label) in new[]
        {
            (CriticalColor, $"Critical ({totalC:N0})"),
            (ErrorColor, $"Errors ({totalE:N0})"),
            (WarningColor, $"Warnings ({totalW:N0})"),
        })
        {
            using var swatch = new SolidBrush(color);
            g.FillRectangle(swatch, lx, 8, 10, 10);
            var size = TextRenderer.MeasureText(g, label, tickFont);
            TextRenderer.DrawText(g, label, tickFont, new Point(lx + 14, 6), TickColor);
            lx += 14 + size.Width + 14;
        }

        // gridlines + y tick labels (integers only)
        using var gridPen = new Pen(GridColor);
        using var basePen = new Pen(BaselineColor);
        var yTicks = maxTotal % 2 == 0 ? new[] { 0, maxTotal / 2, maxTotal } : new[] { 0, maxTotal };
        foreach (var v in yTicks)
        {
            float y = Y(v);
            g.DrawLine(v == 0 ? basePen : gridPen, PadL, y, Width - PadR, y);
            TextRenderer.DrawText(g, v.ToString("N0"), tickFont,
                new Rectangle(0, (int)y - 7, PadL - 6, 14), TickColor,
                TextFormatFlags.Right | TextFormatFlags.VerticalCenter);
        }

        // stacked bars: critical at the baseline, then error, then warning,
        // with 1px surface gaps between touching segments
        float slot = plotW / (float)_data.Buckets.Count;
        float barW = Math.Min(24f, Math.Max(2f, slot - 2f));
        using var bc = new SolidBrush(CriticalColor);
        using var be = new SolidBrush(ErrorColor);
        using var bw = new SolidBrush(WarningColor);
        for (int i = 0; i < _data.Buckets.Count; i++)
        {
            var b = _data.Buckets[i];
            float x = PadL + i * slot + (slot - barW) / 2f;
            float acc = 0;
            foreach (var (brush, v) in new[] { (bc, b.Critical), (be, b.Error), (bw, b.Warning) })
            {
                if (v == 0) continue;
                float y0 = Y(acc + v);
                float h = Y(acc) - y0;
                float gap = acc > 0 ? 1f : 0f;
                g.FillRectangle(brush, x, y0, barW, Math.Max(h - gap, 0.75f));
                acc += v;
            }
        }

        // x-axis time labels: first / middle / last
        var mid = _data.Buckets.Count / 2;
        string Label(int i) => (_data.Start + TimeSpan.FromTicks(_data.Bucket.Ticks * i)).ToString("yyyy-MM-dd HH:mm");
        TextRenderer.DrawText(g, Label(0), tickFont, new Point(PadL, Height - PadB + 8), TickColor);
        TextRenderer.DrawText(g, Label(mid), tickFont,
            new Rectangle(PadL, Height - PadB + 8, plotW, 14), TickColor, TextFormatFlags.HorizontalCenter);
        TextRenderer.DrawText(g, Label(_data.Buckets.Count - 1), tickFont,
            new Rectangle(PadL, Height - PadB + 8, plotW, 14), TickColor, TextFormatFlags.Right);
    }

    static int NiceMax(int v)
    {
        if (v <= 5) return Math.Max(v, 2);
        int mag = (int)Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 2, 5, 10 })
            if (v <= m * mag) return m * mag;
        return 10 * mag;
    }
}
