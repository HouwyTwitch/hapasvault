using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using HapasVault.Motion;

namespace HapasVault.Controls;

/// <summary>Базовый класс анимируемых индикаторов: кадр только пока элемент виден и активен.</summary>
public abstract class AnimatedElement : FrameworkElement
{
    protected readonly Stopwatch Clock = new();
    private bool _hooked;

    protected AnimatedElement()
    {
        IsVisibleChanged += (_, _) => UpdateHook();
        Loaded += (_, _) => UpdateHook();
        Unloaded += (_, _) => Hook(false);
    }

    protected abstract bool WantsFrames { get; }

    protected void UpdateHook() => Hook(WantsFrames && IsVisible && IsLoaded);

    private void Hook(bool on)
    {
        if (on == _hooked) return;
        _hooked = on;
        if (on)
        {
            Clock.Start();
            CompositionTarget.Rendering += OnFrame;
        }
        else
        {
            CompositionTarget.Rendering -= OnFrame;
            Clock.Stop();
        }
    }

    private void OnFrame(object? sender, EventArgs e) => InvalidateVisual();
}

/// <summary>
/// Индикатор загрузки M3 Expressive: форма вращается и морфит через 7 форм.
/// </summary>
public sealed class LoadingIndicator : AnimatedElement
{
    private static readonly ShapeKind[] Sequence =
    [
        ShapeKind.SoftBurst, ShapeKind.Cookie9, ShapeKind.Pentagon, ShapeKind.Pill,
        ShapeKind.Sunny, ShapeKind.Cookie4, ShapeKind.Oval,
    ];

    public static readonly DependencyProperty IsActiveProperty = DependencyProperty.Register(
        nameof(IsActive), typeof(bool), typeof(LoadingIndicator),
        new PropertyMetadata(true, (d, _) => ((LoadingIndicator)d).UpdateHook()));
    public static readonly DependencyProperty ForegroundProperty = DependencyProperty.Register(
        nameof(Foreground), typeof(Brush), typeof(LoadingIndicator),
        new FrameworkPropertyMetadata(Brushes.SlateBlue, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty ContainerProperty = DependencyProperty.Register(
        nameof(Container), typeof(Brush), typeof(LoadingIndicator),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    static LoadingIndicator()
    {
        WidthProperty.OverrideMetadata(typeof(LoadingIndicator), new FrameworkPropertyMetadata(48.0));
        HeightProperty.OverrideMetadata(typeof(LoadingIndicator), new FrameworkPropertyMetadata(48.0));
    }

    public bool IsActive { get => (bool)GetValue(IsActiveProperty); set => SetValue(IsActiveProperty, value); }
    public Brush Foreground { get => (Brush)GetValue(ForegroundProperty); set => SetValue(ForegroundProperty, value); }
    /// <summary>Кисть круглого контейнера (вариант «contained»); null — без контейнера.</summary>
    public Brush? Container { get => (Brush?)GetValue(ContainerProperty); set => SetValue(ContainerProperty, value); }

    protected override bool WantsFrames => IsActive;

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 0) return;
        var c = new Point(ActualWidth / 2, ActualHeight / 2);
        if (Container != null) dc.DrawEllipse(Container, null, c, size / 2, size / 2);

        const double step = 0.65;   // секунд на одну форму
        double t = Clock.Elapsed.TotalSeconds;
        int i = (int)(t / step);
        double local = (t - i * step) / step;
        double morph = SpringEase.Evaluate(Math.Min(1, local / 0.8), 0.55);
        double angle = t * 140 + (i + morph) * 90;
        double s = size * 38 / 48 * (Container != null ? 0.82 : 1);
        var rect = new Rect(c.X - s / 2, c.Y - s / 2, s, s);
        dc.DrawGeometry(Foreground, null, Shapes.Geometry(
            Sequence[i % Sequence.Length], Sequence[(i + 1) % Sequence.Length], morph, angle, rect));
    }
}

/// <summary>
/// Линейный «волнистый» индикатор M3 Expressive: определённый (Value 0..1) или бесконечный.
/// </summary>
public sealed class WavyProgress : AnimatedElement
{
    private static FrameworkPropertyMetadata Render(object def) => new(def, FrameworkPropertyMetadataOptions.AffectsRender);

    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(double), typeof(WavyProgress),
        new PropertyMetadata(0.0, (d, e) => ((WavyProgress)d).BeginAnimation(ShownProperty,
            M3Motion.To(Math.Clamp((double)e.NewValue, 0, 1), 600, M3Motion.SpringSpatial))));
    private static readonly DependencyProperty ShownProperty = DependencyProperty.Register(
        "Shown", typeof(double), typeof(WavyProgress), Render(0.0));
    public static readonly DependencyProperty IsIndeterminateProperty = DependencyProperty.Register(
        nameof(IsIndeterminate), typeof(bool), typeof(WavyProgress),
        new PropertyMetadata(false, (d, _) => ((WavyProgress)d).UpdateHook()));
    public static readonly DependencyProperty IsWavyProperty = DependencyProperty.Register(
        nameof(IsWavy), typeof(bool), typeof(WavyProgress),
        new PropertyMetadata(true, (d, _) => ((WavyProgress)d).UpdateHook()));
    public static readonly DependencyProperty ForegroundProperty = DependencyProperty.Register(
        nameof(Foreground), typeof(Brush), typeof(WavyProgress), Render(Brushes.SlateBlue));
    public static readonly DependencyProperty TrackProperty = DependencyProperty.Register(
        nameof(Track), typeof(Brush), typeof(WavyProgress), Render(Brushes.Lavender));
    public static readonly DependencyProperty ThicknessProperty = DependencyProperty.Register(
        nameof(Thickness), typeof(double), typeof(WavyProgress), Render(4.0));
    public static readonly DependencyProperty AmplitudeProperty = DependencyProperty.Register(
        nameof(Amplitude), typeof(double), typeof(WavyProgress), Render(3.0));
    public static readonly DependencyProperty WavelengthProperty = DependencyProperty.Register(
        nameof(Wavelength), typeof(double), typeof(WavyProgress), Render(24.0));

    static WavyProgress()
    {
        HeightProperty.OverrideMetadata(typeof(WavyProgress), new FrameworkPropertyMetadata(12.0));
    }

    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public bool IsIndeterminate { get => (bool)GetValue(IsIndeterminateProperty); set => SetValue(IsIndeterminateProperty, value); }
    public bool IsWavy { get => (bool)GetValue(IsWavyProperty); set => SetValue(IsWavyProperty, value); }
    public Brush Foreground { get => (Brush)GetValue(ForegroundProperty); set => SetValue(ForegroundProperty, value); }
    public Brush Track { get => (Brush)GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public double Thickness { get => (double)GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    public double Amplitude { get => (double)GetValue(AmplitudeProperty); set => SetValue(AmplitudeProperty, value); }
    public double Wavelength { get => (double)GetValue(WavelengthProperty); set => SetValue(WavelengthProperty, value); }

    protected override bool WantsFrames => IsIndeterminate || IsWavy;

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, th = Thickness, cy = ActualHeight / 2;
        if (w <= th * 2) return;
        double left = th / 2, right = w - th / 2, span = right - left, gap = th + 4;
        double phase = Clock.Elapsed.TotalSeconds * 2 * Math.PI * 0.9;
        var active = new Pen(Foreground, th) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        var track = new Pen(Track, th) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };

        if (IsIndeterminate)
        {
            double p = Clock.Elapsed.TotalSeconds % 1.8 / 1.8;
            double head = BezierEase.Evaluate(Math.Min(1, p / 0.7), 0.05, 0.7, 0.1, 1);
            double tail = BezierEase.Evaluate(Math.Max(0, (p - 0.2) / 0.8), 0.3, 0, 0.8, 0.15);
            double x0 = left + span * tail, x1 = left + span * head;
            if (x0 - gap > left) dc.DrawLine(track, new Point(left, cy), new Point(x0 - gap, cy));
            if (x1 + gap < right) dc.DrawLine(track, new Point(x1 + gap, cy), new Point(right, cy));
            DrawWave(dc, active, x0, x1, cy, IsWavy ? Amplitude : 0, phase);
            return;
        }

        double v = (double)GetValue(ShownProperty);
        double end = left + span * Math.Clamp(v, 0, 1);
        // волна затухает у 0 % и 100 %, как в спецификации
        double amp = IsWavy ? Amplitude * Math.Clamp(v * 12, 0, 1) * Math.Clamp((1 - v) * 25, 0, 1) : 0;
        if (v > 0.001) DrawWave(dc, active, left, end, cy, amp, phase);
        double ts = v > 0.001 ? end + gap : left;
        if (ts < right)
        {
            dc.DrawLine(track, new Point(ts, cy), new Point(right, cy));
            dc.DrawEllipse(Foreground, null, new Point(right, cy), th / 2, th / 2);   // stop indicator
        }
    }

    private void DrawWave(DrawingContext dc, Pen pen, double x0, double x1, double cy, double amp, double phase)
    {
        if (x1 <= x0) return;
        if (amp < 0.05)
        {
            dc.DrawLine(pen, new Point(x0, cy), new Point(x1, cy));
            return;
        }
        double k = 2 * Math.PI / Wavelength;
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(new Point(x0, cy + amp * Math.Sin(k * x0 - phase)), false, false);
            var pts = new List<Point>();
            for (double x = x0 + 1.5; x < x1; x += 1.5) pts.Add(new Point(x, cy + amp * Math.Sin(k * x - phase)));
            pts.Add(new Point(x1, cy + amp * Math.Sin(k * x1 - phase)));
            ctx.PolyLineTo(pts, true, true);
        }
        g.Freeze();
        dc.DrawGeometry(null, pen, g);
    }
}
