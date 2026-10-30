using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using HapasVault.Motion;

namespace HapasVault.Controls;

public sealed record RadialEntry(uint Id, string Name, string Category, ShapeKind Shape, Brush Fill, Brush OnFill,
                                 HapasVault.Core.OtpKind Otp = HapasVault.Core.OtpKind.None)
{
    public string Initial => Name.Trim().Length > 0 ? char.ToUpper(Name.Trim()[0]).ToString() : "?";
}

public sealed record RadialCategory(string Title, IReadOnlyList<RadialEntry> Entries);

public enum AutoTypeMode { LoginPassword, PasswordOnly, LoginOnly, Otp }

/// <summary>
/// Радиальное меню. Выбор — по направлению от центра, а не попаданием в сектор:
/// достаточно махнуть мышью в нужную сторону.
///   • до 12 записей — одно кольцо со всеми записями;
///   • больше — внутреннее кольцо категорий, а записи категории, в сторону которой
///     указывает мышь, раскрываются веером во внешнем кольце;
///   • набранный текст (Filter) — одно кольцо с найденными записями.
/// ЛКМ / Enter — логин ⇥ пароль, ПКМ — только пароль, Shift+ЛКМ — только логин,
/// СКМ / Ctrl+ЛКМ — одноразовый код (если у записи есть 2FA).
/// </summary>
public sealed class RadialMenu : FrameworkElement
{
    public const int FlatLimit = 12;
    private const double Hub = 70, R1a = 84, R1b = 178, R2a = 190, R2b = 304, Pad = 24;

    private static readonly DependencyProperty OpenProperty = DependencyProperty.Register(
        "Open", typeof(double), typeof(RadialMenu), new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    private readonly Stopwatch _clock = new();
    private TimeSpan _last;
    private bool _hooked;

    private IReadOnlyList<RadialCategory> _categories = [];
    private List<RadialEntry> _flat = [];
    private bool _twoRings;
    private string _filter = "";

    private int _hoverCat = -1, _lockedCat = -1, _hoverEntry = -1;
    private double[] _catHover = [], _entryHover = [];
    private double _outer;          // раскрытие внешнего кольца 0..1
    private int _outerFor = -1;     // для какой категории сейчас нарисован веер

    public RadialMenu()
    {
        Focusable = true;
        Width = Height = 2 * (R2b + Pad);
        IsVisibleChanged += (_, _) => Hook(IsVisible);
        Unloaded += (_, _) => Hook(false);
    }

    /// <summary>Выбрана запись (и способ ввода).</summary>
    public event Action<RadialEntry, AutoTypeMode>? Chosen;

    public bool IsEmpty => _twoRings ? _categories.Count == 0 : _flat.Count == 0;
    public int Total { get; private set; }

    public string Filter
    {
        get => _filter;
        set
        {
            _filter = value ?? "";
            Rebuild();
        }
    }

    public void SetItems(IReadOnlyList<RadialCategory> categories)
    {
        _categories = categories;
        Total = categories.Sum(c => c.Entries.Count);
        _filter = "";
        Rebuild();
        BeginAnimation(OpenProperty, new System.Windows.Media.Animation.DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(520))
        { EasingFunction = M3Motion.SpringSpatial });
    }

    private void Rebuild()
    {
        var all = _categories.SelectMany(c => c.Entries);
        if (_filter.Length > 0)
        {
            _twoRings = false;
            _flat = all.Where(e => e.Name.Contains(_filter, StringComparison.CurrentCultureIgnoreCase) ||
                                   e.Category.Contains(_filter, StringComparison.CurrentCultureIgnoreCase))
                       .OrderBy(e => !e.Name.StartsWith(_filter, StringComparison.CurrentCultureIgnoreCase))
                       .ThenBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase)
                       .Take(FlatLimit).ToList();
        }
        else if (Total <= FlatLimit || _categories.Count <= 1)
        {
            _twoRings = false;
            _flat = all.OrderBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase).Take(Math.Max(FlatLimit, 24)).ToList();
        }
        else
        {
            _twoRings = true;
            _flat = [];
        }
        _hoverCat = _lockedCat = _hoverEntry = _outerFor = -1;
        _outer = 0;
        _catHover = new double[_twoRings ? _categories.Count : 0];
        _entryHover = new double[Math.Max(_flat.Count, _categories.Count == 0 ? 0 : _categories.Max(c => c.Entries.Count))];
        InvalidateVisual();
    }

    // ---------------- геометрия ----------------

    private Point Center => new(ActualWidth / 2, ActualHeight / 2);

    /// <summary>Угол в градусах: 0 — вверх, по часовой.</summary>
    private static double AngleOf(Vector v)
    {
        double a = Math.Atan2(v.X, -v.Y) * 180 / Math.PI;
        return a < 0 ? a + 360 : a;
    }

    private static double Diff(double a, double b)
    {
        double d = Math.Abs(a - b) % 360;
        return d > 180 ? 360 - d : d;
    }

    private static int SectorAt(double angle, int n) => n == 0 ? -1 : (int)Math.Floor(((angle + 180.0 / n) % 360) / (360.0 / n)) % n;

    /// <summary>Веер записей категории: центр угла и шаг.</summary>
    private (double Start, double Step) Fan(int cat)
    {
        int n = _categories.Count, m = _categories[cat].Entries.Count;
        double center = cat * 360.0 / n;
        double step = Math.Min(34, 360.0 / m);
        return (center - step * (m - 1) / 2, step);
    }

    private static Point Polar(Point c, double r, double deg)
    {
        double a = deg * Math.PI / 180;
        return new Point(c.X + r * Math.Sin(a), c.Y - r * Math.Cos(a));
    }

    // кольцевой сектор с зазорами; скругление углов даёт обводка с круглыми стыками
    private static Geometry Sector(Point c, double r0, double r1, double a0, double a1, double gapPx)
    {
        const double round = 5;
        r0 += round;
        r1 -= round;
        double gap0 = (gapPx / 2 + round) / r0 * 180 / Math.PI, gap1 = (gapPx / 2 + round) / r1 * 180 / Math.PI;
        double s0 = a0 + gap0, e0 = a1 - gap0, s1 = a0 + gap1, e1 = a1 - gap1;
        if (e1 <= s1) return Geometry.Empty;
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(Polar(c, r1, s1), true, true);
            ctx.ArcTo(Polar(c, r1, e1), new Size(r1, r1), 0, e1 - s1 > 180, SweepDirection.Clockwise, true, true);
            ctx.LineTo(Polar(c, r0, e0), true, true);
            ctx.ArcTo(Polar(c, r0, s0), new Size(r0, r0), 0, e0 - s0 > 180, SweepDirection.Counterclockwise, true, true);
        }
        g.Freeze();
        return g;
    }

    // ---------------- ввод ----------------

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        Track(e.GetPosition(this));
    }

    /// <summary>Обновить выбор по положению указателя (публично — для скриншотов CI).</summary>
    public void Track(Point p)
    {
        var v = p - Center;
        double dist = v.Length, angle = AngleOf(v);
        int prevCat = _hoverCat, prevEntry = _hoverEntry;
        if (dist < Hub - 14)
        {
            _hoverCat = _hoverEntry = -1;
            if (_twoRings) _lockedCat = -1;
        }
        else if (!_twoRings)
        {
            _hoverEntry = SectorAt(angle, _flat.Count);
        }
        else if (dist < R1b + 6)
        {
            _hoverCat = _lockedCat = SectorAt(angle, _categories.Count);
            _hoverEntry = -1;
        }
        else
        {
            int under = SectorAt(angle, _categories.Count);
            if (_lockedCat < 0) _lockedCat = under;
            var (start, step) = Fan(_lockedCat);
            int m = _categories[_lockedCat].Entries.Count;
            int best = -1;
            double bestD = double.MaxValue;
            for (int i = 0; i < m; i++)
            {
                double d = Diff(angle, start + i * step);
                if (d < bestD) { bestD = d; best = i; }
            }
            // ушли далеко в сторону от веера — переключаемся на категорию под курсором
            if (bestD > step / 2 + 24 && under != _lockedCat)
            {
                _lockedCat = under;
                _hoverEntry = -1;
            }
            else
            {
                _hoverEntry = best;
            }
            _hoverCat = _lockedCat;
        }
        if (prevCat != _hoverCat || prevEntry != _hoverEntry) InvalidateVisual();
    }

    protected override void OnMouseUp(MouseButtonEventArgs e)
    {
        base.OnMouseUp(e);
        Commit(ModeFor(e.ChangedButton));
    }

    public static AutoTypeMode ModeFor(MouseButton button) => button switch
    {
        MouseButton.Right => AutoTypeMode.PasswordOnly,
        MouseButton.Middle => AutoTypeMode.Otp,
        _ when Keyboard.Modifiers.HasFlag(ModifierKeys.Control) => AutoTypeMode.Otp,
        _ when Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) => AutoTypeMode.LoginOnly,
        _ => AutoTypeMode.LoginPassword,
    };

    public RadialEntry? Hovered
    {
        get
        {
            if (!_twoRings)
            {
                if (_hoverEntry >= 0 && _hoverEntry < _flat.Count) return _flat[_hoverEntry];
                return _filter.Length > 0 && _flat.Count > 0 ? _flat[0] : null;   // поиск: первое совпадение
            }
            if (_lockedCat < 0) return null;
            var entries = _categories[_lockedCat].Entries;
            if (_hoverEntry >= 0 && _hoverEntry < entries.Count) return entries[_hoverEntry];
            return _hoverCat >= 0 && entries.Count == 1 ? entries[0] : null;   // категория из одной записи
        }
    }

    public void Commit(AutoTypeMode mode)
    {
        if (Hovered is not { } entry) return;
        if (mode == AutoTypeMode.Otp && entry.Otp == HapasVault.Core.OtpKind.None) return;   // кода нет — нечего вводить
        Chosen?.Invoke(entry, mode);
    }

    // ---------------- анимация ----------------

    private void Hook(bool on)
    {
        if (on == _hooked) return;
        _hooked = on;
        if (on)
        {
            _clock.Restart();
            _last = TimeSpan.Zero;
            CompositionTarget.Rendering += OnFrame;
        }
        else
        {
            CompositionTarget.Rendering -= OnFrame;
        }
    }

    private void OnFrame(object? sender, EventArgs e)
    {
        var now = _clock.Elapsed;
        double dt = Math.Min(0.05, (now - _last).TotalSeconds);
        _last = now;
        double k = 1 - Math.Exp(-dt * 16);
        bool changed = false;

        void Approach(ref double v, double target)
        {
            double n = v + (target - v) * k;
            if (Math.Abs(n - target) < 0.002) n = target;
            if (n != v) { v = n; changed = true; }
        }

        for (int i = 0; i < _catHover.Length; i++) Approach(ref _catHover[i], i == _hoverCat ? 1 : 0);
        for (int i = 0; i < _entryHover.Length; i++) Approach(ref _entryHover[i], i == _hoverEntry ? 1 : 0);
        if (_twoRings)
        {
            if (_lockedCat != _outerFor)
            {
                // смена категории: веер сворачивается и раскрывается заново
                Approach(ref _outer, 0);
                if (_outer <= 0.05 || _outerFor < 0)
                {
                    _outerFor = _lockedCat;
                    _outer = 0;
                    changed = true;
                }
            }
            else
            {
                Approach(ref _outer, _lockedCat >= 0 ? 1 : 0);
            }
        }
        if (changed) InvalidateVisual();
    }

    // ---------------- отрисовка ----------------

    private static Brush Res(string key) => Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;

    private static Color C(string key) => (Res(key) as SolidColorBrush)?.Color ?? Colors.Gray;

    private static Brush Mix(string a, string b, double t)
    {
        Color x = C(a), y = C(b);
        t = Math.Clamp(t, 0, 1);
        byte L(byte p, byte q) => (byte)(p + (q - p) * t);
        var brush = new SolidColorBrush(Color.FromArgb(L(x.A, y.A), L(x.R, y.R), L(x.G, y.G), L(x.B, y.B)));
        brush.Freeze();
        return brush;
    }

    private FormattedText Text(string s, double size, FontWeight weight, Brush brush, double maxWidth, bool mono = false)
    {
        var ff = (FontFamily)(Application.Current.TryFindResource(mono ? "Font.Mono" : "Font.Sans") ?? new FontFamily("Segoe UI"));
        var t = new FormattedText(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface(ff, FontStyles.Normal, weight, FontStretches.Normal), size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip)
        {
            MaxTextWidth = Math.Max(8, maxWidth),
            MaxLineCount = 1,
            Trimming = TextTrimming.CharacterEllipsis,
            TextAlignment = TextAlignment.Center,
        };
        return t;
    }

    private void DrawCentered(DrawingContext dc, FormattedText t, Point at) =>
        dc.DrawText(t, new Point(at.X - t.MaxTextWidth / 2, at.Y - t.Height / 2));

    protected override void OnRender(DrawingContext dc)
    {
        var c = Center;
        double open = (double)GetValue(OpenProperty);
        double scale = 0.82 + 0.18 * open;
        dc.PushOpacity(Math.Clamp(open * 1.4, 0, 1));
        dc.PushTransform(new ScaleTransform(scale, scale, c.X, c.Y));

        // подложка: сквозь зазоры между секторами не просвечивает окно позади
        double back = (_twoRings ? R1b + (R2b - R1b) * _outer : R2a + 20) + 10;
        var backdrop = new SolidColorBrush(C("Surface")) { Opacity = 0.88 };
        dc.DrawEllipse(backdrop, null, c, back, back);

        if (_twoRings) DrawTwoRings(dc, c);
        else DrawRing(dc, c, _flat, R1a, R2a + 20, 0, 360.0 / Math.Max(1, _flat.Count), _hoverEntry, 1, alignStart: false);

        DrawHub(dc, c);
        dc.Pop();
        dc.Pop();
    }

    private void DrawTwoRings(DrawingContext dc, Point c)
    {
        int n = _categories.Count;
        double step = 360.0 / n;
        for (int i = 0; i < n; i++)
        {
            double h = _catHover.Length > i ? _catHover[i] : 0;
            double a0 = i * step - step / 2, a1 = a0 + step;
            var fill = Mix("SurfaceContainerHigh", "SecondaryContainer", h);
            var g = Sector(c, R1a, R1b + 6 * h, a0, a1, 6);
            dc.DrawGeometry(fill, new Pen(fill, 10) { LineJoin = PenLineJoin.Round }, g);
            double mid = (R1a + R1b) / 2 + 3 * h;
            double arc = Math.Min(130, (mid * step * Math.PI / 180) - 16);
            var cat = _categories[i];
            var p = Polar(c, mid, i * step);
            var fg = Mix("OnSurface", "OnSecondaryContainer", h);
            DrawCentered(dc, Text(cat.Title, 14, FontWeights.SemiBold, fg, arc), new Point(p.X, p.Y - 9));
            DrawCentered(dc, Text(cat.Entries.Count.ToString(CultureInfo.CurrentCulture), 12, FontWeights.Medium, Mix("OnSurfaceVariant", "OnSecondaryContainer", h), arc),
                new Point(p.X, p.Y + 10));
        }
        if (_outerFor >= 0 && _outer > 0.01)
        {
            var (start, fanStep) = Fan(_outerFor);
            var entries = _categories[_outerFor].Entries;
            double grow = R1b + (R2a - R1b) * _outer;
            dc.PushOpacity(_outer);
            DrawRing(dc, c, entries, grow, grow + (R2b - R2a), start - fanStep / 2, fanStep, _outerFor == _lockedCat ? _hoverEntry : -1, _outer, alignStart: true);
            dc.Pop();
        }
    }

    private void DrawRing(DrawingContext dc, Point c, IReadOnlyList<RadialEntry> entries, double r0, double r1,
                          double start, double step, int hover, double reveal, bool alignStart)
    {
        if (!alignStart) start = -step / 2;
        for (int i = 0; i < entries.Count; i++)
        {
            double h = i < _entryHover.Length ? _entryHover[i] : 0;
            double a0 = start + i * step;
            var fill = Mix("SurfaceContainerHigh", "PrimaryContainer", h);
            var g = Sector(c, r0, r1 + 10 * h, a0, a0 + step, 6);
            dc.DrawGeometry(fill, new Pen(fill, 10) { LineJoin = PenLineJoin.Round }, g);

            var e = entries[i];
            double mid = (r0 + r1) / 2 + 5 * h;
            double arc = Math.Min(118, mid * step * Math.PI / 180 - 14);
            var p = Polar(c, mid, a0 + step / 2);
            double av = 30 + 6 * h;
            var avatar = new Rect(p.X - av / 2, p.Y - av / 2 - 10, av, av);
            dc.DrawGeometry(e.Fill, null, Shapes.Geometry(e.Shape, ShapeKind.Sunny, h, 20 * h, avatar));
            var ini = Text(e.Initial, 13 + 2 * h, FontWeights.SemiBold, e.OnFill, av);
            DrawCentered(dc, ini, new Point(avatar.X + av / 2, avatar.Y + av / 2));
            if (e.Otp != HapasVault.Core.OtpKind.None)   // метка 2FA
                dc.DrawEllipse(Res("Tertiary"), new Pen(fill, 2), new Point(avatar.Right - 3, avatar.Top + 3), 5, 5);
            if (arc > 24)
                DrawCentered(dc, Text(e.Name, 12, h > 0.5 ? FontWeights.SemiBold : FontWeights.Medium,
                    Mix("OnSurface", "OnPrimaryContainer", h), arc), new Point(p.X, p.Y + av / 2 + 2));
        }
    }

    private void DrawHub(DrawingContext dc, Point c)
    {
        var hovered = Hovered;
        double h = hovered != null ? 1 : 0;
        dc.DrawEllipse(Res("SurfaceContainerHighest"), null, c, Hub, Hub);
        string title, sub;
        if (_filter.Length > 0 && _flat.Count == 0)
        {
            title = "Не найдено";
            sub = _filter;
        }
        else if (hovered != null)
        {
            title = hovered.Name;
            sub = hovered.Otp != HapasVault.Core.OtpKind.None ? "СКМ — код 2FA"
                : hovered.Category.Length > 0 ? hovered.Category : "ЛКМ — ввести";
        }
        else if (_twoRings && _hoverCat >= 0)
        {
            title = _categories[_hoverCat].Title;
            sub = "дальше — записи";
        }
        else
        {
            title = _filter.Length > 0 ? _filter : "HapasVault";
            sub = _filter.Length > 0 ? "поиск" : "печатайте для поиска";
        }
        DrawCentered(dc, Text(title, 15, FontWeights.SemiBold, Res(h > 0 ? "Primary" : "OnSurface"), Hub * 1.7), new Point(c.X, c.Y - 9));
        DrawCentered(dc, Text(sub, 11, FontWeights.Medium, Res("OnSurfaceVariant"), Hub * 1.7), new Point(c.X, c.Y + 12));
    }
}
