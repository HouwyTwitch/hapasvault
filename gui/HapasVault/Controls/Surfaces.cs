using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using HapasVault.Motion;

namespace HapasVault.Controls;

/// <summary>
/// Border с «живым» скруглением M3 Expressive. Скругление задаётся долей
/// (1 — «пилюля», 0 — прямоугольник) и анимируется пружиной при нажатии и выборе.
/// В группе соединённых кнопок (Position) внутренние углы малые (InnerRadius),
/// а выбранная кнопка становится полностью круглой.
/// </summary>
public sealed class MorphBorder : Border
{
    private static PropertyMetadata Changed(object def) =>
        new(def, (d, _) => ((MorphBorder)d).Retarget());

    public static readonly DependencyProperty RoundnessProperty = DependencyProperty.Register(
        nameof(Roundness), typeof(double), typeof(MorphBorder), Changed(1.0));
    public static readonly DependencyProperty PressedRoundnessProperty = DependencyProperty.Register(
        nameof(PressedRoundness), typeof(double), typeof(MorphBorder), Changed(double.NaN));
    public static readonly DependencyProperty SelectedRoundnessProperty = DependencyProperty.Register(
        nameof(SelectedRoundness), typeof(double), typeof(MorphBorder), Changed(double.NaN));
    public static readonly DependencyProperty IsPressedProperty = DependencyProperty.Register(
        nameof(IsPressed), typeof(bool), typeof(MorphBorder), Changed(false));
    public static readonly DependencyProperty IsSelectedProperty = DependencyProperty.Register(
        nameof(IsSelected), typeof(bool), typeof(MorphBorder), Changed(false));
    public static readonly DependencyProperty MaxRadiusProperty = DependencyProperty.Register(
        nameof(MaxRadius), typeof(double), typeof(MorphBorder),
        new PropertyMetadata(double.PositiveInfinity, (d, _) => ((MorphBorder)d).UpdateRadius()));
    public static readonly DependencyProperty PositionProperty = DependencyProperty.Register(
        nameof(Position), typeof(GroupPosition), typeof(MorphBorder),
        new PropertyMetadata(GroupPosition.Single, (d, _) => ((MorphBorder)d).UpdateRadius()));
    public static readonly DependencyProperty InnerRadiusProperty = DependencyProperty.Register(
        nameof(InnerRadius), typeof(double), typeof(MorphBorder),
        new PropertyMetadata(8.0, (d, _) => ((MorphBorder)d).UpdateRadius()));

    private static readonly DependencyProperty ShownProperty = DependencyProperty.Register(
        "Shown", typeof(double), typeof(MorphBorder),
        new PropertyMetadata(double.NaN, (d, _) => ((MorphBorder)d).UpdateRadius()));
    private static readonly DependencyProperty JoinProperty = DependencyProperty.Register(
        "Join", typeof(double), typeof(MorphBorder),
        new PropertyMetadata(0.0, (d, _) => ((MorphBorder)d).UpdateRadius()));

    public MorphBorder() => SizeChanged += (_, _) => UpdateRadius();

    /// <summary>Скругление в покое (доля от половины меньшей стороны).</summary>
    public double Roundness { get => (double)GetValue(RoundnessProperty); set => SetValue(RoundnessProperty, value); }
    public double PressedRoundness { get => (double)GetValue(PressedRoundnessProperty); set => SetValue(PressedRoundnessProperty, value); }
    public double SelectedRoundness { get => (double)GetValue(SelectedRoundnessProperty); set => SetValue(SelectedRoundnessProperty, value); }
    public bool IsPressed { get => (bool)GetValue(IsPressedProperty); set => SetValue(IsPressedProperty, value); }
    public bool IsSelected { get => (bool)GetValue(IsSelectedProperty); set => SetValue(IsSelectedProperty, value); }
    public double MaxRadius { get => (double)GetValue(MaxRadiusProperty); set => SetValue(MaxRadiusProperty, value); }
    public GroupPosition Position { get => (GroupPosition)GetValue(PositionProperty); set => SetValue(PositionProperty, value); }
    public double InnerRadius { get => (double)GetValue(InnerRadiusProperty); set => SetValue(InnerRadiusProperty, value); }

    private double Target()
    {
        if (IsPressed && !double.IsNaN(PressedRoundness)) return PressedRoundness;
        if (IsSelected && !double.IsNaN(SelectedRoundness)) return SelectedRoundness;
        return Roundness;
    }

    private void Retarget()
    {
        double to = Target();
        double shown = (double)GetValue(ShownProperty);
        if (double.IsNaN(shown) || !IsLoaded)
        {
            BeginAnimation(ShownProperty, null);
            SetValue(ShownProperty, to);
        }
        else
        {
            // нажатие — быстро и без отскока, отпускание — с упругим перелётом
            BeginAnimation(ShownProperty, IsPressed
                ? M3Motion.To(to, 220, M3Motion.SpringEffects)
                : M3Motion.To(to, 650, M3Motion.SpringBouncy));
        }
        double join = IsSelected || IsPressed ? 1 : 0;
        if (IsLoaded) BeginAnimation(JoinProperty, M3Motion.To(join, 500, M3Motion.SpringSpatial));
        else SetValue(JoinProperty, join);
    }

    private void UpdateRadius()
    {
        double shown = (double)GetValue(ShownProperty);
        if (double.IsNaN(shown)) shown = Target();
        double full = Math.Min(Math.Max(0, shown) * Math.Min(ActualWidth, ActualHeight) / 2, MaxRadius);
        double inner = Math.Min(InnerRadius, full);
        inner += (full - inner) * Math.Clamp((double)GetValue(JoinProperty), 0, 1.2);
        CornerRadius = Position switch
        {
            GroupPosition.First => new CornerRadius(full, inner, inner, full),
            GroupPosition.Middle => new CornerRadius(inner),
            GroupPosition.Last => new CornerRadius(inner, full, full, inner),
            _ => new CornerRadius(full),
        };
    }

    /// <summary>Геометрия прямоугольника с разными радиусами углов (для обрезки).</summary>
    public static Geometry RoundedRect(Rect r, CornerRadius c)
    {
        double max = Math.Min(r.Width, r.Height) / 2;
        double tl = Math.Min(c.TopLeft, max), tr = Math.Min(c.TopRight, max);
        double br = Math.Min(c.BottomRight, max), bl = Math.Min(c.BottomLeft, max);
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(new Point(r.Left + tl, r.Top), true, true);
            ctx.LineTo(new Point(r.Right - tr, r.Top), false, false);
            ctx.ArcTo(new Point(r.Right, r.Top + tr), new Size(tr, tr), 0, false, SweepDirection.Clockwise, false, false);
            ctx.LineTo(new Point(r.Right, r.Bottom - br), false, false);
            ctx.ArcTo(new Point(r.Right - br, r.Bottom), new Size(br, br), 0, false, SweepDirection.Clockwise, false, false);
            ctx.LineTo(new Point(r.Left + bl, r.Bottom), false, false);
            ctx.ArcTo(new Point(r.Left, r.Bottom - bl), new Size(bl, bl), 0, false, SweepDirection.Clockwise, false, false);
            ctx.LineTo(new Point(r.Left, r.Top + tl), false, false);
            ctx.ArcTo(new Point(r.Left + tl, r.Top), new Size(tl, tl), 0, false, SweepDirection.Clockwise, false, false);
        }
        g.Freeze();
        return g;
    }
}

/// <summary>
/// Волна (ripple) от точки нажатия, обрезанная по скруглению фона.
/// Ставится в шаблон поверх фона; события берёт у TemplatedParent.
/// </summary>
public sealed class Ripple : FrameworkElement
{
    public static readonly DependencyProperty CornerRadiusProperty = DependencyProperty.Register(
        nameof(CornerRadius), typeof(CornerRadius), typeof(Ripple),
        new FrameworkPropertyMetadata(new CornerRadius(), FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty FillProperty = TextElement.ForegroundProperty.AddOwner(
        typeof(Ripple), new FrameworkPropertyMetadata(Brushes.Black,
            FrameworkPropertyMetadataOptions.Inherits | FrameworkPropertyMetadataOptions.AffectsRender));
    private static readonly DependencyProperty ScaleProperty = DependencyProperty.Register(
        "Scale", typeof(double), typeof(Ripple), new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));
    private static readonly DependencyProperty StrengthProperty = DependencyProperty.Register(
        "Strength", typeof(double), typeof(Ripple), new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    private UIElement? _owner;
    private Point _origin;

    public Ripple()
    {
        IsHitTestVisible = false;
        Loaded += (_, _) => Attach();
        Unloaded += (_, _) => Detach();
    }

    public CornerRadius CornerRadius { get => (CornerRadius)GetValue(CornerRadiusProperty); set => SetValue(CornerRadiusProperty, value); }
    public Brush Fill { get => (Brush)GetValue(FillProperty); set => SetValue(FillProperty, value); }

    private void Attach()
    {
        _owner = TemplatedParent as UIElement ?? VisualTreeHelper.GetParent(this) as UIElement;
        if (_owner == null) return;
        _owner.PreviewMouseLeftButtonDown += OnDown;
        _owner.PreviewMouseLeftButtonUp += OnUp;
        _owner.MouseLeave += OnUp;
        _owner.LostMouseCapture += OnUp;
    }

    private void Detach()
    {
        if (_owner == null) return;
        _owner.PreviewMouseLeftButtonDown -= OnDown;
        _owner.PreviewMouseLeftButtonUp -= OnUp;
        _owner.MouseLeave -= OnUp;
        _owner.LostMouseCapture -= OnUp;
        _owner = null;
    }

    private void OnDown(object sender, MouseButtonEventArgs e)
    {
        if (_owner is UIElement { IsEnabled: false }) return;
        _origin = e.GetPosition(this);
        BeginAnimation(ScaleProperty, new DoubleAnimation(0.15, 1, TimeSpan.FromMilliseconds(550))
        { EasingFunction = M3Motion.EmphasizedDecelerate });
        BeginAnimation(StrengthProperty, new DoubleAnimation(0.12, TimeSpan.FromMilliseconds(80)));
    }

    private void OnUp(object sender, EventArgs e)
    {
        if ((double)GetValue(StrengthProperty) <= 0) return;
        BeginAnimation(StrengthProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(350))
        { BeginTime = TimeSpan.FromMilliseconds(90) });
    }

    protected override void OnRender(DrawingContext dc)
    {
        double strength = (double)GetValue(StrengthProperty);
        if (strength <= 0.001 || ActualWidth <= 0) return;
        dc.PushClip(MorphBorder.RoundedRect(new Rect(RenderSize), CornerRadius));
        dc.PushOpacity(strength);
        double max = new[] { new Point(0, 0), new Point(ActualWidth, 0), new Point(0, ActualHeight), new Point(ActualWidth, ActualHeight) }
            .Max(p => (p - _origin).Length);
        double rad = max * (double)GetValue(ScaleProperty);
        dc.DrawEllipse(Fill, null, _origin, rad, rad);
        dc.Pop();
        dc.Pop();
    }
}

/// <summary>Содержимое со входной анимацией при смене (общая ось Y или «растворение»).</summary>
public sealed class TransitionPresenter : ContentControl
{
    public static readonly DependencyProperty KindProperty = DependencyProperty.Register(
        nameof(Kind), typeof(TransitionKind), typeof(TransitionPresenter), new PropertyMetadata(TransitionKind.SlideUp));

    /// <summary>Смена этого значения тоже проигрывает переход (например, шаг мастера).</summary>
    public static readonly DependencyProperty KeyProperty = DependencyProperty.Register(
        nameof(Key), typeof(object), typeof(TransitionPresenter),
        new PropertyMetadata(null, (d, _) => ((TransitionPresenter)d).Play()));

    public TransitionKind Kind { get => (TransitionKind)GetValue(KindProperty); set => SetValue(KindProperty, value); }
    public object? Key { get => GetValue(KeyProperty); set => SetValue(KeyProperty, value); }

    public TransitionPresenter()
    {
        Focusable = false;
        IsTabStop = false;
    }

    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);
        if (newContent != null) Play();
    }

    private void Play()
    {
        if (Content == null || !IsLoaded) return;
        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260)) { EasingFunction = M3Motion.EmphasizedDecelerate };
        BeginAnimation(OpacityProperty, fade);
        switch (Kind)
        {
            case TransitionKind.SlideUp:
            {
                var tt = new TranslateTransform();
                RenderTransform = tt;
                tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(36, 0, TimeSpan.FromMilliseconds(600))
                { EasingFunction = M3Motion.SpringSpatial });
                break;
            }
            case TransitionKind.SlideLeft:
            {
                var tt = new TranslateTransform();
                RenderTransform = tt;
                tt.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(48, 0, TimeSpan.FromMilliseconds(600))
                { EasingFunction = M3Motion.SpringSpatial });
                break;
            }
            case TransitionKind.Scale:
            {
                var st = new ScaleTransform();
                RenderTransformOrigin = new Point(0.5, 0.5);
                RenderTransform = st;
                var a = new DoubleAnimation(0.94, 1, TimeSpan.FromMilliseconds(500)) { EasingFunction = M3Motion.SpringSpatial };
                st.BeginAnimation(ScaleTransform.ScaleXProperty, a);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, a);
                break;
            }
        }
    }
}

public enum TransitionKind { Fade, SlideUp, SlideLeft, Scale }
