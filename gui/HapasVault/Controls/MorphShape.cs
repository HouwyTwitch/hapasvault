using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using HapasVault.Motion;

namespace HapasVault.Controls;

/// <summary>
/// Фон-форма M3 Expressive с содержимым по центру. Умеет морфинг в TargetShape
/// (свойство Morph), поворот, реакцию на наведение и медленное вращение.
/// </summary>
public sealed class MorphShape : Decorator
{
    private static FrameworkPropertyMetadata Render(object def) =>
        new(def, FrameworkPropertyMetadataOptions.AffectsRender);

    public static readonly DependencyProperty ShapeProperty =
        DependencyProperty.Register(nameof(Shape), typeof(ShapeKind), typeof(MorphShape), Render(ShapeKind.Cookie9));
    public static readonly DependencyProperty TargetShapeProperty =
        DependencyProperty.Register(nameof(TargetShape), typeof(ShapeKind), typeof(MorphShape), Render(ShapeKind.Circle));
    public static readonly DependencyProperty MorphProperty =
        DependencyProperty.Register(nameof(Morph), typeof(double), typeof(MorphShape), Render(0.0));
    public static readonly DependencyProperty AngleProperty =
        DependencyProperty.Register(nameof(Angle), typeof(double), typeof(MorphShape), Render(0.0));
    public static readonly DependencyProperty FillProperty =
        DependencyProperty.Register(nameof(Fill), typeof(Brush), typeof(MorphShape), Render(null!));
    public static readonly DependencyProperty StrokeProperty =
        DependencyProperty.Register(nameof(Stroke), typeof(Brush), typeof(MorphShape), Render(null!));
    public static readonly DependencyProperty StrokeThicknessProperty =
        DependencyProperty.Register(nameof(StrokeThickness), typeof(double), typeof(MorphShape), Render(0.0));
    public static readonly DependencyProperty HoverMorphProperty =
        DependencyProperty.Register(nameof(HoverMorph), typeof(bool), typeof(MorphShape), new PropertyMetadata(false));
    public static readonly DependencyProperty SpinProperty =
        DependencyProperty.Register(nameof(Spin), typeof(double), typeof(MorphShape),
            new PropertyMetadata(0.0, (d, _) => ((MorphShape)d).UpdateSpin()));
    public static readonly DependencyProperty IsMorphedProperty =
        DependencyProperty.Register(nameof(IsMorphed), typeof(bool), typeof(MorphShape),
            new PropertyMetadata(false, (d, e) => ((MorphShape)d).AnimateMorph((bool)e.NewValue)));

    public ShapeKind Shape { get => (ShapeKind)GetValue(ShapeProperty); set => SetValue(ShapeProperty, value); }
    public ShapeKind TargetShape { get => (ShapeKind)GetValue(TargetShapeProperty); set => SetValue(TargetShapeProperty, value); }
    public double Morph { get => (double)GetValue(MorphProperty); set => SetValue(MorphProperty, value); }
    public double Angle { get => (double)GetValue(AngleProperty); set => SetValue(AngleProperty, value); }
    public Brush? Fill { get => (Brush?)GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public Brush? Stroke { get => (Brush?)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public double StrokeThickness { get => (double)GetValue(StrokeThicknessProperty); set => SetValue(StrokeThicknessProperty, value); }
    /// <summary>При наведении морфинг в TargetShape и поворот на 1/8 оборота.</summary>
    public bool HoverMorph { get => (bool)GetValue(HoverMorphProperty); set => SetValue(HoverMorphProperty, value); }
    /// <summary>Постоянное вращение, градусов в секунду (0 — нет).</summary>
    public double Spin { get => (double)GetValue(SpinProperty); set => SetValue(SpinProperty, value); }
    /// <summary>Привязываемый переключатель морфинга (анимируется пружиной).</summary>
    public bool IsMorphed { get => (bool)GetValue(IsMorphedProperty); set => SetValue(IsMorphedProperty, value); }

    private readonly Stopwatch _clock = new();
    private double _spinBase;
    private bool _hooked;

    public MorphShape()
    {
        IsVisibleChanged += (_, _) => UpdateSpin();
        Unloaded += (_, _) => Hook(false);
        Loaded += (_, _) => UpdateSpin();
    }

    private void AnimateMorph(bool on) =>
        BeginAnimation(MorphProperty, M3Motion.To(on ? 1 : 0, 650, M3Motion.SpringBouncy));

    protected override void OnMouseEnter(MouseEventArgs e)
    {
        base.OnMouseEnter(e);
        if (!HoverMorph) return;
        AnimateMorph(true);
        if (Spin == 0) BeginAnimation(AngleProperty, M3Motion.To(45, 700, M3Motion.SpringBouncy));
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        if (!HoverMorph) return;
        AnimateMorph(IsMorphed);
        if (Spin == 0) BeginAnimation(AngleProperty, M3Motion.To(0, 700, M3Motion.SpringBouncy));
    }

    private void UpdateSpin() => Hook(Spin != 0 && IsVisible && IsLoaded);

    private void Hook(bool on)
    {
        if (on == _hooked) return;
        _hooked = on;
        if (on)
        {
            _spinBase = Angle;
            _clock.Restart();
            CompositionTarget.Rendering += OnFrame;
        }
        else
        {
            CompositionTarget.Rendering -= OnFrame;
            _clock.Stop();
        }
    }

    private void OnFrame(object? sender, EventArgs e) =>
        Angle = (_spinBase + _clock.Elapsed.TotalSeconds * Spin) % 360;

    protected override Size ArrangeOverride(Size arrangeSize)
    {
        if (Child != null)
        {
            var d = Child.DesiredSize;
            Child.Arrange(new Rect((arrangeSize.Width - d.Width) / 2, (arrangeSize.Height - d.Height) / 2, d.Width, d.Height));
        }
        return arrangeSize;
    }

    protected override void OnRender(DrawingContext dc)
    {
        double t = StrokeThickness;
        var r = new Rect(t / 2, t / 2, Math.Max(0, ActualWidth - t), Math.Max(0, ActualHeight - t));
        if (r.Width <= 0 || r.Height <= 0) return;
        var pen = Stroke != null && t > 0 ? new Pen(Stroke, t) { LineJoin = PenLineJoin.Round } : null;
        dc.DrawGeometry(Fill, pen, Shapes.Geometry(Shape, TargetShape, Morph, Angle, r));
    }
}
