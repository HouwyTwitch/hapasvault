using System.Windows;
using System.Windows.Media.Animation;

namespace HapasVault.Motion;

/// <summary>
/// Пружина M3 Expressive, нормированная на длительность анимации: к t = 1 пружина
/// успокаивается. Damping &lt; 1 даёт перелёт (0.9 — едва заметный, 0.5 — упругий).
/// </summary>
public sealed class SpringEase : EasingFunctionBase
{
    public static readonly DependencyProperty DampingProperty =
        DependencyProperty.Register(nameof(Damping), typeof(double), typeof(SpringEase), new PropertyMetadata(0.8));

    public SpringEase() => EasingMode = EasingMode.EaseIn;   // EaseInCore = сама кривая

    public double Damping
    {
        get => (double)GetValue(DampingProperty);
        set => SetValue(DampingProperty, value);
    }

    public static double Evaluate(double t, double damping)
    {
        if (t >= 1) return 1;
        double z = Math.Clamp(damping, 0.05, 2);
        if (z >= 1)
        {
            const double w = 8;
            return 1 - Math.Exp(-w * t) * (1 + w * t);
        }
        double w0 = 6.2 / z;                    // огибающая e^(-z·w0·t) ≈ 0.002 при t = 1
        double wd = w0 * Math.Sqrt(1 - z * z);
        return 1 - Math.Exp(-z * w0 * t) * (Math.Cos(wd * t) + z * w0 / wd * Math.Sin(wd * t));
    }

    protected override double EaseInCore(double t) => Evaluate(t, Damping);

    protected override Freezable CreateInstanceCore() => new SpringEase();
}

/// <summary>cubic-bezier(x1, y1, x2, y2), как в CSS. Emphasized M3: (0.05, 0.7, 0.1, 1).</summary>
public sealed class BezierEase : EasingFunctionBase
{
    public static readonly DependencyProperty X1Property = Reg(nameof(X1), 0.2);
    public static readonly DependencyProperty Y1Property = Reg(nameof(Y1), 0.0);
    public static readonly DependencyProperty X2Property = Reg(nameof(X2), 0.0);
    public static readonly DependencyProperty Y2Property = Reg(nameof(Y2), 1.0);

    private static DependencyProperty Reg(string name, double def) =>
        DependencyProperty.Register(name, typeof(double), typeof(BezierEase), new PropertyMetadata(def));

    public BezierEase() => EasingMode = EasingMode.EaseIn;

    public double X1 { get => (double)GetValue(X1Property); set => SetValue(X1Property, value); }
    public double Y1 { get => (double)GetValue(Y1Property); set => SetValue(Y1Property, value); }
    public double X2 { get => (double)GetValue(X2Property); set => SetValue(X2Property, value); }
    public double Y2 { get => (double)GetValue(Y2Property); set => SetValue(Y2Property, value); }

    public static double Evaluate(double x, double x1, double y1, double x2, double y2)
    {
        if (x <= 0) return 0;
        if (x >= 1) return 1;
        static double B(double t, double a, double b) => 3 * a * t * (1 - t) * (1 - t) + 3 * b * t * t * (1 - t) + t * t * t;
        double lo = 0, hi = 1, s = x;
        for (int i = 0; i < 24; i++)
        {
            s = (lo + hi) / 2;
            if (B(s, x1, x2) < x) lo = s; else hi = s;
        }
        return B(s, y1, y2);
    }

    protected override double EaseInCore(double t) => Evaluate(t, X1, Y1, X2, Y2);

    protected override Freezable CreateInstanceCore() => new BezierEase();
}

/// <summary>Готовые кривые и длительности M3.</summary>
public static class M3Motion
{
    public static readonly IEasingFunction Emphasized = Freeze(new BezierEase { X1 = 0.2, Y1 = 0, X2 = 0, Y2 = 1 });
    public static readonly IEasingFunction EmphasizedDecelerate = Freeze(new BezierEase { X1 = 0.05, Y1 = 0.7, X2 = 0.1, Y2 = 1 });
    public static readonly IEasingFunction EmphasizedAccelerate = Freeze(new BezierEase { X1 = 0.3, Y1 = 0, X2 = 0.8, Y2 = 0.15 });
    public static readonly IEasingFunction SpringSpatial = Freeze(new SpringEase { Damping = 0.72 });
    public static readonly IEasingFunction SpringBouncy = Freeze(new SpringEase { Damping = 0.5 });
    public static readonly IEasingFunction SpringEffects = Freeze(new SpringEase { Damping = 1 });

    private static IEasingFunction Freeze(EasingFunctionBase e)
    {
        e.Freeze();
        return e;
    }

    public static DoubleAnimation To(double to, double ms, IEasingFunction? ease = null) =>
        new(to, TimeSpan.FromMilliseconds(ms)) { EasingFunction = ease ?? SpringSpatial };
}
