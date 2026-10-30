using System.Windows;
using System.Windows.Media;

namespace HapasVault.Controls;

/// <summary>Формы M3 Expressive (библиотека shapes).</summary>
public enum ShapeKind
{
    Circle, Cookie4, Cookie6, Cookie7, Cookie9, Cookie12, Clover4, Clover8,
    Sunny, VerySunny, SoftBurst, Burst, Flower, Triangle, Square, Pentagon,
    Hexagon, Oval, Pill, Gem,
}

/// <summary>
/// Каждая форма — полярная функция r(θ), заранее посчитанная в таблицу и
/// нормированная к max r = 1. Морфинг двух форм — интерполяция радиусов,
/// поэтому переход между любыми двумя формами гладкий.
/// </summary>
public static class Shapes
{
    public const int Samples = 360;

    private static readonly double[]?[] _tables = new double[Enum.GetValues<ShapeKind>().Length][];

    /// <summary>Формы для аватаров и декора (без круга и «острых»).</summary>
    public static readonly ShapeKind[] Decorative =
    [
        ShapeKind.Cookie4, ShapeKind.Cookie6, ShapeKind.Cookie7, ShapeKind.Cookie9, ShapeKind.Cookie12,
        ShapeKind.Clover4, ShapeKind.Clover8, ShapeKind.Sunny, ShapeKind.SoftBurst, ShapeKind.Flower,
        ShapeKind.Triangle, ShapeKind.Square, ShapeKind.Pentagon, ShapeKind.Hexagon, ShapeKind.Gem, ShapeKind.Pill,
    ];

    /// <summary>Стабильный хеш FNV-1a (string.GetHashCode меняется между запусками).</summary>
    public static uint Hash(string s)
    {
        uint h = 2166136261;
        foreach (char c in s) h = (h ^ c) * 16777619;
        return h;
    }

    public static ShapeKind ForText(string s) => Decorative[Hash(s) % (uint)Decorative.Length];

    public static double[] Table(ShapeKind k) => _tables[(int)k] ??= Build(k);

    private static double[] Build(ShapeKind k)
    {
        Func<double, double> f = k switch
        {
            ShapeKind.Circle => _ => 1,
            ShapeKind.Cookie4 => t => Wave(t - Math.PI / 4, 4, 0.20, 0.8),
            ShapeKind.Cookie6 => t => Wave(t, 6, 0.15, 0.85),
            ShapeKind.Cookie7 => t => Wave(t - Math.PI / 2, 7, 0.13, 0.85),
            ShapeKind.Cookie9 => t => Wave(t - Math.PI / 2, 9, 0.10, 0.9),
            ShapeKind.Cookie12 => t => Wave(t, 12, 0.075, 0.9),
            ShapeKind.Clover4 => t => Wave(t - Math.PI / 4, 4, 0.36, 0.45),
            ShapeKind.Clover8 => t => Wave(t, 8, 0.24, 0.5),
            ShapeKind.Sunny => t => Wave(t, 8, 0.11, 1.6),
            ShapeKind.VerySunny => t => Wave(t, 8, 0.20, 1.9),
            ShapeKind.SoftBurst => t => Wave(t, 10, 0.17, 1.5),
            ShapeKind.Burst => t => Wave(t, 12, 0.20, 2.0),
            ShapeKind.Flower => t => Wave(t, 8, 0.30, 0.35),
            ShapeKind.Triangle => RoundedPolygon(3, 0.30),
            ShapeKind.Square => RoundedPolygon(4, 0.30, phase: Math.PI / 4),
            ShapeKind.Pentagon => RoundedPolygon(5, 0.28),
            ShapeKind.Hexagon => RoundedPolygon(6, 0.25),
            ShapeKind.Gem => RoundedPolygon(6, 0.22, sx: 0.82),
            ShapeKind.Oval => t => SuperEllipse(t - Math.PI / 4, 1, 0.72, 2),
            ShapeKind.Pill => t => SuperEllipse(t - Math.PI / 4, 1, 0.56, 3),
            _ => _ => 1,
        };
        var r = new double[Samples];
        for (int i = 0; i < Samples; i++) r[i] = f(2 * Math.PI * i / Samples);
        double max = r.Max();
        for (int i = 0; i < Samples; i++) r[i] /= max;
        return r;
    }

    // Волна по окружности: n выпуклостей глубиной d; p > 1 заостряет вершины, p < 1 — впадины.
    private static double Wave(double t, int n, double d, double p) =>
        1 - d + d * Math.Pow((1 + Math.Cos(n * t)) / 2, p);

    private static double SuperEllipse(double t, double a, double b, double n) =>
        Math.Pow(Math.Pow(Math.Abs(Math.Cos(t)) / a, n) + Math.Pow(Math.Abs(Math.Sin(t)) / b, n), -1 / n);

    // Скруглённый правильный многоугольник = меньший многоугольник ⊕ круг радиуса rho.
    private static Func<double, double> RoundedPolygon(int n, double rho, double phase = 0, double sx = 1)
    {
        double a = 1 - rho;
        var v = Enumerable.Range(0, n)
            .Select(i => (X: a * sx * Math.Cos(-Math.PI / 2 + phase + 2 * Math.PI * i / n),
                          Y: a * Math.Sin(-Math.PI / 2 + phase + 2 * Math.PI * i / n)))
            .ToArray();

        double Dist(double x, double y)
        {
            bool inside = true;
            double best = double.MaxValue;
            for (int i = 0; i < n; i++)
            {
                var (ax, ay) = v[i];
                var (bx, by) = v[(i + 1) % n];
                if ((bx - ax) * (y - ay) - (by - ay) * (x - ax) < 0) inside = false;
                double dx = bx - ax, dy = by - ay;
                double u = Math.Clamp(((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy), 0, 1);
                best = Math.Min(best, Math.Sqrt(Math.Pow(x - ax - u * dx, 2) + Math.Pow(y - ay - u * dy, 2)));
            }
            return inside ? 0 : best;
        }

        return t =>
        {
            double lo = 0, hi = 2;
            for (int i = 0; i < 26; i++)
            {
                double m = (lo + hi) / 2;
                if (Dist(m * Math.Cos(t), m * Math.Sin(t)) <= rho) lo = m; else hi = m;
            }
            return lo;
        };
    }

    private static double Sample(double[] table, double theta)
    {
        double x = theta / (2 * Math.PI) * Samples;
        x %= Samples;
        if (x < 0) x += Samples;
        int i = (int)x;
        double f = x - i;
        return table[i % Samples] * (1 - f) + table[(i + 1) % Samples] * f;
    }

    /// <summary>Геометрия формы (с морфингом в target и поворотом) в прямоугольнике.</summary>
    public static StreamGeometry Geometry(ShapeKind from, ShapeKind to, double morph, double angleDeg, Rect bounds)
    {
        var a = Table(from);
        var b = Table(to);
        double rot = angleDeg * Math.PI / 180;
        double cx = bounds.X + bounds.Width / 2, cy = bounds.Y + bounds.Height / 2;
        double rx = bounds.Width / 2, ry = bounds.Height / 2;
        morph = Math.Clamp(morph, -0.2, 1.2);   // пружина может чуть перелететь

        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            const int n = 180;
            var pts = new Point[n];
            for (int i = 0; i < n; i++)
            {
                double t = 2 * Math.PI * i / n;
                double r = Sample(a, t - rot) * (1 - morph) + Sample(b, t - rot) * morph;
                pts[i] = new Point(cx + rx * r * Math.Cos(t), cy + ry * r * Math.Sin(t));
            }
            ctx.BeginFigure(pts[0], true, true);
            ctx.PolyLineTo(pts.Skip(1).ToArray(), false, true);
        }
        g.Freeze();
        return g;
    }
}
