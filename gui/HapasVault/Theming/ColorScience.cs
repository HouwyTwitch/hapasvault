using System.Windows.Media;

namespace HapasVault.Theming;

/// <summary>
/// Цветовая математика для тональных палитр M3.
/// Тон = L* (CIELAB), как в Material: тон 40 на тоне 100 всегда даёт контраст ≥ 4.5:1.
/// Оттенок и хрома — в OKLCH: в нём синие не «уплывают» в фиолетовый при смене тона.
/// </summary>
public static class ColorScience
{
    public static double ToLinear(double c) => c <= 0.04045 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
    public static double FromLinear(double c) => c <= 0.0031308 ? 12.92 * c : 1.055 * Math.Pow(c, 1 / 2.4) - 0.055;

    public static double YToLstar(double y) => y > 216.0 / 24389 ? 116 * Math.Cbrt(y) - 16 : y * 24389.0 / 27;

    public static double LuminanceY(double r, double g, double b) => 0.2126 * r + 0.7152 * g + 0.0722 * b;

    public static (double L, double C, double H) ToOklch(Color c)
    {
        var (l, a, b) = LinearToOklab(ToLinear(c.R / 255.0), ToLinear(c.G / 255.0), ToLinear(c.B / 255.0));
        double h = Math.Atan2(b, a) * 180 / Math.PI;
        return (l, Math.Sqrt(a * a + b * b), h < 0 ? h + 360 : h);
    }

    public static double Tone(Color c) =>
        YToLstar(LuminanceY(ToLinear(c.R / 255.0), ToLinear(c.G / 255.0), ToLinear(c.B / 255.0)));

    private static (double L, double a, double b) LinearToOklab(double r, double g, double b)
    {
        double l = Math.Cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
        double m = Math.Cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
        double s = Math.Cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
        return (0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
                1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
                0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s);
    }

    private static (double r, double g, double b) OklchToLinear(double L, double C, double hDeg)
    {
        double h = hDeg * Math.PI / 180, a = C * Math.Cos(h), b = C * Math.Sin(h);
        double l = L + 0.3963377774 * a + 0.2158037573 * b;
        double m = L - 0.1055613458 * a - 0.0638541728 * b;
        double s = L - 0.0894841775 * a - 1.2914855480 * b;
        l *= l * l; m *= m * m; s *= s * s;
        return (+4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
                -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
                -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s);
    }

    /// <summary>
    /// Цвет с заданным тоном (L*), оттенком и хромой OKLCH. Если такой хромы нет в sRGB —
    /// берётся максимальная достижимая при этом тоне и оттенке.
    /// </summary>
    public static Color FromTone(double hue, double chroma, double tone)
    {
        if (tone <= 0.5) return Colors.Black;
        if (tone >= 99.5) return Colors.White;

        if (TrySolve(hue, chroma, tone, out var rgb)) return ToColor(rgb);
        double lo = 0, hi = chroma;
        TrySolve(hue, 0, tone, out var best);
        for (int i = 0; i < 18; i++)
        {
            double mid = (lo + hi) / 2;
            if (TrySolve(hue, mid, tone, out var cand)) { lo = mid; best = cand; }
            else hi = mid;
        }
        return ToColor(best);
    }

    // Подобрать L (OKLCH) так, чтобы L* совпал с тоном; true — если цвет в гамме sRGB.
    private static bool TrySolve(double hue, double chroma, double tone, out (double r, double g, double b) rgb)
    {
        double lo = 0, hi = 1;
        rgb = default;
        for (int i = 0; i < 28; i++)
        {
            double mid = (lo + hi) / 2;
            rgb = OklchToLinear(mid, chroma, hue);
            double t = YToLstar(Math.Max(0, LuminanceY(rgb.r, rgb.g, rgb.b)));
            if (t < tone) lo = mid; else hi = mid;
        }
        const double eps = 1e-4;
        return rgb.r >= -eps && rgb.r <= 1 + eps && rgb.g >= -eps && rgb.g <= 1 + eps && rgb.b >= -eps && rgb.b <= 1 + eps;
    }

    private static Color ToColor((double r, double g, double b) c)
    {
        static byte B(double v) => (byte)Math.Round(Math.Clamp(FromLinear(Math.Clamp(v, 0, 1)), 0, 1) * 255);
        return Color.FromRgb(B(c.r), B(c.g), B(c.b));
    }

    public static Color WithAlpha(Color c, double a) => Color.FromArgb((byte)Math.Round(a * 255), c.R, c.G, c.B);
}
