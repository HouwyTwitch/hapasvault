using System.Windows.Media;

namespace HapasVault.Theming;

public enum PaletteStyle { TonalSpot, Vibrant, Expressive }

public sealed record TonalPalette(double Hue, double Chroma)
{
    public Color Tone(double t) => ColorScience.FromTone(Hue, Chroma, t);
}

/// <summary>Цветовые роли Material 3 (имена ресурсов кистей совпадают с именами ролей).</summary>
public static class Roles
{
    public static readonly string[] All =
    [
        "Primary", "OnPrimary", "PrimaryContainer", "OnPrimaryContainer",
        "Secondary", "OnSecondary", "SecondaryContainer", "OnSecondaryContainer",
        "Tertiary", "OnTertiary", "TertiaryContainer", "OnTertiaryContainer",
        "Error", "OnError", "ErrorContainer", "OnErrorContainer",
        "Surface", "OnSurface", "OnSurfaceVariant", "SurfaceDim", "SurfaceBright",
        "SurfaceContainerLowest", "SurfaceContainerLow", "SurfaceContainer",
        "SurfaceContainerHigh", "SurfaceContainerHighest",
        "Outline", "OutlineVariant", "InverseSurface", "InverseOnSurface", "InversePrimary",
        "PrimaryFixed", "OnPrimaryFixed", "TertiaryFixed", "OnTertiaryFixed",
        "Scrim", "Shadow",
    ];
}

public static class Scheme
{
    public static Dictionary<string, Color> Build(Color seed, bool dark, PaletteStyle style)
    {
        var (_, seedC, h) = ColorScience.ToOklch(seed);
        // почти серый акцент: оттенок у такого цвета случаен, хрому держим низкой
        double k = Math.Clamp(seedC / 0.06, 0.25, 1);

        var (p, s, t, n, nv) = style switch
        {
            PaletteStyle.Vibrant => (
                new TonalPalette(h, 0.20 * k), new TonalPalette(h + 15, 0.07 * k),
                new TonalPalette(h + 50, 0.12 * k), new TonalPalette(h, 0.012 * k), new TonalPalette(h, 0.024 * k)),
            PaletteStyle.Expressive => (
                new TonalPalette(h - 30, 0.17 * k), new TonalPalette(h + 40, 0.09 * k),
                new TonalPalette(h + 120, 0.13 * k), new TonalPalette(h + 15, 0.014 * k), new TonalPalette(h + 15, 0.03 * k)),
            _ => (
                new TonalPalette(h, 0.13 * k), new TonalPalette(h, 0.045 * k),
                new TonalPalette(h + 60, 0.08 * k), new TonalPalette(h, 0.008 * k), new TonalPalette(h, 0.018 * k)),
        };
        var e = new TonalPalette(27, 0.19);

        Color P(double l, double d) => p.Tone(dark ? d : l);
        Color S(double l, double d) => s.Tone(dark ? d : l);
        Color T(double l, double d) => t.Tone(dark ? d : l);
        Color E(double l, double d) => e.Tone(dark ? d : l);
        Color N(double l, double d) => n.Tone(dark ? d : l);
        Color NV(double l, double d) => nv.Tone(dark ? d : l);

        return new Dictionary<string, Color>
        {
            ["Primary"] = P(40, 80), ["OnPrimary"] = P(100, 20),
            ["PrimaryContainer"] = P(90, 30), ["OnPrimaryContainer"] = P(30, 90),
            ["Secondary"] = S(40, 80), ["OnSecondary"] = S(100, 20),
            ["SecondaryContainer"] = S(90, 30), ["OnSecondaryContainer"] = S(30, 90),
            ["Tertiary"] = T(40, 80), ["OnTertiary"] = T(100, 20),
            ["TertiaryContainer"] = T(90, 30), ["OnTertiaryContainer"] = T(30, 90),
            ["Error"] = E(40, 80), ["OnError"] = E(100, 20),
            ["ErrorContainer"] = E(90, 30), ["OnErrorContainer"] = E(30, 90),
            ["Surface"] = N(98, 6), ["OnSurface"] = N(10, 90), ["OnSurfaceVariant"] = NV(30, 80),
            ["SurfaceDim"] = N(87, 6), ["SurfaceBright"] = N(98, 24),
            ["SurfaceContainerLowest"] = N(100, 4), ["SurfaceContainerLow"] = N(96, 10),
            ["SurfaceContainer"] = N(94, 12), ["SurfaceContainerHigh"] = N(92, 17),
            ["SurfaceContainerHighest"] = N(90, 22),
            ["Outline"] = NV(50, 60), ["OutlineVariant"] = NV(80, 30),
            ["InverseSurface"] = N(20, 90), ["InverseOnSurface"] = N(95, 20), ["InversePrimary"] = P(80, 40),
            ["PrimaryFixed"] = p.Tone(90), ["OnPrimaryFixed"] = p.Tone(10),
            ["TertiaryFixed"] = t.Tone(90), ["OnTertiaryFixed"] = t.Tone(10),
            ["Scrim"] = Colors.Black, ["Shadow"] = Colors.Black,
        };
    }
}
