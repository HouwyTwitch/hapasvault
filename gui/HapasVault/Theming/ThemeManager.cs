using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using HapasVault.Motion;
using Microsoft.Win32;

namespace HapasVault.Theming;

public enum ThemeMode { System, Light, Dark }

/// <summary>
/// Держит по одной SolidColorBrush на роль в ресурсах приложения и плавно
/// перекрашивает их при смене темы — все DynamicResource обновляются сами.
/// </summary>
public sealed class ThemeManager
{
    public static readonly Color DefaultSeed = Color.FromRgb(0x67, 0x50, 0xA4);

    /// <summary>Готовые цвета-источники для выбора в настройках.</summary>
    public static readonly (string Name, Color Seed)[] Presets =
    [
        ("Аметист", DefaultSeed),
        ("Океан", Color.FromRgb(0x00, 0x63, 0x9B)),
        ("Лагуна", Color.FromRgb(0x00, 0x6A, 0x6A)),
        ("Мох", Color.FromRgb(0x4C, 0x66, 0x2B)),
        ("Янтарь", Color.FromRgb(0x8B, 0x50, 0x00)),
        ("Коралл", Color.FromRgb(0xA4, 0x3B, 0x2E)),
        ("Фуксия", Color.FromRgb(0x9C, 0x2C, 0x78)),
        ("Графит", Color.FromRgb(0x5D, 0x5F, 0x66)),
    ];

    private readonly ResourceDictionary _res;
    private readonly Dictionary<string, ColorSource> _sources = new();

    public ThemeManager(ResourceDictionary resources)
    {
        _res = resources;
        foreach (var role in Roles.All)
        {
            // Кисти в ресурсах приложения WPF замораживает, и анимировать их нельзя.
            // Привязанная кисть заморозке не поддаётся, а анимируется её источник.
            var src = new ColorSource();
            var b = new SolidColorBrush();
            BindingOperations.SetBinding(b, SolidColorBrush.ColorProperty,
                new Binding(nameof(ColorSource.Color)) { Source = src });
            _sources[role] = src;
            _res[role] = b;
        }
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color or UserPreferenceCategory.VisualStyle)
                Application.Current?.Dispatcher.BeginInvoke(() => Apply(animate: true));
        };
    }

    public ThemeMode Mode { get; set; } = ThemeMode.System;
    public PaletteStyle Style { get; set; } = PaletteStyle.TonalSpot;
    /// <summary>null — акцентный цвет Windows.</summary>
    public Color? Seed { get; set; }

    public bool IsDark { get; private set; }
    public Color EffectiveSeed => Seed ?? WindowsAccent() ?? DefaultSeed;

    public event EventHandler? Changed;


    public void Apply(bool animate)
    {
        IsDark = Mode switch { ThemeMode.Dark => true, ThemeMode.Light => false, _ => WindowsIsDark() };
        var scheme = Scheme.Build(EffectiveSeed, IsDark, Style);
        var ease = new BezierEase { X1 = 0.2, Y1 = 0, X2 = 0, Y2 = 1 };
        foreach (var (role, color) in scheme)
        {
            var src = _sources[role];
            if (animate)
            {
                src.BeginAnimation(ColorSource.ColorProperty,
                    new ColorAnimation(color, TimeSpan.FromMilliseconds(450)) { EasingFunction = ease });
            }
            else
            {
                src.BeginAnimation(ColorSource.ColorProperty, null);
                src.Color = color;
            }
        }
        // цвета для эффектов (тени, градиенты) — без анимации
        foreach (var (role, color) in scheme) _res["Color." + role] = color;
        _scheme = scheme;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    private Dictionary<string, Color> _scheme = new();

    /// <summary>Итоговый цвет роли (без учёта текущей анимации).</summary>
    public Color Target(string role) => _scheme.TryGetValue(role, out var c) ? c : Colors.Transparent;

    public static bool WindowsIsDark()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static Color? WindowsAccent()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM");
            if (k?.GetValue("AccentColor") is int abgr)
                return Color.FromRgb((byte)abgr, (byte)(abgr >> 8), (byte)(abgr >> 16));
        }
        catch (Exception)
        {
        }
        return null;
    }
}

/// <summary>Анимируемый цвет — источник привязки для кистей темы.</summary>
public sealed class ColorSource : Animatable
{
    public static readonly DependencyProperty ColorProperty =
        DependencyProperty.Register(nameof(Color), typeof(Color), typeof(ColorSource), new PropertyMetadata(Colors.Transparent));

    public Color Color { get => (Color)GetValue(ColorProperty); set => SetValue(ColorProperty, value); }

    protected override Freezable CreateInstanceCore() => new ColorSource();
}
