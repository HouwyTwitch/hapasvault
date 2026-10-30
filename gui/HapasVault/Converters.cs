using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using HapasVault.Core;

namespace HapasVault;

/// <summary>Непустая строка / коллекция / не null → true.</summary>
public sealed class IsNotEmptyConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        null => false,
        string s => s.Length > 0,
        ICollection col => col.Count > 0,
        bool b => b,
        _ => true,
    };

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Видимость: «непусто» → Visible. Параметр "invert" — наоборот.</summary>
public sealed class VisibleWhenConverter : IValueConverter
{
    private static readonly IsNotEmptyConverter Test = new();

    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        bool on = (bool)Test.Convert(value, t, null, c);
        if (p is "invert") on = !on;
        return on ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Значение равно параметру (для RadioButton по enum/строке) — в обе стороны.</summary>
public sealed class EqualsConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value != null && p != null && string.Equals(value.ToString(), p.ToString(), StringComparison.Ordinal);

    public object? ConvertBack(object? value, Type t, object? p, CultureInfo c)
    {
        if (value is not true || p == null) return Binding.DoNothing;
        if (t.IsEnum) return Enum.Parse(t, p.ToString()!);
        if (t == typeof(int) || t == typeof(int?)) return int.Parse(p.ToString()!, CultureInfo.InvariantCulture);
        return p;
    }
}

/// <summary>Visible, если значение равно параметру (шаги мастера и т. п.).</summary>
public sealed class EqualsVisibleConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value != null && p != null && p.ToString()!.Split('|').Contains(value.ToString())
            ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value is not true;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => value is not true;
}

/// <summary>Оценка стойкости пароля → кисть роли (ошибка / третичный / основной).</summary>
public sealed class StrengthBrushConverter : IValueConverter
{
    public object? Convert(object? value, Type t, object? p, CultureInfo c)
    {
        string role = value switch
        {
            Strength.Weak => "Error",
            Strength.Fair => "Tertiary",
            _ => "Primary",
        };
        return Application.Current.TryFindResource(role) as Brush;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Имя ресурса (например, роли цвета или иконки) → сам ресурс.</summary>
public sealed class ResourceConverter : IValueConverter
{
    public object? Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is string key ? Application.Current.TryFindResource(key) : null;

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Число минус параметр (не меньше 0): максимальная высота диалога и т. п.</summary>
public sealed class SubtractConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        Math.Max(0, System.Convert.ToDouble(value, CultureInfo.InvariantCulture) -
                    System.Convert.ToDouble(p ?? 0, CultureInfo.InvariantCulture));

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}
