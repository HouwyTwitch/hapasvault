// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Win32;

namespace HapasVault.Platform;

/// <summary>
/// Запуск вместе с Windows: значение в HKCU\...\Run (без прав администратора).
/// Реестр — единственный источник правды: выключить можно и из «Автозагрузки» диспетчера задач.
/// </summary>
public static class Autostart
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Name = "HapasVault";
    public const string TrayArg = "--tray";

    private static string Command => $"\"{Environment.ProcessPath}\" {TrayArg}";

    public static bool IsEnabled
    {
        get
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(Key);
                return k?.GetValue(Name) is string;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    /// <returns>false — реестр недоступен (политика), настройка не изменилась.</returns>
    public static bool Set(bool on)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(Key);
            if (on) k.SetValue(Name, Command);
            else k.DeleteValue(Name, throwOnMissingValue: false);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Программу перенесли в другую папку — автозапуск указывает на новое место.</summary>
    public static void Refresh()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(Key, writable: true);
            if (k?.GetValue(Name) is string cur && cur != Command) k.SetValue(Name, Command);
        }
        catch (Exception)
        {
            // не критично
        }
    }
}
