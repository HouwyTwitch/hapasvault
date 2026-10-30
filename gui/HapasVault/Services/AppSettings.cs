using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using HapasVault.Core;
using HapasVault.Platform;
using HapasVault.Theming;

namespace HapasVault.Services;

/// <summary>Настройки интерфейса (%APPDATA%\HapasVault\settings.json). Секретов здесь нет.</summary>
public sealed class AppSettings
{
    public static string Folder { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HapasVault");

    private static string FilePath => Path.Combine(Folder, "settings.json");

    /// <summary>Ключ этого ПК (защищён DPAPI в pmapi).</summary>
    public static string IdentityPath => Path.Combine(Folder, "pmclient.id");

    public ThemeMode Theme { get; set; } = ThemeMode.System;
    public PaletteStyle Palette { get; set; } = PaletteStyle.TonalSpot;
    /// <summary>ARGB цвета-источника; null — акцент Windows.</summary>
    public uint? Seed { get; set; }
    public int AutoLockMinutes { get; set; } = 5;
    public bool LockWithWindows { get; set; } = true;
    public bool ClearClipboard { get; set; } = true;
    public int ClipboardSeconds { get; set; } = 30;
    public ushort Port { get; set; } = 47123;
    /// <summary>Авто: USB-токен, если подключён, иначе симулятор.</summary>
    public TokenConnection Connection { get; set; } = TokenConnection.Auto;
    public bool RadialEnabled { get; set; } = true;
    public HotkeyChoice Hotkey { get; set; } = HotkeyChoice.CtrlAltSpace;
    /// <summary>Нажимать Enter после автоввода пароля.</summary>
    public bool AutoTypeEnter { get; set; } = true;
    /// <summary>Скрывать окна от захвата экрана (скриншоты, запись, демонстрация).</summary>
    public bool HideFromCapture { get; set; } = true;
    /// <summary>Раз в запуск спрашивать GitHub, нет ли новой версии.</summary>
    public bool CheckUpdates { get; set; } = true;

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Json) ?? new AppSettings();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Folder);
            // через временный файл: сбой посреди записи не обнулит настройки
            string tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
