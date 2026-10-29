using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;
using HapasVault.Theming;
using Microsoft.Win32;

namespace HapasVault.ViewModels;

public sealed record LogRow(string IconKey, string Title, string Subtitle, bool Ok, string StatusText);

/// <summary>Журнал операций токена (последние 32, хранится в RAM токена).</summary>
public sealed partial class LogViewModel(ShellViewModel shell) : ObservableObject
{
    public ObservableCollection<LogRow> Rows { get; } = new();

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _summary = "";

    private static (string Icon, string Title) Describe(byte cmd) => cmd switch
    {
        0x21 => ("Icon.Encrypted", "Создание хранилища"),
        0x22 => ("Icon.RestartAlt", "Восстановление"),
        0x30 => ("Icon.LockOpen", "Открытие хранилища"),
        0x41 => ("Icon.Key", "Расшифровка записи"),
        0x42 => ("Icon.Add", "Новая запись"),
        0x43 => ("Icon.Delete", "Удаление записи"),
        0x51 => ("Icon.Download", "Резервная копия"),
        _ => ("Icon.Info", $"Команда 0x{cmd:X2}"),
    };

    [RelayCommand]
    public async Task LoadAsync()
    {
        IsLoading = true;
        var rows = await shell.RunAsync(() => shell.Token.GetLogAsync());
        IsLoading = false;
        if (rows == null) return;
        Rows.Clear();
        foreach (var r in rows)
        {
            var (icon, title) = Describe(r.Command);
            string sub = Ru.Ago(r.AgoSeconds) + (r.ItemId != 0 ? $" · запись #{r.ItemId}" : "");
            Rows.Add(new LogRow(r.Ok ? icon : "Icon.Error", title, sub, r.Ok, r.Ok ? "" : TokenException.DescribeStatus(r.Status)));
        }
        int fails = rows.Count(r => !r.Ok);
        Summary = Ru.Plural(rows.Count, "операция", "операции", "операций") +
                  (fails > 0 ? $" · неудачных: {fails}" : " · все успешны");
    }
}

public sealed partial class Swatch(string name, Color? seed) : ObservableObject
{
    public string Name { get; } = name;
    public Color? Seed { get; } = seed;
    public bool IsAccent => Seed == null;
    public Brush Brush { get; } = new SolidColorBrush(seed ?? ThemeManager.WindowsAccent() ?? ThemeManager.DefaultSeed);
    [ObservableProperty] private bool _isSelected;
}

/// <summary>Настройки: оформление, безопасность, токен.</summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;
    private bool _loading = true;

    public SettingsViewModel(ShellViewModel shell)
    {
        _shell = shell;
        var s = shell.Settings;
        Swatches.Add(new Swatch("Акцент Windows", null));
        foreach (var (name, seed) in ThemeManager.Presets) Swatches.Add(new Swatch(name, seed));
        foreach (var w in Swatches)
            w.IsSelected = w.Seed is { } c ? s.Seed == ToArgb(c) : s.Seed == null;
        Theme = s.Theme;
        Palette = s.Palette;
        AutoLock = s.AutoLockMinutes;
        LockWithWindows = s.LockWithWindows;
        ClearClipboard = s.ClearClipboard;
        PortText = s.Port.ToString(CultureInfo.InvariantCulture);
        _loading = false;
    }

    public ShellViewModel Shell => _shell;
    public ObservableCollection<Swatch> Swatches { get; } = new();
    public bool IsDemo => _shell.IsDemo;
    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "";

    [ObservableProperty] private ThemeMode _theme;
    [ObservableProperty] private PaletteStyle _palette;
    [ObservableProperty] private int _autoLock;
    [ObservableProperty] private bool _lockWithWindows;
    [ObservableProperty] private bool _clearClipboard;
    [ObservableProperty] private string _portText = "";
    [ObservableProperty] private string? _portError;
    [ObservableProperty] private string _tokenText = "";

    private static uint ToArgb(Color c) => (uint)(c.A << 24 | c.R << 16 | c.G << 8 | c.B);

    public async Task LoadAsync()
    {
        var info = await _shell.RunAsync(() => _shell.Token.GetInfoAsync());
        if (info != null)
            TokenText = $"Протокол v{info.Protocol} · {Ru.Plural(info.Count, "запись", "записи", "записей")} · " +
                        $"работает {Ru.Duration(info.UptimeSeconds)}";
    }

    private void ApplyTheme()
    {
        if (_loading) return;
        var t = _shell.Theme;
        t.Mode = Theme;
        t.Style = Palette;
        t.Seed = Swatches.FirstOrDefault(w => w.IsSelected)?.Seed;
        t.Apply(animate: true);
        var s = _shell.Settings;
        s.Theme = Theme;
        s.Palette = Palette;
        s.Seed = t.Seed is { } c ? ToArgb(c) : null;
        s.Save();
    }

    partial void OnThemeChanged(ThemeMode value) => ApplyTheme();
    partial void OnPaletteChanged(PaletteStyle value) => ApplyTheme();

    partial void OnAutoLockChanged(int value) => Save(s => s.AutoLockMinutes = value);
    partial void OnLockWithWindowsChanged(bool value) => Save(s => s.LockWithWindows = value);
    partial void OnClearClipboardChanged(bool value) => Save(s => s.ClearClipboard = value);

    private void Save(Action<Services.AppSettings> change)
    {
        if (_loading) return;
        change(_shell.Settings);
        _shell.Settings.Save();
    }

    [RelayCommand]
    private void PickSwatch(Swatch swatch)
    {
        foreach (var w in Swatches) w.IsSelected = w == swatch;
        ApplyTheme();
    }

    [RelayCommand]
    private async Task ApplyPort()
    {
        if (!ushort.TryParse(PortText.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) || port < 1024)
        {
            PortError = "Порт от 1024 до 65535";
            return;
        }
        PortError = null;
        if (port == _shell.Settings.Port) return;
        await _shell.ChangePortAsync(port);
    }

    [RelayCommand]
    private async Task Backup()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Сохранить резервную копию",
            FileName = $"hapasvault-{DateTime.Now:yyyy-MM-dd}.pmbak",
            Filter = "Резервная копия HapasVault (*.pmbak)|*.pmbak",
        };
        if (dlg.ShowDialog() != true) return;
        var blob = await _shell.RunAsync(() => _shell.Token.BackupAsync());
        if (blob == null) return;
        try
        {
            await File.WriteAllBytesAsync(dlg.FileName, blob);
            _shell.Snackbar.Show($"Копия сохранена: {Path.GetFileName(dlg.FileName)} ({blob.Length / 1024.0:0.#} КБ, зашифрована)");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _shell.Snackbar.Show("Не удалось записать файл: " + e.Message);
        }
    }

    [RelayCommand]
    private async Task FactoryReset()
    {
        bool ok = await _shell.ShowDialogAsync(new ConfirmDialogViewModel
        {
            Title = "Стереть токен?",
            Message = "Все записи и сопряжение будут удалены с токена без возможности отмены. " +
                      "Вернуть данные можно только по 24 словам и резервной копии.\n\nЧтобы продолжить, введите СБРОС.",
            ConfirmText = "Стереть всё",
            IsDanger = true,
            TypeToConfirm = "СБРОС",
            IconKey = "Icon.Warning",
        });
        if (!ok) return;
        if (await _shell.RunAsync(() => _shell.Token.FactoryResetAsync()))
        {
            _shell.Snackbar.Show("Токен стёрт");
            _shell.Page = null;
            await _shell.RefreshAsync();
        }
    }

    [RelayCommand]
    private Task ExitDemo() => _shell.ExitDemoAsync();
}
