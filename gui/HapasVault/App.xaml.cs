using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Interop;
using HapasVault.Core;
using HapasVault.Platform;
using HapasVault.Services;
using HapasVault.Theming;
using HapasVault.ViewModels;

namespace HapasVault;

/// <summary>
/// Запуск:  HapasVault.exe [--demo] [--screenshots &lt;каталог&gt;]
///   --demo         без токена, данные в памяти;
///   --screenshots  отрисовать все экраны в PNG и выйти (для CI).
/// </summary>
public partial class App : Application
{
    private Mutex? _single;
    private ShellViewModel? _shell;

    private static string CrashLog => Path.Combine(AppSettings.Folder, "crash.log");

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string? shots = ArgValue(e.Args, "--screenshots");
        bool demo = shots != null || e.Args.Contains("--demo");

        if (shots == null)
        {
            _single = new Mutex(true, @"Local\HapasVault.SingleInstance", out bool first);
            if (!first)
            {
                MessageBox.Show("HapasVault уже запущен.", "HapasVault", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }
        }
        DispatcherUnhandledException += OnCrash;

        var settings = AppSettings.Load();
        var theme = new ThemeManager(Resources)
        {
            Mode = settings.Theme,
            Style = settings.Palette,
            Seed = settings.Seed is uint argb ? Color.FromArgb(0xFF, (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb) : null,
        };
        theme.Apply(animate: false);

        ITokenClient token;
        string? nativeProblem = null;
        try
        {
            token = new TokenClient(AppSettings.IdentityPath);
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException or TokenException)
        {
            // без pmapi.dll работать с токеном нельзя, но интерфейс можно посмотреть
            token = new DemoTokenClient();
            nativeProblem = "Не найден pmapi.dll — запущен демо-режим.";
            demo = true;
        }

        _shell = new ShellViewModel(token, settings, theme);
        var window = new MainWindow { DataContext = _shell };
        theme.Changed += (_, _) => window.ApplyChrome();
        MainWindow = window;
        window.Show();

        if (shots != null)
        {
            int code = await Screenshots.RunAsync(window, _shell, shots);
            Shutdown(code);
            return;
        }
        _shell.Radial = new Radial.RadialController(_shell);
        _shell.Hotkey = new GlobalHotkey(new WindowInteropHelper(window).Handle);
        _shell.Hotkey.Pressed += async (_, _) => await _shell.Radial.ToggleAsync();
        bool hotkeyOk = _shell.ApplyHotkey();

        if (demo) await _shell.EnterDemoAsync();
        await _shell.StartAsync();
        if (settings.CheckUpdates && !demo) _ = _shell.CheckUpdatesAsync(silent: true);
        if (nativeProblem != null) _shell.Snackbar.Show(nativeProblem);
        if (!hotkeyOk)
            _shell.Snackbar.Show($"Сочетание {GlobalHotkey.Describe(settings.Hotkey)} занято другой программой — выберите другое в настройках");
    }

    private static string? ArgValue(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private void OnCrash(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(AppSettings.Folder);
            File.AppendAllText(CrashLog, $"{DateTime.Now:O}\n{e.Exception}\n\n");
        }
        catch (IOException)
        {
        }
        if (_shell == null) return;   // при старте пусть упадёт с системным отчётом
        _shell.Snackbar.Show("Что-то пошло не так: " + e.Exception.Message);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shell?.Shutdown();   // отключение = токен блокирует хранилище
        _single?.Dispose();
        base.OnExit(e);
    }
}
