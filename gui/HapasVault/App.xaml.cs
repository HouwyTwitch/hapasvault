// SPDX-License-Identifier: GPL-3.0-or-later
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
/// Запуск:  HapasVault.exe [--demo] [--tray] [--screenshots &lt;каталог&gt;]
///   --demo         без токена, данные в памяти;
///   --tray         сразу в трей (автозапуск с Windows);
///   --screenshots  отрисовать все экраны в PNG и выйти (для CI).
/// </summary>
public partial class App : Application
{
    private Mutex? _single;
    private EventWaitHandle? _showSignal;
    private ShellViewModel? _shell;
    private TrayIcon? _tray;
    private bool _exiting, _trayHintShown;

    private static string CrashLog => Path.Combine(AppSettings.Folder, "crash.log");

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string? shots = ArgValue(e.Args, "--screenshots");
        bool demo = shots != null || e.Args.Contains("--demo");
        bool startHidden = shots == null && e.Args.Contains(Platform.Autostart.TrayArg);

        if (shots == null)
        {
            _single = new Mutex(true, @"Local\HapasVault.SingleInstance", out bool first);
            _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\HapasVault.Show");
            if (!first)
            {
                // уже запущен (возможно, в трее) — просим его показаться
                _showSignal.Set();
                Shutdown();
                return;
            }
            ThreadPool.RegisterWaitForSingleObject(_showSignal, (_, _) => Dispatcher.BeginInvoke(ShowFromTray), null, -1, false);
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
        ShutdownMode = ShutdownMode.OnExplicitShutdown;    // окно прячется в трей, выход — явный
        if (startHidden) new WindowInteropHelper(window).EnsureHandle();   // окно-владелец для трея и горячей клавиши
        else window.Show();
        UpdateIcons(window, theme);
        theme.Changed += (_, _) => UpdateIcons(window, theme);

        if (shots != null)
        {
            int code = await Screenshots.RunAsync(window, _shell, shots);
            Shutdown(code);
            return;
        }
        _tray = new TrayIcon(window);
        _tray.Open += (_, _) => ShowFromTray();
        _tray.Menu += (_, _) => ShowTrayMenu();
        UpdateIcons(window, theme);
        window.Closing += (_, ev) =>
        {
            if (_exiting) return;
            ev.Cancel = true;
            if (settings.CloseToTray) HideToTray();
            else ExitApp();
        };
        _shell.Radial = new Radial.RadialController(_shell);
        _shell.Hotkey = new GlobalHotkey(new WindowInteropHelper(window).Handle);
        _shell.Hotkey.Pressed += async (_, _) => await _shell.Radial.ToggleAsync();
        bool hotkeyOk = _shell.ApplyHotkey();

        if (!demo) Platform.Autostart.Refresh();
        if (demo) await _shell.EnterDemoAsync();
        await _shell.StartAsync();
        if (settings.CheckUpdates && !demo) _ = _shell.CheckUpdatesAsync(silent: true);
        if (nativeProblem != null) _shell.Snackbar.Show(nativeProblem);
        if (!hotkeyOk)
            _shell.Snackbar.Show($"Сочетание {GlobalHotkey.Describe(settings.Hotkey)} занято другой программой — выберите другое в настройках");
    }

    /// <summary>Иконка окна, панели задач и трея — знак из заголовка в цветах текущей палитры.</summary>
    private void UpdateIcons(Window window, ThemeManager theme)
    {
        Color fill = theme.Target("Primary"), on = theme.Target("OnPrimary");
        window.Icon = AppIcon.WindowIcon(AppIcon.Ico(fill, on));
        if (_tray == null) return;
        int px = (int)Math.Round(16 * VisualTreeHelper.GetDpi(window).DpiScaleX);
        _tray.SetIcon(AppIcon.Handle(fill, on, Math.Max(16, px)), "HapasVault");
    }

    private void HideToTray()
    {
        MainWindow?.Hide();
        if (_trayHintShown || _shell?.Settings.TrayHintShown == true) return;
        _trayHintShown = true;
        _tray?.Notify("HapasVault работает в трее", "Горячая клавиша и автоблокировка действуют. Выход — правой кнопкой по значку.");
        if (_shell != null) { _shell.Settings.TrayHintShown = true; _shell.Settings.Save(); }
    }

    private void ShowFromTray()
    {
        if (MainWindow is not { } w) return;
        w.Show();
        if (w.WindowState == WindowState.Minimized) w.WindowState = WindowState.Normal;
        w.Activate();
        w.Topmost = true;      // вперёд, даже если фокус у другой программы
        w.Topmost = false;
        w.Focus();
    }

    private void ShowTrayMenu()
    {
        if (_shell == null) return;
        var menu = new System.Windows.Controls.ContextMenu { Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint };
        System.Windows.Controls.MenuItem Item(string text, Action act)
        {
            var mi = new System.Windows.Controls.MenuItem { Header = text };
            mi.Click += (_, _) => act();
            return mi;
        }
        menu.Items.Add(Item("Открыть HapasVault", ShowFromTray));
        if (_shell.Page is VaultShellViewModel)
            menu.Items.Add(Item("Заблокировать", () => _ = _shell.LockAsync()));
        menu.Items.Add(new System.Windows.Controls.Separator());
        menu.Items.Add(Item("Выход", ExitApp));
        if (MainWindow != null) new WindowInteropHelper(MainWindow).EnsureHandle();
        menu.IsOpen = true;
    }

    private void ExitApp()
    {
        _exiting = true;
        MainWindow?.Close();
        Shutdown();
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
        _tray?.Dispose();
        _showSignal?.Dispose();
        _single?.Dispose();
        base.OnExit(e);
    }
}
