using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;
using HapasVault.Platform;
using HapasVault.Services;
using HapasVault.Theming;
using Microsoft.Win32;

namespace HapasVault.ViewModels;

/// <summary>
/// Корень интерфейса: по состоянию токена выбирает экран, обрабатывает ошибки
/// связи централизованно, следит за бездействием и блокировкой Windows.
/// </summary>
public sealed partial class ShellViewModel : ObservableObject
{
    private readonly ITokenClient _real;
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly DispatcherTimer _idle = new() { Interval = TimeSpan.FromSeconds(5) };
    private DateTime _lastInput = DateTime.UtcNow;
    private int _errorDepth;

    public ShellViewModel(ITokenClient token, AppSettings settings, ThemeManager theme)
    {
        _real = token;
        Token = token;
        Settings = settings;
        Theme = theme;
        Token.Port = settings.Port;

        _poll.Tick += async (_, _) => await PollAsync();
        _idle.Tick += async (_, _) => await CheckIdleAsync();
        InputManager.Current.PreProcessInput += (_, e) =>
        {
            if (e.StagingItem.Input is MouseButtonEventArgs or KeyEventArgs or MouseWheelEventArgs) _lastInput = DateTime.UtcNow;
        };
        SystemEvents.SessionSwitch += (_, e) =>
        {
            if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect && Settings.LockWithWindows)
                Application.Current?.Dispatcher.BeginInvoke(async () => await LockAsync("Хранилище заблокировано вместе с Windows"));
        };
        SystemEvents.PowerModeChanged += (_, e) =>
        {
            if (e.Mode == PowerModes.Suspend)
                Application.Current?.Dispatcher.BeginInvoke(async () => await LockAsync("Хранилище заблокировано перед сном"));
        };
    }

    public ITokenClient Token { get; private set; }
    public AppSettings Settings { get; }
    public ThemeManager Theme { get; }
    public SnackbarViewModel Snackbar { get; } = new();
    public SecretClipboard Clipboard { get; } = new();
    public Radial.RadialController? Radial { get; set; }
    public GlobalHotkey? Hotkey { get; set; }

    /// <summary>Зарегистрировать сочетание радиального меню по настройкам. false — занято.</summary>
    public bool ApplyHotkey() => Hotkey == null || Hotkey.Set(Settings.RadialEnabled ? Settings.Hotkey : null);

    [ObservableProperty] private object? _page;
    [ObservableProperty] private DialogViewModel? _dialog;
    [ObservableProperty] private TokenInfo? _info;
    [ObservableProperty] private bool _isDemo;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsBusy))] private int _busy;

    public bool IsBusy => Busy > 0;

    public string Status => Page switch
    {
        _ when IsDemo => "Демо-режим",
        ConnectViewModel => "Токен не найден",
        PairViewModel => "Не сопряжён",
        WelcomeViewModel or SetupViewModel or RestoreViewModel => "Новый токен",
        LockViewModel => "Заблокирован",
        VaultShellViewModel => "Открыт",
        _ => "",
    };

    public bool IsOpen => Page is VaultShellViewModel;

    partial void OnPageChanged(object? value)
    {
        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(IsOpen));
    }

    partial void OnIsDemoChanged(bool value) => OnPropertyChanged(nameof(Status));

    public async Task StartAsync()
    {
        _poll.Start();
        _idle.Start();
        await RefreshAsync();
    }

    /// <summary>Выбрать экран по состоянию токена.</summary>
    public async Task RefreshAsync()
    {
        try
        {
            if (!Token.IsAttached) await Token.AttachAsync();
            if (!Token.IsPaired)
            {
                Show(() => new PairViewModel(this));
                return;
            }
            var info = await Token.GetInfoAsync();
            Info = info;
            if (!info.SetupDone)
            {
                if (Page is not SetupViewModel and not RestoreViewModel) Show(() => new WelcomeViewModel(this));
            }
            else if (!info.Unlocked)
            {
                Show(() => new LockViewModel(this));
            }
            else if (Page is not VaultShellViewModel)
            {
                var shell = new VaultShellViewModel(this);
                Page = shell;
                await shell.Vault.LoadAsync();
            }
        }
        catch (TokenException e)
        {
            await HandleErrorAsync(e);
        }
    }

    public void Show<T>(Func<T> make) where T : class
    {
        if (Page is not T) Page = make();
    }

    /// <summary>Выполнить операцию с токеном с индикатором и общей обработкой ошибок.</summary>
    public async Task<bool> RunAsync(Func<Task> op)
    {
        Busy++;
        try
        {
            await op();
            return true;
        }
        catch (TokenException e)
        {
            await HandleErrorAsync(e);
            return false;
        }
        finally
        {
            Busy--;
        }
    }

    public async Task<T?> RunAsync<T>(Func<Task<T>> op)
    {
        T? result = default;
        await RunAsync(async () => { result = await op(); });
        return result;
    }

    public async Task HandleErrorAsync(TokenException e)
    {
        if (_errorDepth > 2)
        {
            Snackbar.Show(e.Message);
            return;
        }
        _errorDepth++;
        try
        {
            switch (e.Error)
            {
                case TokenError.Disconnected:
                    Info = null;
                    Clipboard.Clear();
                    if (Page is ConnectViewModel c) c.Error = null;
                    else Page = new ConnectViewModel(this);
                    break;
                case TokenError.ForeignToken:
                    Page = new ConnectViewModel(this) { Error = e.Message + " Сбросьте токен на том компьютере или подключите свой." };
                    break;
                case TokenError.SessionLost:
                    // токен закрывает сессию при простое и блокирует хранилище
                    try
                    {
                        await Token.ConnectAsync();
                        if (Page is VaultShellViewModel) Snackbar.Show("Токен закрыл сессию из-за простоя. Хранилище заблокировано.");
                        await RefreshAsync();
                    }
                    catch (TokenException again)
                    {
                        await HandleErrorAsync(again);
                    }
                    break;
                case TokenError.TokenWasReset:
                    await Token.ForgetPairingAsync();
                    Snackbar.Show(e.Message);
                    await RefreshAsync();
                    break;
                case TokenError.Locked:
                    if (Page is VaultShellViewModel) Snackbar.Show("Хранилище заблокировано на токене");
                    await RefreshAsync();
                    break;
                case TokenError.NotPaired:
                case TokenError.NotSetup:
                    await RefreshAsync();
                    break;
                default:
                    Snackbar.Show(e.Message);
                    break;
            }
        }
        finally
        {
            _errorDepth--;
        }
    }

    // опрос: ищем токен, пока его нет; на экранах без открытого хранилища следим за отключением.
    // Когда хранилище открыто — не опрашиваем: любой кадр продлевает сессию и отменил бы
    // автоблокировку токена по простою.
    private async Task PollAsync()
    {
        if (Busy > 0 || Dialog != null) return;
        try
        {
            switch (Page)
            {
                case ConnectViewModel { Error: null }:
                case null:
                    await RefreshAsync();
                    break;
                case LockViewModel or PairViewModel or WelcomeViewModel:
                    if (!Token.IsAttached) await RefreshAsync();
                    else Info = await Token.GetInfoAsync();
                    if (Page is LockViewModel && Info is { Unlocked: true }) await RefreshAsync();
                    break;
            }
        }
        catch (TokenException e)
        {
            await HandleErrorAsync(e);
        }
    }

    private async Task CheckIdleAsync()
    {
        if (Page is not VaultShellViewModel || Settings.AutoLockMinutes <= 0) return;
        if (DateTime.UtcNow - _lastInput > TimeSpan.FromMinutes(Settings.AutoLockMinutes))
            await LockAsync("Хранилище заблокировано из-за бездействия");
    }

    public async Task LockAsync(string? reason = null)
    {
        if (Page is not VaultShellViewModel) return;
        Radial?.Close();
        Clipboard.Clear();
        Dialog?.Close(false);
        await RunAsync(() => Token.LockAsync());
        Page = new LockViewModel(this);
        if (reason != null) Snackbar.Show(reason);
    }

    [RelayCommand]
    private Task Lock() => LockAsync();

    public async Task<bool> ShowDialogAsync(DialogViewModel dialog)
    {
        Dialog = dialog;
        try
        {
            return await dialog.Result;
        }
        finally
        {
            if (Dialog == dialog) Dialog = null;
        }
    }

    [RelayCommand]
    private void CloseDialog() => Dialog?.Close(false);

    public async Task CopySecretAsync(string text, string what)
    {
        int seconds = Settings.ClearClipboard ? Settings.ClipboardSeconds : 0;
        if (await Clipboard.CopyAsync(text, seconds))
            Snackbar.Show(seconds > 0 ? $"{what} скопирован. Буфер очистится через {seconds} с" : $"{what} скопирован");
        else
            Snackbar.Show("Буфер обмена занят другой программой");
    }

    // ---------- демо и порт ----------

    public async Task EnterDemoAsync(DemoTokenClient? demo = null)
    {
        await Token.DetachAsync();
        if (!ReferenceEquals(Token, _real)) Token.Dispose();
        Token = demo ?? new DemoTokenClient();
        IsDemo = true;
        Page = null;
        await RefreshAsync();
        if (demo == null) Snackbar.Show($"Демо: мастер-пароль «{DemoTokenClient.Password}»");
    }

    public async Task ExitDemoAsync()
    {
        if (!IsDemo) return;
        Token.Dispose();
        Token = _real;
        IsDemo = false;
        Page = null;
        await RefreshAsync();
    }

    public async Task ChangePortAsync(ushort port)
    {
        Settings.Port = port;
        Settings.Save();
        Token.Port = port;
        await Token.DetachAsync();
        Page = null;
        await RefreshAsync();
    }

    public void Shutdown()
    {
        _poll.Stop();
        _idle.Stop();
        Radial?.Close();
        Hotkey?.Dispose();
        Clipboard.Clear();
        Token.Dispose();
        if (!ReferenceEquals(Token, _real)) _real.Dispose();
    }
}
