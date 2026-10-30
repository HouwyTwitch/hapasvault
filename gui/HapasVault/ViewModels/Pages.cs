using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;

namespace HapasVault.ViewModels;

/// <summary>Токен не найден: ищем его, предлагаем демо.</summary>
public sealed partial class ConnectViewModel(ShellViewModel shell) : ObservableObject
{
    public ShellViewModel Shell { get; } = shell;

    /// <summary>Ошибка, при которой автоматический поиск бессмыслен (чужой токен).</summary>
    [ObservableProperty] private string? _error;

    public string Hint => Shell.Settings.Connection switch
    {
        TokenConnection.Usb => "Подключите токен к USB. Драйвер не нужен: Windows видит его как COM-порт.",
        TokenConnection.Simulator => $"Запустите pmtoken_sim. Ищу на 127.0.0.1:{Shell.Settings.Port}",
        _ => $"Подключите токен к USB или запустите pmtoken_sim (127.0.0.1:{Shell.Settings.Port})",
    };

    [RelayCommand]
    private async Task Retry()
    {
        Error = null;
        await Shell.RefreshAsync();
    }

    [RelayCommand]
    private Task Demo() => Shell.EnterDemoAsync();
}

/// <summary>
/// Первое знакомство ПК и токена: обмен статическими ключами X25519.
/// Токен запоминает первый ПК и до сброса отказывает остальным.
/// </summary>
public sealed partial class PairViewModel(ShellViewModel shell) : ObservableObject
{
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string? _error;

    [RelayCommand]
    private async Task Pair()
    {
        Error = null;
        IsWorking = true;
        try
        {
            await shell.Token.PairAsync();
            shell.Snackbar.Show("Токен сопряжён с этим компьютером");
            await shell.RefreshAsync();
        }
        catch (TokenException e) when (e.Error is TokenError.AlreadyPaired)
        {
            Error = e.Message;
        }
        catch (TokenException e)
        {
            await shell.HandleErrorAsync(e);
        }
        finally
        {
            IsWorking = false;
        }
    }
}

/// <summary>Токен сопряжён, но пуст: создать новое хранилище или восстановить.</summary>
public sealed partial class WelcomeViewModel(ShellViewModel shell) : ObservableObject
{
    [RelayCommand]
    private void Create() => shell.Page = new SetupViewModel(shell);

    [RelayCommand]
    private void Restore() => shell.Page = new RestoreViewModel(shell);
}

/// <summary>Хранилище закрыто: мастер-пароль.</summary>
public sealed partial class LockViewModel(ShellViewModel shell) : ObservableObject
{
    public ShellViewModel Shell { get; } = shell;

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(UnlockCommand))] private string _password = "";
    [ObservableProperty] private string? _error;
    [ObservableProperty] private int _shake;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(UnlockCommand))] private bool _isWorking;

    public bool HasKey => Shell.Token.HasKey;

    public string Subtitle => Shell.Info is { } i
        ? $"{Ru.Plural(i.Count, "запись", "записи", "записей")} · токен подключён {Ru.Duration(i.UptimeSeconds)}"
        : "Токен подключён";

    partial void OnPasswordChanged(string value) => Error = null;

    private bool CanUnlock() => Password.Length > 0 && !IsWorking && HasKey;

    [RelayCommand(CanExecute = nameof(CanUnlock))]
    private async Task Unlock()
    {
        IsWorking = true;
        try
        {
            await Shell.Token.UnlockAsync(Password);
            Password = "";
            await Shell.RefreshAsync();
        }
        catch (TokenException e) when (e.Error is TokenError.WrongPassword or TokenError.Backoff)
        {
            Error = e.Message;
            Shake++;
        }
        catch (TokenException e)
        {
            await Shell.HandleErrorAsync(e);
        }
        finally
        {
            IsWorking = false;
        }
    }
}
