// SPDX-License-Identifier: GPL-3.0-or-later
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
/// Знакомство ПК и токена. Чистый токен — обмен ключами X25519 (первый ПК).
/// Настроенный (уже работает с другим ПК) — привязка по 24 словам: до 4 ПК на токен.
/// </summary>
public sealed partial class PairViewModel : ObservableObject
{
    private readonly ShellViewModel shell;

    public PairViewModel(ShellViewModel shell)
    {
        this.shell = shell;
        _ = CheckAsync();
    }

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(PairWordsCommand))] private bool _isWorking;
    [ObservableProperty] private string? _error;
    /// <summary>Токен уже настроен: этот ПК привязывается по 24 словам.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Title), nameof(Text))] private bool _needsWords;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(PairWordsCommand))] private string _words = "";
    [ObservableProperty] private string _tokenInfo = "";

    public string Title => NeedsWords ? "Привязать этот компьютер" : "Сопряжение с токеном";
    public string Text => NeedsWords
        ? "Этот токен уже работает с другим компьютером. Введите 24 слова восстановления — токен узнает, что вы владелец, и запомнит этот ПК (до 4 компьютеров). Данные остаются на токене."
        : "Компьютер и токен обменяются ключами. Остальные компьютеры потом привязываются по 24 словам — до 4 на один токен.";

    /// <summary>Что вставлено: чистый или настроенный токен (опрос оболочки зовёт это раз в 2 с).</summary>
    public async Task CheckAsync()
    {
        if (IsWorking) return;
        try
        {
            var who = await shell.Token.WhoAsync();
            NeedsWords = who.SetupDone;
            TokenInfo = who.SetupDone
                ? $"Токен {who.Id[..4]}…{who.Id[^4..]} · привязано компьютеров: {who.PcCount} из 4"
                : $"Новый токен {who.Id[..4]}…{who.Id[^4..]}";
        }
        catch (TokenException)
        {
        }
    }

    private bool CanPairWords() => Bip39.Check(Words) == PhraseCheck.Ok && !IsWorking;

    [RelayCommand(CanExecute = nameof(CanPairWords))]
    private async Task PairWords()
    {
        Error = null;
        IsWorking = true;
        try
        {
            await shell.Token.PairWithWordsAsync(Words);
            Words = "";
            shell.Snackbar.Show("Компьютер привязан. Откройте хранилище своим мастер-паролем");
            await shell.RefreshAsync();
        }
        catch (TokenException e) when (e.Error is TokenError.WrongPhrase or TokenError.PairFull or TokenError.TooManyTokens or TokenError.BadPhrase)
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
        catch (TokenException e) when (e.Error is TokenError.AlreadyPaired or TokenError.NeedWords or TokenError.TooManyTokens)
        {
            Error = e.Message;
            await CheckAsync();
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
