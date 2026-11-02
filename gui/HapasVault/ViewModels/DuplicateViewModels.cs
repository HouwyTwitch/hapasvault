// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;

namespace HapasVault.ViewModels;

public enum DuplicateStep { Intro, Reading, Swap, Writing, Done }

/// <summary>
/// Дублирование токена: зашифрованная копия читается в память, вы меняете плату на чистую,
/// программа привязывает её и восстанавливает копию. Файл на диске не появляется.
/// Нужны 24 слова (из них — ключ токена) и мастер-пароль.
/// </summary>
public sealed partial class DuplicateDialogViewModel(ShellViewModel shell) : DialogViewModel
{
    private byte[]? _backup;
    private string _oldId = "", _oldLabel = "";
    private CancellationTokenSource? _wait;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIntro), nameof(IsBusy), nameof(IsSwap), nameof(IsDone))]
    private DuplicateStep _step = DuplicateStep.Intro;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartCommand))] private string _words = "";
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartCommand))] private string _password = "";
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string? _error;

    public bool IsIntro => Step == DuplicateStep.Intro;
    public bool IsBusy => Step is DuplicateStep.Reading or DuplicateStep.Writing;
    public bool IsSwap => Step == DuplicateStep.Swap;
    public bool IsDone => Step == DuplicateStep.Done;

    private bool CanStart() => Bip39.Check(Words) == PhraseCheck.Ok && Password.Length > 0;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task Start()
    {
        Error = null;
        if (_backup == null)
        {
            Step = DuplicateStep.Reading;
            Status = "Читаю зашифрованную копию с токена…";
            var active = shell.Token.KnownTokens.FirstOrDefault(t => t.Active);
            _oldId = active?.Id ?? "";
            _oldLabel = active?.Label ?? "Токен";
            try
            {
                _backup = await shell.Token.BackupAsync();
            }
            catch (TokenException e)
            {
                Fail(e.Message);
                return;
            }
        }
        await shell.Token.DetachAsync();
        Step = DuplicateStep.Swap;
        Status = $"Копия в памяти ({_backup.Length / 1024.0:0.#} КБ). Отключите «{_oldLabel}» и подключите новый, чистый токен.";
        await WaitForNewTokenAsync();
    }

    private async Task WaitForNewTokenAsync()
    {
        _wait = new CancellationTokenSource();
        var ct = _wait.Token;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!shell.Token.IsAttached) await shell.Token.AttachAsync();
                var who = await shell.Token.WhoAsync();
                if (who.Id.Equals(_oldId, StringComparison.OrdinalIgnoreCase))
                {
                    Error = null;
                    await shell.Token.DetachAsync();
                }
                else if (who.SetupDone)
                {
                    Error = "Этот токен уже настроен. Нужна чистая плата (или сотрите эту в её программе).";
                    await shell.Token.DetachAsync();
                }
                else
                {
                    await WriteAsync();
                    return;
                }
            }
            catch (TokenException)
            {
                // ещё не вставили / порт занят — ждём
            }
            try { await Task.Delay(1000, ct); } catch (TaskCanceledException) { return; }
        }
    }

    private async Task WriteAsync()
    {
        Step = DuplicateStep.Writing;
        Error = null;
        Status = "Новый токен найден: привязываю и записываю копию…";
        try
        {
            await shell.Token.PairAsync();
            await shell.Token.RestoreAsync(Words, Password, _backup);
            var fresh = shell.Token.KnownTokens.FirstOrDefault(t => t.Active);
            if (fresh != null) await shell.Token.RenameTokenAsync(fresh.Index, $"{_oldLabel} (копия)");
            Step = DuplicateStep.Done;
            Status = $"Готово: на новом токене те же записи. Этот компьютер знает оба токена и сам выберет подключённый.";
            Wipe();
        }
        catch (TokenException e)
        {
            // неверные слова или пароль: токен сам стирает недописанное, копия ещё в памяти — можно повторить
            Step = DuplicateStep.Intro;
            Error = e.Error is TokenError.WrongPassword or TokenError.BadPhrase
                ? "Слова или мастер-пароль не подходят к копии. Проверьте и нажмите «Продолжить» ещё раз."
                : e.Message;
        }
    }

    private void Fail(string message)
    {
        Step = DuplicateStep.Intro;
        Error = message;
    }

    private void Wipe()
    {
        if (_backup != null) CryptographicOperations.ZeroMemory(_backup);
        _backup = null;
        Password = "";
        Words = "";
    }

    [RelayCommand]
    private async Task Finish()
    {
        _wait?.Cancel();
        Wipe();
        Close(Step == DuplicateStep.Done);
        shell.Page = null;
        await shell.RefreshAsync();
    }
}
