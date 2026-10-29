using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;
using Microsoft.Win32;

namespace HapasVault.ViewModels;

public enum SetupStep { Intro, Words, Verify, Password, Working, Done }

public sealed record WordCell(int Number, string Word);

public sealed partial class VerifyCell(int number) : ObservableObject
{
    public int Number { get; } = number;
    public string Label => $"Слово № {Number}";
    [ObservableProperty] private string _input = "";
    [ObservableProperty] private string? _error;

    partial void OnInputChanged(string value) => Error = null;
}

/// <summary>Общее для создания и восстановления: мастер-пароль дважды и его оценка.</summary>
public abstract partial class MasterPasswordViewModel : ObservableObject
{
    public const int MinLength = 8;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Strength), nameof(StrengthValue), nameof(StrengthText))]
    private string _password = "";
    [ObservableProperty] private string _confirm = "";
    [ObservableProperty] private string? _passwordError;
    [ObservableProperty] private string? _confirmError;

    public Strength Strength => Passwords.Rate(Password);
    public double StrengthValue => Math.Clamp(Passwords.EntropyBits(Password) / 90, 0, 1);
    public string StrengthText => Password.Length == 0
        ? "Не короче 8 символов. Лучше — фраза из нескольких слов."
        : $"{Passwords.Describe(Strength)} · ≈{Passwords.EntropyBits(Password):0} бит";

    partial void OnPasswordChanged(string value) => PasswordError = null;
    partial void OnConfirmChanged(string value) => ConfirmError = null;

    protected bool ValidatePasswords()
    {
        if (Password.Length < MinLength) PasswordError = $"Нужно не меньше {MinLength} символов";
        else if (Strength == Strength.Weak) PasswordError = "Слишком простой пароль: добавьте длины или слов";
        if (Confirm != Password) ConfirmError = "Пароли не совпадают";
        return PasswordError == null && ConfirmError == null;
    }

    protected void WipePasswords()
    {
        Password = "";
        Confirm = "";
    }
}

/// <summary>Мастер первичной настройки.</summary>
public sealed partial class SetupViewModel(ShellViewModel shell) : MasterPasswordViewModel
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StepIndex), nameof(StepTitle))]
    private SetupStep _step = SetupStep.Intro;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _wordsHidden;
    [ObservableProperty] private int _shake;
    [ObservableProperty] private string? _error;

    public ObservableCollection<WordCell> Words { get; } = new();
    public ObservableCollection<VerifyCell> Verify { get; } = new();

    public int StepIndex => Step switch
    {
        SetupStep.Intro => 0,
        SetupStep.Words => 1,
        SetupStep.Verify => 2,
        _ => 3,
    };

    public string StepTitle => Step switch
    {
        SetupStep.Words => "Шаг 1 из 3 · Фраза восстановления",
        SetupStep.Verify => "Шаг 2 из 3 · Проверка",
        SetupStep.Password or SetupStep.Working => "Шаг 3 из 3 · Мастер-пароль",
        _ => "",
    };

    [RelayCommand]
    private async Task Begin()
    {
        IsBusy = true;
        try
        {
            var words = await shell.Token.BeginSetupAsync();
            Words.Clear();
            for (int i = 0; i < words.Length; i++) Words.Add(new WordCell(i + 1, words[i]));
            Step = SetupStep.Words;
        }
        catch (TokenException e)
        {
            await shell.HandleErrorAsync(e);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void WordsWritten()
    {
        // по одному слову из каждой трети фразы
        Verify.Clear();
        for (int third = 0; third < 3; third++)
            Verify.Add(new VerifyCell(third * 8 + RandomNumberGenerator.GetInt32(8) + 1));
        Error = null;
        Step = SetupStep.Verify;
    }

    [RelayCommand]
    private void CheckWords()
    {
        bool ok = true;
        foreach (var v in Verify)
        {
            string want = Words[v.Number - 1].Word;
            if (!string.Equals(v.Input.Trim(), want, StringComparison.OrdinalIgnoreCase))
            {
                v.Error = v.Input.Trim().Length == 0 ? "Введите слово" : "Не совпадает";
                ok = false;
            }
        }
        if (!ok)
        {
            Shake++;
            return;
        }
        Words.Clear();   // больше не нужны: слова должны остаться только на бумаге
        Step = SetupStep.Password;
    }

    [RelayCommand]
    private void BackToWords()
    {
        // слова уже стёрты после проверки: вернуться можно только со шага проверки
        if (Step == SetupStep.Verify) Step = SetupStep.Words;
    }

    [RelayCommand]
    private async Task Create()
    {
        if (!ValidatePasswords())
        {
            Shake++;
            return;
        }
        Step = SetupStep.Working;
        try
        {
            await shell.Token.CommitSetupAsync(Password);
            WipePasswords();
            Step = SetupStep.Done;
        }
        catch (TokenException e)
        {
            Step = SetupStep.Password;
            await shell.HandleErrorAsync(e);
        }
    }

    [RelayCommand]
    private Task Finish() => shell.RefreshAsync();

    [RelayCommand]
    private void Cancel()
    {
        Words.Clear();
        WipePasswords();
        shell.Page = new WelcomeViewModel(shell);
    }
}

public enum WordState { Empty, Ok, Bad }

public sealed partial class WordInput(RestoreViewModel owner, int number) : ObservableObject
{
    public int Number { get; } = number;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(State))] private string _text = "";

    public WordState State => Text.Trim().Length == 0 ? WordState.Empty
        : Bip39.Resolve(Text) != null ? WordState.Ok : WordState.Bad;

    partial void OnTextChanged(string value)
    {
        // вставили всю фразу в одно поле — раскладываем по ячейкам
        var parts = value.Split((char[])[' ', '\t', '\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 1) owner.Distribute(Number - 1, parts);
        else owner.Changed();
    }
}

/// <summary>Восстановление на новом токене из 24 слов и (необязательно) резервной копии.</summary>
public sealed partial class RestoreViewModel : MasterPasswordViewModel
{
    private readonly ShellViewModel _shell;
    private byte[]? _backup;
    private bool _distributing;

    public RestoreViewModel(ShellViewModel shell)
    {
        _shell = shell;
        for (int i = 1; i <= 24; i++) Words.Add(new WordInput(this, i));
    }

    public ObservableCollection<WordInput> Words { get; } = new();

    [ObservableProperty] private string _phraseStatus = "Введите 24 слова. Можно вставить всю фразу в первое поле.";
    [ObservableProperty] private bool _phraseOk;
    [ObservableProperty] private string? _backupName;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private int _shake;

    internal void Distribute(int start, string[] parts)
    {
        if (_distributing) return;
        _distributing = true;
        try
        {
            for (int i = 0; i < parts.Length && start + i < 24; i++) Words[start + i].Text = parts[i];
        }
        finally
        {
            _distributing = false;
        }
        Changed();
    }

    internal void Changed()
    {
        if (_distributing) return;
        int filled = Words.Count(w => w.State != WordState.Empty);
        int bad = Words.Count(w => w.State == WordState.Bad);
        PhraseOk = false;
        if (bad > 0) PhraseStatus = $"Неизвестных слов: {bad}";
        else if (filled < 24) PhraseStatus = $"Введено {filled} из 24";
        else
        {
            var check = Bip39.Check(Phrase());
            PhraseOk = check == PhraseCheck.Ok;
            PhraseStatus = check switch
            {
                PhraseCheck.Ok => "Фраза верна, контрольная сумма совпала",
                PhraseCheck.BadChecksum => "Контрольная сумма не сошлась: проверьте порядок слов",
                _ => "Фраза неверна",
            };
        }
    }

    private string Phrase() => string.Join(' ', Words.Select(w => Bip39.Resolve(w.Text) ?? w.Text.Trim()));

    [RelayCommand]
    private void PickBackup()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Резервная копия хранилища",
            Filter = "Резервная копия HapasVault (*.pmbak;*.bak)|*.pmbak;*.bak|Все файлы|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var bytes = File.ReadAllBytes(dlg.FileName);
            if (bytes.Length == 0 || bytes.Length > 40 * 1024)
            {
                _shell.Snackbar.Show("Это не похоже на резервную копию: неверный размер");
                return;
            }
            _backup = bytes;
            BackupName = $"{Path.GetFileName(dlg.FileName)} · {bytes.Length / 1024.0:0.#} КБ";
        }
        catch (IOException e)
        {
            _shell.Snackbar.Show("Не удалось прочитать файл: " + e.Message);
        }
    }

    [RelayCommand]
    private void ClearBackup()
    {
        _backup = null;
        BackupName = null;
    }

    [RelayCommand]
    private async Task Restore()
    {
        Changed();
        if (!PhraseOk | !ValidatePasswords())
        {
            Shake++;
            return;
        }
        IsWorking = true;
        try
        {
            await _shell.Token.RestoreAsync(Phrase(), Password, _backup);
            WipePasswords();
            foreach (var w in Words) w.Text = "";
            _shell.Snackbar.Show(_backup != null ? "Хранилище восстановлено из копии" : "Доступ восстановлен, хранилище пусто");
            await _shell.RefreshAsync();
        }
        catch (TokenException e) when (e.Error is TokenError.BadPhrase or TokenError.BadArgs or TokenError.WrongPassword)
        {
            PhraseStatus = e.Error == TokenError.BadPhrase ? e.Message : "Копия не подходит к этой фразе или повреждена";
            PhraseOk = false;
            Shake++;
        }
        catch (TokenException e)
        {
            await _shell.HandleErrorAsync(e);
        }
        finally
        {
            IsWorking = false;
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        WipePasswords();
        _shell.Page = new WelcomeViewModel(_shell);
    }
}
