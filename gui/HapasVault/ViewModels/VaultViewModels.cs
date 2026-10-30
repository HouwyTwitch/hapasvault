using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Controls;
using HapasVault.Core;

namespace HapasVault.ViewModels;

public enum Section { Vault, Log, Settings }

/// <summary>Открытое хранилище: навигация по разделам.</summary>
public sealed partial class VaultShellViewModel : ObservableObject
{
    public VaultShellViewModel(ShellViewModel shell)
    {
        Shell = shell;
        Vault = new VaultViewModel(shell);
        _current = Vault;
    }

    public ShellViewModel Shell { get; }
    public VaultViewModel Vault { get; }

    [ObservableProperty] private Section _section = Section.Vault;
    [ObservableProperty] private object _current;

    async partial void OnSectionChanged(Section value)
    {
        switch (value)
        {
            case Section.Vault:
                Current = Vault;
                break;
            case Section.Log:
                var log = new LogViewModel(Shell);
                Current = log;
                await log.LoadAsync();
                break;
            case Section.Settings:
                var settings = new SettingsViewModel(Shell);
                Current = settings;
                await settings.LoadAsync();
                break;
        }
    }

    [RelayCommand]
    private async Task NewEntry()
    {
        Section = Section.Vault;
        await Vault.AddCommand.ExecuteAsync(null);
    }
}

public sealed partial class EntryViewModel : ObservableObject
{
    private static readonly (string Fill, string On)[] Tones =
    [
        ("PrimaryContainer", "OnPrimaryContainer"),
        ("TertiaryContainer", "OnTertiaryContainer"),
        ("PrimaryFixed", "OnPrimaryFixed"),
        ("TertiaryFixed", "OnTertiaryFixed"),
    ];

    public EntryViewModel(VaultItem item)
    {
        Item = item;
        Shape = Shapes.ForText(item.Name);
        var tone = Tones[Shapes.Hash(item.Category) % (uint)Tones.Length];
        FillKey = tone.Fill;
        OnFillKey = tone.On;
    }

    public VaultItem Item { get; }
    public uint Id => Item.Id;
    public string Name => Item.Name;
    public string Category => Item.Category;
    public string CategoryOrDefault => Item.Category.Length > 0 ? Item.Category : VaultViewModel.NoCategory;
    public string Initial => Item.Name.Trim().Length > 0 ? char.ToUpper(Item.Name.Trim()[0]).ToString() : "?";
    public ShapeKind Shape { get; }
    public OtpKind Otp => Item.Otp;
    public bool HasOtp => Item.Otp != OtpKind.None;
    public string FillKey { get; }
    public string OnFillKey { get; }

    [ObservableProperty] private GroupPosition _position;
    [ObservableProperty] private bool _isSelected;

    /// <summary>Вызывается, когда строку выбрали в списке.</summary>
    public Action<EntryViewModel>? Picked { get; set; }

    partial void OnIsSelectedChanged(bool value)
    {
        if (value) Picked?.Invoke(this);
    }
}

public sealed record EntryGroup(string Title, IReadOnlyList<EntryViewModel> Items);

public sealed partial class CategoryChip(string? name, string title, int count, Action<CategoryChip> picked) : ObservableObject
{
    public string? Name { get; } = name;   // null — «Все»
    public string Title { get; } = title;
    public int Count { get; } = count;
    [ObservableProperty] private bool _isSelected;

    partial void OnIsSelectedChanged(bool value)
    {
        if (value) picked(this);
    }
}

/// <summary>Список записей: поиск, фильтр по категории, группы, выбранная запись.</summary>
public sealed partial class VaultViewModel(ShellViewModel shell) : ObservableObject
{
    public const string NoCategory = "Без категории";

    private List<EntryViewModel> _all = new();

    public ShellViewModel Shell { get; } = shell;
    public ObservableCollection<EntryGroup> Groups { get; } = new();
    public ObservableCollection<CategoryChip> Categories { get; } = new();

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string? _category;
    [ObservableProperty] private EntryViewModel? _selected;
    [ObservableProperty] private DetailViewModel? _detail;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _countText = "";

    public bool IsEmpty => _all.Count == 0 && !IsLoading;
    public bool NothingFound => _all.Count > 0 && Groups.Count == 0;

    partial void OnSearchChanged(string value) => Rebuild();

    partial void OnCategoryChanged(string? value)
    {
        foreach (var c in Categories) c.IsSelected = c.Name == value;
        Rebuild();
    }

    partial void OnSelectedChanged(EntryViewModel? oldValue, EntryViewModel? newValue)
    {
        if (oldValue != null && oldValue != newValue) oldValue.IsSelected = false;
        Detail?.Forget();
        if (newValue != null) newValue.IsSelected = true;
        Detail = newValue != null ? new DetailViewModel(this, newValue) : null;
    }

    public async Task LoadAsync(uint? select = null)
    {
        IsLoading = true;
        var items = await Shell.RunAsync(() => Shell.Token.ListAsync());
        IsLoading = false;
        if (items == null) return;
        uint? keep = select ?? Selected?.Id;
        _all = items.Select(i => new EntryViewModel(i) { Picked = e => Selected = e })
                    .OrderBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        CountText = Ru.Plural(_all.Count, "запись", "записи", "записей");

        Categories.Clear();
        Categories.Add(new CategoryChip(null, "Все", _all.Count, c => Category = c.Name));
        foreach (var g in _all.GroupBy(e => e.Category).OrderBy(g => g.Key.Length == 0).ThenBy(g => g.Key, StringComparer.CurrentCultureIgnoreCase))
            Categories.Add(new CategoryChip(g.Key, g.Key.Length > 0 ? g.Key : NoCategory, g.Count(), c => Category = c.Name));
        if (Category != null && Categories.All(c => c.Name != Category)) Category = null;
        foreach (var c in Categories) c.IsSelected = c.Name == Category;

        Rebuild();
        Selected = keep is { } id ? _all.FirstOrDefault(e => e.Id == id) : null;
        OnPropertyChanged(nameof(IsEmpty));
    }

    public IEnumerable<string> KnownCategories =>
        _all.Select(e => e.Category).Where(c => c.Length > 0).Distinct().OrderBy(c => c, StringComparer.CurrentCultureIgnoreCase);

    private void Rebuild()
    {
        string q = Search.Trim();
        var visible = _all.Where(e => (Category == null || e.Category == Category) &&
            (q.Length == 0 || e.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase) ||
             e.Category.Contains(q, StringComparison.CurrentCultureIgnoreCase)));
        Groups.Clear();
        foreach (var g in visible.GroupBy(e => e.CategoryOrDefault)
                     .OrderBy(g => g.Key == NoCategory).ThenBy(g => g.Key, StringComparer.CurrentCultureIgnoreCase))
        {
            var list = g.ToList();
            for (int i = 0; i < list.Count; i++)
                list[i].Position = list.Count == 1 ? GroupPosition.Single
                    : i == 0 ? GroupPosition.First : i == list.Count - 1 ? GroupPosition.Last : GroupPosition.Middle;
            Groups.Add(new EntryGroup(g.Key, list));
        }
        OnPropertyChanged(nameof(NothingFound));
    }

    [RelayCommand]
    private void CloseDetail() => Selected = null;

    [RelayCommand]
    private async Task Add()
    {
        var editor = new EditorDialogViewModel(KnownCategories, async ed =>
        {
            var (change, secret) = ed.ResolvedOtp;
            uint? id = await Shell.RunAsync(() => Shell.Token.AddAsync(ed.Category.Trim(), ed.Name.Trim(), ed.Login.Trim(), ed.Password,
                change == OtpChange.Set ? secret : null));
            if (id == null) return false;
            await LoadAsync(id);
            Shell.Snackbar.Show($"«{ed.Name.Trim()}» сохранена на токене");
            return true;
        })
        { Category = Category ?? "" };
        await Shell.ShowDialogAsync(editor);
    }

    public async Task EditAsync(EntryViewModel e, Credential current)
    {
        var editor = new EditorDialogViewModel(KnownCategories, async ed =>
        {
            var (change, secret) = ed.ResolvedOtp;
            if (!await Shell.RunAsync(() => Shell.Token.UpdateAsync(e.Id, ed.Category.Trim(), ed.Name.Trim(), ed.Login.Trim(), ed.Password,
                    change, secret)))
                return false;
            await LoadAsync(e.Id);
            Shell.Snackbar.Show("Изменения сохранены");
            return true;
        })
        {
            IsEdit = true,
            ExistingOtp = e.Otp,
            OtpChoice = e.Otp,
            Name = e.Name,
            Category = e.Category,
            Login = current.Login,
            Password = current.Password,
        };
        await Shell.ShowDialogAsync(editor);
    }

    public async Task DeleteAsync(EntryViewModel e)
    {
        var ok = await Shell.ShowDialogAsync(new ConfirmDialogViewModel
        {
            Title = $"Удалить «{e.Name}»?",
            Message = e.Otp != OtpKind.None
                ? "Запись будет стёрта с токена вместе с секретом двухфакторных кодов — его не вернуть, понадобится заново подключить 2FA в сервисе. Логин и пароль можно вернуть кнопкой «Отменить»."
                : "Запись будет стёрта с токена. Сразу после удаления её можно вернуть кнопкой «Отменить».",
            ConfirmText = "Удалить",
            IsDanger = true,
            IconKey = "Icon.Delete",
        });
        if (!ok) return;
        // сохраняем копию для «Отменить» (это одна расшифровка на токене)
        var copy = await Shell.RunAsync(() => Shell.Token.GetAsync(e.Id));
        if (copy == null) return;
        if (!await Shell.RunAsync(() => Shell.Token.DeleteAsync(e.Id))) return;
        Selected = null;
        await LoadAsync();
        var item = e.Item;
        Shell.Snackbar.Show($"«{item.Name}» удалена", "Отменить", async () =>
        {
            uint? id = await Shell.RunAsync(() => Shell.Token.AddAsync(item.Category, item.Name, copy.Login, copy.Password));
            if (id != null) await LoadAsync(id);
        });
    }
}

/// <summary>Правая панель: логин и пароль по запросу, копирование, правка, удаление.</summary>
public sealed partial class DetailViewModel : ObservableObject
{
    private const int ForgetSeconds = 30;
    private readonly VaultViewModel _vault;
    private readonly DispatcherTimer _forget = new() { Interval = TimeSpan.FromSeconds(ForgetSeconds) };
    private Credential? _cred;

    public DetailViewModel(VaultViewModel vault, EntryViewModel entry)
    {
        _vault = vault;
        Entry = entry;
        _forget.Tick += (_, _) => Forget();
        _otpTimer.Tick += async (_, _) => await OtpTickAsync();
    }

    // ---- одноразовый код: по запросу, обновляется на границе периода,
    // через 90 с сам скрывается (не держим сессию токена живой бесконечно) ----
    private const int OtpShowSeconds = 90;
    private readonly DispatcherTimer _otpTimer = new() { Interval = TimeSpan.FromMilliseconds(200) };
    private OtpCode? _otp;
    private DateTime _otpShownAt;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(OtpText))] private bool _isOtpShown;
    [ObservableProperty] private double _otpProgress;
    [ObservableProperty] private string _otpLeft = "";

    public string OtpText => IsOtpShown && _otp != null ? Format(_otp) : Entry.Otp == OtpKind.Steam ? "•••••" : "••• •••";
    public string OtpTitle => Entry.Otp == OtpKind.Steam ? "Код Steam Guard" : "Одноразовый код";

    private static string Format(OtpCode c) => c.Kind == OtpKind.Steam || c.Code.Length < 6
        ? c.Code
        : c.Code.Length == 6 ? $"{c.Code[..3]} {c.Code[3..]}" : $"{c.Code[..(c.Code.Length / 2)]} {c.Code[(c.Code.Length / 2)..]}";

    private async Task<OtpCode?> FetchOtpAsync()
    {
        var code = await _vault.Shell.RunAsync(() => _vault.Shell.Token.GetOtpAsync(Entry.Id));
        _otp = code;
        OnPropertyChanged(nameof(OtpText));
        return code;
    }

    private async Task OtpTickAsync()
    {
        if (_otp == null) return;
        var left = _otp.ValidUntil - DateTimeOffset.UtcNow;
        if (left <= TimeSpan.Zero)
        {
            if ((DateTime.UtcNow - _otpShownAt).TotalSeconds > OtpShowSeconds) { HideOtp(); return; }
            _otpTimer.Stop();
            if (await FetchOtpAsync() == null) { HideOtp(); return; }
            _otpTimer.Start();
            return;
        }
        OtpProgress = left.TotalSeconds / _otp.Period;
        OtpLeft = $"{Math.Ceiling(left.TotalSeconds):0} с";
    }

    private void HideOtp()
    {
        _otpTimer.Stop();
        _otp = null;
        IsOtpShown = false;
        OtpProgress = 0;
        OtpLeft = "";
    }

    [RelayCommand]
    private async Task ShowOtp()
    {
        if (IsOtpShown) { HideOtp(); return; }
        if (await FetchOtpAsync() == null) return;
        _otpShownAt = DateTime.UtcNow;
        IsOtpShown = true;
        await OtpTickAsync();
        _otpTimer.Start();
    }

    [RelayCommand]
    private async Task CopyOtp()
    {
        var code = _otp is { } c && c.ValidUntil - DateTimeOffset.UtcNow > TimeSpan.FromSeconds(3) ? c : await FetchOtpAsync();
        if (code != null) await _vault.Shell.CopySecretAsync(code.Code, "Код");
    }

    public EntryViewModel Entry { get; }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(LoginText), nameof(PasswordText))] private bool _isRevealed;
    [ObservableProperty] private bool _isLoading;

    public string LoginText => _cred?.Login is { Length: > 0 } l ? l : _cred != null ? "—" : "••••••••";
    public string PasswordText => IsRevealed && _cred != null ? _cred.Password : "••••••••••••";

    private async Task<Credential?> FetchAsync()
    {
        if (_cred != null) return _cred;
        IsLoading = true;
        _cred = await _vault.Shell.RunAsync(() => _vault.Shell.Token.GetAsync(Entry.Id));
        IsLoading = false;
        if (_cred != null)
        {
            _forget.Stop();
            _forget.Start();
            OnPropertyChanged(nameof(LoginText));
            OnPropertyChanged(nameof(PasswordText));
        }
        return _cred;
    }

    /// <summary>Стереть расшифрованные данные из памяти интерфейса.</summary>
    public void Forget()
    {
        HideOtp();
        _forget.Stop();
        _cred = null;
        IsRevealed = false;
        OnPropertyChanged(nameof(LoginText));
        OnPropertyChanged(nameof(PasswordText));
    }

    [RelayCommand]
    private async Task Reveal()
    {
        if (IsRevealed)
        {
            IsRevealed = false;
            return;
        }
        if (await FetchAsync() != null) IsRevealed = true;
    }

    [RelayCommand]
    private async Task CopyLogin()
    {
        if (await FetchAsync() is { } c) await _vault.Shell.CopySecretAsync(c.Login, "Логин");
    }

    [RelayCommand]
    private async Task CopyPassword()
    {
        if (await FetchAsync() is { } c) await _vault.Shell.CopySecretAsync(c.Password, "Пароль");
    }

    [RelayCommand]
    private async Task Edit()
    {
        if (await FetchAsync() is { } c) await _vault.EditAsync(Entry, c);
    }

    [RelayCommand]
    private Task Delete() => _vault.DeleteAsync(Entry);

    [RelayCommand]
    private void Close() => _vault.Selected = null;
}

/// <summary>Диалог новой записи / правки с генератором паролей.</summary>
public sealed partial class EditorDialogViewModel : DialogViewModel
{
    private readonly Func<EditorDialogViewModel, Task<bool>> _save;

    public EditorDialogViewModel(IEnumerable<string> categories, Func<EditorDialogViewModel, Task<bool>> save)
    {
        _save = save;
        KnownCategories = categories.ToList();
    }

    public IReadOnlyList<string> KnownCategories { get; }
    public bool IsEdit { get; init; }
    public string Title => IsEdit ? "Изменить запись" : "Новая запись";

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _category = "";
    [ObservableProperty] private string _login = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Strength), nameof(StrengthValue), nameof(StrengthText))]
    private string _password = "";
    [ObservableProperty] private bool _isRevealed;
    [ObservableProperty] private bool _isGeneratorOpen;
    [ObservableProperty] private double _length = 20;
    [ObservableProperty] private bool _lower = true;
    [ObservableProperty] private bool _upper = true;
    [ObservableProperty] private bool _digits = true;
    [ObservableProperty] private bool _symbols = true;
    [ObservableProperty] private string? _nameError;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _isSaving;
    [ObservableProperty] private int _shake;
    [ObservableProperty] private int _spin;

    // ---- двухфакторные коды: секрет уходит на токен и обратно не выдаётся ----
    public OtpKind ExistingOtp { get; init; }
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(OtpVisible), nameof(OtpHint))] private OtpKind _otpChoice;
    [ObservableProperty] private string _otpInput = "";
    [ObservableProperty] private string? _otpStatus;
    [ObservableProperty] private bool _otpOk;
    [ObservableProperty] private string? _otpError;

    public bool OtpVisible => OtpChoice != OtpKind.None;
    public string OtpHint => OtpChoice == OtpKind.Steam
        ? "shared_secret из maFile, сам maFile или steam:// — код Steam Guard будет считать токен"
        : ExistingOtp != OtpKind.None
            ? "Оставьте пустым, чтобы сохранить текущий секрет. Новый — otpauth:// или Base32"
            : "Ссылка otpauth:// из QR-кода или секрет Base32 из настроек 2FA сервиса";

    partial void OnOtpChoiceChanged(OtpKind value) => CheckOtp();
    partial void OnOtpInputChanged(string value) => CheckOtp();

    private void CheckOtp()
    {
        OtpError = null;
        OtpOk = false;
        if (OtpChoice == OtpKind.None || OtpInput.Trim().Length == 0)
        {
            OtpStatus = OtpChoice != OtpKind.None && ExistingOtp == OtpChoice ? "Текущий секрет останется на токене" : null;
            return;
        }
        try
        {
            var s = OtpSecret.Parse(OtpInput, OtpChoice);
            if (s.Kind != OtpChoice) OtpChoice = s.Kind;   // вставили ссылку другого типа — переключаемся
            OtpStatus = s.Describe() + (s.Issuer is { Length: > 0 } i ? $" · {i}" : "") + $" · сейчас {s.Code(DateTimeOffset.UtcNow)}";
            OtpOk = true;
            if (Name.Trim().Length == 0 && s.Issuer is { Length: > 0 } issuer) Name = issuer;
            if (Login.Trim().Length == 0 && s.Account is { Length: > 0 } account) Login = account;
        }
        catch (FormatException e)
        {
            OtpStatus = null;
            OtpError = e.Message;
        }
    }

    /// <summary>Что сделать с OTP при сохранении (после Validate).</summary>
    public (OtpChange Change, OtpSecret? Secret) ResolvedOtp
    {
        get
        {
            if (OtpChoice == OtpKind.None) return (OtpChange.Remove, null);
            if (OtpInput.Trim().Length == 0) return (OtpChange.Keep, null);
            return (OtpChange.Set, OtpSecret.Parse(OtpInput, OtpChoice));
        }
    }

    public Strength Strength => Passwords.Rate(Password);
    public double StrengthValue => Math.Clamp(Passwords.EntropyBits(Password) / 100, 0, 1);
    public string StrengthText => Password.Length == 0 ? "" : $"{Passwords.Describe(Strength)} · ≈{Passwords.EntropyBits(Password):0} бит";

    partial void OnNameChanged(string value) => NameError = null;
    partial void OnLengthChanged(double value) { if (IsGeneratorOpen) Generate(); }
    partial void OnLowerChanged(bool value) { if (IsGeneratorOpen) Generate(); }
    partial void OnUpperChanged(bool value) { if (IsGeneratorOpen) Generate(); }
    partial void OnDigitsChanged(bool value) { if (IsGeneratorOpen) Generate(); }
    partial void OnSymbolsChanged(bool value) { if (IsGeneratorOpen) Generate(); }

    partial void OnIsGeneratorOpenChanged(bool value)
    {
        if (value && Password.Length == 0) Generate();
    }

    [RelayCommand]
    private void Generate()
    {
        Password = Passwords.Generate(new GeneratorOptions((int)Math.Round(Length), Lower, Upper, Digits, Symbols));
        IsRevealed = true;
        Spin++;
    }

    [RelayCommand]
    private void PickCategory(string c) => Category = c;

    [RelayCommand]
    private async Task Save()
    {
        Error = TokenClient.Validate(Category.Trim(), Name.Trim(), Login.Trim(), Password);
        CheckOtp();
        if (OtpChoice != OtpKind.None && OtpInput.Trim().Length == 0 && ExistingOtp != OtpChoice)
            OtpError = "Вставьте секрет или ссылку otpauth://";
        if (OtpError != null) Error ??= OtpError;
        if (Name.Trim().Length == 0)
        {
            NameError = "Укажите название";
            Error = null;
        }
        if (Error != null || NameError != null)
        {
            Shake++;
            return;
        }
        IsSaving = true;
        try
        {
            if (await _save(this)) Close(true);
        }
        finally
        {
            IsSaving = false;
        }
    }
}
