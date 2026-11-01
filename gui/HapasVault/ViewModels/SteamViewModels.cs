using System.Collections.ObjectModel;
using System.Net.Http;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HapasVault.Core;
using HapasVault.Core.Steam;

namespace HapasVault.ViewModels;

public sealed partial class SteamConfirmationItem(SteamConfirmation c, SteamDialogViewModel owner) : ObservableObject
{
    public SteamConfirmation Confirmation => c;
    public string Kind => c.TypeName.Length > 0 ? c.TypeName : "Подтверждение";
    public string Headline => c.Headline;
    public string Summary => string.Join("\n", c.Summary);
    public bool HasSummary => c.Summary.Count > 0;
    public string Ago => Ru.Ago((uint)Math.Max(0, (DateTimeOffset.UtcNow - c.Created).TotalSeconds));
    public string AcceptText => c.AcceptText ?? "Подтвердить";
    public string CancelText => c.CancelText ?? "Отклонить";
    public string IconKey => c.Type switch
    {
        SteamConfirmationTypes.Trade => "Icon.SwapHoriz",
        SteamConfirmationTypes.MarketListing => "Icon.Category",
        SteamConfirmationTypes.ApiKey => "Icon.Key",
        _ => "Icon.ShieldLock",
    };

    [ObservableProperty] private bool _isBusy;

    [RelayCommand]
    private Task Accept() => owner.RespondAsync([this], accept: true);

    [RelayCommand]
    private Task Decline() => owner.RespondAsync([this], accept: false);
}

/// <summary>
/// Мобильные подтверждения Steam одной записи: обмены, торговая площадка, ключ API…
/// Ключ каждого запроса считает токен; без токена ни список, ни ответ невозможны.
/// </summary>
public sealed partial class SteamDialogViewModel : DialogViewModel
{
    private readonly ShellViewModel _shell;
    private readonly SteamConfirmer _confirmer;
    private readonly DispatcherTimer _hideRevocation = new() { Interval = TimeSpan.FromSeconds(30) };

    public SteamDialogViewModel(ShellViewModel shell, EntryViewModel entry)
    {
        _shell = shell;
        Entry = entry;
        _confirmer = new SteamConfirmer(shell.Token, entry.Id, shell.SteamWeb, shell.SteamSessions);
        _hideRevocation.Tick += (_, _) => { _hideRevocation.Stop(); Revocation = null; };
    }

    public EntryViewModel Entry { get; }
    public ObservableCollection<SteamConfirmationItem> Items { get; } = new();

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsEmpty))] private bool _isLoading;
    [ObservableProperty] private string? _status;
    [ObservableProperty] private string? _error;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(AcceptAllText))] private bool _confirmAll;
    [ObservableProperty] private string? _revocation;

    public bool IsEmpty => !IsLoading && Error == null && Items.Count == 0;
    public bool HasMany => Items.Count > 1;
    public string AcceptAllText => ConfirmAll ? $"Точно принять все ({Items.Count})?" : $"Принять все ({Items.Count})";

    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(IsEmpty));

    /// <summary>Ошибки Steam и токена — в текст диалога; пропавший токен — общей обработкой.</summary>
    private async Task<bool> GuardAsync(Func<Task> op, string busy)
    {
        Error = null;
        Status = busy;
        try
        {
            await op();
            return true;
        }
        catch (SteamException e)
        {
            Error = e.Message;
        }
        catch (HttpRequestException)
        {
            Error = "Нет связи со Steam. Проверьте интернет.";
        }
        catch (TaskCanceledException)
        {
            Error = "Steam не ответил вовремя.";
        }
        catch (TokenException e) when (e.Error is TokenError.RateLimit or TokenError.BadTime or TokenError.NoOtp)
        {
            Error = e.Message;
        }
        catch (TokenException e)
        {
            Close(false);
            await _shell.HandleErrorAsync(e);
        }
        finally
        {
            Status = null;
        }
        return false;
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        IsLoading = true;
        ConfirmAll = false;
        IReadOnlyList<SteamConfirmation>? list = null;
        await GuardAsync(async () => list = await _confirmer.ListAsync(),
                         _confirmer.HasSession ? "Загружаю подтверждения…" : "Вход в Steam: пароль и код даёт токен…");
        Items.Clear();
        foreach (var c in list ?? []) Items.Add(new SteamConfirmationItem(c, this));
        IsLoading = false;
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasMany));
        OnPropertyChanged(nameof(AcceptAllText));
    }

    public async Task RespondAsync(IReadOnlyList<SteamConfirmationItem> items, bool accept)
    {
        foreach (var i in items) i.IsBusy = true;
        bool ok = await GuardAsync(() => _confirmer.RespondAsync(items.Select(i => i.Confirmation).ToList(), accept),
                                   accept ? "Подтверждаю…" : "Отклоняю…");
        foreach (var i in items) i.IsBusy = false;
        if (!ok) return;
        foreach (var i in items) Items.Remove(i);
        ConfirmAll = false;
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasMany));
        OnPropertyChanged(nameof(AcceptAllText));
        _shell.Snackbar.Show(items.Count == 1
            ? accept ? "Подтверждено" : "Отклонено"
            : $"Подтверждено: {items.Count}");
    }

    [RelayCommand]
    private async Task AcceptAll()
    {
        if (!ConfirmAll) { ConfirmAll = true; return; }
        await RespondAsync(Items.ToList(), accept: true);
    }

    [RelayCommand]
    private async Task ShowRevocation()
    {
        if (Revocation != null) { Revocation = null; return; }
        var info = await _shell.RunAsync(() => _shell.Token.GetSteamInfoAsync(Entry.Id, revocationCode: true));
        if (info == null) return;
        Revocation = info.RevocationCode is { Length: > 0 } r ? r : "не сохранён";
        _hideRevocation.Start();
    }

    [RelayCommand]
    private void SignOut()
    {
        _confirmer.Forget();
        Items.Clear();
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasMany));
        _shell.Snackbar.Show("Сессия Steam на этом ПК удалена. Секреты остались на токене.");
        Close(false);
    }

    public void Dispose()
    {
        _hideRevocation.Stop();
        Revocation = null;
    }
}
