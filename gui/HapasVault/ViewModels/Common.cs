using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace HapasVault.ViewModels;

/// <summary>Снэкбар: одно сообщение за раз, остальные в очереди.</summary>
public sealed partial class SnackbarViewModel : ObservableObject
{
    private readonly Queue<(string Text, string? Action, Func<Task>? OnAction)> _queue = new();
    private readonly DispatcherTimer _timer = new();
    private Func<Task>? _onAction;

    [ObservableProperty] private string _text = "";
    [ObservableProperty] private string? _actionText;
    [ObservableProperty] private bool _isOpen;

    public SnackbarViewModel() => _timer.Tick += (_, _) => Hide();

    public void Show(string text, string? action = null, Func<Task>? onAction = null)
    {
        _queue.Enqueue((text, action, onAction));
        if (!IsOpen) Next();
    }

    private void Next()
    {
        if (_queue.Count == 0) return;
        var (text, action, onAction) = _queue.Dequeue();
        Text = text;
        ActionText = action;
        _onAction = onAction;
        IsOpen = true;
        _timer.Interval = TimeSpan.FromSeconds(action != null ? 7 : 4);
        _timer.Start();
    }

    [RelayCommand]
    private void Hide()
    {
        _timer.Stop();
        IsOpen = false;
        // дать анимации скрытия отыграть
        var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(260) };
        t.Tick += (_, _) => { t.Stop(); if (!IsOpen) Next(); };
        t.Start();
    }

    [RelayCommand]
    private async Task Act()
    {
        var a = _onAction;
        _onAction = null;
        Hide();
        if (a != null) await a();
    }
}

/// <summary>Модальный диалог внутри окна. Result завершается при закрытии.</summary>
public abstract partial class DialogViewModel : ObservableObject
{
    private readonly TaskCompletionSource<bool> _tcs = new();

    public Task<bool> Result => _tcs.Task;

    public void Close(bool ok) => _tcs.TrySetResult(ok);

    [RelayCommand]
    private void Cancel() => Close(false);
}

/// <summary>Подтверждение; для опасных действий можно потребовать ввести слово.</summary>
public sealed partial class ConfirmDialogViewModel : DialogViewModel
{
    public required string Title { get; init; }
    public required string Message { get; init; }
    public string ConfirmText { get; init; } = "ОК";
    public bool IsDanger { get; init; }
    /// <summary>Слово, которое нужно ввести для подтверждения (null — не нужно).</summary>
    public string? TypeToConfirm { get; init; }
    public string IconKey { get; init; } = "Icon.Info";

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(ConfirmCommand))] private string _typed = "";

    private bool CanConfirm() => TypeToConfirm == null || string.Equals(Typed.Trim(), TypeToConfirm, StringComparison.OrdinalIgnoreCase);

    [RelayCommand(CanExecute = nameof(CanConfirm))]
    private void Confirm() => Close(true);
}

public static class Ru
{
    /// <summary>Склонение по числу: 1 запись, 2 записи, 5 записей.</summary>
    public static string Plural(long n, string one, string few, string many)
    {
        long a = Math.Abs(n) % 100, b = a % 10;
        string w = a is > 10 and < 20 ? many : b == 1 ? one : b is >= 2 and <= 4 ? few : many;
        return $"{n} {w}";
    }

    public static string Ago(uint seconds) => seconds switch
    {
        < 10 => "только что",
        < 60 => Plural(seconds, "секунду", "секунды", "секунд") + " назад",
        < 3600 => Plural(seconds / 60, "минуту", "минуты", "минут") + " назад",
        < 86400 => Plural(seconds / 3600, "час", "часа", "часов") + " назад",
        _ => Plural(seconds / 86400, "день", "дня", "дней") + " назад",
    };

    public static string Duration(uint seconds) => seconds switch
    {
        < 60 => Plural(seconds, "секунда", "секунды", "секунд"),
        < 3600 => Plural(seconds / 60, "минута", "минуты", "минут"),
        _ => $"{seconds / 3600} ч {seconds % 3600 / 60} мин",
    };
}
