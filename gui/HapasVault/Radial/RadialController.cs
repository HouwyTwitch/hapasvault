using System.Windows;
using System.Windows.Media;
using HapasVault.Controls;
using HapasVault.Core;
using HapasVault.Platform;
using HapasVault.ViewModels;

namespace HapasVault.Radial;

/// <summary>
/// Радиальное меню по глобальному сочетанию: запоминает окно, в котором был
/// пользователь, показывает записи, расшифровывает выбранную на токене и
/// набирает её в это окно.
/// </summary>
public sealed class RadialController
{
    private readonly ShellViewModel _shell;
    private RadialWindow? _window;
    private nint _target;
    private (int X, int Y) _cursor;

    public RadialController(ShellViewModel shell) => _shell = shell;

    public bool IsOpen => _window is { IsVisible: true };

    /// <summary>Открыть (или закрыть, если уже открыто).</summary>
    public async Task ToggleAsync()
    {
        if (IsOpen)
        {
            Close();
            return;
        }
        _target = AutoType.ForegroundWindow();
        if (AutoType.IsOwnWindow(_target)) _target = 0;
        _cursor = AutoType.CursorPosition();

        switch (_shell.Page)
        {
            case VaultShellViewModel:
                Open();
                await LoadAsync();
                break;
            case LockViewModel when _shell.Token.HasKey:
                Open();
                _window!.ShowUnlock();
                break;
            default:
                // токена нет или он не настроен — показываем главное окно
                ShowMainWindow();
                _shell.Snackbar.Show("Радиальное меню работает, когда токен подключён и настроен");
                break;
        }
    }

    private void Open()
    {
        _window ??= Create();
        _window.SetTarget(_target != 0 ? $"Ввод в «{Trim(AutoType.WindowTitle(_target))}»" : "Пароль будет скопирован в буфер обмена");
        _window.ShowOn(_cursor.X, _cursor.Y);
        // курсор в центр меню: выбор идёт по направлению от центра
        _window.Dispatcher.BeginInvoke(() =>
        {
            if (_window is not { IsVisible: true } w) return;
            var center = w.Menu.PointToScreen(new Point(w.Menu.Width / 2, w.Menu.Height / 2));
            AutoType.SetCursor((int)center.X, (int)center.Y);
        }, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    /// <summary>Для скриншотов CI: показать меню с данными без токена.</summary>
    internal RadialWindow ShowForTest(IReadOnlyList<RadialCategory> items, string target)
    {
        _target = 0;
        _cursor = AutoType.CursorPosition();
        _window ??= Create();
        _window.ShowOn(_cursor.X, _cursor.Y);
        _window.SetTarget(target);
        _window.ShowMenu(items);
        return _window;
    }

    private static string Trim(string s) => s.Length > 48 ? s[..47] + "…" : s.Length > 0 ? s : "окно без заголовка";

    private RadialWindow Create()
    {
        var w = new RadialWindow();
        w.Cancelled += Close;
        w.UnlockRequested += async pw => await UnlockAsync(pw);
        w.Menu.Chosen += async (e, mode) => await ChooseAsync(e, mode);
        return w;
    }

    public void Close()
    {
        if (_window is not { IsVisible: true } w) return;
        w.Hide();
        AutoType.SetCursor(_cursor.X, _cursor.Y);
    }

    private static void ShowMainWindow()
    {
        if (Application.Current.MainWindow is not { } mw) return;
        if (mw.WindowState == WindowState.Minimized) mw.WindowState = WindowState.Normal;
        mw.Activate();
    }

    /// <summary>Записи хранилища, сгруппированные по категориям.</summary>
    public static IReadOnlyList<RadialCategory> Group(IEnumerable<VaultItem> items) =>
        items.Select(i =>
            {
                var vm = new EntryViewModel(i);
                return new RadialEntry(i.Id, i.Name, i.Category, vm.Shape,
                    (Brush)Application.Current.FindResource(vm.FillKey), (Brush)Application.Current.FindResource(vm.OnFillKey));
            })
            .GroupBy(e => e.Category)
            .OrderBy(g => g.Key.Length == 0).ThenBy(g => g.Key, StringComparer.CurrentCultureIgnoreCase)
            .Select(g => new RadialCategory(g.Key.Length > 0 ? g.Key : VaultViewModel.NoCategory,
                g.OrderBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase).ToList()))
            .ToList();

    private async Task LoadAsync()
    {
        _window!.ShowStatus("Загружаю записи…");
        try
        {
            var items = await _shell.Token.ListAsync();
            if (items.Count == 0)
            {
                _window.ShowStatus("В хранилище пока нет записей", error: true);
                return;
            }
            _window.ShowMenu(Group(items));
        }
        catch (TokenException e)
        {
            _window.ShowStatus(e.Message, error: true);
            await _shell.HandleErrorAsync(e);
        }
    }

    private async Task UnlockAsync(string password)
    {
        try
        {
            await _shell.Token.UnlockAsync(password);
            await _shell.RefreshAsync();   // главное окно тоже переходит в хранилище
            await LoadAsync();
        }
        catch (TokenException e) when (e.Error is TokenError.WrongPassword or TokenError.Backoff)
        {
            _window?.ShowUnlock(e.Message);
        }
        catch (TokenException e)
        {
            _window?.ShowStatus(e.Message, error: true);
            await _shell.HandleErrorAsync(e);
        }
    }

    private async Task ChooseAsync(RadialEntry entry, AutoTypeMode mode)
    {
        _window!.ShowStatus($"Расшифровываю «{entry.Name}» на токене…");
        Credential cred;
        try
        {
            cred = await _shell.Token.GetAsync(entry.Id);
        }
        catch (TokenException e)
        {
            _window.ShowStatus(e.Message, error: true);
            if (e.Error is not (TokenError.RateLimit or TokenError.NotFound)) await _shell.HandleErrorAsync(e);
            return;
        }
        Close();

        string what = mode == AutoTypeMode.LoginOnly ? "Логин" : "Пароль";
        string secret = mode == AutoTypeMode.LoginOnly ? cred.Login : cred.Password;
        if (_target == 0)
        {
            await _shell.CopySecretAsync(secret, what);
            return;
        }
        if (!await AutoType.FocusAsync(_target))
        {
            await _shell.CopySecretAsync(secret, what);
            _shell.Snackbar.Show("Не удалось вернуться в окно — " + what.ToLowerInvariant() + " скопирован");
            return;
        }
        await AutoType.WaitModifiersReleasedAsync();
        await Task.Delay(60);
        if (!await AutoType.TypeAsync(Sequence(cred, mode, _shell.Settings.AutoTypeEnter)))
        {
            await _shell.CopySecretAsync(secret, what);
            _shell.Snackbar.Show("Окно не принимает ввод (запущено от администратора?) — " + what.ToLowerInvariant() + " скопирован");
        }
    }

    /// <summary>Что набирать: логин ⇥ пароль ⏎, только пароль ⏎ или только логин.</summary>
    public static IEnumerable<AutoType.Step> Sequence(Credential c, AutoTypeMode mode, bool pressEnter)
    {
        switch (mode)
        {
            case AutoTypeMode.LoginOnly:
                yield return new AutoType.Text(c.Login);
                yield break;
            case AutoTypeMode.LoginPassword when c.Login.Length > 0:
                yield return new AutoType.Text(c.Login);
                yield return new AutoType.Key(AutoType.VK_TAB);
                break;
        }
        yield return new AutoType.Text(c.Password);
        if (pressEnter) yield return new AutoType.Key(AutoType.VK_RETURN);
    }
}
