using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using HapasVault.Platform;
using System.Windows.Media.Animation;
using HapasVault.Controls;
using HapasVault.Motion;

namespace HapasVault.Radial;

/// <summary>Прозрачный оверлей на весь монитор: меню, разблокировка, статус.</summary>
public partial class RadialWindow : Window
{
    public RadialWindow()
    {
        InitializeComponent();
        PreviewKeyDown += OnKey;
        TextInput += OnText;
        MouseMove += (_, e) => { if (Menu.IsVisible) Menu.Track(e.GetPosition(Menu)); };
        // выбор по направлению работает в любой точке экрана, не только над кольцами
        MouseUp += (_, e) =>
        {
            if (!Menu.IsVisible || Menu.IsMouseOver) return;
            if (e.ChangedButton == MouseButton.Left)
                Menu.Commit(Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? AutoTypeMode.LoginOnly : AutoTypeMode.LoginPassword);
            else if (e.ChangedButton == MouseButton.Right)
                Menu.Commit(AutoTypeMode.PasswordOnly);
        };
        Deactivated += (_, _) => { if (!IsBusy) Cancelled?.Invoke(); };
    }

    public event Action? Cancelled;
    public event Action<string>? UnlockRequested;

    public bool IsBusy { get; private set; }

    public void SetTarget(string text) => TargetText.Text = text;

    public void ShowMenu(IReadOnlyList<RadialCategory> items)
    {
        IsBusy = false;
        UnlockCard.Visibility = Visibility.Collapsed;
        StatusCard.Visibility = Visibility.Collapsed;
        Hint.Visibility = Visibility.Visible;
        Menu.Visibility = Visibility.Visible;
        Menu.SetItems(items);
        Menu.Focus();
    }

    public void ShowUnlock(string? error = null)
    {
        IsBusy = false;
        Menu.Visibility = Visibility.Collapsed;
        StatusCard.Visibility = Visibility.Collapsed;
        Hint.Visibility = Visibility.Collapsed;
        UnlockCard.Visibility = Visibility.Visible;
        UnlockProgress.Visibility = Visibility.Collapsed;
        Password.Error = error;
        if (error != null) A.SetShake(UnlockPanel, A.GetShake(UnlockPanel) + 1);
        Dispatcher.BeginInvoke(() => Password.FocusInput(), System.Windows.Threading.DispatcherPriority.Input);
    }

    public void ShowStatus(string text, bool error = false)
    {
        IsBusy = !error;
        Menu.Visibility = Visibility.Collapsed;
        UnlockCard.Visibility = Visibility.Collapsed;
        Hint.Visibility = Visibility.Collapsed;
        StatusCard.Visibility = Visibility.Visible;
        StatusSpinner.Visibility = error ? Visibility.Collapsed : Visibility.Visible;
        StatusIcon.Visibility = error ? Visibility.Visible : Visibility.Collapsed;
        StatusText.Text = text;
    }

    /// <summary>
    /// Показать на весь монитор, где сейчас курсор (координаты — в пикселях экрана).
    /// Границы ставятся через SetWindowPos в пикселях: WPF сам пересчитает их с
    /// учётом масштаба этого монитора (максимизация прозрачного окна ненадёжна).
    /// </summary>
    public void ShowOn(int cursorX, int cursorY)
    {
        WindowState = WindowState.Normal;
        var hwnd = new WindowInteropHelper(this).EnsureHandle();
        var r = Monitors.BoundsAt(cursorX, cursorY);
        Show();
        Monitors.Place(hwnd, r);
        Activate();
        Scrim.BeginAnimation(OpacityProperty, new DoubleAnimation(0.32, TimeSpan.FromMilliseconds(220))
        { EasingFunction = M3Motion.EmphasizedDecelerate });
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            e.Handled = true;
            if (Menu.IsVisible && Menu.Filter.Length > 0) Menu.Filter = "";
            else if (!IsBusy) Cancelled?.Invoke();
            return;
        }
        if (UnlockCard.IsVisible && e.Key == Key.Enter)
        {
            e.Handled = true;
            if (Password.Password.Length == 0) return;
            UnlockProgress.Visibility = Visibility.Visible;
            IsBusy = true;
            UnlockRequested?.Invoke(Password.Password);
            Password.Password = "";
            return;
        }
        if (!Menu.IsVisible) return;
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            Menu.Commit(Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? AutoTypeMode.PasswordOnly : AutoTypeMode.LoginPassword);
        }
        else if (e.Key == Key.Back && Menu.Filter.Length > 0)
        {
            e.Handled = true;
            Menu.Filter = Menu.Filter[..^1];
        }
    }

    private void OnText(object sender, TextCompositionEventArgs e)
    {
        if (!Menu.IsVisible || string.IsNullOrEmpty(e.Text) || char.IsControl(e.Text[0])) return;
        Menu.Filter += e.Text;
        e.Handled = true;
    }
}
