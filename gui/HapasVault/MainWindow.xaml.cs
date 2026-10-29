using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using HapasVault.Controls;
using HapasVault.Platform;
using HapasVault.ViewModels;

namespace HapasVault;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => ApplyChrome();
        StateChanged += (_, _) => OnStateChanged();
        PreviewKeyDown += OnKey;
    }

    private ShellViewModel? Shell => DataContext as ShellViewModel;

    /// <summary>Цвет рамки и тёмный режим DWM под текущую тему.</summary>
    public void ApplyChrome()
    {
        if (Shell is not { } s) return;
        Win32.StyleWindow(this, s.Theme.IsDark, s.Theme.Target("Surface"));
    }

    private void OnStateChanged()
    {
        // развёрнутое окно с WindowChrome выходит за экран на толщину рамки
        Root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
        A.SetIcon(MaxButton, (Geometry)FindResource(WindowState == WindowState.Maximized ? "Icon.FilterNone" : "Icon.CropSquare"));
        MaxButton.ToolTip = WindowState == WindowState.Maximized ? "Восстановить" : "Развернуть";
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);

    private void OnMaximize(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(this);
        else SystemCommands.MaximizeWindow(this);
    }

    private void OnClose(object sender, RoutedEventArgs e) => SystemCommands.CloseWindow(this);

    private void OnScrimClick(object sender, MouseButtonEventArgs e) => Shell?.Dialog?.Close(false);

    private async void OnKey(object sender, KeyEventArgs e)
    {
        if (Shell is not { } s) return;
        bool ctrl = Keyboard.Modifiers == ModifierKeys.Control;
        if (e.Key == Key.Escape)
        {
            if (s.Dialog != null) s.Dialog.Close(false);
            else if (s.Page is VaultShellViewModel { Current: VaultViewModel { Selected: not null } v }) v.Selected = null;
            else return;
            e.Handled = true;
        }
        else if (ctrl && e.Key == Key.L && s.Page is VaultShellViewModel)
        {
            e.Handled = true;
            await s.LockAsync();
        }
        else if (ctrl && e.Key == Key.N && s.Dialog == null && s.Page is VaultShellViewModel shell)
        {
            e.Handled = true;
            await shell.NewEntryCommand.ExecuteAsync(null);
        }
        else if (ctrl && e.Key == Key.F && s.Dialog == null && s.Page is VaultShellViewModel vs)
        {
            e.Handled = true;
            vs.Section = Section.Vault;
            await Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
            if (Find<TextBox>(this, "SearchBox") is { } box)
            {
                box.Focus();
                box.SelectAll();
            }
        }
    }

    private static T? Find<T>(DependencyObject root, string name) where T : FrameworkElement
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T fe && fe.Name == name) return fe;
            if (Find<T>(child, name) is { } found) return found;
        }
        return null;
    }
}
