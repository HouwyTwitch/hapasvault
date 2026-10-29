using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using HapasVault.Services;
using HapasVault.Theming;
using HapasVault.ViewModels;

namespace HapasVault;

/// <summary>
/// Прогон всех экранов на демо-токене с сохранением PNG (HapasVault.exe --screenshots каталог).
/// Нужен CI: проверяет, что разметка грузится без ошибок, и даёт картинки для ревью.
/// </summary>
internal static class Screenshots
{
    public static async Task<int> RunAsync(MainWindow window, ShellViewModel shell, string dir)
    {
        Directory.CreateDirectory(dir);
        window.WindowState = WindowState.Normal;
        window.Width = 1280;
        window.Height = 820;
        window.Left = 0;
        window.Top = 0;
        var errors = new List<string>();

        async Task Shot(string name, Func<Task> setup)
        {
            try
            {
                await setup();
                await Settle();
                Save(window, Path.Combine(dir, name + ".png"));
                Console.WriteLine($"ok   {name}");
            }
            catch (Exception e)
            {
                errors.Add($"{name}: {e}");
                Console.WriteLine($"FAIL {name}: {e.Message}");
            }
        }

        var theme = shell.Theme;
        theme.Mode = ThemeMode.Light;
        theme.Style = PaletteStyle.TonalSpot;
        theme.Seed = ThemeManager.DefaultSeed;
        theme.Apply(animate: false);

        await Shot("01-connect", () => { shell.Page = new ConnectViewModel(shell); return Task.CompletedTask; });

        await Shot("02-pair", async () =>
        {
            await shell.EnterDemoAsync(new DemoTokenClient(setup: false, paired: false));
            var pair = (PairViewModel)shell.Page!;
            await pair.PairCommand.ExecuteAsync(null);
        });

        await Shot("03-welcome", async () => { await shell.RefreshAsync(); });

        SetupViewModel? setup = null;
        await Shot("04-setup-intro", () =>
        {
            setup = new SetupViewModel(shell);
            shell.Page = setup;
            return Task.CompletedTask;
        });
        await Shot("05-setup-words", () => setup!.BeginCommand.ExecuteAsync(null));
        await Shot("06-setup-password", () =>
        {
            setup!.Step = SetupStep.Password;
            setup.Password = "корова-батарея-скрепка";
            return Task.CompletedTask;
        });

        await Shot("07-restore", () =>
        {
            var restore = new RestoreViewModel(shell);
            shell.Page = restore;
            restore.Words[0].Text = "orbit velvet canyon puzzle harbor magic lunar ticket forest anchor bright copper";
            return Task.CompletedTask;
        });

        await Shot("08-lock", async () => { await shell.EnterDemoAsync(new DemoTokenClient()); });

        await Shot("09-lock-error", async () =>
        {
            var lockVm = (LockViewModel)shell.Page!;
            lockVm.Password = "не тот";
            await lockVm.UnlockCommand.ExecuteAsync(null);
        });

        await Shot("10-vault", async () =>
        {
            var lockVm = (LockViewModel)shell.Page!;
            lockVm.Password = DemoTokenClient.Password;
            await lockVm.UnlockCommand.ExecuteAsync(null);
            await Settle();
            var vault = ((VaultShellViewModel)shell.Page!).Vault;
            vault.Selected = vault.Groups[1].Items[0];
            await vault.Detail!.RevealCommand.ExecuteAsync(null);
        });

        var vaultShell = (VaultShellViewModel?)shell.Page;
        await Shot("11-editor", () =>
        {
            _ = vaultShell!.Vault.AddCommand.ExecuteAsync(null);
            var ed = (EditorDialogViewModel)shell.Dialog!;
            ed.Name = "Госуслуги";
            ed.Login = "ivan.petrov@yandex.ru";
            ed.IsGeneratorOpen = true;
            return Task.CompletedTask;
        });

        await Shot("12-confirm", () =>
        {
            shell.Dialog?.Close(false);
            var settings = new SettingsViewModel(shell);
            _ = settings.FactoryResetCommand.ExecuteAsync(null);
            return Task.CompletedTask;
        });

        await Shot("13-log", async () =>
        {
            shell.Dialog?.Close(false);
            await Settle();
            vaultShell!.Section = Section.Log;
        });

        await Shot("14-settings", () => { vaultShell!.Section = Section.Settings; return Task.CompletedTask; });

        await Shot("15-vault-dark", async () =>
        {
            theme.Mode = ThemeMode.Dark;
            theme.Style = PaletteStyle.Expressive;
            theme.Seed = Color.FromRgb(0x00, 0x63, 0x9B);
            theme.Apply(animate: false);
            vaultShell!.Section = Section.Vault;
            await Settle();
            vaultShell.Vault.Search = "о";
        });

        await Shot("16-lock-dark", async () => { await shell.LockAsync("Хранилище заблокировано из-за бездействия"); });

        await Shot("17-settings-dark", async () =>
        {
            await shell.EnterDemoAsync(new DemoTokenClient());
            var lockVm = (LockViewModel)shell.Page!;
            lockVm.Password = DemoTokenClient.Password;
            await lockVm.UnlockCommand.ExecuteAsync(null);
            await Settle();
            ((VaultShellViewModel)shell.Page!).Section = Section.Settings;
        });

        if (errors.Count > 0)
        {
            File.WriteAllLines(Path.Combine(dir, "errors.txt"), errors);
            return 1;
        }
        return 0;
    }

    // дать отыграть анимациям и привязкам
    private static async Task Settle()
    {
        await Task.Delay(1400);
        await Application.Current.Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
    }

    private static void Save(Window w, string path)
    {
        var root = (FrameworkElement)w.Content;
        var dpi = VisualTreeHelper.GetDpi(w);
        var bmp = new RenderTargetBitmap(
            (int)Math.Ceiling(root.ActualWidth * dpi.DpiScaleX), (int)Math.Ceiling(root.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        // фон окна (Window.Background) не входит в корневой Grid — рисуем его отдельно
        var bg = new DrawingVisual();
        using (var dc = bg.RenderOpen())
            dc.DrawRectangle(w.Background, null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
        bmp.Render(bg);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var f = File.Create(path);
        enc.Save(f);
    }
}
