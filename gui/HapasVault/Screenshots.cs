using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using HapasVault.Controls;
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

        async Task Shot(string name, Func<Task> setup, Func<Window?>? over = null)
        {
            try
            {
                await setup();
                await Settle();
                if (over?.Invoke() is { } o) SaveComposite(window, o, Path.Combine(dir, name + ".png"));
                else Save(window, Path.Combine(dir, name + ".png"));
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

        await Shot("02-pair", () => shell.EnterDemoAsync(new DemoTokenClient(setup: false, paired: false)));

        await Shot("03-welcome", async () =>
        {
            var pair = (PairViewModel)shell.Page!;
            await pair.PairCommand.ExecuteAsync(null);
        });

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

        // буфер обмена: быстро, без блокировки, текст на месте, очистка работает
        await Shot("10b-clipboard", async () =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            if (!await shell.Clipboard.CopyAsync("секрет-123", 0)) throw new InvalidOperationException("копирование не удалось");
            if (sw.ElapsedMilliseconds > 1000) throw new InvalidOperationException($"копирование заняло {sw.ElapsedMilliseconds} мс");
            if (Clipboard.GetText() != "секрет-123") throw new InvalidOperationException("в буфере не тот текст");
            shell.Clipboard.Clear();
            if (Clipboard.ContainsText()) throw new InvalidOperationException("буфер не очистился");
            Console.WriteLine($"     clipboard: {sw.ElapsedMilliseconds} мс");
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

        // ---------- радиальное меню и автоввод ----------
        shell.Radial ??= new Radial.RadialController(shell);
        Radial.RadialWindow? overlay = null;
        await Shot("18-radial", async () =>
        {
            var items = await shell.Token.ListAsync();
            overlay = shell.Radial.ShowForTest(Radial.RadialController.Group(items), "Ввод в «Вход — Google Chrome»");
            await Settle();
            var m = overlay.Menu;
            m.Track(new Point(m.ActualWidth / 2 + 150, m.ActualHeight / 2 - 60));
            CheckFullScreen(overlay);
        }, () => overlay);

        await Shot("19-radial-rings", async () =>
        {
            var many = new List<HapasVault.Core.VaultItem>();
            string[] cats = ["Почта", "Работа", "Банки", "Соцсети", "Игры"];
            string[] names = ["Яндекс", "Gmail", "Outlook", "GitLab", "Jira", "VPN", "Confluence", "Сбербанк", "Тинькофф",
                              "Альфа", "Telegram", "ВКонтакте", "Discord", "Steam", "Epic", "Battle.net", "Proton", "Slack", "Figma", "ВТБ"];
            for (int i = 0; i < names.Length; i++) many.Add(new HapasVault.Core.VaultItem((uint)i + 1, cats[i % cats.Length], names[i]));
            shell.Radial.Close();   // повторное открытие того же окна тоже должно быть на весь экран
            await Task.Delay(200);
            overlay = shell.Radial.ShowForTest(Radial.RadialController.Group(many), "Ввод в «Вход — Google Chrome»");
            await Settle();
            CheckFullScreen(overlay);
            var m = overlay.Menu;
            var c = new Point(m.ActualWidth / 2, m.ActualHeight / 2);
            m.Track(c + new Vector(40, -110));    // категория справа сверху
            await Task.Delay(400);
            m.Track(c + new Vector(150, -200));   // дальше — запись в веере
        }, () => overlay);
        shell.Radial.Close();

        await Shot("20-autotype", async () =>
        {
            var box1 = new System.Windows.Controls.TextBox { Margin = new Thickness(20), FontSize = 18 };
            var box2 = new System.Windows.Controls.TextBox { Margin = new Thickness(20), FontSize = 18 };
            var test = new Window
            {
                Title = "Автоввод — тест",
                Width = 420, Height = 200, Left = 100, Top = 100,
                Content = new System.Windows.Controls.StackPanel { Children = { box1, box2 } },
            };
            test.Show();
            test.Activate();
            box1.Focus();
            await Task.Delay(300);
            var cred = new HapasVault.Core.Credential("ivan.petrov", "Пароль-123 @#$ 🔑");
            bool ok = await Platform.AutoType.TypeAsync(Radial.RadialController.Sequence(cred, AutoTypeMode.LoginPassword, pressEnter: false));
            await Task.Delay(300);
            string got = $"«{box1.Text}» / «{box2.Text}»";
            test.Close();
            if (!ok) throw new InvalidOperationException("SendInput не принял ввод");
            if (box1.Text != cred.Login || box2.Text != cred.Password)
                throw new InvalidOperationException("автоввод набрал не то: " + got);
            Console.WriteLine("     autotype: " + got);
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

    private static void CheckFullScreen(Window w)
    {
        double sw = SystemParameters.PrimaryScreenWidth, sh = SystemParameters.PrimaryScreenHeight;
        if (Math.Abs(w.ActualWidth - sw) > 2 || Math.Abs(w.ActualHeight - sh) > 2)
            throw new InvalidOperationException($"оверлей {w.ActualWidth}×{w.ActualHeight}, а экран {sw}×{sh}");
        Console.WriteLine($"     overlay: {w.ActualWidth}×{w.ActualHeight}");
    }

    // главное окно и полупрозрачный оверлей поверх него — как видит пользователь
    private static void SaveComposite(Window main, Window overlay, string path)
    {
        var root = (FrameworkElement)overlay.Content;
        var dpi = VisualTreeHelper.GetDpi(overlay);
        var under = Render(main);
        var bmp = new RenderTargetBitmap(
            (int)Math.Ceiling(root.ActualWidth * dpi.DpiScaleX), (int)Math.Ceiling(root.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        var bg = new DrawingVisual();
        using (var dc = bg.RenderOpen())
        {
            dc.DrawRectangle((Brush)Application.Current.FindResource("SurfaceDim"), null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
            var mainRoot = (FrameworkElement)main.Content;
            dc.DrawImage(under, new Rect(main.Left - overlay.Left, main.Top - overlay.Top, mainRoot.ActualWidth, mainRoot.ActualHeight));
        }
        bmp.Render(bg);
        bmp.Render(root);
        Encode(bmp, path);
    }

    private static RenderTargetBitmap Render(Window w)
    {
        var root = (FrameworkElement)w.Content;
        var dpi = VisualTreeHelper.GetDpi(w);
        var bmp = new RenderTargetBitmap(
            (int)Math.Ceiling(root.ActualWidth * dpi.DpiScaleX), (int)Math.Ceiling(root.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        var bg = new DrawingVisual();
        using (var dc = bg.RenderOpen())
            dc.DrawRectangle(w.Background, null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
        bmp.Render(bg);
        bmp.Render(root);
        return bmp;
    }

    private static void Encode(BitmapSource bmp, string path)
    {
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var f = File.Create(path);
        enc.Save(f);
    }

    private static void Save(Window w, string path) => Encode(Render(w), path);
}
