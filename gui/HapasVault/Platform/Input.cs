using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace HapasVault.Platform;

public enum HotkeyChoice { CtrlAltSpace, CtrlShiftSpace, CtrlAltP }

/// <summary>Глобальное сочетание клавиш через RegisterHotKey (WM_HOTKEY в окно приложения).</summary>
public sealed partial class GlobalHotkey : IDisposable
{
    private const int WM_HOTKEY = 0x0312;
    private const int Id = 0x4856;   // 'HV'
    private const uint MOD_ALT = 0x1, MOD_CONTROL = 0x2, MOD_SHIFT = 0x4, MOD_NOREPEAT = 0x4000;
    private const uint VK_SPACE = 0x20, VK_P = 0x50;

    private readonly HwndSource _source;
    private bool _registered;

    public GlobalHotkey(nint hwnd)
    {
        _source = HwndSource.FromHwnd(hwnd) ?? throw new InvalidOperationException("нет окна для горячей клавиши");
        _source.AddHook(Hook);
    }

    public event EventHandler? Pressed;

    public static string Describe(HotkeyChoice c) => c switch
    {
        HotkeyChoice.CtrlShiftSpace => "Ctrl+Shift+Space",
        HotkeyChoice.CtrlAltP => "Ctrl+Alt+P",
        _ => "Ctrl+Alt+Space",
    };

    /// <summary>Зарегистрировать сочетание (null — снять). false — занято другой программой.</summary>
    public bool Set(HotkeyChoice? choice)
    {
        if (_registered) UnregisterHotKey(_source.Handle, Id);
        _registered = false;
        if (choice is not { } c) return true;
        var (mods, vk) = c switch
        {
            HotkeyChoice.CtrlShiftSpace => (MOD_CONTROL | MOD_SHIFT, VK_SPACE),
            HotkeyChoice.CtrlAltP => (MOD_CONTROL | MOD_ALT, VK_P),
            _ => (MOD_CONTROL | MOD_ALT, VK_SPACE),
        };
        _registered = RegisterHotKey(_source.Handle, Id, mods | MOD_NOREPEAT, vk);
        return _registered;
    }

    private nint Hook(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam == Id)
        {
            handled = true;
            Pressed?.Invoke(this, EventArgs.Empty);
        }
        return 0;
    }

    public void Dispose()
    {
        Set(null);
        _source.RemoveHook(Hook);
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RegisterHotKey(nint hwnd, int id, uint modifiers, uint vk);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UnregisterHotKey(nint hwnd, int id);
}

/// <summary>
/// Автоввод: возврат фокуса в окно, где был пользователь, и набор текста
/// событиями клавиатуры (KEYEVENTF_UNICODE — не зависит от раскладки).
/// </summary>
public static partial class AutoType
{
    public static nint ForegroundWindow() => GetForegroundWindow();

    public static bool IsOwnWindow(nint hwnd)
    {
        if (hwnd == 0) return true;
        GetWindowThreadProcessId(hwnd, out uint pid);
        return pid == (uint)Environment.ProcessId;
    }

    public static unsafe string WindowTitle(nint hwnd)
    {
        char* buf = stackalloc char[256];
        int n = GetWindowTextW(hwnd, buf, 256);
        return n > 0 ? new string(buf, 0, n) : "";
    }

    /// <summary>Вернуть окно на передний план (мы сейчас активны, поэтому Windows разрешит).</summary>
    public static async Task<bool> FocusAsync(nint hwnd)
    {
        if (hwnd == 0 || !IsWindow(hwnd)) return false;
        if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        for (int i = 0; i < 20; i++)
        {
            if (GetForegroundWindow() == hwnd) return true;
            await Task.Delay(15);
        }
        return GetForegroundWindow() == hwnd;
    }

    /// <summary>Дождаться, пока пользователь отпустит Ctrl/Alt/Shift/Win, иначе они смешаются с вводом.</summary>
    public static async Task WaitModifiersReleasedAsync(int timeoutMs = 1500)
    {
        int[] keys = [0x10, 0x11, 0x12, 0x5B, 0x5C];   // Shift, Ctrl, Alt, LWin, RWin
        for (int waited = 0; waited < timeoutMs; waited += 20)
        {
            if (keys.All(k => (GetAsyncKeyState(k) & 0x8000) == 0)) return;
            await Task.Delay(20);
        }
    }

    public abstract record Step;
    public sealed record Text(string Value) : Step;
    public sealed record Key(ushort VirtualKey) : Step;

    public const ushort VK_TAB = 0x09, VK_RETURN = 0x0D;

    /// <summary>Набрать последовательность. false — Windows не приняла ввод (например, окно администратора).</summary>
    public static async Task<bool> TypeAsync(IEnumerable<Step> steps)
    {
        foreach (var step in steps)
        {
            switch (step)
            {
                case Key k:
                    if (!SendKey(k.VirtualKey)) return false;
                    break;
                case Text t:
                    foreach (char ch in t.Value)
                    {
                        bool ok = ch switch
                        {
                            '\r' => true,
                            '\n' => SendKey(VK_RETURN),
                            '\t' => SendKey(VK_TAB),
                            _ => SendChar(ch),
                        };
                        if (!ok) return false;
                        await Task.Delay(2);   // некоторые поля теряют слишком быстрый ввод
                    }
                    break;
            }
            await Task.Delay(30);
        }
        return true;
    }

    private static unsafe bool SendChar(char ch)
    {
        INPUT* x = stackalloc INPUT[2];
        x[0] = Keyboard(0, ch, KEYEVENTF_UNICODE);
        x[1] = Keyboard(0, ch, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
        return SendInput(2, x, sizeof(INPUT)) == 2;
    }

    private static unsafe bool SendKey(ushort vk)
    {
        INPUT* x = stackalloc INPUT[2];
        x[0] = Keyboard(vk, 0, 0);
        x[1] = Keyboard(vk, 0, KEYEVENTF_KEYUP);
        return SendInput(2, x, sizeof(INPUT)) == 2;
    }

    private static INPUT Keyboard(ushort vk, ushort scan, uint flags) => new()
    {
        Type = INPUT_KEYBOARD,
        U = new InputUnion { Ki = new KEYBDINPUT { Vk = vk, Scan = scan, Flags = flags } },
    };

    // ---- курсор: меню появляется под курсором, после закрытия курсор возвращается ----
    public static (int X, int Y) CursorPosition()
    {
        GetCursorPos(out var p);
        return (p.X, p.Y);
    }

    public static void SetCursor(int x, int y) => SetCursorPos(x, y);

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x2, KEYEVENTF_UNICODE = 0x4;
    private const int SW_RESTORE = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort Vk;
        public ushort Scan;
        public uint Flags;
        public uint Time;
        public nint ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int Dx, Dy;
        public uint MouseData, Flags, Time;
        public nint ExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT Mi;
        [FieldOffset(0)] public KEYBDINPUT Ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint Type;
        public InputUnion U;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X, Y;
    }

    [LibraryImport("user32.dll")]
    private static unsafe partial uint SendInput(uint count, INPUT* inputs, int size);

    [LibraryImport("user32.dll")]
    private static partial nint GetForegroundWindow();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(nint hwnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWindow(nint hwnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsIconic(nint hwnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShowWindow(nint hwnd, int cmd);

    [LibraryImport("user32.dll")]
    private static partial uint GetWindowThreadProcessId(nint hwnd, out uint pid);

    [LibraryImport("user32.dll", EntryPoint = "GetWindowTextW")]
    private static unsafe partial int GetWindowTextW(nint hwnd, char* text, int max);

    [LibraryImport("user32.dll")]
    private static partial short GetAsyncKeyState(int vk);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out POINT p);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetCursorPos(int x, int y);
}
