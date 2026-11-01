// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace HapasVault.Platform;

/// <summary>
/// Значок в области уведомлений (Shell_NotifyIcon) на окне программы: окно скрыто —
/// HapasVault продолжает работать (горячая клавиша, автоблокировка).
/// </summary>
public sealed partial class TrayIcon : IDisposable
{
    private const int WM_APP_TRAY = 0x8000 + 0x4E;
    private const int NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2;
    private const int NIF_MESSAGE = 1, NIF_ICON = 2, NIF_TIP = 4, NIF_INFO = 0x10;
    private const int WM_LBUTTONUP = 0x0202, WM_LBUTTONDBLCLK = 0x0203, WM_RBUTTONUP = 0x0205;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public int cbSize;
        public nint hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public nint hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public int dwState, dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public nint hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int message, ref NOTIFYICONDATA data);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegisterWindowMessageW(string name);

    private readonly nint _hwnd;
    private readonly HwndSource _source;
    private readonly int _taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
    private nint _icon;
    private string _tip = "HapasVault";
    private bool _added;

    /// <summary>Левый клик — показать окно; правый — меню.</summary>
    public event EventHandler? Open;
    public event EventHandler? Menu;

    public TrayIcon(Window owner)
    {
        _hwnd = new WindowInteropHelper(owner).EnsureHandle();
        _source = HwndSource.FromHwnd(_hwnd);
        _source.AddHook(Hook);
    }

    private NOTIFYICONDATA Data(int flags) => new()
    {
        cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _hwnd,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = WM_APP_TRAY,
        hIcon = _icon,
        szTip = _tip,
        szInfo = "",
        szInfoTitle = "",
    };

    /// <summary>Новая картинка (смена палитры). Старая освобождается.</summary>
    public void SetIcon(nint icon, string tip)
    {
        nint old = _icon;
        _icon = icon;
        _tip = tip;
        var d = Data(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        _added = Shell_NotifyIcon(_added ? NIM_MODIFY : NIM_ADD, ref d) || _added;
        if (old != 0 && old != icon) AppIcon.DestroyIcon(old);
    }

    /// <summary>Всплывающее уведомление Windows рядом со значком.</summary>
    public void Notify(string title, string text)
    {
        var d = Data(NIF_INFO);
        d.szInfoTitle = title;
        d.szInfo = text;
        Shell_NotifyIcon(NIM_MODIFY, ref d);
    }

    private nint Hook(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg == WM_APP_TRAY)
        {
            int mouse = (int)(lParam & 0xFFFF);
            if (mouse is WM_LBUTTONUP or WM_LBUTTONDBLCLK) Open?.Invoke(this, EventArgs.Empty);
            else if (mouse == WM_RBUTTONUP) Menu?.Invoke(this, EventArgs.Empty);
            handled = true;
        }
        else if (msg == _taskbarCreated && _added)
        {
            // перезапустился проводник — значки нужно добавить заново
            _added = false;
            SetIcon(_icon, _tip);
        }
        return 0;
    }

    public void Dispose()
    {
        if (_added)
        {
            var d = Data(0);
            Shell_NotifyIcon(NIM_DELETE, ref d);
            _added = false;
        }
        _source.RemoveHook(Hook);
        if (_icon != 0) AppIcon.DestroyIcon(_icon);
        _icon = 0;
    }
}
