using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

namespace HapasVault.Services;

/// <summary>
/// Копирование секретов прямо через Win32 (без OLE: WPF-шный Clipboard при занятом
/// буфере блокирует UI-поток своими повторами). Текст не попадает в журнал Win+V
/// и облачный буфер; через N секунд буфер очищается, если после нас в него
/// ничего не копировали (проверка по номеру последовательности, без чтения).
/// </summary>
public sealed partial class SecretClipboard
{
    private readonly DispatcherTimer _timer = new();
    private uint _ourSequence;

    public SecretClipboard()
    {
        _timer.Tick += (_, _) => Clear();
    }

    public async Task<bool> CopyAsync(string text, int clearAfterSeconds)
    {
        _timer.Stop();
        // буфер может быть на мгновение открыт другим процессом — ждём, не блокируя UI
        for (int attempt = 0; attempt < 20; attempt++)
        {
            if (TrySet(text))
            {
                _ourSequence = GetClipboardSequenceNumber();
                if (clearAfterSeconds > 0)
                {
                    _timer.Interval = TimeSpan.FromSeconds(clearAfterSeconds);
                    _timer.Start();
                }
                return true;
            }
            await Task.Delay(25);
        }
        return false;
    }

    /// <summary>Очистить буфер, если там всё ещё наш секрет.</summary>
    public void Clear()
    {
        _timer.Stop();
        if (_ourSequence == 0) return;
        if (GetClipboardSequenceNumber() == _ourSequence)
        {
            for (int attempt = 0; attempt < 10; attempt++)
            {
                if (OpenClipboard(Owner()))
                {
                    EmptyClipboard();
                    CloseClipboard();
                    break;
                }
                Thread.Sleep(10);
            }
        }
        _ourSequence = 0;
    }

    private static nint Owner() =>
        Application.Current?.MainWindow is { } w ? new WindowInteropHelper(w).Handle : 0;

    private static bool TrySet(string text)
    {
        if (!OpenClipboard(Owner())) return false;
        try
        {
            if (!EmptyClipboard()) return false;
            if (!SetText(text)) return false;
            // флаги Windows 10+: не сохранять в журнале и не синхронизировать
            SetDword("ExcludeClipboardContentFromMonitorProcessing", 0);
            SetDword("CanIncludeInClipboardHistory", 0);
            SetDword("CanUploadToCloudClipboard", 0);
            return true;
        }
        finally
        {
            CloseClipboard();
        }
    }

    private static bool SetText(string text)
    {
        nint bytes = (text.Length + 1) * 2;
        nint h = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (h == 0) return false;
        nint p = GlobalLock(h);
        if (p == 0)
        {
            GlobalFree(h);
            return false;
        }
        Marshal.Copy(text.ToCharArray(), 0, p, text.Length);
        Marshal.WriteInt16(p, text.Length * 2, 0);
        GlobalUnlock(h);
        if (SetClipboardData(CF_UNICODETEXT, h) != 0) return true;   // память теперь принадлежит системе
        GlobalFree(h);
        return false;
    }

    private static void SetDword(string format, int value)
    {
        uint id = RegisterClipboardFormatW(format);
        if (id == 0) return;
        nint h = GlobalAlloc(GMEM_MOVEABLE, 4);
        if (h == 0) return;
        nint p = GlobalLock(h);
        if (p == 0)
        {
            GlobalFree(h);
            return;
        }
        Marshal.WriteInt32(p, value);
        GlobalUnlock(h);
        if (SetClipboardData(id, h) == 0) GlobalFree(h);
    }

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenClipboard(nint owner);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseClipboard();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EmptyClipboard();

    [LibraryImport("user32.dll")]
    private static partial nint SetClipboardData(uint format, nint mem);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint RegisterClipboardFormatW(string name);

    [LibraryImport("user32.dll")]
    private static partial uint GetClipboardSequenceNumber();

    [LibraryImport("kernel32.dll")]
    private static partial nint GlobalAlloc(uint flags, nint bytes);

    [LibraryImport("kernel32.dll")]
    private static partial nint GlobalLock(nint mem);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalUnlock(nint mem);

    [LibraryImport("kernel32.dll")]
    private static partial nint GlobalFree(nint mem);
}
