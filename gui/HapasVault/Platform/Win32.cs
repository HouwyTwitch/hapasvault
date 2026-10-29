using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace HapasVault.Platform;

/// <summary>DWM: скругление углов Windows 11, тёмная рамка, цвет границы окна.</summary>
internal static partial class Win32
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_BORDER_COLOR = 34;
    private const int DWMWA_CAPTION_COLOR = 35;
    private const int DWMWCP_ROUND = 2;

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint hwnd, int attr, ref int value, int size);

    private const uint WDA_NONE = 0, WDA_EXCLUDEFROMCAPTURE = 0x11;

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowDisplayAffinity(nint hwnd, uint affinity);

    /// <summary>
    /// Не отдавать окно в захват экрана (скриншоты, запись, демонстрация):
    /// вместо него будет пустое место. Windows 10 2004+.
    /// </summary>
    public static void ExcludeFromCapture(Window w, bool exclude)
    {
        nint h = new WindowInteropHelper(w).Handle;
        if (h == 0) return;
        try
        {
            SetWindowDisplayAffinity(h, exclude ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
        }
        catch (EntryPointNotFoundException)
        {
        }
    }

    public static void StyleWindow(Window w, bool dark, Color border)
    {
        nint h = new WindowInteropHelper(w).Handle;
        if (h == 0) return;
        try
        {
            int v = dark ? 1 : 0;
            DwmSetWindowAttribute(h, DWMWA_USE_IMMERSIVE_DARK_MODE, ref v, sizeof(int));
            v = DWMWCP_ROUND;
            DwmSetWindowAttribute(h, DWMWA_WINDOW_CORNER_PREFERENCE, ref v, sizeof(int));
            v = border.R | border.G << 8 | border.B << 16;   // COLORREF 0x00BBGGRR
            DwmSetWindowAttribute(h, DWMWA_BORDER_COLOR, ref v, sizeof(int));
            DwmSetWindowAttribute(h, DWMWA_CAPTION_COLOR, ref v, sizeof(int));
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
    }
}
