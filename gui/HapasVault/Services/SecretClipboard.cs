using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace HapasVault.Services;

/// <summary>
/// Копирование секретов: без журнала буфера обмена Windows (Win+V) и облачной
/// синхронизации; через N секунд буфер очищается, если в нём всё ещё наш текст.
/// </summary>
public sealed class SecretClipboard
{
    private readonly DispatcherTimer _timer = new();
    private string? _ours;

    public SecretClipboard()
    {
        _timer.Tick += (_, _) => Clear();
    }

    public bool Copy(string text, int clearAfterSeconds)
    {
        var data = new DataObject();
        data.SetText(text, TextDataFormat.UnicodeText);
        // форматы-флаги Windows 10+: не сохранять в истории и не синхронизировать
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[4]));
        data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
        data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
        if (!Retry(() => Clipboard.SetDataObject(data, copy: true))) return false;
        _ours = text;
        _timer.Stop();
        if (clearAfterSeconds > 0)
        {
            _timer.Interval = TimeSpan.FromSeconds(clearAfterSeconds);
            _timer.Start();
        }
        return true;
    }

    /// <summary>Очистить буфер, если там наш секрет.</summary>
    public void Clear()
    {
        _timer.Stop();
        if (_ours == null) return;
        string? now = null;
        Retry(() => now = Clipboard.ContainsText() ? Clipboard.GetText() : null);
        if (now == _ours) Retry(Clipboard.Clear);
        _ours = null;
    }

    // буфер обмена бывает занят другим процессом
    private static bool Retry(Action a)
    {
        for (int i = 0; i < 5; i++)
        {
            try
            {
                a();
                return true;
            }
            catch (ExternalException)   // в т. ч. COMException CLIPBRD_E_CANT_OPEN
            {
                Thread.Sleep(30);
            }
        }
        return false;
    }
}
