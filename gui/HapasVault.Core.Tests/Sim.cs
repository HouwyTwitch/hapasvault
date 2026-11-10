// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net.Sockets;
using System.Reflection;

[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]

namespace HapasVault.Core.Tests;

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class NativeDirAttribute(string path) : Attribute
{
    public string Path { get; } = path;
}

/// <summary>pmtoken_sim на свободном порту с flash во временном каталоге.</summary>
public sealed class Sim : IDisposable
{
    // ниже эфемерных портов (Linux 32768+, Windows 49152+): исходящее соединение
    // теста не займёт порт, на котором должен слушать следующий симулятор
    private static int _next = 21000 + Environment.ProcessId % 4000 * 2;
    private Process? _proc;

    public string Dir { get; }
    public ushort Port { get; private set; }

    public Sim(string? dir = null, bool pty = false)
    {
        Dir = dir ?? Directory.CreateTempSubdirectory("hapas-test-").FullName;
        Port = (ushort)Interlocked.Increment(ref _next);
        UsePty = pty;
        Start();
    }

    /// <summary>Псевдотерминал вместо TCP: тот же поток байт, что у USB CDC прошивки.</summary>
    public bool UsePty { get; }
    public string? PtyPath { get; private set; }

    public string FlashPath => Path.Combine(Dir, "token_flash.bin");

    public static string Executable
    {
        get
        {
            string dir = typeof(Sim).Assembly.GetCustomAttribute<NativeDirAttribute>()!.Path;
            string exe = OperatingSystem.IsWindows() ? "pmtoken_sim.exe" : "pmtoken_sim";
            foreach (var p in new[] { Path.Combine(dir, exe), Path.Combine(dir, "Release", exe) })
                if (File.Exists(p)) return p;
            throw new FileNotFoundException($"pmtoken_sim не найден в {dir}");
        }
    }

    public void Start()
    {
        if (UsePty)
        {
            StartPty();
            return;
        }
        var err = new System.Text.StringBuilder();
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (attempt > 0) Port = (ushort)Interlocked.Increment(ref _next);   // порт занят — другой
            err.Clear();
            _proc = Process.Start(new ProcessStartInfo(Executable)
            {
                ArgumentList = { FlashPath, Port.ToString() },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            })!;
            _proc.OutputDataReceived += (_, _) => { };
            _proc.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (err) err.AppendLine(e.Data); };
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            for (int i = 0; i < 300 && !_proc.HasExited; i++)
            {
                try
                {
                    using var c = new TcpClient();
                    c.Connect("127.0.0.1", Port);
                    return;   // пробное подключение: симулятор его примет и отпустит
                }
                catch (SocketException)
                {
                    Thread.Sleep(50);
                }
            }
            if (!_proc.HasExited) break;
            _proc.Dispose();
            _proc = null;
        }
        _proc?.Kill();
        throw new TimeoutException($"симулятор не запустился (порт {Port}): {err}");
    }

    private void StartPty()
    {
        _proc = Process.Start(new ProcessStartInfo(Executable)
        {
            ArgumentList = { FlashPath, "--pty" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        _proc.BeginErrorReadLine();
        string? line;
        do line = _proc.StandardOutput.ReadLine();
        while (line != null && !line.StartsWith("PTY "));
        if (line == null) throw new InvalidOperationException("симулятор не дал pty");
        PtyPath = line[4..].Trim();
        var stdout = _proc.StandardOutput;
        _ = Task.Run(() => { while (stdout.ReadLine() != null) { } });   // не дать трубе заполниться
    }

    public void Stop()
    {
        if (_proc is { HasExited: false }) { _proc.Kill(); _proc.WaitForExit(); }
        _proc?.Dispose();
        _proc = null;
    }

    public TokenClient Client(string identity = "pc.id")
    {
        // профиль с кириллицей в пути: на Windows ловит открытие файла через ANSI
        // по умолчанию клиент ищет только USB: симулятор — явным выбором
        var c = new TokenClient(Path.Combine(Dir, "Профиль Иван", identity))
        {
            Port = Port, SerialPath = PtyPath, Connection = TokenConnection.Simulator,
        };
        c.SetArgon(1024, 1);   // быстрее в тестах; на всех «ПК» теста одинаково
        return c;
    }

    public void Dispose()
    {
        Stop();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
