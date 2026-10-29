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
    private static int _next = 47200 + Environment.ProcessId % 500;
    private Process? _proc;

    public string Dir { get; }
    public ushort Port { get; }

    public Sim(string? dir = null)
    {
        Dir = dir ?? Directory.CreateTempSubdirectory("hapas-test-").FullName;
        Port = (ushort)Interlocked.Increment(ref _next);
        Start();
    }

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
        _proc = Process.Start(new ProcessStartInfo(Executable)
        {
            ArgumentList = { FlashPath, Port.ToString() },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        _proc.OutputDataReceived += (_, _) => { };
        _proc.BeginOutputReadLine();
        _proc.BeginErrorReadLine();
        for (int i = 0; i < 100; i++)
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
        throw new TimeoutException("симулятор не запустился");
    }

    public void Stop()
    {
        if (_proc is { HasExited: false }) { _proc.Kill(); _proc.WaitForExit(); }
        _proc?.Dispose();
        _proc = null;
    }

    public TokenClient Client(string identity = "pc.id")
    {
        var c = new TokenClient(Path.Combine(Dir, identity)) { Port = Port };
        c.SetArgon(1024, 1);   // быстрее в тестах; на всех «ПК» теста одинаково
        return c;
    }

    public void Dispose()
    {
        Stop();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
