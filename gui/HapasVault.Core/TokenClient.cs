using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace HapasVault.Core;

public sealed record TokenInfo(bool Paired, bool SetupDone, bool Unlocked, uint Protocol, uint Count, uint UptimeSeconds);

public sealed record VaultItem(uint Id, string Category, string Name);

public sealed record Credential(string Login, string Password);

/// <summary>Запись журнала токена. Ago — сколько секунд назад (по аптайму токена).</summary>
public sealed record LogRecord(uint UptimeSeconds, byte Command, byte Status, uint ItemId, uint AgoSeconds)
{
    public bool Ok => Status == 0;
}

/// <summary>
/// Асинхронная обёртка над pmapi. Вызовы выполняются по одному в пуле потоков:
/// Argon2id (64 МиБ) и сеть не блокируют UI.
/// </summary>
public sealed unsafe partial class TokenClient : ITokenClient
{
    public const ushort DefaultPort = 47123;
    public const int MaxField = 255;      // PM_MAX_STR, байт UTF-8
    public const int MaxPassword = 1024;  // PM_MAX_PASSWORD

    private readonly SemaphoreSlim _gate = new(1, 1);
    private nint _h;

    public TokenClient(string identityPath)
    {
        string? dir = Path.GetDirectoryName(Path.GetFullPath(identityPath));
        if (dir != null) Directory.CreateDirectory(dir);
        _h = Native.pmapi_create(identityPath);
        if (_h == 0) throw new TokenException(TokenError.Other, "Не удалось инициализировать клиент токена.");
    }

    public ushort Port { get; set; } = DefaultPort;

    public static int NativeVersion => Native.pmapi_version();

    public bool IsPaired => Native.pmapi_is_paired(Handle) != 0;
    public bool HasKey => Native.pmapi_has_key(Handle) != 0;
    public bool IsAttached => Native.pmapi_is_attached(Handle) != 0;

    private nint Handle => _h != 0 ? _h : throw new ObjectDisposedException(nameof(TokenClient));

    /// <summary>Параметры Argon2id. Только для тестов: должны совпадать на всех ПК.</summary>
    public void SetArgon(uint kib, uint passes) => Native.pmapi_set_argon(Handle, kib, passes);

    /// <summary>Вызов pmapi, возвращающий код: ненулевой код — исключение.</summary>
    private Task Call(Func<nint, int> f, bool connecting = false) =>
        Run(h => { Check(f(h), connecting); return 0; });

    private static void Check(int rc, bool connecting = false)
    {
        if (rc != 0) throw TokenException.FromCode(rc, connecting);
    }

    // ---------- соединение ----------

    public Task AttachAsync() { ushort port = Port; return Call(h => Native.pmapi_attach(h, port), connecting: true); }

    public Task DetachAsync() => Call(h => { Native.pmapi_detach(h); return 0; });

    public Task ConnectAsync() => Call(h => Native.pmapi_connect(h), connecting: true);

    public Task PairAsync() => Call(h => Native.pmapi_pair(h), connecting: true);

    public Task ForgetPairingAsync() => Call(h => Native.pmapi_forget_pairing(h));

    public Task<TokenInfo> GetInfoAsync() => Run(h =>
    {
        Check(Native.pmapi_info(h, out var i));
        return new TokenInfo(i.Paired != 0, i.SetupDone != 0, i.Unlocked != 0, i.Proto, i.Count, i.UptimeS);
    });

    // ---------- настройка, восстановление, замок ----------

    public Task<string[]> BeginSetupAsync() => Run(h =>
    {
        byte* buf = stackalloc byte[512];
        try
        {
            Check(Native.pmapi_setup_begin(h, buf, 512));
            return Native.Utf8(buf).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
        finally
        {
            new Span<byte>(buf, 512).Clear();
        }
    });

    public Task CommitSetupAsync(string masterPassword) => Call(h =>
    {
        using var pw = new Utf8Secret(masterPassword);
        return Native.pmapi_setup_commit(h, pw.Pointer);
    });

    public Task RestoreAsync(string words, string masterPassword, byte[]? backup) => Call(h =>
    {
        using var w = new Utf8Secret(words);
        using var pw = new Utf8Secret(masterPassword);
        fixed (byte* b = backup)
            return Native.pmapi_restore(h, w.Pointer, pw.Pointer, b, (nuint)(backup?.Length ?? 0));
    });

    public Task UnlockAsync(string masterPassword) => Call(h =>
    {
        using var pw = new Utf8Secret(masterPassword);
        return Native.pmapi_unlock(h, pw.Pointer);
    });

    public Task LockAsync() => Call(h => Native.pmapi_lock(h));

    // ---------- записи ----------

    public Task<IReadOnlyList<VaultItem>> ListAsync() => Run<IReadOnlyList<VaultItem>>(h =>
    {
        var items = new List<VaultItem>();
        var gc = GCHandle.Alloc(items);
        try
        {
            Check(Native.pmapi_list(h, &OnItem, GCHandle.ToIntPtr(gc)));
        }
        finally
        {
            gc.Free();
        }
        return items;
    });

    [UnmanagedCallersOnly]
    private static void OnItem(nint ctx, uint id, byte* category, byte* name)
    {
        var items = (List<VaultItem>)GCHandle.FromIntPtr(ctx).Target!;
        items.Add(new VaultItem(id, Native.Utf8(category), Native.Utf8(name)));
    }

    public Task<Credential> GetAsync(uint id) => Run(h =>
    {
        const int loginCap = MaxField + 1, pwCap = MaxPassword + 1;
        byte* login = stackalloc byte[loginCap];
        byte* pw = stackalloc byte[pwCap];
        try
        {
            Check(Native.pmapi_get(h, id, login, loginCap, pw, pwCap));
            return new Credential(Native.Utf8(login), Native.Utf8(pw));
        }
        finally
        {
            new Span<byte>(login, loginCap).Clear();
            new Span<byte>(pw, pwCap).Clear();
        }
    });

    /// <summary>Проверить длины полей до отправки. null — всё в порядке.</summary>
    public static string? Validate(string category, string name, string login, string password)
    {
        if (string.IsNullOrWhiteSpace(name)) return "Укажите название.";
        if (Encoding.UTF8.GetByteCount(category) > MaxField) return "Слишком длинная категория.";
        if (Encoding.UTF8.GetByteCount(name) > MaxField) return "Слишком длинное название.";
        if (Encoding.UTF8.GetByteCount(login) > MaxField) return "Слишком длинный логин.";
        if (Encoding.UTF8.GetByteCount(password) > MaxPassword) return "Слишком длинный пароль.";
        return null;
    }

    public Task<uint> AddAsync(string category, string name, string login, string password)
    {
        if (Validate(category, name, login, password) is { } err)
            throw new TokenException(TokenError.BadArgs, err);
        return Run(h =>
        {
            using var c = new Utf8Secret(category);
            using var n = new Utf8Secret(name);
            using var l = new Utf8Secret(login);
            using var p = new Utf8Secret(password);
            Check(Native.pmapi_add(h, c.Pointer, n.Pointer, l.Pointer, p.Pointer, out uint id));
            return id;
        });
    }

    public Task DeleteAsync(uint id) => Call(h => Native.pmapi_delete(h, id));

    public Task<IReadOnlyList<LogRecord>> GetLogAsync() => Run<IReadOnlyList<LogRecord>>(h =>
    {
        Check(Native.pmapi_info(h, out var info));
        var rows = new List<LogRecord>();
        var gc = GCHandle.Alloc(rows);
        try
        {
            Check(Native.pmapi_log(h, &OnLog, GCHandle.ToIntPtr(gc)));
        }
        finally
        {
            gc.Free();
        }
        // новые сверху; «сколько назад» — по аптайму токена (часов у него нет)
        return rows.Select(r => r with { AgoSeconds = info.UptimeS >= r.UptimeSeconds ? info.UptimeS - r.UptimeSeconds : 0 })
                   .Reverse().ToList();
    });

    [UnmanagedCallersOnly]
    private static void OnLog(nint ctx, uint uptime, byte cmd, byte status, uint id)
    {
        var rows = (List<LogRecord>)GCHandle.FromIntPtr(ctx).Target!;
        rows.Add(new LogRecord(uptime, cmd, status, id, 0));
    }

    public Task<byte[]> BackupAsync() => Run(h =>
    {
        var buf = new byte[Native.pmapi_max_backup()];
        nuint len;
        fixed (byte* p = buf)
            Check(Native.pmapi_backup(h, p, (nuint)buf.Length, out len));
        return buf[..(int)len];
    });

    public Task FactoryResetAsync() => Call(h => Native.pmapi_factory_reset(h));

    public void Dispose()
    {
        if (_h == 0) return;
        _gate.Wait();
        try
        {
            Native.pmapi_destroy(_h);
            _h = 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Строка UTF-8 с нулём в закреплённом массиве; затирается при Dispose.</summary>
    private sealed class Utf8Secret : IDisposable
    {
        private readonly byte[] _buf;
        private readonly GCHandle _pin;

        public Utf8Secret(string s)
        {
            _buf = GC.AllocateUninitializedArray<byte>(Encoding.UTF8.GetByteCount(s) + 1, pinned: true);
            Encoding.UTF8.GetBytes(s, _buf);
            _buf[^1] = 0;
            _pin = GCHandle.Alloc(_buf, GCHandleType.Pinned);
        }

        public byte* Pointer => (byte*)_pin.AddrOfPinnedObject();

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_buf);
            _pin.Free();
        }
    }
}
