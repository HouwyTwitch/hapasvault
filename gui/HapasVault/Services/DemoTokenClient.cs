using HapasVault.Core;

namespace HapasVault.Services;

/// <summary>
/// Токен в памяти для демо-режима и скриншотов: ведёт себя как настоящий
/// (блокировка, неверный пароль, журнал), но ничего не хранит. Пароль: demo.
/// </summary>
public sealed class DemoTokenClient : ITokenClient
{
    public const string Password = "demo";

    // фиксированная фраза: демо работает и без pmapi.dll
    private static readonly string[] DemoWords =
    [
        "orbit", "velvet", "canyon", "puzzle", "harbor", "magic", "lunar", "ticket",
        "forest", "anchor", "bright", "copper", "dolphin", "echo", "garden", "island",
        "jungle", "kitten", "ladder", "mirror", "noble", "ocean", "pepper", "quantum",
    ];

    private readonly Dictionary<uint, (string Cat, string Name, string Login, string Pw)> _items = new();
    private readonly Dictionary<uint, OtpSecret> _otp = new();
    private readonly List<LogRecord> _log = new();
    private readonly DateTime _boot = DateTime.UtcNow.AddMinutes(-47);
    private uint _next = 1;
    private bool _setup, _unlocked;

    public DemoTokenClient(bool setup = true, bool paired = true)
    {
        _setup = setup;
        IsPaired = paired;
        HasKey = setup;
        if (!setup) return;
        Seed("Почта", "Яндекс Почта", "ivan.petrov@yandex.ru");
        Seed("Почта", "Gmail", "ivan.petrov@gmail.com");
        Seed("Работа", "GitLab", "ipetrov");
        _otp[_next - 1] = new OtpSecret(OtpKind.Totp, "demo-gitlab-totp-secret"u8.ToArray());
        Seed("Работа", "VPN офиса", "petrov");
        Seed("Работа", "Jira", "ipetrov@corp.example");
        Seed("Банки", "Сбербанк Онлайн", "ivan_p");
        Seed("Банки", "Тинькофф", "+7 900 123-45-67");
        Seed("Соцсети", "Telegram", "@ivanpetrov");
        Seed("Соцсети", "ВКонтакте", "ivan.petrov");
        Seed("", "Wi-Fi дома", "HomeNet-5G");
        Seed("Игры", "Steam", "ivan_gamer");
        _otp[_next - 1] = new OtpSecret(OtpKind.Steam, "demo-steam-shared-key"u8.ToArray());
        AddLog(0x30, 0, 0, 2500);
        AddLog(0x41, 0, 3, 1900);
        AddLog(0x42, 0, 11, 1300);
        AddLog(0x30, 5, 0, 420);
        AddLog(0x30, 0, 0, 400);
        AddLog(0x41, 0, 6, 120);
    }

    private void Seed(string cat, string name, string login) =>
        _items[_next++] = (cat, name, login, Passwords.Generate(new GeneratorOptions(18)));

    private uint Uptime => (uint)(DateTime.UtcNow - _boot).TotalSeconds;

    private void AddLog(byte cmd, byte st, uint id, uint agoSeconds = 0) =>
        _log.Add(new LogRecord(Uptime - agoSeconds, cmd, st, id, 0));

    public ushort Port { get; set; }
    public TokenConnection Connection { get; set; }
    public TokenTransport Transport => TokenTransport.Simulator;
    public bool IsPaired { get; private set; }
    public bool HasKey { get; private set; }
    public bool IsAttached { get; private set; }

    private static Task Delay(int ms = 120) => Task.Delay(ms);

    private void RequireOpen()
    {
        if (!_unlocked) throw new TokenException(2, TokenError.Locked, TokenException.Describe(TokenError.Locked));
    }

    public async Task AttachAsync() { await Delay(); IsAttached = true; }
    public Task DetachAsync() { IsAttached = false; _unlocked = false; return Task.CompletedTask; }
    public Task ConnectAsync() => Task.CompletedTask;

    public async Task PairAsync()
    {
        await Delay(400);
        IsPaired = true;
    }

    public Task ForgetPairingAsync() { IsPaired = false; return Task.CompletedTask; }

    public async Task<TokenInfo> GetInfoAsync()
    {
        await Delay(40);
        return new TokenInfo(IsPaired, _setup, _unlocked, 1, (uint)_items.Count, Uptime);
    }

    public async Task<string[]> BeginSetupAsync()
    {
        await Delay(300);
        return DemoWords.ToArray();
    }

    public async Task CommitSetupAsync(string masterPassword)
    {
        await Delay(1200);   // как Argon2id
        _setup = _unlocked = HasKey = true;
        AddLog(0x21, 0, 0);
    }

    public async Task RestoreAsync(string words, string masterPassword, byte[]? backup)
    {
        await Delay(1200);
        _setup = _unlocked = HasKey = true;
        AddLog(0x22, 0, 0);
    }

    public async Task UnlockAsync(string masterPassword)
    {
        await Delay(900);
        if (masterPassword != Password)
        {
            AddLog(0x30, 5, 0);
            throw new TokenException(5, TokenError.WrongPassword, TokenException.Describe(TokenError.WrongPassword) + " (в демо — demo)");
        }
        _unlocked = true;
        AddLog(0x30, 0, 0);
    }

    public Task LockAsync() { _unlocked = false; return Task.CompletedTask; }

    public async Task<IReadOnlyList<VaultItem>> ListAsync()
    {
        await Delay(80);
        RequireOpen();
        return _items.Select(kv => new VaultItem(kv.Key, kv.Value.Cat, kv.Value.Name,
            _otp.TryGetValue(kv.Key, out var o) ? o.Kind : OtpKind.None)).ToList();
    }

    public async Task<Credential> GetAsync(uint id)
    {
        await Delay(150);
        RequireOpen();
        if (!_items.TryGetValue(id, out var it))
            throw new TokenException(6, TokenError.NotFound, TokenException.Describe(TokenError.NotFound));
        AddLog(0x41, 0, id);
        return new Credential(it.Login, it.Pw);
    }

    public async Task<uint> AddAsync(string category, string name, string login, string password, OtpSecret? otp = null)
    {
        if (TokenClient.Validate(category, name, login, password) is { } err)
            throw new TokenException(TokenError.BadArgs, err);
        await Delay(200);
        RequireOpen();
        uint id = _next++;
        _items[id] = (category, name, login, password);
        if (otp != null) _otp[id] = otp;
        AddLog(0x42, 0, id);
        return id;
    }

    public async Task UpdateAsync(uint id, string category, string name, string login, string password, OtpChange otp, OtpSecret? secret = null)
    {
        if (TokenClient.Validate(category, name, login, password) is { } err)
            throw new TokenException(TokenError.BadArgs, err);
        await Delay(200);
        RequireOpen();
        if (!_items.ContainsKey(id))
            throw new TokenException(6, TokenError.NotFound, TokenException.Describe(TokenError.NotFound));
        _items[id] = (category, name, login, password);
        if (otp == OtpChange.Remove) _otp.Remove(id);
        else if (otp == OtpChange.Set && secret != null) _otp[id] = secret;
        AddLog(0x44, 0, id);
    }

    public async Task<OtpCode> GetOtpAsync(uint id, DateTimeOffset? at = null)
    {
        await Delay(60);
        RequireOpen();
        if (!_otp.TryGetValue(id, out var o))
            throw new TokenException(12, TokenError.NoOtp, TokenException.Describe(TokenError.NoOtp));
        var when = at ?? DateTimeOffset.UtcNow;
        AddLog(0x45, 0, id);
        long next = (when.ToUnixTimeSeconds() / o.Period + 1) * o.Period;
        return new OtpCode(o.Code(when), o.Kind, o.Period, DateTimeOffset.FromUnixTimeSeconds(next));
    }

    public async Task DeleteAsync(uint id)
    {
        await Delay(150);
        RequireOpen();
        _items.Remove(id);
        _otp.Remove(id);
        AddLog(0x43, 0, id);
    }

    public async Task<IReadOnlyList<LogRecord>> GetLogAsync()
    {
        await Delay(80);
        RequireOpen();
        uint now = Uptime;
        return _log.Select(r => r with { AgoSeconds = now - r.UptimeSeconds }).Reverse().Take(32).ToList();
    }

    public async Task<byte[]> BackupAsync()
    {
        await Delay(200);
        RequireOpen();
        AddLog(0x51, 0, 0);
        return new byte[2048];
    }

    public async Task FactoryResetAsync()
    {
        await Delay(300);
        RequireOpen();
        _items.Clear();
        _setup = _unlocked = IsPaired = HasKey = false;
    }

    public void Dispose()
    {
    }
}
