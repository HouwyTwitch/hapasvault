using System.Text.Json;

namespace HapasVault.Core.Steam;

/// <summary>Где ПК хранит сессии Steam. Реализация в GUI шифрует их DPAPI.</summary>
public interface ISteamSessionStore
{
    SteamSession? Load(uint entryId);
    void Save(uint entryId, SteamSession session);
    void Delete(uint entryId);
}

/// <summary>
/// Файлы сессий: steam-&lt;id&gt;.session в каталоге, содержимое — через protect/unprotect
/// (DPAPI на Windows, в тестах — как есть).
/// </summary>
public sealed class FileSteamSessionStore(string folder, Func<byte[], byte[]> protect, Func<byte[], byte[]> unprotect) : ISteamSessionStore
{
    private string PathFor(uint id) => Path.Combine(folder, $"steam-{id}.session");

    public SteamSession? Load(uint entryId)
    {
        try
        {
            string p = PathFor(entryId);
            return File.Exists(p) ? JsonSerializer.Deserialize<SteamSession>(unprotect(File.ReadAllBytes(p))) : null;
        }
        catch (Exception e) when (e is IOException or JsonException or System.Security.Cryptography.CryptographicException
                                       or UnauthorizedAccessException)
        {
            return null;    // испорчен или от другого пользователя Windows — войдём заново
        }
    }

    public void Save(uint entryId, SteamSession session)
    {
        Directory.CreateDirectory(folder);
        string p = PathFor(entryId), tmp = p + ".tmp";
        File.WriteAllBytes(tmp, protect(JsonSerializer.SerializeToUtf8Bytes(session)));
        File.Move(tmp, p, overwrite: true);
    }

    public void Delete(uint entryId)
    {
        try { File.Delete(PathFor(entryId)); } catch (IOException) { }
    }
}

/// <summary>
/// Подтверждения Steam для одной записи хранилища: пароль и код входа даёт токен,
/// ключи подтверждений считает токен, сеть — на ПК.
/// </summary>
public sealed class SteamConfirmer(ITokenClient token, uint entryId, ISteamWeb web, ISteamSessionStore store)
{
    private SteamSession? _session;
    // по одной операции: обновление сессии меняет refresh token, параллельный запрос получил бы старый
    private readonly SemaphoreSlim _gate = new(1, 1);

    public uint EntryId => entryId;
    public bool HasSession => (_session ??= store.Load(entryId)) != null;

    private SteamKeySource Key => (t, tag) => token.GetSteamConfirmationKeyAsync(entryId, t, tag);

    /// <summary>Войти заново: логин и пароль — из записи на токене, код Steam Guard — от токена.</summary>
    public async Task LoginAsync(CancellationToken ct = default)
    {
        var cred = await token.GetAsync(entryId);
        var info = await token.GetSteamInfoAsync(entryId);
        var s = await web.LoginAsync(cred.Login, cred.Password, async () => (await token.GetOtpAsync(entryId)).Code, ct);
        if (info.SteamId != 0 && s.SteamId != info.SteamId)
            throw new SteamException("Вход выполнен в другой аккаунт Steam, чем привязан к секретам этой записи.");
        var old = store.Load(entryId);
        Save(s with { DeviceId = old?.DeviceId });
    }

    private void Save(SteamSession s)
    {
        _session = s;
        store.Save(entryId, s);
    }

    /// <summary>Выполнить с действующей сессией; истекла — один раз войти заново.</summary>
    private async Task<T> WithSessionAsync<T>(Func<SteamSession, Task<T>> op, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return await WithSessionLockedAsync(op, ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<T> WithSessionLockedAsync<T>(Func<SteamSession, Task<T>> op, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                if (!HasSession) await LoginAsync(ct);
                var fresh = await web.EnsureFreshAsync(_session!, ct);
                if (!ReferenceEquals(fresh, _session)) Save(fresh);
                return await op(fresh);
            }
            catch (SteamException e) when (e.NeedsLogin && attempt == 0)
            {
                _session = null;
                store.Delete(entryId);
            }
        }
    }

    public Task<IReadOnlyList<SteamConfirmation>> ListAsync(CancellationToken ct = default) =>
        WithSessionAsync(s => web.ListAsync(s, Key, ct), ct);

    public Task RespondAsync(IReadOnlyList<SteamConfirmation> items, bool accept, CancellationToken ct = default) =>
        WithSessionAsync(async s => { await web.RespondAsync(s, Key, items, accept, ct); return true; }, ct);

    /// <summary>Сессия из maFile (SDA): вход не понадобится, пока она жива.</summary>
    public static void Import(ISteamSessionStore store, uint entryId, SteamMobile m)
    {
        if (m.RefreshToken is { Length: > 0 } rt && m.SteamId != 0)
            store.Save(entryId, new SteamSession(m.SteamId, rt, DeviceId: m.DeviceId));
    }

    public void Forget()
    {
        _session = null;
        store.Delete(entryId);
    }
}
