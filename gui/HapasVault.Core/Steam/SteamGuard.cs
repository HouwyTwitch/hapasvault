// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HapasVault.Core.Steam;

/// <summary>
/// Сессия Steam на этом ПК (как в браузере): refresh token сайта и cookie steamLoginSecure
/// сообщества. Сама по себе ничего не подтверждает: ключи подтверждений считает токен.
/// RefreshToken пустой — сессии нет, но device_id уже известен (из maFile).
/// </summary>
public sealed record SteamSession(ulong SteamId, string RefreshToken, string? AccessToken = null,
                                  DateTimeOffset AccessTokenAt = default, string? DeviceId = null, string? SessionId = null)
{
    public string Device => DeviceId is { Length: > 0 } d ? d : SteamWeb.DeviceIdFor(SteamId);
    public bool IsLoggedIn => RefreshToken.Length > 0;
}

public static class SteamConfirmationTypes
{
    public const int Trade = 2, MarketListing = 3, AccountRecovery = 6, ApiKey = 9;
}

public sealed record SteamConfirmation(
    string Id, string Nonce, int Type, string TypeName, string Headline, IReadOnlyList<string> Summary,
    string? Icon, DateTimeOffset Created, string? AcceptText, string? CancelText, ulong CreatorId);

/// <summary>Ключ подтверждения по (время, тег) — его считает токен.</summary>
public delegate Task<byte[]> SteamKeySource(long unixTime, string tag);

public sealed class SteamException(string message, bool needsLogin = false, int eresult = 0, bool network = false) : Exception(message)
{
    /// <summary>Не дошли до сервера (сеть, TLS, прокси).</summary>
    public bool Network { get; } = network;
    /// <summary>Сессия недействительна — нужен вход заново.</summary>
    public bool NeedsLogin { get; } = needsLogin;
    public int EResult { get; } = eresult;
}

public interface ISteamWeb
{
    /// <summary>Время по часам Steam (QueryTime): коды и ключи считаются по нему.</summary>
    Task<DateTimeOffset> SteamTimeAsync(CancellationToken ct = default);
    /// <summary>Вход. guardCode(время Steam) — код Steam Guard, его считает токен.</summary>
    Task<SteamSession> LoginAsync(string account, string password, Func<DateTimeOffset, Task<string>> guardCode, CancellationToken ct = default);
    /// <summary>Новая cookie сообщества по refresh token (без пароля).</summary>
    Task<SteamSession> RefreshAsync(SteamSession session, CancellationToken ct = default);
    /// <summary>Обновить cookie, если она истекла или вот-вот истечёт. Результат нужно сохранить.</summary>
    Task<SteamSession> EnsureFreshAsync(SteamSession session, CancellationToken ct = default);
    Task<IReadOnlyList<SteamConfirmation>> ListAsync(SteamSession session, SteamKeySource key, CancellationToken ct = default);
    Task RespondAsync(SteamSession session, SteamKeySource key, IReadOnlyList<SteamConfirmation> items, bool accept,
                      CancellationToken ct = default);
}

/// <summary>
/// Steam Web — так же, как рабочий Modern-SDA (Android) и aiosteampy:
/// вход как браузер (IAuthenticationService, WebBrowser/Community), затем
/// login.steampowered.com/jwt/finalizelogin и transfer_info — они ставят cookie
/// steamLoginSecure сообщества; подтверждения — steamcommunity.com/mobileconf.
/// </summary>
public sealed class SteamWeb : ISteamWeb, IDisposable
{
    public const string Api = "https://api.steampowered.com";
    public const string Community = "https://steamcommunity.com";
    public const string Login = "https://login.steampowered.com";
    private const string AppAgent = "Dalvik/2.1.0 (Linux; Android 14)";
    private const string WebAgent = "Mozilla/5.0 (Linux; Android 14; Pixel 6 Pro) AppleWebKit/537.36";

    private readonly HttpClient _http;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private TimeSpan? _offset;     // время Steam минус часы ПК

    public SteamWeb(HttpMessageHandler? handler = null, Func<DateTimeOffset>? clock = null,
                    Func<TimeSpan, CancellationToken, Task>? delay = null, IWebProxy? proxy = null)
    {
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            UseCookies = false,                       // cookie ведём сами: нужен steamLoginSecure сообщества
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            // null — системный прокси Windows; иначе свой (http://, socks5://)
            Proxy = proxy ?? HttpClient.DefaultProxy,
            UseProxy = true,
        }) { Timeout = TimeSpan.FromSeconds(30) };
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
    }

    public void Dispose() => _http.Dispose();

    public static IWebProxy? ParseProxy(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        string t = text.Trim();
        if (!t.Contains("://")) t = "http://" + t;
        if (!Uri.TryCreate(t, UriKind.Absolute, out var uri) || uri.Port <= 0 ||
            uri.Scheme is not ("http" or "https" or "socks4" or "socks4a" or "socks5"))
            throw new FormatException("Прокси: http://host:port или socks5://host:port");
        var p = new WebProxy(uri);
        if (uri.UserInfo is { Length: > 0 } ui && ui.Split(':', 2) is [var user, var pass])
            p.Credentials = new NetworkCredential(Uri.UnescapeDataString(user), Uri.UnescapeDataString(pass));
        return p;
    }


    /// <summary>Идентификатор устройства, как у steam-totp/SDA: android:<sha1(steamid) в виде GUID>.</summary>
    public static string DeviceIdFor(ulong steamId)
    {
        string h = Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(steamId.ToString()))).ToLowerInvariant();
        return $"android:{h[..8]}-{h[8..12]}-{h[12..16]}-{h[16..20]}-{h[20..32]}";
    }

    private static string NewSessionId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();

    // ---------------- сеть ----------------

    /// <summary>Запрос; один повтор, если сервер оборвал ответ (старое keep-alive соединение);
    /// сетевая ошибка — с именем сервера и причиной.</summary>
    private async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> make, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            var req = make();
            string host = req.RequestUri?.Host ?? "Steam";
            try
            {
                return await _http.SendAsync(req, ct);
            }
            catch (HttpRequestException e) when (attempt == 0 && e.HttpRequestError is HttpRequestError.ResponseEnded
                                                     or HttpRequestError.ConnectionError)
            {
                await _delay(TimeSpan.FromMilliseconds(500), ct);
            }
            catch (HttpRequestException e)
            {
                throw new SteamException($"Нет связи с {host}: {Innermost(e)}. Если интернет работает, сервер может быть " +
                                         "недоступен у провайдера — укажите прокси в Настройки → Steam.", network: true);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new SteamException($"{host} не ответил за 30 с. Проверьте интернет или прокси (Настройки → Steam).", network: true);
            }
            finally
            {
                req.Dispose();
            }
        }
    }

    private static string Innermost(Exception e)
    {
        while (e.InnerException != null) e = e.InnerException;
        return e.Message.TrimEnd('.');
    }

    private static HttpRequestMessage ApiReq(HttpMethod m, string url, HttpContent? body = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = body };
        req.Headers.UserAgent.ParseAdd(AppAgent);
        req.Headers.Referrer = new Uri(Community + "/");
        req.Headers.Add("Origin", Community);
        return req;
    }

    private static string AuthUrl(string method) => $"{Api}/IAuthenticationService/{method}/v1";

    private static int EResultOf(HttpResponseMessage r) =>
        r.Headers.TryGetValues("x-eresult", out var v) && int.TryParse(v.FirstOrDefault(), out int e) ? e : 1;

    private static string DescribeEResult(int e) => e switch
    {
        5 => "Steam: неверный логин или пароль.",
        65 => "Steam: неверный код Steam Guard. Проверьте время на компьютере.",
        84 => "Steam: слишком много попыток входа, подождите.",
        88 => "Steam: неверный код Steam Guard.",
        _ => $"Steam: ошибка входа (EResult {e}).",
    };


    /// <summary>Ответ IAuthenticationService: protobuf или JSON.</summary>
    private static async Task<(ProtoMessage? Proto, JsonElement Json)> ReadAuthAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (!resp.IsSuccessStatusCode) throw new SteamException($"Steam ответил {(int)resp.StatusCode}", eresult: EResultOf(resp));
        int er = EResultOf(resp);
        if (er != 1) throw new SteamException(DescribeEResult(er), eresult: er);
        byte[] body = await resp.Content.ReadAsByteArrayAsync(ct);
        bool json = resp.Content.Headers.ContentType?.MediaType == "application/json" || (body.Length > 0 && body[0] == (byte)'{');
        if (json)
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement.TryGetProperty("response", out var r) ? r.Clone() : default;
            return (null, root);
        }
        return (ProtoMessage.Parse(body), default);
    }

    private static string JStr(JsonElement o, string n) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(n, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind == JsonValueKind.Number ? v.GetRawText() : ""
            : "";

    // ---------------- время Steam ----------------

    public async Task<DateTimeOffset> SteamTimeAsync(CancellationToken ct = default)
    {
        if (_offset is null)
        {
            try
            {
                using var resp = await SendAsync(() => ApiReq(HttpMethod.Post, $"{Api}/ITwoFactorService/QueryTime/v0001",
                                                            new ByteArrayContent([])), ct);
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                long server = long.TryParse(JStr(doc.RootElement.TryGetProperty("response", out var r) ? r : default, "server_time"),
                                            out long t) ? t : 0;
                _offset = server > 0 ? DateTimeOffset.FromUnixTimeSeconds(server) - _clock() : TimeSpan.Zero;
            }
            catch (Exception e) when (e is SteamException or JsonException)
            {
                return _clock();                       // как Modern-SDA: без сверки — по часам ПК
            }
        }
        return _clock() + _offset.Value;
    }

    // ---------------- вход ----------------

    public async Task<SteamSession> LoginAsync(string account, string password, Func<DateTimeOffset, Task<string>> guardCode,
                                               CancellationToken ct = default)
    {
        string sessionId = NewSessionId();
        // 1. RSA-ключ: GET с account_name, JSON
        string mod, exp;
        ulong keyTime;
        using (var resp = await SendAsync(() => ApiReq(HttpMethod.Get,
                   $"{AuthUrl("GetPasswordRSAPublicKey")}?format=json&account_name={Uri.EscapeDataString(account)}"), ct))
        {
            var (_, j) = await ReadAuthAsync(resp, ct);
            mod = JStr(j, "publickey_mod");
            exp = JStr(j, "publickey_exp");
            keyTime = ulong.TryParse(JStr(j, "timestamp"), out ulong kt) ? kt : 0;
        }
        if (mod.Length == 0 || exp.Length == 0) throw new SteamException("Steam не выдал ключ для пароля. Проверьте логин.");
        string encrypted;
        using (var key = RSA.Create())
        {
            key.ImportParameters(new RSAParameters { Modulus = Convert.FromHexString(mod), Exponent = Convert.FromHexString(exp) });
            encrypted = Convert.ToBase64String(key.Encrypt(Encoding.UTF8.GetBytes(password), RSAEncryptionPadding.Pkcs1));
        }

        // 2. Начало сессии как браузер на steamcommunity.com (поля — как в aiosteampy/Modern-SDA)
        var device = new ProtoWriter().String(1, "HapasVault").UInt(2, 2);   // k_EAuthTokenPlatformType_WebBrowser
        string begin64 = Convert.ToBase64String(new ProtoWriter()
            .String(2, account).String(3, encrypted).UInt(4, keyTime)
            .UInt(5, 1)                // remember_login
            .UInt(7, 1)                // persistence
            .String(8, "Community")
            .Message(9, device)
            .UInt(11, 8)               // как в aiosteampy / Modern-SDA
            .ToArray());
        ulong clientId, steamId;
        byte[] requestId;
        HashSet<int> allowed;
        using (var resp = await SendAsync(() => ApiReq(HttpMethod.Post, AuthUrl("BeginAuthSessionViaCredentials"),
                   new FormUrlEncodedContent([new("input_protobuf_encoded", begin64)])), ct))
        {
            var (p, j) = await ReadAuthAsync(resp, ct);
            if (p != null)
            {
                clientId = p.UInt(1);
                requestId = p.Bytes(2);
                steamId = p.UInt(5);
                allowed = p.Messages(4).Select(m => (int)m.UInt(1)).ToHashSet();
            }
            else
            {
                clientId = ulong.TryParse(JStr(j, "client_id"), out ulong c) ? c : 0;
                steamId = ulong.TryParse(JStr(j, "steamid"), out ulong sid) ? sid : 0;
                requestId = JStr(j, "request_id") is { Length: > 0 } rid ? Convert.FromBase64String(rid) : [];
                allowed = j.ValueKind == JsonValueKind.Object && j.TryGetProperty("allowed_confirmations", out var a) &&
                          a.ValueKind == JsonValueKind.Array
                    ? a.EnumerateArray().Select(x => int.TryParse(JStr(x, "confirmation_type"), out int t) ? t : 0).ToHashSet()
                    : [3];
            }
        }
        if (clientId == 0 || requestId.Length == 0) throw new SteamException("Steam не начал вход. Попробуйте позже.");

        // 3. Код Steam Guard (по времени Steam) — обычными полями формы
        if (allowed.Count == 0 || allowed.Contains(3))
        {
            string code = await guardCode(await SteamTimeAsync(ct));
            using var resp = await SendAsync(() => ApiReq(HttpMethod.Post, AuthUrl("UpdateAuthSessionWithSteamGuardCode"),
                new FormUrlEncodedContent([
                    new("client_id", clientId.ToString()), new("steamid", steamId.ToString()),
                    new("code_type", "3"), new("code", code)])), ct);
            int er = EResultOf(resp);
            if ((int)resp.StatusCode == 400 || er != 1)
                throw new SteamException(DescribeEResult(er == 1 ? 88 : er), eresult: er == 1 ? 88 : er);
        }
        else if (!allowed.Contains(1))
        {
            throw new SteamException("Steam просит подтверждение, которое токен дать не может (код из письма). " +
                                     "Для подтверждений нужен мобильный аутентификатор, привязанный к этим секретам.");
        }

        // 4. Ждём токены
        string poll64 = Convert.ToBase64String(new ProtoWriter().UInt(1, clientId).Bytes(2, requestId).ToArray());
        string refresh = "";
        for (int attempt = 0; attempt < 10 && refresh.Length == 0; attempt++)
        {
            if (attempt > 0) await _delay(TimeSpan.FromSeconds(3), ct);
            using var resp = await SendAsync(() => ApiReq(HttpMethod.Post, AuthUrl("PollAuthSessionStatus"),
                new FormUrlEncodedContent([new("input_protobuf_encoded", poll64)])), ct);
            if (!resp.IsSuccessStatusCode) continue;
            var (p, j) = await ReadAuthAsync(resp, ct);
            refresh = p != null ? p.String(3) : JStr(j, "refresh_token");
        }
        if (refresh.Length == 0) throw new SteamException("Steam не завершил вход. Попробуйте ещё раз.");

        // 5. finalizelogin + transfer_info → cookie steamLoginSecure сообщества
        return await FinalizeAsync(new SteamSession(steamId, refresh, SessionId: sessionId), ct);
    }

    /// <summary>
    /// refresh token → cookie сообщества: так делают Modern-SDA и aiosteampy. Мобильный токен из
    /// GenerateAccessTokenForApp для steamcommunity.com не годится.
    /// </summary>
    private async Task<SteamSession> FinalizeAsync(SteamSession s, CancellationToken ct)
    {
        string sessionId = s.SessionId is { Length: > 0 } sid ? sid : NewSessionId();
        JsonElement fin;
        using (var resp = await SendAsync(() =>
               {
                   var req = ApiReq(HttpMethod.Post, $"{Login}/jwt/finalizelogin", new FormUrlEncodedContent([
                       new("nonce", s.RefreshToken), new("sessionid", sessionId), new("redir", $"{Community}/login/home/?goto=")]));
                   req.Headers.Accept.ParseAdd("application/json, text/plain, */*");
                   req.Headers.Add("sec-fetch-site", "cross-site");
                   req.Headers.Add("sec-fetch-mode", "cors");
                   req.Headers.Add("sec-fetch-dest", "empty");
                   return req;
               }, ct))
        {
            string body = await resp.Content.ReadAsStringAsync(ct);
            try
            {
                fin = JsonDocument.Parse(body).RootElement.Clone();
            }
            catch (JsonException)
            {
                throw new SteamException($"login.steampowered.com ответил {(int)resp.StatusCode}: не JSON.", needsLogin: true);
            }
        }
        if (JStr(fin, "error") is { Length: > 0 } err && err != "null")
            throw new SteamException("Сессия Steam истекла — нужен вход заново.", needsLogin: true);
        string finSteamId = JStr(fin, "steamID");
        ulong steamId = ulong.TryParse(finSteamId, out ulong f) ? f : s.SteamId;

        string? secure = null;
        if (fin.TryGetProperty("transfer_info", out var transfers) && transfers.ValueKind == JsonValueKind.Array)
            foreach (var t in transfers.EnumerateArray())
            {
                string url = JStr(t, "url");
                // параметры входа (nonce/auth) уходят только на https-адреса Steam
                if (!TransferUrlOk(url) || !t.TryGetProperty("params", out var prm) || prm.ValueKind != JsonValueKind.Object) continue;
                var form = prm.EnumerateObject().Select(x => new KeyValuePair<string, string>(x.Name,
                    x.Value.ValueKind == JsonValueKind.String ? x.Value.GetString() ?? "" : x.Value.GetRawText())).ToList();
                if (finSteamId.Length > 0) form.Add(new("steamID", finSteamId));
                try
                {
                    using var resp = await SendAsync(() => ApiReq(HttpMethod.Post, url, new FormUrlEncodedContent(form)), ct);
                    if (new Uri(url).Host != new Uri(Community).Host) continue;
                    if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
                        foreach (var c in cookies)
                            if (c.StartsWith("steamLoginSecure=", StringComparison.Ordinal))
                                secure = WebUtility.UrlDecode(c["steamLoginSecure=".Length..].Split(';')[0]);
                }
                catch (SteamException e) when (!e.Network)
                {
                }
            }
        if (secure is not { Length: > 0 } || !secure.Contains("||"))
            throw new SteamException("Steam не выдал cookie сообщества (steamLoginSecure). Попробуйте позже.", needsLogin: true);
        string jwt = secure[(secure.IndexOf("||", StringComparison.Ordinal) + 2)..];
        return s with { SteamId = steamId, AccessToken = jwt, AccessTokenAt = _clock(), SessionId = sessionId };
    }

    private static readonly string[] TransferHosts = ["steamcommunity.com", "steampowered.com", "steam.tv"];

    /// <summary>Адрес из transfer_info: https и домен Steam (или его поддомен,
    /// например store.steampowered.com, checkout.steampowered.com).</summary>
    internal static bool TransferUrlOk(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return false;
        if (u.UserInfo.Length > 0 || !u.IsDefaultPort) return false;
        string host = u.IdnHost.ToLowerInvariant();
        return TransferHosts.Any(h => host == h || host.EndsWith("." + h, StringComparison.Ordinal));
    }

    public Task<SteamSession> RefreshAsync(SteamSession s, CancellationToken ct = default)
    {
        if (!s.IsLoggedIn) throw new SteamException("Нет сессии Steam.", needsLogin: true);
        return FinalizeAsync(s with { SessionId = NewSessionId() }, ct);
    }

    /// <summary>Срок cookie — из самого JWT (exp); без него — 12 часов.</summary>
    public static DateTimeOffset? JwtExpiry(string? jwt)
    {
        try
        {
            string[] parts = (jwt ?? "").Split('.');
            if (parts.Length != 3) return null;
            string b = parts[1].Replace('-', '+').Replace('_', '/');
            b = b.PadRight(b.Length + (4 - b.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Convert.FromBase64String(b));
            return doc.RootElement.TryGetProperty("exp", out var e) && e.TryGetInt64(out long x) ? DateTimeOffset.FromUnixTimeSeconds(x) : null;
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }

    public async Task<SteamSession> EnsureFreshAsync(SteamSession s, CancellationToken ct = default)
    {
        if (!s.IsLoggedIn) throw new SteamException("Нет сессии Steam.", needsLogin: true);
        var expires = JwtExpiry(s.AccessToken) ?? s.AccessTokenAt + TimeSpan.FromHours(12);
        return s.AccessToken is { Length: > 0 } && expires - _clock() > TimeSpan.FromMinutes(2) ? s : await RefreshAsync(s, ct);
    }

    // ---------------- mobileconf ----------------

    private static void RequireAccess(SteamSession s)
    {
        if (s.AccessToken is not { Length: > 0 }) throw new SteamException("Нет сессии Steam.", needsLogin: true);
    }

    private HttpRequestMessage Conf(SteamSession s, string pathAndQuery)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{Community}/mobileconf/{pathAndQuery}");
        req.Headers.UserAgent.ParseAdd(WebAgent);
        req.Headers.Add("X-Requested-With", "com.valvesoftware.android.steam.community");
        req.Headers.Accept.ParseAdd("application/json");
        // как Modern-SDA: steamLoginSecure в виде «steamid||jwt», sessionid, steamMachineAuth
        req.Headers.Add("Cookie", $"sessionid={s.SessionId ?? NewSessionId()}; steamLoginSecure={s.SteamId}||{s.AccessToken}; " +
                                  $"steamMachineAuth{s.SteamId}=1; mobileClient=android; mobileClientVersion=0 (3.0.0)");
        return req;
    }

    private async Task<string> ParamsAsync(SteamSession s, SteamKeySource key, string tag, CancellationToken ct)
    {
        long t = (await SteamTimeAsync(ct)).ToUnixTimeSeconds();
        byte[] k = await key(t, tag);
        return $"p={Uri.EscapeDataString(s.Device)}&a={s.SteamId}&k={Uri.EscapeDataString(Convert.ToBase64String(k))}" +
               $"&t={t}&m=react&tag={tag}";
    }

    private async Task<JsonElement> SendConfAsync(Func<HttpRequestMessage> make, CancellationToken ct)
    {
        using var resp = await SendAsync(make, ct);
        if ((int)resp.StatusCode is 401 or 403 or 302) throw new SteamException("Сессия Steam истекла.", needsLogin: true);
        if (!resp.IsSuccessStatusCode) throw new SteamException($"steamcommunity.com ответил {(int)resp.StatusCode}");
        string body = await resp.Content.ReadAsStringAsync(ct);
        JsonElement json;
        try
        {
            json = JsonDocument.Parse(body).RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new SteamException("Steam вернул страницу входа — сессия истекла.", needsLogin: true);
        }
        if (json.TryGetProperty("needauth", out var na) && na.ValueKind == JsonValueKind.True)
            throw new SteamException("Сессия Steam истекла.", needsLogin: true);
        if (!json.TryGetProperty("success", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new SteamException(json.TryGetProperty("message", out var m) && m.GetString() is { Length: > 0 } msg
                ? "Steam: " + msg
                : "Steam отклонил запрос (неверный ключ подтверждения: проверьте identity_secret и device_id).");
        return json;
    }

    public async Task<IReadOnlyList<SteamConfirmation>> ListAsync(SteamSession s, SteamKeySource key, CancellationToken ct = default)
    {
        RequireAccess(s);
        string q = await ParamsAsync(s, key, "conf", ct);
        var json = await SendConfAsync(() => Conf(s, $"getlist?{q}"), ct);
        var list = new List<SteamConfirmation>();
        if (!json.TryGetProperty("conf", out var conf) || conf.ValueKind != JsonValueKind.Array) return list;
        foreach (var c in conf.EnumerateArray())
        {
            string Str(string n) => JStr(c, n);
            var summary = c.TryGetProperty("summary", out var sm) && sm.ValueKind == JsonValueKind.Array
                ? sm.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                : new List<string>();
            list.Add(new SteamConfirmation(
                Str("id"), Str("nonce"), int.TryParse(Str("type"), out int t) ? t : 0,
                Str("type_name"), Str("headline"), summary, Str("icon") is { Length: > 0 } ic ? ic : null,
                DateTimeOffset.FromUnixTimeSeconds(long.TryParse(Str("creation_time"), out long tt) ? tt : 0),
                Str("accept") is { Length: > 0 } a ? a : null, Str("cancel") is { Length: > 0 } cn ? cn : null,
                ulong.TryParse(Str("creator_id"), out ulong cr) ? cr : 0));
        }
        return list;
    }

    public async Task RespondAsync(SteamSession s, SteamKeySource key, IReadOnlyList<SteamConfirmation> items, bool accept,
                                   CancellationToken ct = default)
    {
        if (items.Count == 0) return;
        RequireAccess(s);
        string op = accept ? "allow" : "cancel";
        string q = await ParamsAsync(s, key, op, ct);
        string path = items.Count == 1
            ? $"ajaxop?op={op}&{q}&cid={Uri.EscapeDataString(items[0].Id)}&ck={Uri.EscapeDataString(items[0].Nonce)}"
            : $"multiajaxop?op={op}&{q}&" + string.Join("&", items.Select(i => $"cid[]={Uri.EscapeDataString(i.Id)}")) +
              "&" + string.Join("&", items.Select(i => $"ck[]={Uri.EscapeDataString(i.Nonce)}"));
        await SendConfAsync(() => Conf(s, path), ct);
    }

    /// <summary>Доступность серверов Steam: вход (api), cookie (login) и подтверждения (community).</summary>
    public async Task<IReadOnlyList<(string Host, string? Error)>> ProbeAsync(CancellationToken ct = default)
    {
        var result = new List<(string, string?)>();
        foreach (var url in new[] { $"{Api}/ITwoFactorService/QueryTime/v0001", $"{Login}/", $"{Community}/mobileconf/getlist" })
        {
            string host = new Uri(url).Host;
            try
            {
                using var resp = await SendAsync(() => ApiReq(url.Contains("QueryTime") ? HttpMethod.Post : HttpMethod.Get, url,
                                                            url.Contains("QueryTime") ? new ByteArrayContent([]) : null), ct);
                result.Add((host, null));     // любой HTTP-ответ — сервер доступен
            }
            catch (SteamException e)
            {
                result.Add((host, e.Message));
            }
        }
        return result;
    }
}
