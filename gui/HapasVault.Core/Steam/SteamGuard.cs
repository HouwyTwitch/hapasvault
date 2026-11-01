// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HapasVault.Core.Steam;

/// <summary>
/// Сессия Steam на этом ПК. Refresh token — временный (месяцы), обновляется и сам по себе
/// ничего не подтверждает: ключи подтверждений считает токен из identity_secret.
/// </summary>
public sealed record SteamSession(ulong SteamId, string RefreshToken, string? AccessToken = null,
                                  DateTimeOffset AccessTokenAt = default, string? DeviceId = null)
{
    public string Device => DeviceId ?? SteamWeb.DeviceIdFor(SteamId);
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
    /// <summary>Вход как мобильное приложение. guardCode — код Steam Guard (его считает токен).</summary>
    Task<SteamSession> LoginAsync(string account, string password, Func<Task<string>> guardCode, CancellationToken ct = default);
    /// <summary>Свежий access token (и, если Steam выдаст, новый refresh token — старый перестаёт работать).</summary>
    Task<SteamSession> RefreshAsync(SteamSession session, CancellationToken ct = default);
    /// <summary>Обновить access token, если он старше 10 минут. Результат нужно сохранить.</summary>
    Task<SteamSession> EnsureFreshAsync(SteamSession session, CancellationToken ct = default);
    Task<IReadOnlyList<SteamConfirmation>> ListAsync(SteamSession session, SteamKeySource key, CancellationToken ct = default);
    Task RespondAsync(SteamSession session, SteamKeySource key, IReadOnlyList<SteamConfirmation> items, bool accept,
                      CancellationToken ct = default);
}

/// <summary>
/// Steam Web: IAuthenticationService (вход, обновление токена) и mobileconf (подтверждения),
/// так же, как это делает официальное мобильное приложение.
/// </summary>
public sealed class SteamWeb : ISteamWeb, IDisposable
{
    public const string Api = "https://api.steampowered.com";
    public const string Community = "https://steamcommunity.com";
    private const string MobileCookies = "mobileClient=android; mobileClientVersion=777777 3.10.3";

    private readonly HttpClient _http;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public SteamWeb(HttpMessageHandler? handler = null, Func<DateTimeOffset>? clock = null,
                    Func<TimeSpan, CancellationToken, Task>? delay = null, IWebProxy? proxy = null)
    {
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            // null — системный прокси Windows; иначе свой (http://, socks5://) — на случай, если
            // провайдер не пускает к steamcommunity.com
            Proxy = proxy ?? HttpClient.DefaultProxy,
            UseProxy = true,
        }) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("okhttp/4.9.2");
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
    }

    public void Dispose() => _http.Dispose();

    /// <summary>Прокси из настроек: http://, https://, socks4://, socks5://host:port. null — пусто (системный).</summary>
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

    /// <summary>
    /// Отправить запрос; сетевую ошибку превратить в понятное сообщение: какой сервер
    /// и что именно (обрыв TLS, DNS, таймаут) — иначе «нет связи» не диагностировать.
    /// </summary>
    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        string host = req.RequestUri?.Host ?? "Steam";
        try
        {
            return await _http.SendAsync(req, ct);
        }
        catch (HttpRequestException e)
        {
            throw NetworkError(host, e);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw TimeoutError(host);
        }
    }

    private static SteamException NetworkError(string? host, HttpRequestException e) =>
        new($"Нет связи с {host ?? "Steam"}: {Innermost(e)}. Если интернет работает, сервер может быть " +
            "недоступен у провайдера — укажите прокси в Настройки → Steam.", network: true);

    private static SteamException TimeoutError(string? host) =>
        new($"{host ?? "Steam"} не ответил за 30 с. Проверьте интернет или прокси (Настройки → Steam).", network: true);

    /// <summary>Доступность серверов Steam: вход (api) и подтверждения (community).</summary>
    public async Task<IReadOnlyList<(string Host, string? Error)>> ProbeAsync(CancellationToken ct = default)
    {
        var result = new List<(string, string?)>();
        foreach (var url in new[] { $"{Api}/ISteamWebAPIUtil/GetServerInfo/v1/", $"{Community}/mobileconf/getlist" })
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            try
            {
                using var resp = await SendAsync(req, ct);
                result.Add((req.RequestUri!.Host, null));     // любой HTTP-ответ — сервер доступен
            }
            catch (SteamException e)
            {
                result.Add((req.RequestUri!.Host, e.Message));
            }
        }
        return result;
    }

    private static string Innermost(Exception e)
    {
        while (e.InnerException != null) e = e.InnerException;
        return e.Message.TrimEnd('.');
    }

    /// <summary>Идентификатор устройства, как у steam-totp/SDA: android:<sha1(steamid) в виде GUID>.</summary>
    public static string DeviceIdFor(ulong steamId)
    {
        string h = Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(steamId.ToString()))).ToLowerInvariant();
        return $"android:{h[..8]}-{h[8..12]}-{h[12..16]}-{h[16..20]}-{h[20..32]}";
    }

    // ---------------- IAuthenticationService ----------------

    // Как браузер на steamcommunity.com (так делают steam-session и aiosteampy): без этих
    // заголовков api.steampowered.com иногда просто закрывает соединение
    private static void ApiHeaders(HttpRequestMessage req)
    {
        req.Headers.Referrer = new Uri(Community + "/");
        req.Headers.Add("Origin", Community);
        req.Headers.Accept.ParseAdd("application/json, text/plain, */*");
    }

    /// <summary>Ответ IAuthenticationService: protobuf или JSON — Steam отдаёт и так, и так.</summary>
    private sealed class ApiResult(ProtoMessage? proto, JsonElement json)
    {
        private JsonElement Field(string name) =>
            json.ValueKind == JsonValueKind.Object && json.TryGetProperty("response", out var r) &&
            r.ValueKind == JsonValueKind.Object && r.TryGetProperty(name, out var v) ? v : default;

        public string Str(string name, int field) => proto != null ? proto.String(field)
            : Field(name) is { ValueKind: JsonValueKind.String } v ? v.GetString() ?? "" : "";

        public ulong UInt(string name, int field)
        {
            if (proto != null) return proto.UInt(field);
            var v = Field(name);
            return v.ValueKind == JsonValueKind.Number ? v.GetUInt64()
                 : v.ValueKind == JsonValueKind.String && ulong.TryParse(v.GetString(), out ulong x) ? x : 0;
        }

        public byte[] Bytes(string name, int field) => proto != null ? proto.Bytes(field)
            : Field(name) is { ValueKind: JsonValueKind.String } v ? Convert.FromBase64String(v.GetString() ?? "") : [];

        public HashSet<int> ConfirmationTypes(string name, int field) => proto != null
            ? proto.Messages(field).Select(m => (int)m.UInt(1)).ToHashSet()
            : Field(name) is { ValueKind: JsonValueKind.Array } a
                ? a.EnumerateArray().Select(c => c.TryGetProperty("confirmation_type", out var t) && t.TryGetInt32(out int i) ? i : 0).ToHashSet()
                : [];
    }

    /// <summary>Запрос к api.steampowered.com: один повтор, если сервер оборвал ответ
    /// (так бывает со старым keep-alive соединением).</summary>
    private async Task<ApiResult> ApiAsync(Func<HttpRequestMessage> make, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            using var req = make();
            ApiHeaders(req);
            HttpResponseMessage resp;
            try
            {
                resp = await _http.SendAsync(req, ct);
            }
            catch (HttpRequestException e) when (attempt == 0 && e.HttpRequestError is HttpRequestError.ResponseEnded
                                                     or HttpRequestError.ConnectionError)
            {
                await _delay(TimeSpan.FromMilliseconds(500), ct);
                continue;
            }
            catch (HttpRequestException e)
            {
                throw NetworkError(req.RequestUri?.Host, e);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                throw TimeoutError(req.RequestUri?.Host);
            }
            using (resp)
            {
                if (!resp.IsSuccessStatusCode) throw new SteamException($"Steam ответил {(int)resp.StatusCode}");
                int eresult = resp.Headers.TryGetValues("x-eresult", out var er) && int.TryParse(er.FirstOrDefault(), out int e) ? e : 1;
                if (eresult != 1) throw new SteamException(DescribeEResult(eresult), eresult: eresult);
                byte[] body = await resp.Content.ReadAsByteArrayAsync(ct);
                string? type = resp.Content.Headers.ContentType?.MediaType;
                if (type is "application/json" || (body.Length > 0 && body[0] == (byte)'{'))
                {
                    using var doc = JsonDocument.Parse(body);
                    return new ApiResult(null, doc.RootElement.Clone());
                }
                return new ApiResult(ProtoMessage.Parse(body), default);
            }
        }
    }

    private static string Url(string method) => $"{Api}/IAuthenticationService/{method}/v1/";

    /// <summary>Метод с телом protobuf (input_protobuf_encoded), как у steam-session и aiosteampy.</summary>
    private Task<ApiResult> CallAsync(string method, ProtoWriter body, CancellationToken ct)
    {
        string encoded = Convert.ToBase64String(body.ToArray());
        return ApiAsync(() => new HttpRequestMessage(HttpMethod.Post, Url(method))
        {
            Content = new FormUrlEncodedContent([new("input_protobuf_encoded", encoded)]),
        }, ct);
    }

    /// <summary>Метод с обычными полями формы.</summary>
    private Task<ApiResult> FormAsync(string method, IEnumerable<KeyValuePair<string, string>> fields, CancellationToken ct)
    {
        var list = fields.ToList();
        return ApiAsync(() => new HttpRequestMessage(HttpMethod.Post, Url(method)) { Content = new FormUrlEncodedContent(list) }, ct);
    }

    private static string DescribeEResult(int e) => e switch
    {
        5 => "Steam: неверный логин или пароль.",
        65 => "Steam: неверный код Steam Guard. Проверьте время на компьютере.",
        84 => "Steam: слишком много попыток входа, подождите.",
        88 => "Steam: неверный код Steam Guard.",
        _ => $"Steam: ошибка входа (EResult {e}).",
    };

    public async Task<SteamSession> LoginAsync(string account, string password, Func<Task<string>> guardCode, CancellationToken ct = default)
    {
        // ключ RSA — простым GET с account_name (ответ JSON), как в aiosteampy
        var rsa = await ApiAsync(() => new HttpRequestMessage(HttpMethod.Get,
            $"{Url("GetPasswordRSAPublicKey")}?account_name={Uri.EscapeDataString(account)}"), ct);
        string mod = rsa.Str("publickey_mod", 1), exp = rsa.Str("publickey_exp", 2);
        ulong keyTime = rsa.UInt("timestamp", 3);
        if (mod.Length == 0 || exp.Length == 0) throw new SteamException("Steam не выдал ключ для пароля. Проверьте логин.");
        string encrypted;
        using (var key = RSA.Create())
        {
            key.ImportParameters(new RSAParameters
            {
                Modulus = Convert.FromHexString(mod),
                Exponent = Convert.FromHexString(exp),
            });
            encrypted = Convert.ToBase64String(key.Encrypt(Encoding.UTF8.GetBytes(password), RSAEncryptionPadding.Pkcs1));
        }

        // платформа MobileApp: refresh token обновляется через GenerateAccessTokenForApp
        var device = new ProtoWriter().String(1, "HapasVault").UInt(2, 3).Int(3, -500).UInt(4, 528);
        var begin = await CallAsync("BeginAuthSessionViaCredentials", new ProtoWriter()
            .String(1, "HapasVault")
            .String(2, account)
            .String(3, encrypted)
            .UInt(4, keyTime)
            .Bool(5, true)
            .UInt(6, 3)                 // k_EAuthTokenPlatformType_MobileApp
            .UInt(7, 1)                 // k_ESessionPersistence_Persistent
            .String(8, "Mobile")
            .Message(9, device), ct);

        ulong clientId = begin.UInt("client_id", 1), steamId = begin.UInt("steamid", 5);
        byte[] requestId = begin.Bytes("request_id", 2);
        var allowed = begin.ConfirmationTypes("allowed_confirmations", 4);
        if (clientId == 0 || requestId.Length == 0) throw new SteamException("Steam не начал вход. Попробуйте позже.");
        if (allowed.Contains(3))        // k_EAuthSessionGuardType_DeviceCode — код Steam Guard
        {
            string code = await guardCode();
            // обычными полями формы, как в aiosteampy
            await FormAsync("UpdateAuthSessionWithSteamGuardCode",
            [
                new("client_id", clientId.ToString()), new("steamid", steamId.ToString()),
                new("code", code), new("code_type", "3"),
            ], ct);
        }
        else if (!allowed.Contains(1))  // k_EAuthSessionGuardType_None
        {
            throw new SteamException("Steam просит подтверждение, которое токен дать не может (код из письма). " +
                                     "Для подтверждений нужен мобильный аутентификатор, привязанный к этим секретам.");
        }

        for (int attempt = 0; attempt < 10; attempt++)
        {
            var poll = await CallAsync("PollAuthSessionStatus", new ProtoWriter().UInt(1, clientId).Bytes(2, requestId), ct);
            if (poll.UInt("new_client_id", 1) is ulong nc and not 0) clientId = nc;
            string refresh = poll.Str("refresh_token", 3);
            if (refresh.Length > 0)
                return new SteamSession(steamId, refresh, poll.Str("access_token", 4), _clock());
            await _delay(TimeSpan.FromSeconds(1), ct);
        }
        throw new SteamException("Steam не завершил вход. Попробуйте ещё раз.");
    }

    public async Task<SteamSession> RefreshAsync(SteamSession s, CancellationToken ct = default)
    {
        ApiResult r;
        try
        {
            r = await CallAsync("GenerateAccessTokenForApp", new ProtoWriter()
                .String(1, s.RefreshToken).Fixed64(2, s.SteamId).UInt(3, 1), ct);
        }
        catch (SteamException e) when (e.EResult != 0)
        {
            throw new SteamException("Сессия Steam истекла — нужен вход заново.", needsLogin: true, eresult: e.EResult);
        }
        string refresh = r.Str("refresh_token", 2);
        return s with { AccessToken = r.Str("access_token", 1), AccessTokenAt = _clock(), RefreshToken = refresh.Length > 0 ? refresh : s.RefreshToken };
    }

    // ---------------- mobileconf ----------------

    private string Cookies(SteamSession s) =>
        $"{MobileCookies}; Steam_Language=russian; sessionid={Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant()}; " +
        $"steamLoginSecure={Uri.EscapeDataString($"{s.SteamId}||{s.AccessToken}")}";

    private async Task<List<KeyValuePair<string, string>>> ParamsAsync(SteamSession s, SteamKeySource key, string tag)
    {
        long t = _clock().ToUnixTimeSeconds();
        byte[] k = await key(t, tag);
        return
        [
            new("p", s.Device), new("a", s.SteamId.ToString()), new("k", Convert.ToBase64String(k)),
            new("t", t.ToString()), new("m", "react"), new("tag", tag),
        ];
    }

    private static string Query(IEnumerable<KeyValuePair<string, string>> p) =>
        string.Join("&", p.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    private async Task<JsonElement> SendConfAsync(SteamSession s, HttpRequestMessage req, CancellationToken ct)
    {
        req.Headers.Add("Cookie", Cookies(s));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var resp = await SendAsync(req, ct);
        if ((int)resp.StatusCode is 401 or 403) throw new SteamException("Сессия Steam истекла.", needsLogin: true);
        if (!resp.IsSuccessStatusCode) throw new SteamException($"steamcommunity.com ответил {(int)resp.StatusCode}");
        string body = await resp.Content.ReadAsStringAsync(ct);
        JsonElement json;
        try
        {
            json = JsonDocument.Parse(body).RootElement.Clone();
        }
        catch (JsonException)
        {
            // без сессии Steam отдаёт HTML страницы входа
            throw new SteamException("Steam вернул страницу входа — сессия истекла.", needsLogin: true);
        }
        if (json.TryGetProperty("needauth", out var na) && na.ValueKind == JsonValueKind.True)
            throw new SteamException("Сессия Steam истекла.", needsLogin: true);
        if (!json.TryGetProperty("success", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new SteamException(json.TryGetProperty("message", out var m) && m.GetString() is { Length: > 0 } msg
                ? "Steam: " + msg
                : "Steam отклонил запрос. Проверьте время на компьютере.");
        return json;
    }

    public async Task<SteamSession> EnsureFreshAsync(SteamSession s, CancellationToken ct = default) =>
        s.AccessToken is { Length: > 0 } && _clock() - s.AccessTokenAt < TimeSpan.FromMinutes(10) ? s : await RefreshAsync(s, ct);

    private static void RequireAccess(SteamSession s)
    {
        if (s.AccessToken is not { Length: > 0 }) throw new SteamException("Нет сессии Steam.", needsLogin: true);
    }

    public async Task<IReadOnlyList<SteamConfirmation>> ListAsync(SteamSession s, SteamKeySource key, CancellationToken ct = default)
    {
        RequireAccess(s);
        var p = await ParamsAsync(s, key, "list");
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{Community}/mobileconf/getlist?{Query(p)}");
        var json = await SendConfAsync(s, req, ct);
        var list = new List<SteamConfirmation>();
        if (!json.TryGetProperty("conf", out var conf) || conf.ValueKind != JsonValueKind.Array) return list;
        foreach (var c in conf.EnumerateArray())
        {
            string Str(string n) => c.TryGetProperty(n, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString() : "";
            var summary = c.TryGetProperty("summary", out var sm) && sm.ValueKind == JsonValueKind.Array
                ? sm.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                : new List<string>();
            list.Add(new SteamConfirmation(
                Str("id"), Str("nonce"), c.TryGetProperty("type", out var ty) && ty.TryGetInt32(out int t) ? t : 0,
                Str("type_name"), Str("headline"), summary, Str("icon") is { Length: > 0 } ic ? ic : null,
                DateTimeOffset.FromUnixTimeSeconds(c.TryGetProperty("creation_time", out var ctm) && ctm.TryGetInt64(out long tt) ? tt : 0),
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
        var p = await ParamsAsync(s, key, op);
        p.Insert(0, new("op", op));
        HttpRequestMessage req;
        if (items.Count == 1)
        {
            p.Add(new("cid", items[0].Id));
            p.Add(new("ck", items[0].Nonce));
            req = new HttpRequestMessage(HttpMethod.Get, $"{Community}/mobileconf/ajaxop?{Query(p)}");
        }
        else
        {
            foreach (var c in items) { p.Add(new("cid[]", c.Id)); p.Add(new("ck[]", c.Nonce)); }
            req = new HttpRequestMessage(HttpMethod.Post, $"{Community}/mobileconf/multiajaxop") { Content = new FormUrlEncodedContent(p) };
        }
        using (req) await SendConfAsync(s, req, ct);
    }
}
