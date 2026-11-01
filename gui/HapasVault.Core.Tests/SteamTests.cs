// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using HapasVault.Core.Steam;
using Xunit;

namespace HapasVault.Core.Tests;

public class SteamParseTests
{
    private static readonly byte[] Shared = "steam-test-secret-1234"u8.ToArray();
    private static readonly byte[] Identity = "steam-identity-secret-01"u8.ToArray();

    public static string MaFile(string? refresh = "RT-from-mafile")
    {
        string rt = refresh == null ? "null" : $"\"{refresh}\"";
        return $$"""
            {"shared_secret":"{{Convert.ToBase64String(Shared)}}","identity_secret":"{{Convert.ToBase64String(Identity)}}",
             "account_name":"ivan_gamer","revocation_code":"R12345","device_id":"android:mafile-device",
             "Session":{"SteamID":76561197960287930,"RefreshToken":{{rt}} } }
            """;
    }

    [Fact]
    public void ReferenceKeyMatchesKnownVector()
    {
        // те же значения проверяет C-тест токена (hex)
        Assert.Equal("GNl7DuRAnqCyiRkpO2i+rEavs7Y=", Convert.ToBase64String(OtpSecret.SteamConfirmationKey(Identity, 1700000000, "conf")));
    }

    [Fact]
    public void MaFileWithIdentitySecretBecomesMobileBlob()
    {
        var s = OtpSecret.Parse(MaFile(), OtpKind.None);
        Assert.Equal(OtpKind.Steam, s.Kind);
        Assert.NotNull(s.Mobile);
        Assert.Equal(Identity, s.Mobile!.IdentitySecret);
        Assert.Equal(76561197960287930ul, s.Mobile.SteamId);
        Assert.Equal(("R12345", "android:mafile-device", "RT-from-mafile"), (s.Mobile.RevocationCode, s.Mobile.DeviceId, s.Mobile.RefreshToken));
        byte[] blob = s.ToBlob();
        Assert.Equal([3, 1, 5, 30, (byte)Shared.Length], blob[..5]);
        Assert.Equal("T7WDC", s.Code(DateTimeOffset.FromUnixTimeSeconds(1700000000)));
    }

    [Fact]
    public void SharedSecretPlusSeparateIdentitySecret()
    {
        // не maFile, а два секрета по отдельности: код входа + подтверждения
        var s = OtpSecret.Parse(Convert.ToBase64String(Shared), OtpKind.Steam);
        Assert.Null(s.Mobile);
        var both = s.WithMobile(OtpSecret.ParseIdentity(Convert.ToBase64String(Identity)));
        Assert.Equal(Identity, both.Mobile!.IdentitySecret);
        Assert.Equal(3, both.ToBlob()[0]);                              // блок STEAM_MOBILE
        Assert.Equal(s.Code(DateTimeOffset.FromUnixTimeSeconds(1700000000)), both.Code(DateTimeOffset.FromUnixTimeSeconds(1700000000)));
        Assert.Contains("Base64", Assert.Throws<FormatException>(() => OtpSecret.ParseIdentity("не base64!")).Message);
        Assert.Contains("10–64", Assert.Throws<FormatException>(() => OtpSecret.ParseIdentity("AAAA")).Message);
    }

    [Theory]
    [InlineData("socks5://127.0.0.1:1080", "socks5")]
    [InlineData("http://user:p%40ss@proxy.local:3128", "http")]
    [InlineData("10.0.0.1:8080", "http")]
    public void ProxyParsing(string text, string scheme)
    {
        var p = (System.Net.WebProxy)SteamWeb.ParseProxy(text)!;
        Assert.Equal(scheme, p.Address!.Scheme);
        if (text.Contains('@')) Assert.Equal("p@ss", ((System.Net.NetworkCredential)p.Credentials!).Password);
        Assert.Null(SteamWeb.ParseProxy("  "));
        Assert.Throws<FormatException>(() => SteamWeb.ParseProxy("ftp://x:21"));
    }

    private sealed class ResetHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) =>
            throw new HttpRequestException("send failed", new System.Net.Sockets.SocketException(10054));
    }

    [Fact]
    public async Task NetworkErrorNamesHostAndCause()
    {
        using var web = new SteamWeb(new ResetHandler());
        var probe = await web.ProbeAsync();
        Assert.Equal(["api.steampowered.com", "login.steampowered.com", "steamcommunity.com"], probe.Select(p => p.Host));
        Assert.All(probe, p => Assert.Contains("прокси", p.Error));
        Assert.Contains("steamcommunity.com", probe[2].Error);
    }

    [Fact]
    public void DeviceIdLikeSteamTotp()
    {
        // steam-totp: android: + sha1("76561197960287930") в виде GUID
        string hex = Convert.ToHexString(SHA1.HashData("76561197960287930"u8.ToArray())).ToLowerInvariant();
        Assert.Equal($"android:{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..32]}", SteamWeb.DeviceIdFor(76561197960287930));
    }

    [Fact]
    public void SessionStoreRoundTripAndBadFile()
    {
        string dir = Directory.CreateTempSubdirectory("steam-store-").FullName;
        Func<byte[], byte[]> xor = b => b.Select(x => (byte)(x ^ 0x5A)).ToArray();
        var store = new FileSteamSessionStore(dir, xor, xor);
        var s = new SteamSession(7, "rt", "at", DateTimeOffset.FromUnixTimeSeconds(100), "dev");
        store.Save(5, s);
        Assert.Equal(s, store.Load(5));
        Assert.DoesNotContain("rt", File.ReadAllText(Path.Combine(dir, "steam-5.session")));
        File.WriteAllText(Path.Combine(dir, "steam-6.session"), "мусор");
        Assert.Null(store.Load(6));
        store.Delete(5);
        Assert.Null(store.Load(5));
        Directory.Delete(dir, true);
    }
}

/// <summary>
/// Поддельный Steam по схеме Modern-SDA: QueryTime (часы Steam на 2 мин впереди), вход как браузер,
/// finalizelogin + transfer_info (Set-Cookie steamLoginSecure), mobileconf с проверкой cookie и ключа.
/// </summary>
internal sealed class FakeSteam : HttpMessageHandler
{
    public const ulong SteamId = 76561197960287930;
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly byte[] _identity, _shared;
    private readonly string _account, _password;
    private int _token;

    public FakeSteam(string account, string password, byte[] shared, byte[] identity)
    {
        (_account, _password, _shared, _identity) = (account, password, shared, identity);
    }

    public List<(string Op, string[] Ids)> Responses { get; } = new();
    public int Logins { get; private set; }
    public int Finalizes { get; private set; }
    public bool ExpireOnce { get; set; }
    public int ResetsLeft { get; set; }
    public string? LastDevice { get; private set; }
    private string _jwt = "";

    private static DateTimeOffset SteamNow => DateTimeOffset.UtcNow + ClockSkew;

    private static HttpResponseMessage Proto(ProtoWriter w, int eresult = 1)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(w.ToArray()) };
        r.Headers.Add("x-eresult", eresult.ToString());
        return r;
    }

    private static HttpResponseMessage Json(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static async Task<System.Collections.Specialized.NameValueCollection> Form(HttpRequestMessage req) =>
        HttpUtility.ParseQueryString(await req.Content!.ReadAsStringAsync());

    private static async Task<ProtoMessage> Body(HttpRequestMessage req) =>
        ProtoMessage.Parse(Convert.FromBase64String((await Form(req))["input_protobuf_encoded"]!));

    private static string B64Url(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private bool KeyOk(System.Collections.Specialized.NameValueCollection q, string tag)
    {
        long t = long.Parse(q["t"]!);
        LastDevice = q["p"];
        return q["tag"] == tag && q["a"] == SteamId.ToString() &&
               q["k"] == Convert.ToBase64String(OtpSecret.SteamConfirmationKey(_identity, t, tag)) &&
               Math.Abs(t - SteamNow.ToUnixTimeSeconds()) < 30;      // время — по часам Steam
    }

    private bool CookieOk(HttpRequestMessage req)
    {
        string c = req.Headers.GetValues("Cookie").Single();
        return _jwt.Length > 0 && c.Contains($"steamLoginSecure={SteamId}||{_jwt}") && c.Contains($"steamMachineAuth{SteamId}=1") &&
               req.Headers.GetValues("X-Requested-With").Single() == "com.valvesoftware.android.steam.community";
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        var uri = req.RequestUri!;
        var p = _rsa.ExportParameters(false);
        if (uri.Host == "api.steampowered.com" && ResetsLeft > 0)
        {
            ResetsLeft--;
            throw new HttpRequestException(HttpRequestError.ResponseEnded, "The response ended prematurely.");
        }
        switch (uri.Host + uri.AbsolutePath)
        {
            case "api.steampowered.com/ITwoFactorService/QueryTime/v0001":
                return Json($"{{\"response\":{{\"server_time\":\"{SteamNow.ToUnixTimeSeconds()}\"}}}}");
            case "api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1":
            {
                var q = HttpUtility.ParseQueryString(uri.Query);
                Assert.Equal((_account, "json"), (q["account_name"], q["format"]));
                Assert.Equal("https://steamcommunity.com/", req.Headers.Referrer?.ToString());
                string mod = Convert.ToHexString(p.Modulus!), exp = Convert.ToHexString(p.Exponent!);
                return Json("{\"response\":{\"publickey_mod\":\"" + mod + "\",\"publickey_exp\":\"" + exp + "\",\"timestamp\":\"4242\"}}");
            }
            case "api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1":
            {
                var b = await Body(req);
                string pw = Encoding.UTF8.GetString(_rsa.Decrypt(Convert.FromBase64String(b.String(3)), RSAEncryptionPadding.Pkcs1));
                if (b.String(2) != _account || pw != _password) return Proto(new ProtoWriter(), eresult: 5);
                // как браузер на steamcommunity.com (aiosteampy / Modern-SDA)
                Assert.Equal((4242ul, "Community", 8ul), (b.UInt(4), b.String(8), b.UInt(11)));
                Assert.Equal(2ul, b.Messages(9).Single().UInt(2));
                return Proto(new ProtoWriter().UInt(1, 77).Bytes(2, [1, 2, 3]).Message(4, new ProtoWriter().UInt(1, 3)).UInt(5, SteamId));
            }
            case "api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1":
            {
                var f = await Form(req);
                var otp = new OtpSecret(OtpKind.Steam, _shared);
                bool ok = f["code"] == otp.Code(SteamNow) || f["code"] == otp.Code(SteamNow.AddSeconds(-30));   // по часам Steam
                Assert.Equal(("77", SteamId.ToString(), "3"), (f["client_id"], f["steamid"], f["code_type"]));
                return Proto(new ProtoWriter(), eresult: ok ? 1 : 88);
            }
            case "api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1":
                Logins++;
                _token++;
                return Proto(new ProtoWriter().String(3, $"RT{_token}").String(4, $"mobile-access-{_token}"));
            case "login.steampowered.com/jwt/finalizelogin":
            {
                var f = await Form(req);
                if (!(f["nonce"] ?? "").StartsWith("RT") || (f["sessionid"] ?? "").Length != 24) return Json("{\"error\":8}");
                Finalizes++;
                return Json("{\"steamID\":\"" + SteamId + "\",\"transfer_info\":[" +
                            "{\"url\":\"https://steamcommunity.com/login/settoken\",\"params\":{\"nonce\":\"n1\",\"auth\":\"a1\"}}," +
                            "{\"url\":\"https://store.steampowered.com/login/settoken\",\"params\":{\"nonce\":\"n2\",\"auth\":\"a2\"}}]}");
            }
            case "steamcommunity.com/login/settoken":
            {
                var f = await Form(req);
                Assert.Equal((SteamId.ToString(), "n1"), (f["steamID"], f["nonce"]));
                _jwt = B64Url("{\"alg\":\"EdDSA\"}") + "." +
                       B64Url($"{{\"sub\":\"{SteamId}\",\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()},\"n\":{Finalizes}}}") + ".sig";
                var r = new HttpResponseMessage(HttpStatusCode.OK);
                r.Headers.Add("Set-Cookie", $"steamLoginSecure={SteamId}%7C%7C{_jwt}; Path=/; Secure; HttpOnly; SameSite=None");
                return r;
            }
            case "store.steampowered.com/login/settoken":
                return new HttpResponseMessage(HttpStatusCode.OK);
            case "steamcommunity.com/mobileconf/getlist":
            {
                var q = HttpUtility.ParseQueryString(uri.Query);
                if (ExpireOnce) { ExpireOnce = false; return Json("""{"success":false,"needauth":true}"""); }
                if (!CookieOk(req)) return Json("""{"success":false,"needauth":true}""");
                if (!KeyOk(q, "conf")) return Json("""{"success":false,"message":"Invalid authenticator"}""");
                return Json("""
                    {"success":true,"conf":[
                      {"type":2,"type_name":"Обмен","id":"111","creator_id":"9001","nonce":"n111","creation_time":1700000000,
                       "cancel":"Отклонить","accept":"Подтвердить","icon":"https://x/a.jpg","multi":false,
                       "headline":"Gabe","summary":["Вы отдаёте: AK-47 | Redline","Вы получаете: ничего"]},
                      {"type":3,"type_name":"Торговая площадка","id":"222","creator_id":"9002","nonce":"n222","creation_time":1700000100,
                       "headline":"Mann Co. Key","summary":["Цена: 150 ₽"]}]}
                    """);
            }
            case "steamcommunity.com/mobileconf/ajaxop":
            case "steamcommunity.com/mobileconf/multiajaxop":
            {
                Assert.Equal(HttpMethod.Get, req.Method);                     // как Modern-SDA: GET
                var q = HttpUtility.ParseQueryString(uri.Query);
                if (!CookieOk(req) || !KeyOk(q, q["op"]!)) return Json("""{"success":false}""");
                Responses.Add((q["op"]!, q.GetValues(uri.AbsolutePath.EndsWith("multiajaxop") ? "cid[]" : "cid")!));
                return Json("""{"success":true}""");
            }
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}

internal sealed class MemoryStore : ISteamSessionStore
{
    public readonly Dictionary<uint, SteamSession> Items = new();
    public SteamSession? Load(uint id) => Items.GetValueOrDefault(id);
    public void Save(uint id, SteamSession s) => Items[id] = s;
    public void Delete(uint id) => Items.Remove(id);
}

public class SteamTokenTests
{
    [Fact]
    public async Task TokenComputesKeysAndConfirmerDrivesSteam()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await c.AttachAsync();
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("steam-master");

        var secret = OtpSecret.Parse(SteamParseTests.MaFile(refresh: null), OtpKind.None);
        uint id = await c.AddAsync("Игры", "Steam", "ivan_gamer", "steam-password", secret);
        uint plain = await c.AddAsync("", "Без Steam", "a", "b");

        var item = (await c.ListAsync()).Single(i => i.Id == id);
        Assert.Equal((OtpKind.Steam, true), (item.Otp, item.SteamConfirmations));
        Assert.False((await c.ListAsync()).Single(i => i.Id == plain).SteamConfirmations);

        long t = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Equal(OtpSecret.SteamConfirmationKey(secret.Mobile!.IdentitySecret, t, "allow"),
                     await c.GetSteamConfirmationKeyAsync(id, t, "allow"));
        Assert.Equal(new SteamInfo(FakeSteam.SteamId, null), await c.GetSteamInfoAsync(id));
        Assert.Equal("R12345", (await c.GetSteamInfoAsync(id, revocationCode: true)).RevocationCode);
        var e = await Assert.ThrowsAsync<TokenException>(() => c.GetSteamConfirmationKeyAsync(plain, t, "list"));
        Assert.Equal(TokenError.NoOtp, e.Error);

        // вход, список, ответы — пароль и код Steam Guard берутся у токена
        var steam = new FakeSteam("ivan_gamer", "steam-password", secret.Secret, secret.Mobile.IdentitySecret);
        steam.ResetsLeft = 1;                            // первый ответ оборвётся — повтор
        using var web = new SteamWeb(steam, delay: (_, _) => Task.CompletedTask);
        var store = new MemoryStore();
        var confirmer = new SteamConfirmer(c, id, web, store);
        var list = await confirmer.ListAsync();
        Assert.Equal(1, steam.Logins);
        Assert.Equal(["111", "222"], list.Select(x => x.Id));
        Assert.Equal(("Gabe", 2, "Вы отдаёте: AK-47 | Redline"), (list[0].Headline, list[0].Type, list[0].Summary[0]));
        Assert.Equal(SteamWeb.DeviceIdFor(FakeSteam.SteamId), steam.LastDevice);
        Assert.Equal("RT1", store.Items[id].RefreshToken);
        Assert.Equal(24, store.Items[id].SessionId!.Length);

        await confirmer.RespondAsync(list, accept: true);
        await confirmer.RespondAsync([list[1]], accept: false);
        Assert.Equal([("allow", new[] { "111", "222" }), ("cancel", new[] { "222" })],
                     steam.Responses.Select(r => (r.Op, r.Ids)).ToList(), new ResponseComparer());

        // сессия истекла — один повторный вход, без участия пользователя
        steam.ExpireOnce = true;
        Assert.Equal(2, (await confirmer.ListAsync()).Count);
        Assert.Equal(2, steam.Logins);

        // новый процесс: сессия из хранилища, без входа
        var again = new SteamConfirmer(c, id, web, store);
        Assert.Equal(2, (await again.ListAsync()).Count);
        Assert.Equal(2, steam.Logins);
    }

    [Fact]
    public async Task MaFileSessionAndDeviceIdAreUsed()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await c.AttachAsync();
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("steam-master");
        var secret = OtpSecret.Parse(SteamParseTests.MaFile(refresh: "RT0"), OtpKind.None);
        uint id = await c.AddAsync("Игры", "Steam", "ivan_gamer", "steam-password", secret);
        var store = new MemoryStore();
        SteamConfirmer.Import(store, id, secret.Mobile!);

        var steam = new FakeSteam("ivan_gamer", "steam-password", secret.Secret, secret.Mobile!.IdentitySecret);
        using var web = new SteamWeb(steam, delay: (_, _) => Task.CompletedTask);
        Assert.Equal(2, (await new SteamConfirmer(c, id, web, store).ListAsync()).Count);
        Assert.Equal((0, 1), (steam.Logins, steam.Finalizes));        // сессия из maFile: cookie по refresh token, без входа
        Assert.Equal("android:mafile-device", steam.LastDevice);      // device_id из maFile, а не вычисленный
        Assert.Equal("RT0", store.Items[id].RefreshToken);
    }

    [Fact]
    public async Task MaFileWithoutSessionKeepsDeviceIdThroughLogin()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await c.AttachAsync();
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("steam-master");
        var secret = OtpSecret.Parse(SteamParseTests.MaFile(refresh: null), OtpKind.None);
        uint id = await c.AddAsync("Игры", "Steam", "ivan_gamer", "steam-password", secret);
        var store = new MemoryStore();
        SteamConfirmer.Import(store, id, secret.Mobile!);
        Assert.False(store.Items[id].IsLoggedIn);                      // только device_id

        var steam = new FakeSteam("ivan_gamer", "steam-password", secret.Secret, secret.Mobile!.IdentitySecret);
        using var web = new SteamWeb(steam, delay: (_, _) => Task.CompletedTask);
        var confirmer = new SteamConfirmer(c, id, web, store);
        Assert.Equal(2, (await confirmer.ListAsync()).Count);
        Assert.Equal(1, steam.Logins);
        Assert.Equal("android:mafile-device", steam.LastDevice);
        confirmer.Forget();                                            // выход: сессия — нет, device_id — да
        Assert.Equal(("", "android:mafile-device"), (store.Items[id].RefreshToken, store.Items[id].DeviceId));
    }

    [Fact]
    public async Task WrongPasswordIsReported()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await c.AttachAsync();
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("steam-master");
        var secret = OtpSecret.Parse(SteamParseTests.MaFile(refresh: null), OtpKind.None);
        uint id = await c.AddAsync("Игры", "Steam", "ivan_gamer", "old-password", secret);
        var steam = new FakeSteam("ivan_gamer", "new-password", secret.Secret, secret.Mobile!.IdentitySecret);
        using var web = new SteamWeb(steam, delay: (_, _) => Task.CompletedTask);
        var e = await Assert.ThrowsAsync<SteamException>(() => new SteamConfirmer(c, id, web, new MemoryStore()).ListAsync());
        Assert.Equal(5, e.EResult);
        Assert.Contains("пароль", e.Message);
    }

    private sealed class ResponseComparer : IEqualityComparer<(string, string[])>
    {
        public bool Equals((string, string[]) a, (string, string[]) b) => a.Item1 == b.Item1 && a.Item2.SequenceEqual(b.Item2);
        public int GetHashCode((string, string[]) o) => o.Item1.GetHashCode();
    }
}
