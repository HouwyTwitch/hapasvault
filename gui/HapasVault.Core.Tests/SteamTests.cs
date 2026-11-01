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

/// <summary>Поддельный Steam: проверяет пароль (RSA), код Steam Guard и ключи подтверждений.</summary>
internal sealed class FakeSteam : HttpMessageHandler
{
    public const ulong SteamId = 76561197960287930;
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
    public int Refreshes { get; private set; }
    public bool ExpireOnce { get; set; }
    public string? LastDevice { get; private set; }
    public string CurrentAccess => $"AT{_token}";

    private static HttpResponseMessage Proto(ProtoWriter w, int eresult = 1)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(w.ToArray()) };
        r.Headers.Add("x-eresult", eresult.ToString());
        return r;
    }

    private static HttpResponseMessage Json(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static async Task<ProtoMessage> Body(HttpRequestMessage req)
    {
        string b64 = req.Method == HttpMethod.Get
            ? HttpUtility.ParseQueryString(req.RequestUri!.Query)["input_protobuf_encoded"]!
            : await ((MultipartFormDataContent)req.Content!).First(p => p.Headers.ContentDisposition!.Name!.Trim('"') == "input_protobuf_encoded").ReadAsStringAsync();
        return ProtoMessage.Parse(Convert.FromBase64String(b64));
    }

    private bool KeyOk(System.Collections.Specialized.NameValueCollection q, string tag)
    {
        long t = long.Parse(q["t"]!);
        LastDevice = q["p"];
        return q["tag"] == tag && q["a"] == SteamId.ToString() && q["m"] == "react" &&
               q["k"] == Convert.ToBase64String(OtpSecret.SteamConfirmationKey(_identity, t, tag)) &&
               Math.Abs(t - DateTimeOffset.UtcNow.ToUnixTimeSeconds()) < 60;
    }

    private bool CookieOk(HttpRequestMessage req) =>
        req.Headers.GetValues("Cookie").Single().Contains("steamLoginSecure=" + Uri.EscapeDataString($"{SteamId}||{CurrentAccess}"));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        string path = req.RequestUri!.AbsolutePath;
        var p = _rsa.ExportParameters(false);
        switch (path)
        {
            case "/IAuthenticationService/GetPasswordRSAPublicKey/v1/":
                Assert.Equal(_account, (await Body(req)).String(1));
                return Proto(new ProtoWriter().String(1, Convert.ToHexString(p.Modulus!)).String(2, Convert.ToHexString(p.Exponent!)).UInt(3, 4242));
            case "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/":
            {
                var b = await Body(req);
                string pw = Encoding.UTF8.GetString(_rsa.Decrypt(Convert.FromBase64String(b.String(3)), RSAEncryptionPadding.Pkcs1));
                if (b.String(2) != _account || pw != _password) return Proto(new ProtoWriter(), eresult: 5);
                Assert.Equal((4242ul, 3ul, "Mobile"), (b.UInt(4), b.UInt(6), b.String(8)));
                return Proto(new ProtoWriter().UInt(1, 77).Bytes(2, [1, 2, 3]).Message(4, new ProtoWriter().UInt(1, 3)).UInt(5, SteamId));
            }
            case "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/":
            {
                var b = await Body(req);
                var otp = new OtpSecret(OtpKind.Steam, _shared);
                var now = DateTimeOffset.UtcNow;
                bool ok = b.String(3) == otp.Code(now) || b.String(3) == otp.Code(now.AddSeconds(-30));
                Assert.Equal((77ul, SteamId, 3ul), (b.UInt(1), b.UInt(2), b.UInt(4)));
                return Proto(new ProtoWriter(), eresult: ok ? 1 : 88);
            }
            case "/IAuthenticationService/PollAuthSessionStatus/v1/":
                Logins++;
                _token++;
                return Proto(new ProtoWriter().String(3, $"RT{_token}").String(4, CurrentAccess));
            case "/IAuthenticationService/GenerateAccessTokenForApp/v1/":
            {
                var b = await Body(req);
                if (!b.String(1).StartsWith("RT")) return Proto(new ProtoWriter(), eresult: 15);   // AccessDenied
                Refreshes++;
                _token++;
                return Proto(new ProtoWriter().String(1, CurrentAccess).String(2, $"RT{_token}"));
            }
            case "/mobileconf/getlist":
            {
                var q = HttpUtility.ParseQueryString(req.RequestUri.Query);
                if (ExpireOnce) { ExpireOnce = false; return Json("""{"success":false,"needauth":true}"""); }
                if (!CookieOk(req)) return Json("""{"success":false,"needauth":true}""");
                if (!KeyOk(q, "list")) return Json("""{"success":false,"message":"Invalid authenticator"}""");
                return Json("""
                    {"success":true,"conf":[
                      {"type":2,"type_name":"Обмен","id":"111","creator_id":"9001","nonce":"n111","creation_time":1700000000,
                       "cancel":"Отклонить","accept":"Подтвердить","icon":"https://x/a.jpg","multi":false,
                       "headline":"Gabe","summary":["Вы отдаёте: AK-47 | Redline","Вы получаете: ничего"]},
                      {"type":3,"type_name":"Торговая площадка","id":"222","creator_id":"9002","nonce":"n222","creation_time":1700000100,
                       "headline":"Mann Co. Key","summary":["Цена: 150 ₽"]}]}
                    """);
            }
            case "/mobileconf/ajaxop":
            {
                var q = HttpUtility.ParseQueryString(req.RequestUri.Query);
                if (!CookieOk(req) || !KeyOk(q, q["op"]!)) return Json("""{"success":false}""");
                Responses.Add((q["op"]!, [q["cid"]!]));
                return Json("""{"success":true}""");
            }
            case "/mobileconf/multiajaxop":
            {
                var q = HttpUtility.ParseQueryString(await req.Content!.ReadAsStringAsync(ct));
                if (!CookieOk(req) || !KeyOk(q, q["op"]!)) return Json("""{"success":false}""");
                Responses.Add((q["op"]!, q.GetValues("cid[]")!));
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
        using var web = new SteamWeb(steam, delay: (_, _) => Task.CompletedTask);
        var store = new MemoryStore();
        var confirmer = new SteamConfirmer(c, id, web, store);
        var list = await confirmer.ListAsync();
        Assert.Equal(1, steam.Logins);
        Assert.Equal(["111", "222"], list.Select(x => x.Id));
        Assert.Equal(("Gabe", 2, "Вы отдаёте: AK-47 | Redline"), (list[0].Headline, list[0].Type, list[0].Summary[0]));
        Assert.Equal(SteamWeb.DeviceIdFor(FakeSteam.SteamId), steam.LastDevice);
        Assert.Equal("RT1", store.Items[id].RefreshToken);

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
        Assert.Equal((0, 1), (steam.Logins, steam.Refreshes));          // сессия из maFile обновлена, не новый вход
        Assert.Equal("android:mafile-device", steam.LastDevice);
        Assert.Equal("RT1", store.Items[id].RefreshToken);            // новый refresh token сохранён
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
