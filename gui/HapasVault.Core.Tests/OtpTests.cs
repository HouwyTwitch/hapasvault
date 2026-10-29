using Xunit;

namespace HapasVault.Core.Tests;

public class OtpParseTests
{
    private const string Rfc = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";   // Base32("12345678901234567890")

    [Fact]
    public void ReferenceMatchesRfc6238()
    {
        var s = new OtpSecret(OtpKind.Totp, "12345678901234567890"u8.ToArray(), digits: 8);
        Assert.Equal("94287082", s.Code(DateTimeOffset.FromUnixTimeSeconds(59)));
        Assert.Equal("07081804", s.Code(DateTimeOffset.FromUnixTimeSeconds(1111111109)));
        var steam = new OtpSecret(OtpKind.Steam, "steam-test-secret-1234"u8.ToArray());
        Assert.Equal("T7WDC", steam.Code(DateTimeOffset.FromUnixTimeSeconds(1700000000)));
    }

    [Fact]
    public void ParsesOtpauthUri()
    {
        var s = OtpSecret.Parse($"otpauth://totp/GitHub:ivan%40mail.ru?secret={Rfc}&issuer=GitHub&algorithm=SHA256&digits=8&period=60", OtpKind.None);
        Assert.Equal(OtpKind.Totp, s.Kind);
        Assert.Equal(OtpAlgorithm.Sha256, s.Algorithm);
        Assert.Equal(8, s.Digits);
        Assert.Equal(60, s.Period);
        Assert.Equal("GitHub", s.Issuer);
        Assert.Equal("ivan@mail.ru", s.Account);
        Assert.Equal("12345678901234567890"u8.ToArray(), s.Secret);
        Assert.Equal([1, 2, 8, 60], s.ToBlob()[..4]);
    }

    [Theory]
    [InlineData("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")]
    [InlineData("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====")]
    public void ParsesBareBase32(string input)
    {
        var s = OtpSecret.Parse(input, OtpKind.Totp);
        Assert.Equal((OtpKind.Totp, 6, 30), (s.Kind, s.Digits, s.Period));
        Assert.Equal("12345678901234567890"u8.ToArray(), s.Secret);
    }

    [Fact]
    public void ParsesSteamVariants()
    {
        byte[] raw = "steam-test-secret-12"u8.ToArray();
        string b64 = Convert.ToBase64String(raw);
        Assert.Equal(raw, OtpSecret.Parse(b64, OtpKind.Steam).Secret);
        var ma = OtpSecret.Parse($$"""{"shared_secret":"{{b64}}","account_name":"ivan_gamer","identity_secret":"x"}""", OtpKind.None);
        Assert.Equal((OtpKind.Steam, "ivan_gamer"), (ma.Kind, ma.Account));
        Assert.Equal(OtpKind.Steam, OtpSecret.Parse("steam://" + Rfc, OtpKind.None).Kind);
        Assert.Equal(OtpKind.Steam, OtpSecret.Parse($"otpauth://totp/Steam:ivan?secret={Rfc}&encoder=steam", OtpKind.None).Kind);
        Assert.Equal([2, 1, 5, 30], ma.ToBlob()[..4]);
    }

    [Theory]
    [InlineData("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1", "HOTP")]
    [InlineData("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBV&algorithm=SHA512", "SHA512")]
    [InlineData("otpauth://totp/x?issuer=a", "secret")]
    [InlineData("GEZD", "короткий")]
    [InlineData("not base32 !!", "Base32")]
    [InlineData("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBV&digits=9", "6–8")]
    public void RejectsWithReadableMessage(string input, string fragment)
    {
        var e = Assert.Throws<FormatException>(() => OtpSecret.Parse(input, OtpKind.Totp));
        Assert.Contains(fragment, e.Message);
    }
}

public class OtpTokenTests
{
    [Fact]
    public async Task TokenComputesCodesAndKeepsSecret()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await c.AttachAsync();
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("пароль-для-теста");

        var totp = OtpSecret.Parse("otpauth://totp/GitHub:ivan?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8", OtpKind.None);
        var steam = new OtpSecret(OtpKind.Steam, "steam-test-secret-1234"u8.ToArray());
        uint a = await c.AddAsync("Работа", "GitHub", "ivan", "pw", totp);
        uint b = await c.AddAsync("Игры", "Steam", "ivan_gamer", "pw2", steam);
        uint plain = await c.AddAsync("", "Без кода", "x", "y");

        var list = await c.ListAsync();
        Assert.Equal(OtpKind.Totp, list.Single(i => i.Id == a).Otp);
        Assert.Equal(OtpKind.Steam, list.Single(i => i.Id == b).Otp);
        Assert.Equal(OtpKind.None, list.Single(i => i.Id == plain).Otp);

        var now = DateTimeOffset.UtcNow;
        var code = await c.GetOtpAsync(a, now);
        Assert.Equal(totp.Code(now), code.Code);
        Assert.Equal(30, code.Period);
        Assert.True(code.ValidUntil > now && code.ValidUntil <= now.AddSeconds(30));
        Assert.Equal(steam.Code(now), (await c.GetOtpAsync(b, now)).Code);

        var e = await Assert.ThrowsAsync<TokenException>(() => c.GetOtpAsync(plain, now));
        Assert.Equal(TokenError.NoOtp, e.Error);
        e = await Assert.ThrowsAsync<TokenException>(() => c.GetOtpAsync(a, now.AddMinutes(10)));
        Assert.Equal(TokenError.BadTime, e.Error);

        // правка на месте: id тот же, секрет OTP остаётся на токене
        await c.UpdateAsync(a, "Работа", "GitHub (рабочий)", "ivan2", "pw-new", OtpChange.Keep);
        Assert.Equal("pw-new", (await c.GetAsync(a)).Password);
        Assert.Equal(totp.Code(now), (await c.GetOtpAsync(a, now)).Code);
        Assert.Contains(await c.ListAsync(), i => i.Id == a && i.Name == "GitHub (рабочий)" && i.Otp == OtpKind.Totp);
        await c.UpdateAsync(a, "Работа", "GitHub", "ivan", "pw", OtpChange.Remove);
        Assert.Equal(OtpKind.None, (await c.ListAsync()).Single(i => i.Id == a).Otp);

        var flash = await File.ReadAllBytesAsync(sim.FlashPath);
        Assert.Equal(-1, flash.AsSpan().IndexOf("steam-test-secret"u8));
    }
}
