using Xunit;

namespace HapasVault.Core.Tests;

public class TokenClientTests
{
    private const string Master = "корова-батарея-скрепка";

    private static async Task<string[]> SetupFresh(TokenClient c)
    {
        await c.AttachAsync();
        uint code = await c.PairAsync();
        Assert.InRange(code, 0u, 999_999u);
        var words = await c.BeginSetupAsync();
        await c.CommitSetupAsync(Master);
        return words;
    }

    private static async Task<TokenException> Fails(TokenError expected, Func<Task> f)
    {
        var e = await Assert.ThrowsAsync<TokenException>(f);
        Assert.Equal(expected, e.Error);
        return e;
    }

    [Fact]
    public async Task FullFlow()
    {
        using var sim = new Sim();
        using var c = sim.Client();

        await c.AttachAsync();
        Assert.True(c.IsAttached);
        Assert.False(c.IsPaired);

        await c.PairAsync();
        Assert.True(c.IsPaired);
        var info = await c.GetInfoAsync();
        Assert.False(info.SetupDone);

        var words = await c.BeginSetupAsync();
        Assert.Equal(24, words.Length);
        Assert.Equal(PhraseCheck.Ok, Bip39.Check(string.Join(' ', words)));
        await c.CommitSetupAsync(Master);
        Assert.True(c.HasKey);

        info = await c.GetInfoAsync();
        Assert.True(info.SetupDone);
        Assert.True(info.Unlocked);

        uint a = await c.AddAsync("Почта", "Яндекс", "ivan@ya.ru", "пароль 🔑 с юникодом");
        uint b = await c.AddAsync("", "GitHub", "ivan", Passwords.Generate(new GeneratorOptions(64)));
        var list = await c.ListAsync();
        Assert.Equal(2, list.Count);
        Assert.Contains(new VaultItem(a, "Почта", "Яндекс"), list);
        Assert.Contains(list, i => i.Id == b && i.Category == "" && i.Name == "GitHub");

        var cred = await c.GetAsync(a);
        Assert.Equal("ivan@ya.ru", cred.Login);
        Assert.Equal("пароль 🔑 с юникодом", cred.Password);

        await c.DeleteAsync(b);
        Assert.Single(await c.ListAsync());
        await Fails(TokenError.NotFound, () => c.GetAsync(b));

        var log = await c.GetLogAsync();
        Assert.NotEmpty(log);
        // новые сверху: неудачный GET удалённой записи, перед ним DELETE
        Assert.Equal((0x41, (byte)6, b), (log[0].Command, log[0].Status, log[0].ItemId));
        Assert.Equal((0x43, true), (log[1].Command, log[1].Ok));
    }

    [Fact]
    public async Task LockUnlockAndReconnect()
    {
        using var sim = new Sim();
        using (var c = sim.Client())
        {
            await SetupFresh(c);
            await c.AddAsync("Банк", "Карта", "1234", "0000");
            await c.LockAsync();
            await Fails(TokenError.Locked, () => c.ListAsync());
            await Fails(TokenError.WrongPassword, () => c.UnlockAsync("не тот"));
            await c.UnlockAsync(Master);
            Assert.Single(await c.ListAsync());
        }

        // новый процесс GUI: ключ ПК из файла, сессия устанавливается при attach,
        // а отключение заблокировало хранилище
        using var c2 = sim.Client();
        Assert.True(c2.IsPaired);
        Assert.True(c2.HasKey);
        await c2.AttachAsync();
        var info = await c2.GetInfoAsync();
        Assert.True(info.SetupDone);
        Assert.False(info.Unlocked);
        await c2.UnlockAsync(Master);
        Assert.Equal("Карта", (await c2.ListAsync())[0].Name);
    }

    [Fact]
    public async Task BackupAndRestoreOnNewToken()
    {
        string[] words;
        byte[] backup;
        using (var sim = new Sim())
        using (var c = sim.Client())
        {
            words = await SetupFresh(c);
            await c.AddAsync("Работа", "VPN", "ivanov", "s3cret!");
            backup = await c.BackupAsync();
            Assert.InRange(backup.Length, 1, 40 * 1024);
        }

        using var sim2 = new Sim();           // «новая плата» и новый ПК
        using var c2 = sim2.Client();
        await c2.AttachAsync();
        await c2.PairAsync();
        await Fails(TokenError.BadPhrase, () => c2.RestoreAsync(string.Join(' ', words.Reverse()), Master, backup));
        await c2.RestoreAsync(string.Join(' ', words), Master, backup);
        var list = await c2.ListAsync();
        Assert.Equal("VPN", Assert.Single(list).Name);
        Assert.Equal("s3cret!", (await c2.GetAsync(list[0].Id)).Password);
    }

    [Fact]
    public async Task DetectsResetTokenAndForeignPc()
    {
        using var sim = new Sim();
        using (var c = sim.Client())
            await SetupFresh(c);

        // другой ПК: токен уже сопряжён
        using (var other = sim.Client("other.id"))
        {
            await other.AttachAsync();
            await Fails(TokenError.AlreadyPaired, () => other.PairAsync());
        }

        // токен «стёрли»: ПК помнит сопряжение, токен — нет
        sim.Stop();
        File.Delete(sim.FlashPath);
        sim.Start();
        using var c2 = sim.Client();
        await Fails(TokenError.TokenWasReset, () => c2.AttachAsync());
        await c2.ForgetPairingAsync();
        Assert.False(c2.IsPaired);
        await c2.AttachAsync();
        await c2.PairAsync();
    }

    [Fact]
    public async Task FactoryReset()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await SetupFresh(c);
        await c.FactoryResetAsync();
        Assert.False(c.IsPaired);
        Assert.False(c.HasKey);
        await c.PairAsync();
        Assert.False((await c.GetInfoAsync()).SetupDone);
    }

    [Fact]
    public async Task DisconnectedWhenNoToken()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        sim.Stop();
        await Fails(TokenError.Disconnected, () => c.AttachAsync());
        Assert.False(c.IsAttached);
    }

    [Fact]
    public async Task TokenGoneMidSession()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await SetupFresh(c);
        sim.Stop();
        await Fails(TokenError.Disconnected, () => c.ListAsync());
        Assert.False(c.IsAttached);
        sim.Start();
        await c.AttachAsync();
        Assert.False((await c.GetInfoAsync()).Unlocked);
    }

    [Fact]
    public async Task BusyTokenTimesOutInsteadOfHanging()
    {
        using var sim = new Sim();
        using var first = sim.Client();
        await SetupFresh(first);              // first держит единственное соединение симулятора
        using var second = sim.Client();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Fails(TokenError.Disconnected, () => second.AttachAsync());
        Assert.InRange(sw.Elapsed.TotalSeconds, 4, 15);
        Assert.False(second.IsAttached);
    }

    [Fact]
    public async Task RejectsTooLongFieldsLocally()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        await SetupFresh(c);
        await Fails(TokenError.BadArgs, () => c.AddAsync("", new string('я', 200), "", "x"));
        Assert.Empty(await c.ListAsync());
    }
}
