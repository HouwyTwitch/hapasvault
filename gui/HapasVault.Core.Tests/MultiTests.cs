// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace HapasVault.Core.Tests;

/// <summary>До 4 токенов на ПК, до 4 ПК на токен, отвязка и дублирование — на настоящих симуляторах.</summary>
public class MultiTests
{
    private static async Task<string[]> SetupAsync(TokenClient c, string pw)
    {
        await c.PairAsync();
        var words = await c.BeginSetupAsync();
        await c.CommitSetupAsync(pw);
        return words;
    }

    [Fact]
    public async Task OnePcTwoTokensChosenAutomatically()
    {
        using var a = new Sim();
        using var b = new Sim();
        using var c = a.Client();
        await c.AttachAsync();
        await SetupAsync(c, "pw-A");
        uint ia = await c.AddAsync("", "На A", "u", "pa");

        c.Port = b.Port;                                   // «вынули A, вставили B»
        await c.DetachAsync();
        await c.AttachAsync();
        Assert.False(c.IsPaired);                          // незнакомый — не ошибка, а предложение привязать
        var who = await c.WhoAsync();
        Assert.False(who.SetupDone);
        await SetupAsync(c, "pw-B");
        await c.AddAsync("", "На B", "u", "pb");
        Assert.Equal(2, c.KnownTokens.Count);
        Assert.Single(c.KnownTokens, t => t.Active);

        c.Port = a.Port;                                   // снова A — выбран сам
        await c.DetachAsync();
        await c.AttachAsync();
        Assert.True(c.IsPaired);
        await c.UnlockAsync("pw-A");
        Assert.Equal("pa", (await c.GetAsync(ia)).Password);
        Assert.Equal(["На A"], (await c.ListAsync()).Select(x => x.Name));
        Assert.Equal(c.KnownTokens.Single(t => t.Active).Id, (await c.WhoAsync()).Id);
    }

    [Fact]
    public async Task SecondPcByWordsAndRemoval()
    {
        using var sim = new Sim();
        using var home = sim.Client("home.id");
        await home.AttachAsync();
        var words = await SetupAsync(home, "master");
        uint id = await home.AddAsync("", "Почта", "me", "secret");
        await home.SetPcLabelAsync("Домашний");
        await home.DetachAsync();                          // токен переносят на другой ПК

        using var work = sim.Client("work.id");
        await work.AttachAsync();
        Assert.False(work.IsPaired);
        Assert.True((await work.WhoAsync()).SetupDone);
        var e = await Assert.ThrowsAsync<TokenException>(work.PairAsync);
        Assert.Equal(TokenError.AlreadyPaired, e.Error);
        await work.PairWithWordsAsync(string.Join("  ", words) + "\n");      // лишние пробелы не мешают
        await work.UnlockAsync("master");
        Assert.Equal("secret", (await work.GetAsync(id)).Password);
        await work.SetPcLabelAsync("Рабочий");
        var pcs = await work.GetPcsAsync();
        Assert.Equal([("Домашний", false), ("Рабочий", true)], pcs.Select(p => (p.Label, p.IsMe)));

        // дома отвязали рабочий ПК — он больше не подключается
        await work.DetachAsync();
        await home.AttachAsync();
        await home.UnlockAsync("master");
        await home.RemovePcAsync(pcs.Single(p => p.Label == "Рабочий").Slot);
        Assert.Single(await home.GetPcsAsync());
        await home.DetachAsync();
        var gone = await Assert.ThrowsAsync<TokenException>(work.AttachAsync);
        Assert.Equal(TokenError.TokenWasReset, gone.Error);
    }

    [Fact]
    public async Task DuplicateToBlankToken()
    {
        using var oldSim = new Sim();
        using var newSim = new Sim();
        using var c = oldSim.Client();
        await c.AttachAsync();
        var words = await SetupAsync(c, "dup-pass");
        for (int i = 0; i < 30; i++) await c.AddAsync("Кат", $"Запись {i}", "u", new string('x', 500));
        byte[] backup = await c.BackupAsync();
        Assert.True(backup.Length > 8192);                 // больше кадра — частями

        c.Port = newSim.Port;
        await c.DetachAsync();
        await c.AttachAsync();
        Assert.False((await c.WhoAsync()).SetupDone);
        await c.PairAsync();
        await c.RestoreAsync(string.Join(' ', words), "dup-pass", backup);
        Assert.Equal(30, (await c.ListAsync()).Count);
        Assert.Equal(2, c.KnownTokens.Count);              // ПК знает оба
        await c.RenameTokenAsync(c.KnownTokens.Single(t => t.Active).Index, "Запасной");
        Assert.Contains(c.KnownTokens, t => t.Label == "Запасной" && t.Active);
    }
}
