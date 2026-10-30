using Xunit;

namespace HapasVault.Core.Tests;

/// <summary>
/// Последовательный транспорт (как у USB CDC прошивки) против симулятора на pty.
/// Только Linux/macOS: на Windows pty нет, там USB проверяется на железе.
/// </summary>
public class SerialTests
{
    [Fact]
    public async Task FullFlowOverSerialStream()
    {
        if (OperatingSystem.IsWindows()) return;
        using var sim = new Sim(pty: true);
        using var c = sim.Client();
        await c.AttachAsync();
        Assert.Equal(TokenTransport.Usb, c.Transport);
        await c.PairAsync();
        await c.BeginSetupAsync();
        await c.CommitSetupAsync("serial-master-pw");

        // крупные кадры: поток режется на куски, сборщик кадров должен их склеить
        string big = new('x', TokenClient.MaxPassword);
        for (int i = 0; i < 20; i++)
            await c.AddAsync("Кат", $"Запись {i}", $"user{i}", big);
        Assert.Equal(20, (await c.ListAsync()).Count);
        Assert.Equal(big, (await c.GetAsync(1)).Password);
        byte[] backup = await c.BackupAsync();
        Assert.True(backup.Length > 20 * TokenClient.MaxPassword);

        // порт монопольный: вторая программа получает «занят» (root обходит TIOCEXCL)
        if (Environment.UserName != "root")
        using (var other = sim.Client("other.id"))
        {
            var e = await Assert.ThrowsAsync<TokenException>(other.AttachAsync);
            Assert.Equal(TokenError.Busy, e.Error);
        }

        // закрыли порт (= сброс DTR / выдернули токен): хранилище заблокировано
        await c.DetachAsync();
        await c.AttachAsync();
        Assert.False((await c.GetInfoAsync()).Unlocked);
        await c.UnlockAsync("serial-master-pw");
        Assert.Equal("user3", (await c.GetAsync(4)).Login);
    }

    [Fact]
    public async Task UsbModeWithoutDeviceIsDisconnected()
    {
        using var sim = new Sim();
        using var c = sim.Client();
        c.Connection = TokenConnection.Usb;
        if (TokenClient.FindUsb() != null) return;   // на машине разработчика может стоять настоящий токен
        var e = await Assert.ThrowsAsync<TokenException>(c.AttachAsync);
        Assert.Equal(TokenError.Disconnected, e.Error);

        c.Connection = TokenConnection.Auto;         // авто: USB нет — симулятор
        await c.AttachAsync();
        Assert.Equal(TokenTransport.Simulator, c.Transport);
    }
}
