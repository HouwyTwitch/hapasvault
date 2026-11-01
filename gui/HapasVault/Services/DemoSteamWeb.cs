// SPDX-License-Identifier: GPL-3.0-or-later
using HapasVault.Core;
using HapasVault.Core.Steam;

namespace HapasVault.Services;

/// <summary>Steam для демо-режима и скриншотов: ключи всё равно берёт у (демо-)токена.</summary>
public sealed class DemoSteamWeb : ISteamWeb
{
    private readonly List<SteamConfirmation> _items =
    [
        new("4210001", "n1", SteamConfirmationTypes.Trade, "Обмен", "Обмен с Gabe",
            ["Вы отдаёте: AK-47 | Redline (Закалённое в боях)", "Вы получаете: Ключ от кейса «Грёзы и кошмары»"],
            null, DateTimeOffset.UtcNow.AddMinutes(-3), "Подтвердить", "Отклонить", 1),
        new("4210002", "n2", SteamConfirmationTypes.MarketListing, "Торговая площадка", "Mann Co. Supply Crate Key",
            ["Цена: 172,50 ₽", "Вы получите: 150,00 ₽"], null, DateTimeOffset.UtcNow.AddMinutes(-12), "Выставить", "Отменить", 2),
        new("4210003", "n3", SteamConfirmationTypes.ApiKey, "Ключ Web API", "Регистрация ключа Steam Web API",
            ["Домен: example.com"], null, DateTimeOffset.UtcNow.AddHours(-2), "Подтвердить", "Отклонить", 3),
    ];

    public Task<DateTimeOffset> SteamTimeAsync(CancellationToken ct = default) => Task.FromResult(DateTimeOffset.UtcNow);

    public async Task<SteamSession> LoginAsync(string account, string password, Func<DateTimeOffset, Task<string>> guardCode,
                                               CancellationToken ct = default)
    {
        await guardCode(DateTimeOffset.UtcNow);
        await Task.Delay(600, ct);
        return new SteamSession(76561197960287930, "demo-refresh", "demo-access", DateTimeOffset.UtcNow);
    }

    public Task<SteamSession> RefreshAsync(SteamSession s, CancellationToken ct = default) =>
        Task.FromResult(s with { AccessToken = "demo-access", AccessTokenAt = DateTimeOffset.UtcNow });

    public Task<SteamSession> EnsureFreshAsync(SteamSession s, CancellationToken ct = default) => Task.FromResult(s);

    public async Task<IReadOnlyList<SteamConfirmation>> ListAsync(SteamSession s, SteamKeySource key, CancellationToken ct = default)
    {
        await key(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "list");
        await Task.Delay(350, ct);
        return _items.ToList();
    }

    public async Task RespondAsync(SteamSession s, SteamKeySource key, IReadOnlyList<SteamConfirmation> items, bool accept,
                                   CancellationToken ct = default)
    {
        await key(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), accept ? "allow" : "cancel");
        await Task.Delay(300, ct);
        _items.RemoveAll(c => items.Any(i => i.Id == c.Id));
    }
}

/// <summary>Сессии в памяти (демо).</summary>
public sealed class MemorySteamSessionStore : ISteamSessionStore
{
    private readonly Dictionary<uint, SteamSession> _items = new();
    public SteamSession? Load(uint entryId) => _items.GetValueOrDefault(entryId);
    public void Save(uint entryId, SteamSession session) => _items[entryId] = session;
    public void Delete(uint entryId) => _items.Remove(entryId);
}
