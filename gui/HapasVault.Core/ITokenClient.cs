// SPDX-License-Identifier: GPL-3.0-or-later
namespace HapasVault.Core;

/// <summary>Операции с токеном. Реализации: TokenClient (pmapi) и демо-клиент GUI.</summary>
public interface ITokenClient : IDisposable
{
    ushort Port { get; set; }
    TokenConnection Connection { get; set; }
    TokenTransport Transport { get; }
    bool IsPaired { get; }
    bool HasKey { get; }
    bool IsAttached { get; }

    Task AttachAsync();
    Task DetachAsync();
    Task ConnectAsync();
    Task PairAsync();
    /// <summary>Привязать этот ПК к уже настроенному токену по 24 словам.</summary>
    Task PairWithWordsAsync(string words);
    /// <summary>Что подключено (до сессии): чистый токен или уже настроенный.</summary>
    Task<TokenWho> WhoAsync();
    /// <summary>Токены, которые знает этот ПК (до 4); нужный выбирается сам.</summary>
    IReadOnlyList<KnownToken> KnownTokens { get; }
    Task RenameTokenAsync(int index, string label);
    Task ForgetTokenAsync(int index);
    /// <summary>Компьютеры, привязанные к подключённому токену (до 4).</summary>
    Task<IReadOnlyList<PairedPc>> GetPcsAsync();
    Task RemovePcAsync(int slot);
    Task SetPcLabelAsync(string label);
    Task ForgetPairingAsync();
    Task<TokenInfo> GetInfoAsync();

    Task<string[]> BeginSetupAsync();
    Task CommitSetupAsync(string masterPassword);
    Task RestoreAsync(string words, string masterPassword, byte[]? backup);
    Task UnlockAsync(string masterPassword);
    Task LockAsync();

    Task<IReadOnlyList<VaultItem>> ListAsync();
    Task<Credential> GetAsync(uint id);
    Task<uint> AddAsync(string category, string name, string login, string password, OtpSecret? otp = null);
    /// <summary>Изменить запись на месте (id сохраняется).</summary>
    Task UpdateAsync(uint id, string category, string name, string login, string password, OtpChange otp, OtpSecret? secret = null);
    Task DeleteAsync(uint id);
    /// <summary>Одноразовый код: считает токен по времени ПК.</summary>
    Task<OtpCode> GetOtpAsync(uint id, DateTimeOffset? at = null);
    /// <summary>Steam: ключ мобильного подтверждения (HMAC от identity_secret считает токен).</summary>
    Task<byte[]> GetSteamConfirmationKeyAsync(uint id, long unixTime, string tag);
    /// <summary>Steam: SteamID записи; код восстановления — только по явному запросу.</summary>
    Task<SteamInfo> GetSteamInfoAsync(uint id, bool revocationCode = false);
    Task<IReadOnlyList<LogRecord>> GetLogAsync();
    Task<byte[]> BackupAsync();
    Task FactoryResetAsync();
}
