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
    Task<IReadOnlyList<LogRecord>> GetLogAsync();
    Task<byte[]> BackupAsync();
    Task FactoryResetAsync();
}
