namespace HapasVault.Core;

/// <summary>Операции с токеном. Реализации: TokenClient (pmapi) и демо-клиент GUI.</summary>
public interface ITokenClient : IDisposable
{
    ushort Port { get; set; }
    bool IsPaired { get; }
    bool HasKey { get; }
    bool IsAttached { get; }

    Task AttachAsync();
    Task DetachAsync();
    Task ConnectAsync();
    Task<uint> PairAsync();
    Task ForgetPairingAsync();
    Task<TokenInfo> GetInfoAsync();

    Task<string[]> BeginSetupAsync();
    Task CommitSetupAsync(string masterPassword);
    Task RestoreAsync(string words, string masterPassword, byte[]? backup);
    Task UnlockAsync(string masterPassword);
    Task LockAsync();

    Task<IReadOnlyList<VaultItem>> ListAsync();
    Task<Credential> GetAsync(uint id);
    Task<uint> AddAsync(string category, string name, string login, string password);
    Task DeleteAsync(uint id);
    Task<IReadOnlyList<LogRecord>> GetLogAsync();
    Task<byte[]> BackupAsync();
    Task FactoryResetAsync();
}
