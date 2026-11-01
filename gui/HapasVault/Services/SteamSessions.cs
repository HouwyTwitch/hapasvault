using System.IO;
using System.Security.Cryptography;
using HapasVault.Core.Steam;

namespace HapasVault.Services;

/// <summary>
/// Сессии Steam этого ПК: %APPDATA%\HapasVault\steam\steam-&lt;id&gt;.session под DPAPI
/// текущего пользователя (как ключ ПК). Долгоживущие секреты Steam — только на токене.
/// </summary>
public static class SteamSessions
{
    private static readonly byte[] Entropy = "HapasVault steam session v1"u8.ToArray();

    public static ISteamSessionStore Create() => new FileSteamSessionStore(
        Path.Combine(AppSettings.Folder, "steam"),
        data => ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser),
        data => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser));
}
