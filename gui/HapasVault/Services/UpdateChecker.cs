using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;

namespace HapasVault.Services;

public sealed record UpdateInfo(Version Version, string Url);

/// <summary>
/// Проверка новой версии по GitHub Releases. Уходит один анонимный GET без данных
/// о пользователе; предрелизы (dev) не предлагаются.
/// </summary>
public static class UpdateChecker
{
    public const string Repository = "HouwyTwitch/hapasvault";
    private static readonly string ReleasesPrefix = $"https://github.com/{Repository}/releases/";

    public static Version Current { get; } = typeof(UpdateChecker).Assembly.GetName().Version is { } v
        ? new Version(v.Major, v.Minor, Math.Max(0, v.Build))
        : new Version(0, 0, 0);

    /// <summary>Локальная сборка (не из CI) — сравнивать не с чем.</summary>
    public static bool IsDevBuild => Current == new Version(0, 0, 0);

    public static string DisplayVersion =>
        typeof(UpdateChecker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion is { } iv
            ? Shorten(iv)
            : Current.ToString(3);

    private static string Shorten(string iv)
    {
        int plus = iv.IndexOf('+');
        return plus > 0 && iv.Length > plus + 8 ? $"{iv[..plus]} ({iv[(plus + 1)..(plus + 8)]})" : iv;
    }

    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct = default)
    {
        if (IsDevBuild) return null;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("HapasVault", Current.ToString(3)));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var resp = await http.GetAsync($"https://api.github.com/repos/{Repository}/releases/latest", ct);
        if (!resp.IsSuccessStatusCode) return null;
        await using var body = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(body, cancellationToken: ct);
        var root = doc.RootElement;
        if (root.TryGetProperty("prerelease", out var pre) && pre.GetBoolean()) return null;
        string tag = root.GetProperty("tag_name").GetString() ?? "";
        string url = root.GetProperty("html_url").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v'), out var latest) || !url.StartsWith(ReleasesPrefix, StringComparison.Ordinal))
            return null;
        return latest > Current ? new UpdateInfo(latest, url) : null;
    }

    public static void Open(UpdateInfo info)
    {
        // ссылка проверена в CheckAsync: только страница релиза этого репозитория
        Process.Start(new ProcessStartInfo(info.Url) { UseShellExecute = true });
    }
}
