using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HapasVault.Core;

public enum OtpKind : byte { None = 0, Totp = 1, Steam = 2 }

public enum OtpAlgorithm : byte { Sha1 = 1, Sha256 = 2 }

/// <summary>Что сделать с OTP при правке записи.</summary>
public enum OtpChange { Remove = 0, Set = 1, Keep = 2 }

public sealed record OtpCode(string Code, OtpKind Kind, int Period, DateTimeOffset ValidUntil);

/// <summary>
/// Параметры одноразовых кодов, как их понимает токен (core/otp.h):
/// [u8 type][u8 alg][u8 digits][u8 period][secret]. Секрет уходит на токен один раз.
/// </summary>
public sealed class OtpSecret
{
    public const int MinSecret = 10, MaxSecret = 64;

    public OtpSecret(OtpKind kind, byte[] secret, OtpAlgorithm algorithm = OtpAlgorithm.Sha1, int digits = 6, int period = 30)
    {
        if (kind == OtpKind.Steam) { algorithm = OtpAlgorithm.Sha1; digits = 5; period = 30; }
        if (kind == OtpKind.None) throw new ArgumentException("kind");
        if (secret.Length < MinSecret) throw new FormatException("Секрет слишком короткий (меньше 80 бит).");
        if (secret.Length > MaxSecret) throw new FormatException("Секрет длиннее 64 байт — токен его не примет.");
        if (kind == OtpKind.Totp && digits is < 6 or > 8) throw new FormatException("Поддерживается 6–8 цифр.");
        if (kind == OtpKind.Totp && period is < 15 or > 120) throw new FormatException("Период должен быть от 15 до 120 секунд.");
        Kind = kind;
        Secret = secret;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
    }

    public OtpKind Kind { get; }
    public byte[] Secret { get; }
    public OtpAlgorithm Algorithm { get; }
    public int Digits { get; }
    public int Period { get; }
    /// <summary>Издатель/метка из otpauth:// — подсказка для названия записи.</summary>
    public string? Issuer { get; init; }
    public string? Account { get; init; }

    public string Describe() => Kind == OtpKind.Steam
        ? "Steam Guard · 5 символов · 30 с"
        : $"TOTP · {(Algorithm == OtpAlgorithm.Sha1 ? "SHA1" : "SHA256")} · {Digits} цифр · {Period} с";

    public byte[] ToBlob()
    {
        var b = new byte[4 + Secret.Length];
        b[0] = (byte)Kind;
        b[1] = (byte)Algorithm;
        b[2] = (byte)(Kind == OtpKind.Steam ? 5 : Digits);
        b[3] = (byte)Period;
        Secret.CopyTo(b, 4);
        return b;
    }

    /// <summary>Эталонный расчёт кода (демо и проверка токена в тестах).</summary>
    public string Code(DateTimeOffset at)
    {
        long counter = at.ToUnixTimeSeconds() / Period;
        Span<byte> msg = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(msg, counter);
        byte[] mac = Algorithm == OtpAlgorithm.Sha256 ? HMACSHA256.HashData(Secret, msg) : HMACSHA1.HashData(Secret, msg);
        int off = mac[^1] & 0x0F;
        uint bin = (uint)(mac[off] & 0x7F) << 24 | (uint)mac[off + 1] << 16 | (uint)mac[off + 2] << 8 | mac[off + 3];
        if (Kind == OtpKind.Steam)
        {
            const string alphabet = "23456789BCDFGHJKMNPQRTVWXY";
            var sb = new StringBuilder(5);
            for (int i = 0; i < 5; i++) { sb.Append(alphabet[(int)(bin % 26)]); bin /= 26; }
            return sb.ToString();
        }
        uint mod = 1;
        for (int i = 0; i < Digits; i++) mod *= 10;
        return (bin % mod).ToString(new string('0', Digits), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Разобрать то, что вставил пользователь:
    ///   otpauth://totp/...?secret=…&amp;algorithm=…&amp;digits=…&amp;period=…
    ///   otpauth://steam/...?secret=…   ·   steam://BASE32
    ///   maFile Steam Desktop Authenticator (JSON с shared_secret)
    ///   голый секрет: Base32 (TOTP) или Base64 shared_secret (Steam).
    /// </summary>
    public static OtpSecret Parse(string input, OtpKind kind)
    {
        string s = input.Trim();
        if (s.Length == 0) throw new FormatException("Вставьте секрет или ссылку otpauth://.");

        if (s.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(s);
                if (doc.RootElement.TryGetProperty("shared_secret", out var ss) && ss.GetString() is { } b64)
                    return new OtpSecret(OtpKind.Steam, Convert.FromBase64String(b64))
                    {
                        Account = doc.RootElement.TryGetProperty("account_name", out var an) ? an.GetString() : null,
                        Issuer = "Steam",
                    };
            }
            catch (JsonException)
            {
            }
            throw new FormatException("Это не похоже на maFile: нет поля shared_secret.");
        }

        if (s.StartsWith("steam://", StringComparison.OrdinalIgnoreCase))
            return new OtpSecret(OtpKind.Steam, Base32(s[8..])) { Issuer = "Steam" };

        if (s.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            return ParseUri(s);

        if (kind == OtpKind.Steam && LooksBase64(s))
            return new OtpSecret(OtpKind.Steam, Convert.FromBase64String(s)) { Issuer = "Steam" };
        return new OtpSecret(kind == OtpKind.None ? OtpKind.Totp : kind, Base32(s));
    }

    private static OtpSecret ParseUri(string s)
    {
        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri)) throw new FormatException("Ссылка otpauth:// повреждена.");
        string type = uri.Host.ToLowerInvariant();
        if (type == "hotp") throw new FormatException("HOTP (по счётчику) не поддерживается — нужен TOTP.");
        var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0) q[Uri.UnescapeDataString(part[..eq])] = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
        }
        if (!q.TryGetValue("secret", out var secret)) throw new FormatException("В ссылке нет параметра secret.");

        string label = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        string? issuer = q.GetValueOrDefault("issuer");
        string? account = label;
        int colon = label.IndexOf(':');
        if (colon >= 0)
        {
            issuer ??= label[..colon].Trim();
            account = label[(colon + 1)..].Trim();
        }

        if (type == "steam" || (q.TryGetValue("encoder", out var enc) && enc.Equals("steam", StringComparison.OrdinalIgnoreCase)))
            return new OtpSecret(OtpKind.Steam, Base32(secret)) { Issuer = issuer ?? "Steam", Account = account };
        if (type != "totp") throw new FormatException($"Тип «{type}» не поддерживается.");

        var alg = OtpAlgorithm.Sha1;
        if (q.TryGetValue("algorithm", out var a))
        {
            alg = a.ToUpperInvariant() switch
            {
                "SHA1" => OtpAlgorithm.Sha1,
                "SHA256" => OtpAlgorithm.Sha256,
                "SHA512" => throw new FormatException("SHA512 токен пока не поддерживает (только SHA1 и SHA256)."),
                _ => throw new FormatException($"Неизвестный алгоритм «{a}»."),
            };
        }
        int digits = q.TryGetValue("digits", out var d) && int.TryParse(d, out int dv) ? dv : 6;
        int period = q.TryGetValue("period", out var p) && int.TryParse(p, out int pv) ? pv : 30;
        return new OtpSecret(OtpKind.Totp, Base32(secret), alg, digits, period) { Issuer = issuer, Account = account };
    }

    private static bool LooksBase64(string s) =>
        s.Length % 4 == 0 && s.Any(c => c is '+' or '/' or '=' || char.IsLower(c)) &&
        s.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=');

    public static byte[] Base32(string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (char raw in text)
        {
            if (raw is ' ' or '-' or '=' or '\t') continue;
            int v = alphabet.IndexOf(char.ToUpperInvariant(raw));
            if (v < 0) throw new FormatException($"Символ «{raw}» не из Base32. Скопируйте секрет целиком.");
            buffer = buffer << 5 | v;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return bytes.ToArray();
    }
}
