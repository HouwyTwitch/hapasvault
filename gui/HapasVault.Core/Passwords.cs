using System.Security.Cryptography;

namespace HapasVault.Core;

public sealed record GeneratorOptions(
    int Length = 20,
    bool Lower = true,
    bool Upper = true,
    bool Digits = true,
    bool Symbols = true,
    bool AvoidAmbiguous = true);

public enum Strength { Empty, Weak, Fair, Good, Strong }

public static class Passwords
{
    private const string LowerSet = "abcdefghijklmnopqrstuvwxyz";
    private const string UpperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string DigitSet = "0123456789";
    private const string SymbolSet = "!#$%&*+-=?@^_~.,:;";
    private const string Ambiguous = "lIO01";

    /// <summary>Криптостойкий пароль: по символу из каждой выбранной группы, остальное — из объединения.</summary>
    public static string Generate(GeneratorOptions o)
    {
        var groups = new List<string>();
        if (o.Lower) groups.Add(LowerSet);
        if (o.Upper) groups.Add(UpperSet);
        if (o.Digits) groups.Add(DigitSet);
        if (o.Symbols) groups.Add(SymbolSet);
        if (groups.Count == 0) groups.Add(LowerSet);
        if (o.AvoidAmbiguous)
            groups = groups.Select(g => new string(g.Where(c => !Ambiguous.Contains(c)).ToArray())).ToList();

        int length = Math.Clamp(o.Length, Math.Max(4, groups.Count), 128);
        string all = string.Concat(groups);
        var chars = new char[length];
        for (int i = 0; i < length; i++)
        {
            string set = i < groups.Count ? groups[i] : all;
            chars[i] = set[RandomNumberGenerator.GetInt32(set.Length)];
        }
        // перемешать, чтобы обязательные символы не стояли в начале (Фишер — Йетс)
        for (int i = length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }

    /// <summary>Грубая оценка энтропии в битах: алфавит × длина со штрафом за повторы.</summary>
    public static double EntropyBits(string pw)
    {
        if (string.IsNullOrEmpty(pw)) return 0;
        int pool = 0;
        if (pw.Any(char.IsLower)) pool += 26;
        if (pw.Any(char.IsUpper)) pool += 26;
        if (pw.Any(char.IsDigit)) pool += 10;
        if (pw.Any(c => !char.IsLetterOrDigit(c) && c < 128)) pool += 32;
        if (pw.Any(c => c >= 128)) pool += 64;   // кириллица и прочее
        int unique = pw.Distinct().Count();
        double effectiveLength = Math.Min(pw.Length, unique * 1.5);
        return effectiveLength * Math.Log2(Math.Max(pool, 2));
    }

    public static Strength Rate(string pw)
    {
        if (string.IsNullOrEmpty(pw)) return Strength.Empty;
        double bits = EntropyBits(pw);
        return bits switch
        {
            < 40 => Strength.Weak,
            < 60 => Strength.Fair,
            < 80 => Strength.Good,
            _ => Strength.Strong,
        };
    }

    public static string Describe(Strength s) => s switch
    {
        Strength.Weak => "Слабый",
        Strength.Fair => "Средний",
        Strength.Good => "Хороший",
        Strength.Strong => "Отличный",
        _ => "",
    };
}
