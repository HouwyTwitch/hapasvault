using System.Text;

namespace HapasVault.Core;

public enum PhraseCheck { Ok = 0, UnknownWord = -1, WrongCount = -2, BadChecksum = -3 }

/// <summary>Словарь BIP39 из pmapi и локальная проверка фразы (без токена).</summary>
public static unsafe class Bip39
{
    private static readonly Lazy<string[]> _words = new(() =>
        Enumerable.Range(0, 2048).Select(i => Native.Utf8(Native.pmapi_bip39_word(i))).ToArray());

    public static IReadOnlyList<string> Words => _words.Value;

    /// <summary>Нормализовать введённое слово: нижний регистр, без пробелов.</summary>
    public static string Normalize(string w) => w.Trim().ToLowerInvariant();

    /// <summary>
    /// Слово из словаря, которому соответствует ввод: точное совпадение или
    /// однозначный префикс от 4 букв (так же считает bip39_decode).
    /// </summary>
    public static string? Resolve(string input)
    {
        string w = Normalize(input);
        if (w.Length == 0) return null;
        var words = Words;
        int i = BinarySearch(words, w);
        if (i >= 0) return words[i];
        if (w.Length < 4) return null;
        string? found = null;
        foreach (var cand in words)
        {
            if (!cand.StartsWith(w, StringComparison.Ordinal)) continue;
            if (found != null) return null;
            found = cand;
        }
        return found;
    }

    /// <summary>Подсказки для автодополнения (до max штук).</summary>
    public static IEnumerable<string> Suggest(string prefix, int max = 5)
    {
        string p = Normalize(prefix);
        if (p.Length == 0) return [];
        return Words.Where(w => w.StartsWith(p, StringComparison.Ordinal)).Take(max);
    }

    public static PhraseCheck Check(string phrase)
    {
        byte[] buf = Encoding.UTF8.GetBytes(phrase + "\0");
        try
        {
            fixed (byte* p = buf)
                return (PhraseCheck)Native.pmapi_check_phrase(p);
        }
        finally
        {
            Array.Clear(buf);
        }
    }

    private static int BinarySearch(IReadOnlyList<string> words, string w)
    {
        int lo = 0, hi = words.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            int c = string.CompareOrdinal(words[mid], w);
            if (c == 0) return mid;
            if (c < 0) lo = mid + 1; else hi = mid - 1;
        }
        return -1;
    }
}
