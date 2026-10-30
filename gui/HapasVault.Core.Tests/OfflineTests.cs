using Xunit;

namespace HapasVault.Core.Tests;

public class OfflineTests
{
    [Fact]
    public void Bip39Dictionary()
    {
        Assert.Equal(2048, Bip39.Words.Count);
        Assert.Equal("abandon", Bip39.Words[0]);
        Assert.Equal("zoo", Bip39.Words[^1]);
        Assert.Equal("abandon", Bip39.Resolve(" Abandon "));
        Assert.Equal("abandon", Bip39.Resolve("aban"));
        Assert.Null(Bip39.Resolve("aba"));
        Assert.Null(Bip39.Resolve("qwerty"));
        Assert.Contains("zone", Bip39.Suggest("zo"));
    }

    [Fact]
    public void PhraseCheck()
    {
        string ok = string.Join(' ', Enumerable.Repeat("abandon", 23).Append("art"));
        Assert.Equal(Core.PhraseCheck.Ok, Bip39.Check(ok));
        Assert.Equal(Core.PhraseCheck.BadChecksum, Bip39.Check(string.Join(' ', Enumerable.Repeat("abandon", 24))));
        Assert.Equal(Core.PhraseCheck.WrongCount, Bip39.Check("abandon abandon"));
        Assert.Equal(Core.PhraseCheck.UnknownWord, Bip39.Check(ok.Replace("art", "qwerty")));
    }

    [Theory]
    [InlineData(8, true, false, false, false)]
    [InlineData(20, true, true, true, true)]
    [InlineData(64, false, false, true, false)]
    public void Generator(int length, bool lower, bool upper, bool digits, bool symbols)
    {
        var o = new GeneratorOptions(length, lower, upper, digits, symbols);
        var seen = new HashSet<string>();
        for (int i = 0; i < 50; i++)
        {
            string p = Passwords.Generate(o);
            Assert.Equal(length, p.Length);
            Assert.Equal(lower, p.Any(char.IsLower));
            Assert.Equal(upper, p.Any(char.IsUpper));
            Assert.Equal(digits, p.Any(char.IsDigit));
            Assert.Equal(symbols, p.Any(c => !char.IsLetterOrDigit(c)));
            Assert.DoesNotContain(p, "lIO01".Contains);
            seen.Add(p);
        }
        Assert.Equal(50, seen.Count);
    }

    [Fact]
    public void StrengthRating()
    {
        Assert.Equal(Strength.Empty, Passwords.Rate(""));
        Assert.Equal(Strength.Weak, Passwords.Rate("12345678"));
        Assert.Equal(Strength.Weak, Passwords.Rate("aaaaaaaaaaaaaaaa"));
        Assert.Equal(Strength.Strong, Passwords.Rate(Passwords.Generate(new GeneratorOptions(20))));
        Assert.True(Passwords.Rate("корова-батарея-скрепка") >= Strength.Good);
    }

    [Fact]
    public void FieldValidation()
    {
        Assert.Null(TokenClient.Validate("a", "b", "c", "d"));
        Assert.NotNull(TokenClient.Validate("", " ", "", ""));
        Assert.NotNull(TokenClient.Validate("", new string('я', 128), "", ""));   // 256 байт UTF-8
        Assert.Null(TokenClient.Validate("", new string('я', 127), "", ""));
    }
}
