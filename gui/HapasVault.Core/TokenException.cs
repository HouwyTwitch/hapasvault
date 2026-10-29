namespace HapasVault.Core;

/// <summary>Что случилось, с точки зрения интерфейса.</summary>
public enum TokenError
{
    Other,
    Disconnected,     // нет связи с токеном / таймаут
    SessionLost,      // сессия закрыта (простой, сбой кадра) — нужен connect
    NotPaired,        // этот ПК не сопряжён
    TokenWasReset,    // ПК помнит токен, а токен — нет (сброшен/новая плата)
    ForeignToken,     // токен сопряжён с другим ПК
    AlreadyPaired,
    NotSetup,
    AlreadySetup,
    Locked,
    WrongPassword,
    Backoff,
    RateLimit,
    NotFound,
    Full,
    BadPhrase,
    NoKey,
    BadArgs,
    Flash,
    IdentityFile,
    NoOtp,
    BadTime,
    Version,
}

public sealed class TokenException : Exception
{
    public int Code { get; }
    public TokenError Error { get; }

    public TokenException(int code, TokenError error, string message) : base(message)
    {
        Code = code;
        Error = error;
    }

    public TokenException(TokenError error, string message) : this(0, error, message) { }

    // коды: proto.h (ST_*, FE_*) и pmclient.h (PMC_E_*)
    internal static TokenException FromCode(int code, bool connecting = false)
    {
        var e = code switch
        {
            1 => TokenError.BadArgs,
            2 => TokenError.Locked,
            3 => TokenError.NotSetup,
            4 => TokenError.AlreadySetup,
            5 => TokenError.WrongPassword,
            6 => TokenError.NotFound,
            7 => TokenError.RateLimit,
            8 => TokenError.Full,
            9 => TokenError.Backoff,
            10 => TokenError.Flash,
            12 => TokenError.NoOtp,
            13 => TokenError.BadTime,
            -10 => TokenError.Version,
            -1 => TokenError.Disconnected,
            -2 or -3 => TokenError.SessionLost,
            -4 => TokenError.NotPaired,
            -5 => TokenError.BadPhrase,
            -6 => TokenError.NoKey,
            -8 => TokenError.IdentityFile,
            -102 => TokenError.AlreadyPaired,
            -103 => TokenError.TokenWasReset,
            -104 => TokenError.SessionLost,
            // при установке сессии «не расшифровал» = токен знает другой ключ ПК
            -105 => connecting ? TokenError.ForeignToken : TokenError.SessionLost,
            _ => TokenError.Other,
        };
        return new TokenException(code, e, Describe(e, code));
    }

    /// <summary>Текст для статуса токена (ST_*), например из журнала.</summary>
    public static string DescribeStatus(int status) => status == 0 ? "Успешно" : FromCode(status).Message;

    public static string Describe(TokenError e, int code = 0) => e switch
    {
        TokenError.Disconnected => "Нет связи с токеном. Проверьте подключение.",
        TokenError.SessionLost => "Сессия с токеном закрыта.",
        TokenError.NotPaired => "Этот компьютер ещё не сопряжён с токеном.",
        TokenError.TokenWasReset => "Токен был сброшен. Выполните сопряжение заново.",
        TokenError.ForeignToken => "Токен сопряжён с другим компьютером.",
        TokenError.AlreadyPaired => "Токен уже сопряжён с другим компьютером. Сбросьте его там.",
        TokenError.NotSetup => "Токен ещё не настроен.",
        TokenError.AlreadySetup => "Токен уже настроен.",
        TokenError.Locked => "Хранилище заблокировано.",
        TokenError.WrongPassword => "Неверный мастер-пароль.",
        TokenError.Backoff => "Слишком много неверных попыток. Подождите немного.",
        TokenError.RateLimit => "Слишком много расшифровок подряд. Подождите минуту.",
        TokenError.NotFound => "Запись не найдена.",
        TokenError.Full => "Хранилище заполнено.",
        TokenError.BadPhrase => "Фраза восстановления неверна.",
        TokenError.NoKey => "На этом компьютере нет ключа хранилища. Восстановите доступ по 24 словам.",
        TokenError.BadArgs => "Токен отклонил данные: слишком длинные поля?",
        TokenError.Flash => "Ошибка записи во flash токена.",
        TokenError.IdentityFile => "Не удалось прочитать или сохранить ключ этого компьютера.",
        TokenError.NoOtp => "У этой записи нет одноразовых кодов.",
        TokenError.BadTime => "Часы компьютера ушли вперёд относительно токена. Проверьте время или переподключите токен.",
        TokenError.Version => "Прошивка токена и программа разных версий. Обновите HapasVault или прошивку.",
        _ => code != 0 ? $"Ошибка токена ({code})." : "Неизвестная ошибка.",
    };
}
