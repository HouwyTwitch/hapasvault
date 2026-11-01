using System.Text;

namespace HapasVault.Core.Steam;

/// <summary>
/// Минимальный protobuf для IAuthenticationService (Steam принимает запрос в
/// input_protobuf_encoded и отвечает бинарным protobuf): varint, fixed64, строки,
/// вложенные сообщения. Без внешних зависимостей.
/// </summary>
internal sealed class ProtoWriter
{
    private readonly MemoryStream _s = new();

    public byte[] ToArray() => _s.ToArray();

    private void Tag(int field, int wire) => Varint((ulong)(field << 3 | wire));

    private void Varint(ulong v)
    {
        while (v >= 0x80) { _s.WriteByte((byte)(v | 0x80)); v >>= 7; }
        _s.WriteByte((byte)v);
    }

    public ProtoWriter UInt(int field, ulong v) { Tag(field, 0); Varint(v); return this; }
    // int32 отрицательные кодируются как 64-битный varint
    public ProtoWriter Int(int field, int v) { Tag(field, 0); Varint((ulong)(long)v); return this; }
    public ProtoWriter Bool(int field, bool v) => UInt(field, v ? 1u : 0u);

    public ProtoWriter Fixed64(int field, ulong v)
    {
        Tag(field, 1);
        Span<byte> b = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        _s.Write(b);
        return this;
    }

    public ProtoWriter Bytes(int field, ReadOnlySpan<byte> v)
    {
        Tag(field, 2);
        Varint((ulong)v.Length);
        _s.Write(v);
        return this;
    }

    public ProtoWriter String(int field, string v) => Bytes(field, Encoding.UTF8.GetBytes(v));
    public ProtoWriter Message(int field, ProtoWriter m) => Bytes(field, m.ToArray());
}

/// <summary>Разобранное сообщение: номер поля -> значения (varint/fixed как ulong, длинные — как байты).</summary>
internal sealed class ProtoMessage
{
    private readonly Dictionary<int, List<object>> _f = new();

    public static ProtoMessage Parse(ReadOnlySpan<byte> data)
    {
        var m = new ProtoMessage();
        int p = 0;
        while (p < data.Length)
        {
            ulong key = ReadVarint(data, ref p);
            int field = (int)(key >> 3), wire = (int)(key & 7);
            object value = wire switch
            {
                0 => ReadVarint(data, ref p),
                1 => Fixed(data, ref p, 8),
                2 => Length(data, ref p),
                5 => Fixed(data, ref p, 4),
                _ => throw new FormatException($"protobuf: тип {wire}"),
            };
            if (!m._f.TryGetValue(field, out var list)) m._f[field] = list = new List<object>();
            list.Add(value);
        }
        return m;
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> d, ref int p)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            if (p >= d.Length) throw new FormatException("protobuf: обрыв varint");
            byte b = d[p++];
            v |= (ulong)(b & 0x7F) << shift;
            if (b < 0x80) return v;
        }
        throw new FormatException("protobuf: длинный varint");
    }

    private static ulong Fixed(ReadOnlySpan<byte> d, ref int p, int n)
    {
        if (p + n > d.Length) throw new FormatException("protobuf: обрыв fixed");
        ulong v = 0;
        for (int i = n - 1; i >= 0; i--) v = v << 8 | d[p + i];
        p += n;
        return v;
    }

    private static byte[] Length(ReadOnlySpan<byte> d, ref int p)
    {
        ulong n = ReadVarint(d, ref p);
        if (n > (ulong)(d.Length - p)) throw new FormatException("protobuf: обрыв строки");
        var b = d.Slice(p, (int)n).ToArray();
        p += (int)n;
        return b;
    }

    public ulong UInt(int field) => _f.TryGetValue(field, out var l) && l[0] is ulong v ? v : 0;
    public byte[] Bytes(int field) => _f.TryGetValue(field, out var l) && l[0] is byte[] b ? b : [];
    public string String(int field) => Encoding.UTF8.GetString(Bytes(field));
    public IEnumerable<ProtoMessage> Messages(int field) =>
        _f.TryGetValue(field, out var l) ? l.OfType<byte[]>().Select(b => Parse(b)) : [];
}
