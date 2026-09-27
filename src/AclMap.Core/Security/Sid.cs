using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace AclMap.Core.Security;

/// <summary>Conversion des SID entre forme binaire et forme texte (S-1-…), sans dépendance à Windows.</summary>
public static partial class Sid
{
    [GeneratedRegex(@"^S-1-(\d{1,15})(-\d{1,10}){0,15}$", RegexOptions.CultureInvariant)]
    private static partial Regex SidRegex();

    /// <summary>Vrai si <paramref name="s"/> est un SID texte valide.</summary>
    public static bool IsValid(string? s)
    {
        if (string.IsNullOrEmpty(s) || !SidRegex().IsMatch(s)) return false;
        foreach (var part in s.Split('-').Skip(3)) if (!uint.TryParse(part, out _)) return false;
        return true;
    }

    /// <summary>Lit un SID binaire à la position donnée.</summary>
    /// <param name="data">Données.</param>
    /// <param name="offset">Position.</param>
    /// <param name="length">Taille lue.</param>
    /// <returns>SID texte.</returns>
    /// <exception cref="FormatException">SID mal formé.</exception>
    public static string Read(ReadOnlySpan<byte> data, int offset, out int length)
    {
        if (offset < 0 || offset + 8 > data.Length) throw new FormatException("SID tronqué.");
        var revision = data[offset];
        int count = data[offset + 1];
        if (revision != 1 || count > 15) throw new FormatException("SID invalide.");
        length = 8 + 4 * count;
        if (offset + length > data.Length) throw new FormatException("SID tronqué.");
        ulong authority = 0;
        for (var i = 0; i < 6; i++) authority = (authority << 8) | data[offset + 2 + i];
        var sb = new StringBuilder("S-1-");
        sb.Append(authority);
        for (var i = 0; i < count; i++)
            sb.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset + 8 + 4 * i, 4)));
        return sb.ToString();
    }

    /// <summary>Encode un SID texte en binaire.</summary>
    /// <exception cref="FormatException">SID invalide.</exception>
    public static byte[] ToBinary(string sid)
    {
        if (!IsValid(sid)) throw new FormatException($"SID invalide : {sid}");
        var parts = sid.Split('-');
        var authority = ulong.Parse(parts[2]);
        var subs = parts.Skip(3).Select(uint.Parse).ToArray();
        var buf = new byte[8 + 4 * subs.Length];
        buf[0] = 1; buf[1] = (byte)subs.Length;
        for (var i = 0; i < 6; i++) buf[2 + i] = (byte)(authority >> (8 * (5 - i)));
        for (var i = 0; i < subs.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8 + 4 * i), subs[i]);
        return buf;
    }

    /// <summary>RID (dernière sous-autorité) ou null.</summary>
    public static uint? Rid(string sid)
    {
        var i = sid.LastIndexOf('-');
        return i > 0 && uint.TryParse(sid.AsSpan(i + 1), out var r) ? r : null;
    }

    /// <summary>SID du domaine (S-1-5-21-a-b-c) d'un SID de compte, ou null.</summary>
    public static string? DomainOf(string sid)
    {
        if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) return null;
        var parts = sid.Split('-');
        return parts.Length >= 8 ? string.Join('-', parts.Take(7)) : null;
    }

    /// <summary>Échappement LDAP d'un SID binaire, pour un filtre (objectSid=\01\05…).</summary>
    public static string ToLdapFilterValue(string sid) =>
        string.Concat(ToBinary(sid).Select(b => "\\" + b.ToString("x2")));
}
