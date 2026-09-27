using System.Globalization;
using System.Text;
using AclMap.Models.Security;

namespace AclMap.Core.Security;

/// <summary>
/// Écriture et lecture du format SDDL. L'écriture est normalisée (SID complets, masques hexadécimaux) pour que deux
/// descripteurs identiques aient exactement le même texte. La lecture accepte aussi les alias courants
/// (FA, FR, FW, FX, GA, GR, GW, GX, SD, RC, WD, WO ; WD, AU, BA, BU, SY, CO, NS, LS, DA, DU…).
/// </summary>
public static class Sddl
{
    private static readonly Dictionary<string, string> SidAliases = new(StringComparer.Ordinal)
    {
        ["WD"] = WellKnownSids.Everyone, ["CO"] = WellKnownSids.CreatorOwner, ["CG"] = WellKnownSids.CreatorGroup,
        ["OW"] = WellKnownSids.OwnerRights, ["NU"] = WellKnownSids.Network, ["IU"] = WellKnownSids.Interactive,
        ["SU"] = WellKnownSids.Service, ["AN"] = WellKnownSids.Anonymous, ["ED"] = WellKnownSids.EnterpriseDcs,
        ["PS"] = WellKnownSids.Self, ["AU"] = WellKnownSids.AuthenticatedUsers, ["SY"] = WellKnownSids.System,
        ["LS"] = WellKnownSids.LocalService, ["NS"] = WellKnownSids.NetworkService, ["BA"] = WellKnownSids.Administrators,
        ["BU"] = WellKnownSids.Users, ["BG"] = WellKnownSids.Guests, ["PU"] = WellKnownSids.PowerUsers,
        ["AO"] = WellKnownSids.AccountOperators, ["SO"] = WellKnownSids.ServerOperators, ["PO"] = WellKnownSids.PrintOperators,
        ["BO"] = WellKnownSids.BackupOperators, ["AC"] = WellKnownSids.AllAppPackages,
    };

    private static readonly Dictionary<string, uint> RightAliases = new(StringComparer.Ordinal)
    {
        ["GA"] = FileRights.GenericAll, ["GR"] = FileRights.GenericRead, ["GW"] = FileRights.GenericWrite, ["GX"] = FileRights.GenericExecute,
        ["FA"] = FileRights.FullControl, ["FR"] = FileRights.FileGenericRead, ["FW"] = FileRights.FileGenericWrite, ["FX"] = FileRights.FileGenericExecute,
        ["SD"] = FileRights.Delete, ["RC"] = FileRights.ReadControl, ["WD"] = FileRights.WriteDac, ["WO"] = FileRights.WriteOwner,
        ["CC"] = 0x1, ["DC"] = 0x2, ["LC"] = 0x4, ["SW"] = 0x8, ["RP"] = 0x10, ["WP"] = 0x20, ["DT"] = 0x40, ["LO"] = 0x80, ["CR"] = 0x100,
    };

    /// <summary>SDDL normalisé d'un descripteur.</summary>
    public static string Format(SecurityDescriptorInfo sd)
    {
        var sb = new StringBuilder();
        if (sd.Owner is not null) sb.Append("O:").Append(sd.Owner);
        if (sd.Group is not null) sb.Append("G:").Append(sd.Group);
        sb.Append("D:");
        if ((sd.Control & SdControl.DaclProtected) != 0) sb.Append('P');
        if ((sd.Control & SdControl.DaclAutoInheritReq) != 0) sb.Append("AR");
        if ((sd.Control & SdControl.DaclAutoInherited) != 0) sb.Append("AI");
        if (!sd.DaclPresent) { sb.Append("NO_ACCESS_CONTROL"); return sb.ToString(); }
        foreach (var a in sd.Aces) sb.Append(FormatAce(a));
        return sb.ToString();
    }

    /// <summary>Texte SDDL d'une ACE.</summary>
    public static string FormatAce(AceInfo a)
    {
        var type = a.Kind switch { AceKind.Allow => "A", AceKind.Deny => "D", AceKind.AllowCallback => "XA", AceKind.DenyCallback => "XD", _ => "0x" + a.RawType.ToString("x2", CultureInfo.InvariantCulture) };
        var f = new StringBuilder();
        if ((a.Flags & AceFlags.ObjectInherit) != 0) f.Append("OI");
        if ((a.Flags & AceFlags.ContainerInherit) != 0) f.Append("CI");
        if ((a.Flags & AceFlags.NoPropagateInherit) != 0) f.Append("NP");
        if ((a.Flags & AceFlags.InheritOnly) != 0) f.Append("IO");
        if ((a.Flags & AceFlags.Inherited) != 0) f.Append("ID");
        return $"({type};{f};0x{a.Mask.ToString("x", CultureInfo.InvariantCulture)};;;{a.Sid})";
    }

    /// <summary>Lit un SDDL (propriétaire, groupe, DACL ; la SACL est ignorée).</summary>
    /// <exception cref="FormatException">SDDL invalide ou non pris en charge.</exception>
    public static SecurityDescriptorInfo Parse(string sddl)
    {
        ArgumentNullException.ThrowIfNull(sddl);
        string? owner = null, group = null;
        ushort control = SdControl.SelfRelative;
        var aces = new List<AceInfo>();
        var daclPresent = false;
        var i = 0;
        while (i < sddl.Length)
        {
            if (i + 1 >= sddl.Length || sddl[i + 1] != ':') throw new FormatException($"SDDL invalide à la position {i}.");
            var tag = sddl[i];
            i += 2;
            var end = NextTag(sddl, i);
            var body = sddl[i..end];
            switch (tag)
            {
                case 'O': owner = ParseSid(body); break;
                case 'G': group = ParseSid(body); break;
                case 'D':
                    daclPresent = true;
                    control |= SdControl.DaclPresent;
                    var p = body.IndexOf('(');
                    var flags = p < 0 ? body : body[..p];
                    if (flags.Contains("NO_ACCESS_CONTROL", StringComparison.Ordinal)) { daclPresent = false; control &= unchecked((ushort)~SdControl.DaclPresent); flags = flags.Replace("NO_ACCESS_CONTROL", ""); }
                    if (flags.Contains('P')) control |= SdControl.DaclProtected;
                    if (flags.Contains("AR", StringComparison.Ordinal)) control |= SdControl.DaclAutoInheritReq;
                    if (flags.Contains("AI", StringComparison.Ordinal)) control |= SdControl.DaclAutoInherited;
                    if (p >= 0) foreach (var a in SplitAces(body[p..])) aces.Add(ParseAce(a));
                    break;
                case 'S': break; // SACL ignorée
                default: throw new FormatException($"Section SDDL inconnue : {tag}");
            }
            i = end;
        }
        var info = new SecurityDescriptorInfo { Owner = owner, Group = group, Control = control, DaclPresent = daclPresent, Aces = aces };
        return info with { Sddl = Format(info) };
    }

    private static int NextTag(string s, int from)
    {
        var depth = 0;
        for (var j = from; j < s.Length; j++)
        {
            if (s[j] == '(') depth++;
            else if (s[j] == ')') depth--;
            else if (depth == 0 && j + 1 < s.Length && s[j + 1] == ':' && s[j] is 'O' or 'G' or 'D' or 'S') return j;
        }
        return s.Length;
    }

    private static IEnumerable<string> SplitAces(string s)
    {
        var start = -1;
        for (var j = 0; j < s.Length; j++)
        {
            if (s[j] == '(') start = j + 1;
            else if (s[j] == ')' && start >= 0) { yield return s[start..j]; start = -1; }
        }
    }

    private static AceInfo ParseAce(string ace)
    {
        var f = ace.Split(';');
        if (f.Length < 6) throw new FormatException($"ACE SDDL invalide : ({ace})");
        var kind = f[0] switch { "A" => AceKind.Allow, "D" => AceKind.Deny, "XA" => AceKind.AllowCallback, "XD" => AceKind.DenyCallback, _ => throw new FormatException($"Type d'ACE non pris en charge : {f[0]}") };
        AceFlags flags = 0;
        if (f[1].Length % 2 != 0) throw new FormatException($"Drapeaux d'ACE invalides : {f[1]}");
        for (var j = 0; j < f[1].Length; j += 2)
        {
            flags |= f[1].Substring(j, 2) switch
            {
                "OI" => AceFlags.ObjectInherit, "CI" => AceFlags.ContainerInherit, "NP" => AceFlags.NoPropagateInherit,
                "IO" => AceFlags.InheritOnly, "ID" => AceFlags.Inherited, _ => throw new FormatException($"Drapeau d'ACE inconnu : {f[1].Substring(j, 2)}"),
            };
        }
        return new AceInfo(kind, ParseSid(f[5]), ParseRights(f[2]), flags, (byte)kind);
    }

    /// <summary>Lit un masque SDDL (hexadécimal, décimal ou alias).</summary>
    public static uint ParseRights(string r)
    {
        if (r.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return uint.Parse(r[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (r.Length > 0 && char.IsDigit(r[0])) return uint.Parse(r, CultureInfo.InvariantCulture);
        uint m = 0;
        for (var j = 0; j < r.Length; j += 2)
        {
            if (j + 2 > r.Length || !RightAliases.TryGetValue(r.Substring(j, 2), out var v)) throw new FormatException($"Droit SDDL inconnu : {r}");
            m |= v;
        }
        return m;
    }

    /// <summary>Lit un SID SDDL (S-1-… ou alias à deux lettres).</summary>
    public static string ParseSid(string s)
    {
        if (SidAliases.TryGetValue(s, out var v)) return v;
        if (Sid.IsValid(s)) return s;
        throw new FormatException($"SID SDDL inconnu : {s} (les alias de domaine comme DA/DU exigent le SID complet).");
    }
}
