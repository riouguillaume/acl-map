using System.Buffers.Binary;
using AclMap.Models.Security;

namespace AclMap.Core.Security;

/// <summary>
/// Lecture et écriture des descripteurs de sécurité au format binaire « self-relative » (celui que renvoient
/// GetKernelObjectSecurity / NetShareGetInfo et qu'attend SetNamedSecurityInfo pour la DACL). Code géré, sans
/// appel Windows : il est donc testé sur toutes les plateformes.
/// </summary>
public static class SecurityDescriptorCodec
{
    /// <summary>Décode un descripteur binaire.</summary>
    /// <param name="data">Descripteur self-relative.</param>
    /// <returns>Descripteur décodé (SDDL renseigné).</returns>
    /// <exception cref="FormatException">Données invalides.</exception>
    public static SecurityDescriptorInfo Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 20 || data[0] != 1) throw new FormatException("Descripteur de sécurité invalide.");
        var control = BinaryPrimitives.ReadUInt16LittleEndian(data[2..]);
        var offOwner = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
        var offGroup = BinaryPrimitives.ReadInt32LittleEndian(data[8..]);
        var offDacl = BinaryPrimitives.ReadInt32LittleEndian(data[16..]);
        string? owner = offOwner > 0 ? Sid.Read(data, offOwner, out _) : null;
        string? group = offGroup > 0 ? Sid.Read(data, offGroup, out _) : null;
        var daclPresent = (control & SdControl.DaclPresent) != 0 && offDacl > 0;
        var aces = daclPresent ? ParseAcl(data, offDacl) : [];
        var info = new SecurityDescriptorInfo { Owner = owner, Group = group, Control = control, DaclPresent = daclPresent, Aces = aces };
        return info with { Sddl = Sddl.Format(info) };
    }

    /// <summary>Décode une ACL binaire.</summary>
    public static List<AceInfo> ParseAcl(ReadOnlySpan<byte> data, int offset)
    {
        if (offset + 8 > data.Length) throw new FormatException("ACL tronquée.");
        var size = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 2)..]);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 4)..]);
        if (offset + size > data.Length) throw new FormatException("ACL tronquée.");
        var list = new List<AceInfo>(count);
        var p = offset + 8;
        for (var i = 0; i < count; i++)
        {
            if (p + 4 > offset + size) throw new FormatException("ACE tronquée.");
            var type = data[p];
            var flags = (AceFlags)data[p + 1];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(p + 2)..]);
            if (aceSize < 8 || p + aceSize > offset + size) throw new FormatException("Taille d'ACE invalide.");
            var mask = BinaryPrimitives.ReadUInt32LittleEndian(data[(p + 4)..]);
            AceKind kind = type switch { 0 => AceKind.Allow, 1 => AceKind.Deny, 9 => AceKind.AllowCallback, 10 => AceKind.DenyCallback, _ => AceKind.Other };
            string sid;
            if (type is 0 or 1 or 9 or 10) sid = Sid.Read(data, p + 8, out _);
            else if (type is 5 or 6 or 11 or 12)
            {
                // ACE objet : drapeaux puis GUID facultatifs, puis SID
                var objFlags = BinaryPrimitives.ReadUInt32LittleEndian(data[(p + 8)..]);
                var q = p + 12 + ((objFlags & 1) != 0 ? 16 : 0) + ((objFlags & 2) != 0 ? 16 : 0);
                sid = Sid.Read(data, q, out _);
            }
            else sid = "S-1-0-0";
            list.Add(new AceInfo(kind, sid, mask, flags, type));
            p += aceSize;
        }
        return list;
    }

    /// <summary>Encode une DACL (ACE simples autorisation/refus uniquement).</summary>
    /// <exception cref="NotSupportedException">ACE conditionnelle ou objet (non réécrite par ACL Map).</exception>
    public static byte[] BuildAcl(IReadOnlyList<AceInfo> aces)
    {
        var parts = new List<byte[]>();
        foreach (var a in aces)
        {
            if (a.Kind is not (AceKind.Allow or AceKind.Deny)) throw new NotSupportedException("ACL Map ne réécrit pas les ACE conditionnelles ou objet.");
            var sid = Sid.ToBinary(a.Sid);
            var ace = new byte[8 + sid.Length];
            ace[0] = (byte)(a.Kind == AceKind.Allow ? 0 : 1);
            ace[1] = (byte)a.Flags;
            BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), a.Mask);
            sid.CopyTo(ace, 8);
            parts.Add(ace);
        }
        var total = 8 + parts.Sum(x => x.Length);
        if (total > ushort.MaxValue) throw new InvalidOperationException("ACL trop grande (64 Ko maximum).");
        var acl = new byte[total];
        acl[0] = 2; // ACL_REVISION
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2), (ushort)total);
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4), (ushort)parts.Count);
        var p = 8;
        foreach (var x in parts) { x.CopyTo(acl, p); p += x.Length; }
        return acl;
    }

    /// <summary>Encode un descripteur complet self-relative (propriétaire, groupe, DACL).</summary>
    public static byte[] Build(SecurityDescriptorInfo sd)
    {
        var owner = sd.Owner is null ? null : Sid.ToBinary(sd.Owner);
        var group = sd.Group is null ? null : Sid.ToBinary(sd.Group);
        var dacl = sd.DaclPresent ? BuildAcl(sd.Aces) : null;
        var control = (ushort)((sd.Control | SdControl.SelfRelative) & ~SdControl.SaclPresent);
        control = sd.DaclPresent ? (ushort)(control | SdControl.DaclPresent) : (ushort)(control & ~SdControl.DaclPresent);
        var buf = new List<byte>(new byte[20]);
        int offOwner = 0, offGroup = 0, offDacl = 0;
        if (owner is not null) { offOwner = buf.Count; buf.AddRange(owner); }
        if (group is not null) { offGroup = buf.Count; buf.AddRange(group); }
        if (dacl is not null) { offDacl = buf.Count; buf.AddRange(dacl); }
        var arr = buf.ToArray();
        arr[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(arr.AsSpan(2), control);
        BinaryPrimitives.WriteInt32LittleEndian(arr.AsSpan(4), offOwner);
        BinaryPrimitives.WriteInt32LittleEndian(arr.AsSpan(8), offGroup);
        BinaryPrimitives.WriteInt32LittleEndian(arr.AsSpan(16), offDacl);
        return arr;
    }
}
