using System.ComponentModel;
using AclMap.Core.Security;
using AclMap.Models.Security;
using AclMap.Operations;

namespace AclMap.FileSystem;

/// <summary>Lecture/écriture réelle des ACL NTFS (utilisé uniquement par le verbe « apply » du collecteur, après confirmation).</summary>
public sealed class WindowsAclStore : IAclStore
{
    /// <inheritdoc/>
    public SecurityDescriptorInfo Read(string path)
    {
        using var h = SecurityReader.Open(path, Native.READ_CONTROL, reparse: false, out var err);
        if (h.IsInvalid) throw new Win32Exception(err, $"Lecture de l'ACL impossible : {SecurityReader.Describe(err)} — {path}");
        var bytes = SecurityReader.ReadSecurity(h, out err) ?? throw new Win32Exception(err, $"Lecture de l'ACL impossible : {SecurityReader.Describe(err)} — {path}");
        return SecurityDescriptorCodec.Parse(bytes);
    }

    /// <inheritdoc/>
    public void WriteDacl(string path, IReadOnlyList<AceInfo> aces, bool protectedDacl)
    {
        var dacl = SecurityDescriptorCodec.BuildAcl(aces);
        var info = Native.DACL_SECURITY_INFORMATION | (protectedDacl ? Native.PROTECTED_DACL_SECURITY_INFORMATION : Native.UNPROTECTED_DACL_SECURITY_INFORMATION);
        // SetNamedSecurityInfo recalcule et propage l'héritage vers les descendants (comme l'Explorateur).
        var rc = Native.SetNamedSecurityInfoW(LongPath.ToExtended(path), Native.SE_FILE_OBJECT, info, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
        if (rc != 0) throw new Win32Exception((int)rc, $"Écriture de l'ACL refusée : {SecurityReader.Describe((int)rc)} — {path}");
    }
}
