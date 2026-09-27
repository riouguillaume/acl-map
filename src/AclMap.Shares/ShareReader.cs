using System.ComponentModel;
using System.Runtime.InteropServices;
using AclMap.Core.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Shares;

/// <summary>
/// Lecture des partages d'un serveur (NetShareEnum / NetShareGetInfo niveau 502 pour les droits de partage).
/// Le niveau 502 exige d'être administrateur du serveur ; à défaut, les partages sont listés au niveau 1 et leurs
/// droits signalés comme illisibles.
/// </summary>
public static class ShareReader
{
    private const uint STYPE_MASK = 0xFF, STYPE_SPECIAL = 0x80000000;
    private const int NERR_Success = 0, ERROR_MORE_DATA = 234, MAX_PREFERRED_LENGTH = -1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHARE_INFO_1 { public string netname; public uint type; public string remark; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHARE_INFO_502
    {
        public string netname; public uint type; public string remark; public uint permissions; public uint max_uses; public uint current_uses;
        public string path; public IntPtr passwd; public uint reserved; public IntPtr security_descriptor;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(string server, int level, out IntPtr buf, int prefmaxlen, out int entriesread, out int totalentries, ref int resume);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareGetInfo(string server, string netname, int level, out IntPtr buf);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr sd);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool IsValidSecurityDescriptor(IntPtr sd);

    private static ShareKind Kind(uint type) => (type & STYPE_MASK) switch { 0 => ShareKind.Disk, 1 => ShareKind.Print, 2 => ShareKind.Device, 3 => ShareKind.Ipc, _ => ShareKind.Other };

    /// <summary>Liste les partages du serveur.</summary>
    /// <exception cref="Win32Exception">Serveur injoignable ou énumération refusée.</exception>
    public static List<ShareInfo> List(string server)
    {
        var result = new List<ShareInfo>();
        var resume = 0;
        var rc = NetShareEnum(server, 1, out var buf, MAX_PREFERRED_LENGTH, out var read, out _, ref resume);
        if (rc is not (NERR_Success or ERROR_MORE_DATA)) throw new Win32Exception(rc, $"Énumération des partages de {server} impossible : {new Win32Exception(rc).Message} ({rc})");
        var names = new List<(string Name, uint Type, string? Remark)>();
        try
        {
            var size = Marshal.SizeOf<SHARE_INFO_1>();
            for (var i = 0; i < read; i++)
            {
                var si = Marshal.PtrToStructure<SHARE_INFO_1>(buf + i * size);
                names.Add((si.netname, si.type, si.remark));
            }
        }
        finally { NetApiBufferFree(buf); }
        foreach (var (name, type, remark) in names)
        {
            var info = new ShareInfo { Server = server, Name = name, Kind = Kind(type), Special = (type & STYPE_SPECIAL) != 0 || name is "IPC$" or "ADMIN$" or "print$" || (name.Length == 2 && name[1] == '$'), Remark = remark };
            rc = NetShareGetInfo(server, name, 502, out var b502);
            if (rc != NERR_Success) { result.Add(info with { SecurityError = rc == 5 ? "Accès refusé (5) : droits d'administrateur du serveur requis pour lire les droits de partage." : $"{new Win32Exception(rc).Message} ({rc})" }); continue; }
            try
            {
                var s = Marshal.PtrToStructure<SHARE_INFO_502>(b502);
                info = info with { LocalPath = s.path };
                if (s.security_descriptor != IntPtr.Zero && IsValidSecurityDescriptor(s.security_descriptor))
                {
                    var len = (int)GetSecurityDescriptorLength(s.security_descriptor);
                    var bytes = new byte[len];
                    Marshal.Copy(s.security_descriptor, bytes, 0, len);
                    info = info with { Security = SecurityDescriptorCodec.Parse(bytes) };
                }
                else if (info.Kind == ShareKind.Disk) info = info with { SecurityError = "Aucun descripteur de partage : accès « Tout le monde : Contrôle total » par défaut." , Security = DefaultEveryone() };
            }
            catch (FormatException ex) { info = info with { SecurityError = "Droits de partage illisibles : " + ex.Message }; }
            finally { NetApiBufferFree(b502); }
            result.Add(info);
        }
        return result;
    }

    private static AclMap.Models.Security.SecurityDescriptorInfo DefaultEveryone()
    {
        var sd = new AclMap.Models.Security.SecurityDescriptorInfo
        {
            Control = AclMap.Models.Security.SdControl.SelfRelative | AclMap.Models.Security.SdControl.DaclPresent,
            Aces = [new AclMap.Models.Security.AceInfo(AclMap.Models.Security.AceKind.Allow, WellKnownSids.Everyone, AclMap.Models.Security.FileRights.ShareFull, 0)],
        };
        return sd with { Sddl = Sddl.Format(sd) };
    }

    /// <summary>
    /// Relie les partages à l'instantané : dossier racine de chaque partage et partage parent quand un partage est
    /// un sous-dossier d'un autre.
    /// </summary>
    public static List<ShareInfo> Link(IReadOnlyList<ShareInfo> shares, Func<string, int?> findLocal)
    {
        var disks = shares.Where(s => s.Kind == ShareKind.Disk && !string.IsNullOrEmpty(s.LocalPath)).ToList();
        return shares.Select(s =>
        {
            if (s.Kind != ShareKind.Disk || string.IsNullOrEmpty(s.LocalPath)) return s;
            var lp = s.LocalPath.TrimEnd('\\');
            var parent = disks.Where(o => !ReferenceEquals(o, s) && !o.Special && lp.StartsWith(o.LocalPath!.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(o => o.LocalPath!.Length).FirstOrDefault();
            return s with { RootFolderId = findLocal(s.LocalPath), NestedIn = parent?.Name };
        }).ToList();
    }
}
