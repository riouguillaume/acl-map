using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using AclMap.Core.Security;
using AclMap.Models.Snapshot;

namespace AclMap.ActiveDirectory;

/// <summary>Résolution des SID par Windows (LookupAccountSid) et groupes locaux d'un serveur (NetLocalGroup*).</summary>
public static class WindowsAccounts
{
    private const int ERROR_NONE_MAPPED = 1332;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSidW(string? system, byte[] sid, StringBuilder? name, ref uint nameLen, StringBuilder? domain, ref uint domainLen, out int use);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupEnum(string server, int level, out IntPtr buf, int prefmax, out int read, out int total, ref IntPtr resume);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buf, int prefmax, out int read, out int total, ref IntPtr resume);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountNameW(string? system, string name, byte[]? sid, ref uint sidLen, StringBuilder? domain, ref uint domainLen, out int use);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_INFO_1 { public string name; public string comment; }

    /// <summary>Résultat de LookupAccountSid.</summary>
    public sealed record Lookup(string Name, PrincipalKind Kind, bool Orphan);

    /// <summary>Nom d'un SID tel que le voit <paramref name="server"/> (null = poste local).</summary>
    public static Lookup Resolve(string? server, string sid)
    {
        var bin = Sid.ToBinary(sid);
        uint n = 256, d = 256;
        var name = new StringBuilder((int)n); var dom = new StringBuilder((int)d);
        if (!LookupAccountSidW(server, bin, name, ref n, dom, ref d, out var use))
        {
            var err = Marshal.GetLastWin32Error();
            if (err == ERROR_NONE_MAPPED) return new Lookup(sid, PrincipalKind.Unknown, Sid.DomainOf(sid) is not null);
            return new Lookup(WellKnownSids.NameOf(sid) ?? sid, WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown, false);
        }
        var kind = use switch { 1 => PrincipalKind.User, 2 or 4 => PrincipalKind.Group, 5 => PrincipalKind.WellKnown, 6 or 8 => PrincipalKind.Unknown, 9 => PrincipalKind.Computer, 3 => PrincipalKind.WellKnown, _ => PrincipalKind.Unknown };
        if (use == 4) kind = PrincipalKind.LocalGroup;   // SidTypeAlias : groupe local
        var full = dom.Length > 0 ? $"{dom}\\{name}" : name.ToString();
        return new Lookup(full, kind, use is 6 or 8);    // SidTypeDeletedAccount / SidTypeUnknown
    }

    /// <summary>Groupes locaux d'un serveur et leurs membres (SID). Exige souvent d'être administrateur du serveur.</summary>
    /// <exception cref="Win32Exception">Énumération refusée.</exception>
    public static List<PrincipalInfo> LocalGroups(string server)
    {
        var result = new List<PrincipalInfo>();
        var resume = IntPtr.Zero;
        var rc = NetLocalGroupEnum(server, 1, out var buf, -1, out var read, out _, ref resume);
        if (rc != 0) throw new Win32Exception(rc, $"Groupes locaux de {server} illisibles : {new Win32Exception(rc).Message} ({rc})");
        var groups = new List<(string Name, string Comment)>();
        try
        {
            var size = Marshal.SizeOf<LOCALGROUP_INFO_1>();
            for (var i = 0; i < read; i++) { var g = Marshal.PtrToStructure<LOCALGROUP_INFO_1>(buf + i * size); groups.Add((g.name, g.comment)); }
        }
        finally { NetApiBufferFree(buf); }
        foreach (var (name, comment) in groups)
        {
            var sid = SidOfName(server, name);
            if (sid is null) continue;
            var r2 = IntPtr.Zero;
            var mrc = NetLocalGroupGetMembers(server, name, 0, out var mb, -1, out var mread, out _, ref r2);
            List<string>? members = null; string? error = null;
            if (mrc == 0)
            {
                members = [];
                try { for (var i = 0; i < mread; i++) members.Add(Sid.Read(ReadSid(Marshal.ReadIntPtr(mb, i * IntPtr.Size)), 0, out _)); }
                finally { NetApiBufferFree(mb); }
            }
            else error = $"Membres illisibles ({mrc}) : droits d'administrateur du serveur requis.";
            result.Add(new PrincipalInfo { Sid = sid, Name = WellKnownSids.NameOf(sid) ?? $"{server.Split('.')[0].ToUpperInvariant()}\\{name}", Kind = PrincipalKind.LocalGroup, Scope = GroupScope.Local, Description = comment, Members = members, MembersError = error });
        }
        return result;
    }

    [DllImport("advapi32.dll")] private static extern int GetLengthSid(IntPtr sid);

    private static byte[] ReadSid(IntPtr p)
    {
        var len = GetLengthSid(p);
        var b = new byte[len];
        Marshal.Copy(p, b, 0, len);
        return b;
    }

    private static string? SidOfName(string server, string name)
    {
        uint sl = 0, dl = 0;
        LookupAccountNameW(server, name, null, ref sl, null, ref dl, out _);
        if (sl == 0) return null;
        var sid = new byte[sl]; var dom = new StringBuilder((int)dl);
        return LookupAccountNameW(server, name, sid, ref sl, dom, ref dl, out _) ? Sid.Read(sid, 0, out _) : null;
    }
}
