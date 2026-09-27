using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AclMap.FileSystem;

/// <summary>Appels Win32 utilisés pour lire et écrire les ACL de fichiers.</summary>
internal static class Native
{
    public const uint FILE_LIST_DIRECTORY = 0x0001;
    public const uint READ_CONTROL = 0x00020000;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint FILE_SHARE_ALL = 0x7;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    public const int FileFullDirectoryInfo = 14;
    public const int FileFullDirectoryRestartInfo = 15;
    public const int ERROR_ACCESS_DENIED = 5;
    public const int ERROR_NO_MORE_FILES = 18;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;
    public const int ERROR_FILE_NOT_FOUND = 2;
    public const int ERROR_PATH_NOT_FOUND = 3;
    public const uint OWNER_SECURITY_INFORMATION = 0x1;
    public const uint GROUP_SECURITY_INFORMATION = 0x2;
    public const uint DACL_SECURITY_INFORMATION = 0x4;
    public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
    public const uint UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
    public const int SE_FILE_OBJECT = 1;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint info, byte[]? sd, uint length, out uint needed);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetFileSecurityW(string name, uint info, byte[]? sd, uint length, out uint needed);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, byte[] buffer, uint size);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint SetNamedSecurityInfoW(string name, int objectType, uint info, IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LookupPrivilegeValueW(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll, ref TOKEN_PRIVILEGES state, uint len, IntPtr prev, IntPtr retLen);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}

/// <summary>Chemins étendus (\\?\) pour dépasser la limite de 260 caractères.</summary>
public static class LongPath
{
    /// <summary>Forme étendue d'un chemin UNC ou local.</summary>
    public static string ToExtended(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path[2..];
        return @"\\?\" + path;
    }
}

/// <summary>Activation d'un privilège du jeton du processus (SeBackupPrivilege pour le mode sauvegarde).</summary>
public static class Privileges
{
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;

    /// <summary>Active un privilège détenu par le compte ; faux s'il n'est pas détenu.</summary>
    public static bool Enable(string name)
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return false;
        using (token)
        {
            if (!Native.LookupPrivilegeValueW(null, name, out var luid)) return false;
            var tp = new Native.TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!Native.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0;   // ERROR_NOT_ALL_ASSIGNED (1300) si le privilège n'est pas détenu
        }
    }
}
