using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AclMap.FileSystem;

/// <summary>Lecture des descripteurs de sécurité et des listes de dossiers (API Win32, sémantique de sauvegarde).</summary>
public static class SecurityReader
{
    private const uint Info = Native.OWNER_SECURITY_INFORMATION | Native.GROUP_SECURITY_INFORMATION | Native.DACL_SECURITY_INFORMATION;

    /// <summary>Ouvre un dossier (ou un fichier) ; handle invalide et code d'erreur en cas d'échec.</summary>
    public static SafeFileHandle Open(string path, uint access, bool reparse, out int error)
    {
        var flags = Native.FILE_FLAG_BACKUP_SEMANTICS | (reparse ? Native.FILE_FLAG_OPEN_REPARSE_POINT : 0);
        var h = Native.CreateFileW(LongPath.ToExtended(path), access | Native.SYNCHRONIZE, Native.FILE_SHARE_ALL, IntPtr.Zero, Native.OPEN_EXISTING, flags, IntPtr.Zero);
        error = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    /// <summary>Lit le descripteur (propriétaire, groupe, DACL) d'un handle ouvert avec READ_CONTROL.</summary>
    public static byte[]? ReadSecurity(SafeFileHandle h, out int error)
    {
        Native.GetKernelObjectSecurity(h, Info, null, 0, out var needed);
        error = Marshal.GetLastWin32Error();
        if (error != Native.ERROR_INSUFFICIENT_BUFFER || needed == 0) return null;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buf = new byte[needed];
            if (Native.GetKernelObjectSecurity(h, Info, buf, needed, out var n2)) { error = 0; return buf; }
            error = Marshal.GetLastWin32Error();
            if (error != Native.ERROR_INSUFFICIENT_BUFFER) return null;
            needed = n2;
        }
        return null;
    }

    /// <summary>Lit le descripteur d'un fichier par son chemin.</summary>
    public static byte[]? ReadFileSecurity(string path, out int error)
    {
        var p = LongPath.ToExtended(path);
        Native.GetFileSecurityW(p, Info, null, 0, out var needed);
        error = Marshal.GetLastWin32Error();
        if (error != Native.ERROR_INSUFFICIENT_BUFFER) return null;
        var buf = new byte[needed];
        if (Native.GetFileSecurityW(p, Info, buf, needed, out _)) { error = 0; return buf; }
        error = Marshal.GetLastWin32Error();
        return null;
    }

    /// <summary>Entrée d'un dossier.</summary>
    public readonly record struct Entry(string Name, bool IsDirectory, bool IsReparsePoint);

    /// <summary>Liste le contenu d'un dossier ouvert avec FILE_LIST_DIRECTORY.</summary>
    /// <exception cref="Win32Exception">Erreur de lecture.</exception>
    public static List<Entry> List(SafeFileHandle h)
    {
        var list = new List<Entry>();
        var buf = new byte[64 * 1024];
        var cls = Native.FileFullDirectoryRestartInfo;
        while (true)
        {
            if (!Native.GetFileInformationByHandleEx(h, cls, buf, (uint)buf.Length))
            {
                var err = Marshal.GetLastWin32Error();
                if (err == Native.ERROR_NO_MORE_FILES) break;
                throw new Win32Exception(err);
            }
            cls = Native.FileFullDirectoryInfo;
            var p = 0;
            while (true)
            {
                var next = BitConverter.ToInt32(buf, p);
                var attrs = BitConverter.ToUInt32(buf, p + 56);
                var nameLen = BitConverter.ToInt32(buf, p + 60);
                var name = System.Text.Encoding.Unicode.GetString(buf, p + 68, nameLen);
                if (name is not "." and not "..")
                    list.Add(new Entry(name, (attrs & Native.FILE_ATTRIBUTE_DIRECTORY) != 0, (attrs & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0));
                if (next == 0) break;
                p += next;
            }
        }
        return list;
    }

    /// <summary>Message français d'une erreur Windows.</summary>
    public static string Describe(int code) => code switch
    {
        5 => "Accès refusé (5)",
        2 or 3 => $"Introuvable ({code})",
        32 => "Utilisé par un autre processus (32)",
        53 => "Chemin réseau introuvable (53)",
        64 => "Le serveur n'est plus disponible (64)",
        67 => "Nom réseau introuvable (67)",
        1219 => "Connexion SMB existante avec d'autres identifiants (1219)",
        1326 => "Identifiants refusés (1326)",
        _ => $"{new Win32Exception(code).Message} ({code})",
    };
}
