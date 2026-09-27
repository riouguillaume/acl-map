using System.ComponentModel;
using System.Runtime.InteropServices;
using AclMap.Core.Security;

namespace AclMap.ActiveDirectory;

/// <summary>
/// Vérification par Windows (API AuthZ, comme l'onglet « Accès effectif ») de l'accès d'un compte du domaine à un
/// descripteur de sécurité. Windows reconstitue lui-même les groupes du compte (poste joint au domaine requis).
/// Les groupes locaux pris en compte sont ceux du poste qui exécute la vérification, pas ceux du serveur de fichiers.
/// </summary>
public static class AuthzCheck
{
    private const uint AUTHZ_RM_FLAG_NO_AUDIT = 1, MAXIMUM_ALLOWED = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AUTHZ_ACCESS_REQUEST { public uint DesiredAccess; public IntPtr PrincipalSelfSid; public IntPtr ObjectTypeList; public uint ObjectTypeListLength; public IntPtr OptionalArguments; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AUTHZ_ACCESS_REPLY { public uint ResultListLength; public IntPtr GrantedAccessMask; public IntPtr SaclEvaluationResults; public IntPtr Error; }

    [DllImport("authz.dll", SetLastError = true)]
    private static extern bool AuthzInitializeResourceManager(uint flags, IntPtr access, IntPtr compute, IntPtr free, string? name, out IntPtr rm);

    [DllImport("authz.dll", SetLastError = true)]
    private static extern bool AuthzInitializeContextFromSid(uint flags, byte[] sid, IntPtr rm, IntPtr expiration, LUID id, IntPtr dynamicGroupArgs, out IntPtr ctx);

    [DllImport("authz.dll", SetLastError = true)]
    private static extern bool AuthzAccessCheck(uint flags, IntPtr ctx, ref AUTHZ_ACCESS_REQUEST request, IntPtr audit, byte[] sd, IntPtr optional, uint optionalCount, ref AUTHZ_ACCESS_REPLY reply, IntPtr results);

    [DllImport("authz.dll")] private static extern bool AuthzFreeContext(IntPtr ctx);
    [DllImport("authz.dll")] private static extern bool AuthzFreeResourceManager(IntPtr rm);

    /// <summary>Droits accordés (masque) au compte par le descripteur.</summary>
    /// <exception cref="Win32Exception">Contexte AuthZ impossible (poste hors domaine, compte inconnu…).</exception>
    public static uint MaximumAllowed(string sid, byte[] securityDescriptor)
    {
        if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, null, out var rm))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!AuthzInitializeContextFromSid(0, Sid.ToBinary(sid), rm, IntPtr.Zero, default, IntPtr.Zero, out var ctx))
            {
                var e = Marshal.GetLastWin32Error();
                throw new Win32Exception(e, $"Windows ne peut pas reconstituer le jeton de ce compte ({e}) : la vérification AuthZ exige un poste joint au domaine et un compte du domaine.");
            }
            var granted = Marshal.AllocHGlobal(4); var error = Marshal.AllocHGlobal(4);
            try
            {
                var req = new AUTHZ_ACCESS_REQUEST { DesiredAccess = MAXIMUM_ALLOWED };
                var reply = new AUTHZ_ACCESS_REPLY { ResultListLength = 1, GrantedAccessMask = granted, Error = error };
                if (!AuthzAccessCheck(0, ctx, ref req, IntPtr.Zero, securityDescriptor, IntPtr.Zero, 0, ref reply, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return unchecked((uint)Marshal.ReadInt32(granted));
            }
            finally { Marshal.FreeHGlobal(granted); Marshal.FreeHGlobal(error); AuthzFreeContext(ctx); }
        }
        finally { AuthzFreeResourceManager(rm); }
    }
}
