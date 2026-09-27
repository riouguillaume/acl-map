using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using AclMap.ActiveDirectory;

namespace AclMap.Collector;

/// <summary>Résolution des cibles réseau et connexion à l'annuaire.</summary>
public static class Targets
{
    /// <summary>
    /// Remplace une adresse IP par le nom DNS (Kerberos et SMB fonctionnent alors normalement ; une IP impose NTLM,
    /// souvent restreint — leçon du correctif GPO Map 2.2.3).
    /// </summary>
    public static string PreferFqdn(string server)
    {
        if (!IPAddress.TryParse(server, out var ip)) return server;
        try { var h = Dns.GetHostEntry(ip).HostName; return string.IsNullOrWhiteSpace(h) ? server : h; }
        catch (System.Net.Sockets.SocketException) { return server; }
    }

    /// <summary>Domaine du poste (null s'il n'est pas joint).</summary>
    public static string? JoinedDomain()
    {
        try { var d = IPGlobalProperties.GetIPGlobalProperties().DomainName; return string.IsNullOrWhiteSpace(d) ? null : d; }
        catch (NetworkInformationException) { return null; }
    }

    /// <summary>Ouvre une connexion LDAP (contrôleur indiqué, sinon domaine indiqué, sinon domaine du poste).</summary>
    public static LdapDirectory Connect(string? dc, string? domain)
    {
        var target = !string.IsNullOrWhiteSpace(dc) ? PreferFqdn(dc!) : !string.IsNullOrWhiteSpace(domain) ? domain! : JoinedDomain()
            ?? throw new InvalidOperationException("Aucun domaine indiqué et poste hors domaine : renseignez le domaine et le contrôleur dans le profil.");
        return new LdapDirectory(target);
    }

    /// <summary>Compte de la session Windows (hors « netonly »).</summary>
    public static (string Name, string? Sid) CurrentUser()
    {
        using var id = WindowsIdentity.GetCurrent();
        return (id.Name, id.User?.Value);
    }
}
