using AclMap.Models.Snapshot;

namespace AclMap.Core.Security;

/// <summary>SID connus : noms français, catégories utiles à l'analyse (groupes larges, administrateurs).</summary>
public static class WellKnownSids
{
    public const string Everyone = "S-1-1-0";
    public const string CreatorOwner = "S-1-3-0";
    public const string CreatorGroup = "S-1-3-1";
    public const string OwnerRights = "S-1-3-4";
    public const string Network = "S-1-5-2";
    public const string Batch = "S-1-5-3";
    public const string Interactive = "S-1-5-4";
    public const string Service = "S-1-5-6";
    public const string Anonymous = "S-1-5-7";
    public const string EnterpriseDcs = "S-1-5-9";
    public const string Self = "S-1-5-10";
    public const string AuthenticatedUsers = "S-1-5-11";
    public const string ThisOrganization = "S-1-5-15";
    public const string System = "S-1-5-18";
    public const string LocalService = "S-1-5-19";
    public const string NetworkService = "S-1-5-20";
    public const string Administrators = "S-1-5-32-544";
    public const string Users = "S-1-5-32-545";
    public const string Guests = "S-1-5-32-546";
    public const string PowerUsers = "S-1-5-32-547";
    public const string AccountOperators = "S-1-5-32-548";
    public const string ServerOperators = "S-1-5-32-549";
    public const string PrintOperators = "S-1-5-32-550";
    public const string BackupOperators = "S-1-5-32-551";
    public const string AllAppPackages = "S-1-15-2-1";
    public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    public const uint RidDomainAdmins = 512, RidDomainUsers = 513, RidDomainGuests = 514, RidDomainComputers = 515,
        RidDomainControllers = 516, RidSchemaAdmins = 518, RidEnterpriseAdmins = 519, RidAdministrator = 500, RidGuest = 501;

    private static readonly Dictionary<string, string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        [Everyone] = "Tout le monde",
        [CreatorOwner] = "CREATEUR PROPRIETAIRE",
        [CreatorGroup] = "GROUPE CREATEUR",
        [OwnerRights] = "DROITS DU PROPRIETAIRE",
        [Network] = "AUTORITE NT\\RESEAU",
        [Batch] = "AUTORITE NT\\TACHE",
        [Interactive] = "AUTORITE NT\\INTERACTIF",
        [Service] = "AUTORITE NT\\SERVICE",
        [Anonymous] = "AUTORITE NT\\ANONYMOUS LOGON",
        [EnterpriseDcs] = "AUTORITE NT\\CONTROLEURS DE DOMAINE D'ENTREPRISE",
        [Self] = "AUTORITE NT\\SELF",
        [AuthenticatedUsers] = "AUTORITE NT\\Utilisateurs authentifiés",
        [ThisOrganization] = "AUTORITE NT\\Cette organisation",
        [System] = "AUTORITE NT\\Système",
        [LocalService] = "AUTORITE NT\\SERVICE LOCAL",
        [NetworkService] = "AUTORITE NT\\SERVICE RÉSEAU",
        [Administrators] = "BUILTIN\\Administrateurs",
        [Users] = "BUILTIN\\Utilisateurs",
        [Guests] = "BUILTIN\\Invités",
        [PowerUsers] = "BUILTIN\\Utilisateurs avec pouvoir",
        [AccountOperators] = "BUILTIN\\Opérateurs de compte",
        [ServerOperators] = "BUILTIN\\Opérateurs de serveur",
        [PrintOperators] = "BUILTIN\\Opérateurs d'impression",
        [BackupOperators] = "BUILTIN\\Opérateurs de sauvegarde",
        [AllAppPackages] = "AUTORITÉ DE PACKAGE D'APPLICATION\\TOUS LES PACKAGES D'APPLICATION",
        [TrustedInstaller] = "NT SERVICE\\TrustedInstaller",
    };

    /// <summary>Nom français d'un SID connu (y compris les RID de domaine standards), sinon null.</summary>
    public static string? NameOf(string sid)
    {
        if (Names.TryGetValue(sid, out var n)) return n;
        if (sid.StartsWith("S-1-15-3-", StringComparison.Ordinal)) return "Capacité d'application (" + sid + ")";
        if (Security.Sid.DomainOf(sid) is not null && sid.Split('-').Length == 8)
        {
            return Security.Sid.Rid(sid) switch
            {
                RidDomainAdmins => "Admins du domaine",
                RidDomainUsers => "Utilisateurs du domaine",
                RidDomainGuests => "Invités du domaine",
                RidDomainComputers => "Ordinateurs du domaine",
                RidDomainControllers => "Contrôleurs de domaine",
                RidSchemaAdmins => "Administrateurs du schéma",
                RidEnterpriseAdmins => "Administrateurs de l'entreprise",
                _ => null,
            };
        }
        return null;
    }

    /// <summary>Nature d'un SID bien connu (null si c'est un SID de compte ordinaire).</summary>
    public static PrincipalKind? KindOf(string sid)
    {
        if (sid.StartsWith("S-1-5-32-", StringComparison.Ordinal)) return PrincipalKind.LocalGroup;
        if (sid.StartsWith("S-1-15-", StringComparison.Ordinal)) return PrincipalKind.Capability;
        if (sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) return PrincipalKind.WellKnown;
        if (Names.ContainsKey(sid)) return PrincipalKind.WellKnown;
        return null;
    }

    /// <summary>
    /// Groupes « larges » : quasiment tous les comptes y sont (Tout le monde, Utilisateurs authentifiés, Utilisateurs,
    /// Utilisateurs du domaine, Invités, Anonyme). Leur donner l'écriture ouvre le dossier à tous.
    /// </summary>
    public static bool IsBroad(string sid)
    {
        if (sid is Everyone or AuthenticatedUsers or Users or Guests or Anonymous or Network or Interactive or ThisOrganization) return true;
        var rid = Security.Sid.Rid(sid);
        return Security.Sid.DomainOf(sid) is not null && sid.Split('-').Length == 8 && rid is RidDomainUsers or RidDomainGuests or RidDomainComputers;
    }

    /// <summary>Identités d'administration attendues dans les ACL (système, administrateurs, propriétaire créateur…).</summary>
    public static bool IsAdministrative(string sid)
    {
        if (sid is System or Administrators or TrustedInstaller or CreatorOwner or OwnerRights or BackupOperators or ServerOperators) return true;
        if (Security.Sid.DomainOf(sid) is not null && sid.Split('-').Length == 8)
            return Security.Sid.Rid(sid) is RidDomainAdmins or RidEnterpriseAdmins or RidAdministrator;
        return false;
    }

    /// <summary>SID implicitement présents dans le jeton d'un utilisateur du domaine qui accède par le réseau.</summary>
    public static readonly IReadOnlyList<string> ImplicitNetworkSids = [Everyone, AuthenticatedUsers, Network, ThisOrganization];
}
