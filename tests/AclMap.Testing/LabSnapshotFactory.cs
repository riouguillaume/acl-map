using AclMap.Core.Security;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Testing;

/// <summary>
/// Instantané de démonstration « contoso.local » : un serveur de fichiers FS01 et une arborescence piégée
/// (héritage rompu, refus, SID orphelin, droits nominatifs, compte prestataire à privilèges, Tout le monde en
/// écriture, ACE conditionnelle, dossier inaccessible, partages imbriqués, imbrication de groupes profonde…).
/// Sert aux tests, à l'hôte de développement et au fichier samples/demo.aclmap.
/// </summary>
public static class LabSnapshotFactory
{
    public const string D = "S-1-5-21-1111111111-2222222222-3333333333";
    public static string Rid(int rid) => $"{D}-{rid}";

    public static readonly string Administrator = Rid(500), DomainAdmins = Rid(512), DomainUsers = Rid(513), EnterpriseAdmins = Rid(519);
    public static readonly string Alice = Rid(1101), Bruno = Rid(1102), Chloe = Rid(1103), David = Rid(1104), Prestataire = Rid(1105), Emma = Rid(1106), Farid = Rid(1107), Gilles = Rid(1108);
    public static readonly string GgCompta = Rid(2001), GgRh = Rid(2002), GgDirection = Rid(2003), GgCommercial = Rid(2004), GgIt = Rid(2005), GgVide = Rid(2107);
    public static readonly string DlComptaRw = Rid(2101), DlComptaRo = Rid(2102), DlRhRw = Rid(2103), DlDirectionRw = Rid(2104), DlCommercialRw = Rid(2105), DlCommunRw = Rid(2106);
    public static readonly string GlNiv1 = Rid(2201), GlNiv2 = Rid(2202), GlNiv3 = Rid(2203), GlNiv4 = Rid(2204);
    public static readonly string Orphan = Rid(3181);
    public const string Foreign = "S-1-5-21-7777777777-8888888888-9999999999-1200";
    public const string LocalAdmin = "S-1-5-21-4444444444-5555555555-6666666666-500";

    private const uint FA = FileRights.FullControl, M = FileRights.Modify, RX = FileRights.ReadAndExecute, R = FileRights.Read;
    private const AceFlags OICI = AceFlags.ObjectInherit | AceFlags.ContainerInherit;

    private static AceInfo A(string sid, uint mask, AceFlags f = OICI) => new(AceKind.Allow, sid, mask, f, 0);
    private static AceInfo Dn(string sid, uint mask, AceFlags f = OICI) => new(AceKind.Deny, sid, mask, f, 1);

    private static PrincipalInfo U(string sid, string sam, string display, bool admin = false, bool disabled = false) =>
        new() { Sid = sid, Name = "CONTOSO\\" + sam, SamAccountName = sam, DisplayName = display, Kind = PrincipalKind.User, AdminCount = admin, Disabled = disabled, PrimaryGroupRid = 513,
            DistinguishedName = $"CN={display},OU=Utilisateurs,DC=contoso,DC=local" };

    private static PrincipalInfo G(string sid, string sam, GroupScope scope, params string[] members) =>
        new() { Sid = sid, Name = "CONTOSO\\" + sam, SamAccountName = sam, Kind = PrincipalKind.Group, Scope = scope, Members = members,
            DistinguishedName = $"CN={sam},OU=Groupes,DC=contoso,DC=local" };

    /// <summary>Calcule les ACE héritées par un sous-dossier (règles NTFS simplifiées : CREATOR OWNER conservé comme modèle).</summary>
    public static List<AceInfo> Inherited(IEnumerable<AceInfo> parent)
    {
        var list = new List<AceInfo>();
        foreach (var a in parent)
        {
            if ((a.Flags & AceFlags.ContainerInherit) != 0)
            {
                var f = (a.Flags & AceFlags.NoPropagateInherit) != 0 ? AceFlags.None : a.Flags & (OICI | AceFlags.InheritOnly);
                if (a.Sid == WellKnownSids.CreatorOwner) f |= AceFlags.InheritOnly; else f &= ~AceFlags.InheritOnly;
                list.Add(a with { Flags = f | AceFlags.Inherited });
            }
            else if ((a.Flags & AceFlags.ObjectInherit) != 0 && (a.Flags & AceFlags.NoPropagateInherit) == 0)
                list.Add(a with { Flags = AceFlags.ObjectInherit | AceFlags.InheritOnly | AceFlags.Inherited });
        }
        return list;
    }

    /// <summary>Construit l'instantané de démonstration.</summary>
    public static AclSnapshot Create(int generatedProjects = 20)
    {
        var principals = new List<PrincipalInfo>
        {
            U(Administrator, "Administrateur", "Administrateur", admin: true),
            U(Alice, "alice.martin", "Alice Martin"), U(Bruno, "bruno.leroy", "Bruno Leroy"), U(Chloe, "chloe.bernard", "Chloé Bernard"),
            U(David, "david.moreau", "David Moreau"), U(Prestataire, "prestataire", "Compte prestataire", admin: true),
            U(Emma, "emma.petit", "Emma Petit"), U(Farid, "farid.roux", "Farid Roux", disabled: true), U(Gilles, "gilles.fournier", "Gilles Fournier"),
            G(DomainAdmins, "Admins du domaine", GroupScope.Global, Administrator, Prestataire) with { AdminCount = true },
            G(EnterpriseAdmins, "Administrateurs de l'entreprise", GroupScope.Universal, Administrator) with { AdminCount = true },
            G(DomainUsers, "Utilisateurs du domaine", GroupScope.Global, Administrator, Alice, Bruno, Chloe, David, Prestataire, Emma, Farid, Gilles),
            G(GgCompta, "GG_Compta", GroupScope.Global, Alice, Bruno), G(GgRh, "GG_RH", GroupScope.Global, Chloe), G(GgDirection, "GG_Direction", GroupScope.Global, David),
            G(GgCommercial, "GG_Commercial", GroupScope.Global, Emma, Farid), G(GgIt, "GG_IT", GroupScope.Global, Gilles), G(GgVide, "GG_Vide", GroupScope.Global),
            G(DlComptaRw, "DL_Donnees-Compta_RW", GroupScope.DomainLocal, GgCompta), G(DlComptaRo, "DL_Donnees-Compta_RO", GroupScope.DomainLocal, GgDirection),
            G(DlRhRw, "DL_Donnees-RH_RW", GroupScope.DomainLocal, GgRh), G(DlDirectionRw, "DL_Donnees-Direction_RW", GroupScope.DomainLocal, GgDirection),
            G(DlCommercialRw, "DL_Donnees-Commercial_RW", GroupScope.DomainLocal, GgCommercial), G(DlCommunRw, "DL_Donnees-Commun_RW", GroupScope.DomainLocal, DomainUsers),
            G(GlNiv1, "GL_Niveau1", GroupScope.DomainLocal, GlNiv2), G(GlNiv2, "GL_Niveau2", GroupScope.Global, GlNiv3), G(GlNiv3, "GL_Niveau3", GroupScope.Global, GlNiv4),
            G(GlNiv4, "GL_Niveau4", GroupScope.Global, Emma),
            new() { Sid = Orphan, Name = Orphan, Kind = PrincipalKind.Unknown, Orphan = true },
            new() { Sid = Foreign, Name = "PARTENAIRE\\GG_Audit", Kind = PrincipalKind.Foreign, MembersError = "Groupe d'un domaine approuvé : membres non lisibles depuis contoso.local." },
            new() { Sid = WellKnownSids.Administrators, Name = "BUILTIN\\Administrateurs", Kind = PrincipalKind.LocalGroup, Scope = GroupScope.Local, Members = [DomainAdmins, LocalAdmin] },
            new() { Sid = WellKnownSids.Users, Name = "BUILTIN\\Utilisateurs", Kind = PrincipalKind.LocalGroup, Scope = GroupScope.Local, Members = [DomainUsers, WellKnownSids.AuthenticatedUsers, WellKnownSids.Interactive] },
            new() { Sid = WellKnownSids.BackupOperators, Name = "BUILTIN\\Opérateurs de sauvegarde", Kind = PrincipalKind.LocalGroup, Scope = GroupScope.Local, Members = [] },
            new() { Sid = LocalAdmin, Name = "FS01\\Administrateur", Kind = PrincipalKind.LocalUser },
        };
        foreach (var s in new[] { WellKnownSids.System, WellKnownSids.CreatorOwner, WellKnownSids.Everyone, WellKnownSids.AuthenticatedUsers, WellKnownSids.Interactive })
            principals.Add(new() { Sid = s, Name = WellKnownSids.NameOf(s)!, Kind = PrincipalKind.WellKnown });

        var folders = new List<FolderNode>();
        var sds = new List<SecurityDescriptorInfo>();
        var sdIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var acesOf = new Dictionary<int, List<AceInfo>>();
        int Sd(List<AceInfo> aces, bool prot, string owner)
        {
            var info = new SecurityDescriptorInfo
            {
                Owner = owner, Group = DomainUsers, Control = (ushort)(SdControl.SelfRelative | SdControl.DaclPresent | SdControl.DaclAutoInherited | (prot ? SdControl.DaclProtected : 0)), Aces = aces,
            };
            var sddl = Sddl.Format(info);
            if (!sdIndex.TryGetValue(sddl, out var id)) { id = sds.Count; sdIndex[sddl] = id; sds.Add(info with { Id = id, Sddl = sddl }); }
            return id;
        }
        int Add(int parent, string name, List<AceInfo>? explicitAces = null, bool prot = false, string? owner = null, NodeFlags flags = NodeFlags.None, bool unreadable = false)
        {
            var id = folders.Count;
            var aces = new List<AceInfo>(explicitAces ?? []);
            if (!prot && parent >= 0) aces.AddRange(Inherited(acesOf[parent]));
            acesOf[id] = aces;
            var sd = unreadable ? -1 : Sd(aces, prot, owner ?? WellKnownSids.Administrators);
            folders.Add(new FolderNode(id, parent, name, sd, flags | (unreadable ? NodeFlags.SecurityUnreadable | NodeFlags.ListDenied : NodeFlags.None)));
            return id;
        }

        var root = Add(-1, @"\\FS01.contoso.local\Donnees", [
            A(WellKnownSids.System, FA), A(WellKnownSids.Administrators, FA), A(WellKnownSids.CreatorOwner, FA, OICI | AceFlags.InheritOnly),
            A(DomainUsers, RX, AceFlags.None)], prot: true);
        Add(root, "Commun", [A(DlCommunRw, M)]);
        var compta = Add(root, "Compta", [A(WellKnownSids.System, FA), A(WellKnownSids.Administrators, FA), A(DlComptaRw, M), A(DlComptaRo, RX)], prot: true);
        var c2025 = Add(compta, "2025");
        Add(c2025, "Clôture", [Dn(Bruno, FileRights.Delete | FileRights.DeleteChild | FileRights.AddFile | FileRights.AddSubdirectory)]);
        Add(compta, "Archives", [A(Alice, M)]);
        var rh = Add(root, "RH", [A(WellKnownSids.System, FA), A(WellKnownSids.Administrators, FA), A(DlRhRw, M)], prot: true, owner: Chloe);
        Add(rh, "Paie", unreadable: true);
        Add(root, "Direction", [A(WellKnownSids.System, FA), A(WellKnownSids.Administrators, FA), A(DlDirectionRw, M), A(Prestataire, FA), A(Orphan, RX)], prot: true);
        var com = Add(root, "Commercial", [A(DlCommercialRw, M), A(GlNiv1, R)]);
        Add(com, "Prospects", [A(WellKnownSids.Everyone, M)]);
        Add(com, "Contrats", [new AceInfo(AceKind.AllowCallback, GgCommercial, M, OICI, 9)]);
        var scan = Add(root, "Scan", [A(WellKnownSids.AuthenticatedUsers, M)]);
        var it = Add(root, "IT", [A(GgIt, FA), A(GgVide, R), A(Foreign, RX)]);
        Add(it, "Outils", [A(Gilles, M), Dn(Emma, FileRights.Delete)]);
        Add(it, "Lien vers archives", flags: NodeFlags.ReparsePoint);
        var projets = Add(root, "Projets", [A(DlCommunRw, RX)]);
        for (var i = 1; i <= generatedProjects; i++)
        {
            var p = Add(projets, $"Projet-{i:000}");
            Add(p, "Livrables");
            Add(p, "Sources", flags: i == 1 ? NodeFlags.DepthLimit : NodeFlags.None);
        }

        SecurityDescriptorInfo ShareSd(params AceInfo[] aces) { var s = new SecurityDescriptorInfo { Owner = WellKnownSids.Administrators, Control = SdControl.SelfRelative | SdControl.DaclPresent, Aces = aces }; return s with { Sddl = Sddl.Format(s) }; }
        var shares = new List<ShareInfo>
        {
            new() { Server = "FS01.contoso.local", Name = "Donnees", LocalPath = @"D:\Donnees", Kind = ShareKind.Disk, Security = ShareSd(A(WellKnownSids.Everyone, FileRights.ShareFull, 0)), RootFolderId = root },
            new() { Server = "FS01.contoso.local", Name = "Scan", LocalPath = @"D:\Donnees\Scan", Kind = ShareKind.Disk, Security = ShareSd(A(WellKnownSids.Everyone, FileRights.ShareFull, 0)), RootFolderId = scan, NestedIn = "Donnees" },
            new() { Server = "FS01.contoso.local", Name = "Archives", LocalPath = @"D:\Archives", Kind = ShareKind.Disk, Security = ShareSd(A(Orphan, FileRights.ShareFull, 0), A(Prestataire, FileRights.ShareFull, 0), A(Gilles, FileRights.ShareRead, 0), A(WellKnownSids.AuthenticatedUsers, FileRights.ShareChange, 0)) },
            new() { Server = "FS01.contoso.local", Name = "Compta$", LocalPath = @"D:\Donnees\Compta", Kind = ShareKind.Disk, SecurityError = "Accès refusé (5) : droits d'administrateur du serveur requis.", RootFolderId = compta, NestedIn = "Donnees" },
        };
        var errors = new List<CollectionError> { new("scan", @"\\FS01.contoso.local\Donnees\RH\Paie", 5, "Accès refusé (5) : ni la liste ni les autorisations ne sont lisibles avec le compte de collecte.") };
        return new AclSnapshot
        {
            Manifest = new SnapshotManifest
            {
                ToolVersion = "1.0.0", CreatedUtc = new DateTimeOffset(2026, 9, 25, 14, 0, 0, TimeSpan.Zero), RootPath = @"\\FS01.contoso.local\Donnees",
                Server = "FS01.contoso.local", ShareName = "Donnees", RootLocalPath = @"D:\Donnees",
                Domain = new DomainRef("contoso.local", "CONTOSO", D, "DC01.contoso.local"), CollectedBy = @"CONTOSO\audit", Machine = "ADMIN01",
                Options = new ScanOptions { MaxDepth = 3 }, DurationMs = 1900,
            },
            Folders = folders, Descriptors = sds, Principals = principals, Shares = shares, Errors = errors,
        };
    }
}
