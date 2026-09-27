using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.ACL.Rules;

/// <summary>Description d'une règle ACL-*.</summary>
public sealed record RuleDescriptor(string Id, Severity Severity, string Category, string Title, string Description, string Recommendation);

/// <summary>
/// Règles d'audit des ACL NTFS et des partages. Les constats portent sur les ACE explicites (là où le droit est
/// posé) pour ne pas répéter le même problème sur des milliers de sous-dossiers qui en héritent.
/// </summary>
public sealed class RuleEngine
{
    /// <summary>Nombre maximal d'éléments détaillés par constat (le total reste dans <see cref="Finding.Count"/>).</summary>
    public const int MaxItems = 500;

    /// <summary>Catalogue des règles.</summary>
    public static readonly IReadOnlyList<RuleDescriptor> Catalog =
    [
        new("ACL-001", Severity.Critical, "Sécurité", "DACL nulle", "Le dossier n'a pas de liste de contrôle d'accès : tout le monde y a tous les droits, y compris celui de modifier les autorisations.", "Rétablir une ACL (héritage du parent ou ACL explicite) immédiatement."),
        new("ACL-002", Severity.High, "Sécurité", "Écriture accordée à un groupe large", "Tout le monde, Utilisateurs authentifiés, Utilisateurs ou Utilisateurs du domaine peuvent écrire, supprimer ou modifier les autorisations. Tous les comptes du domaine (et un rançongiciel exécuté par n'importe lequel d'entre eux) peuvent altérer ces données.", "Remplacer par des groupes métiers (modèle AGDLP : GG_Métier → DL_Partage-Dossier_RW) et limiter les groupes larges à la lecture si nécessaire."),
        new("ACL-003", Severity.Medium, "Sécurité", "Contrôle total ou modification des autorisations pour un non-administrateur", "Une identité non administrative peut modifier les autorisations (WRITE_DAC) ou s'approprier le dossier (WRITE_OWNER) : elle peut s'accorder n'importe quel droit.", "Réserver le contrôle total aux administrateurs ; accorder « Modification » aux utilisateurs."),
        new("ACL-004", Severity.Low, "Conception", "Droit attribué directement à un utilisateur", "Un compte utilisateur est nommé dans l'ACL au lieu d'un groupe : les droits deviennent difficiles à auditer et persistent après un changement de poste.", "Passer par un groupe (AGDLP) puis retirer l'ACE nominative."),
        new("ACL-005", Severity.Medium, "Hygiène", "SID orphelin", "L'ACL contient un SID qui ne correspond plus à aucun compte ni groupe (objet supprimé). Il est inoffensif mais masque l'historique et peut être réattribué lors d'une restauration.", "Supprimer l'ACE orpheline après vérification."),
        new("ACL-006", Severity.Medium, "Sécurité", "Compte à privilèges nommé dans une ACL", "Un compte membre d'un groupe d'administration (ou protégé par AdminSDHolder) est cité nommément : c'est souvent un compte partagé ou de prestataire utilisé pour des accès courants.", "Utiliser des groupes dédiés et des comptes non privilégiés pour l'accès aux données."),
        new("ACL-007", Severity.Info, "Conception", "Héritage désactivé", "Le dossier n'hérite plus des autorisations de son parent : les droits posés plus haut ne s'y appliquent pas.", "Vérifier que la rupture d'héritage est voulue et documentée."),
        new("ACL-008", Severity.Info, "Conception", "Refus explicite", "Une ACE de refus est posée. Les refus compliquent l'analyse et l'emportent sur les autorisations héritées.", "Préférer l'absence d'autorisation à un refus, sauf besoin précis."),
        new("ACL-009", Severity.Medium, "Cohérence", "ACL non canonique", "L'ordre des ACE n'est pas celui de Windows (refus explicites, autorisations explicites, puis héritées). Le résultat réel peut différer de ce qu'affiche l'Explorateur.", "Réordonner l'ACL (l'Explorateur propose de le faire à l'ouverture de l'onglet Sécurité)."),
        new("ACL-010", Severity.High, "Collecte", "Dossier inaccessible", "Le dossier n'a pas pu être listé ou ses autorisations lues avec le compte de collecte. Les droits de cette branche sont inconnus.", "Relancer l'analyse en mode sauvegarde (Opérateurs de sauvegarde) — sans takeown — ou avec un compte habilité."),
        new("ACL-011", Severity.Low, "Conception", "Propriétaire non administrateur (haut de l'arborescence)", "Un compte utilisateur est propriétaire d'un dossier structurant : le propriétaire peut toujours modifier les autorisations.", "Réattribuer la propriété aux Administrateurs pour les dossiers de premier niveau."),
        new("ACL-012", Severity.Info, "Collecte", "ACE conditionnelle", "Une ACE conditionnelle (revendications, contrôle d'accès dynamique) est présente : l'accès effectif ne peut pas être calculé exactement hors ligne.", "Vérifier l'accès avec l'onglet « Accès effectif » de Windows."),
        new("ACL-020", Severity.High, "Sécurité", "Partage et NTFS ouverts à tous en écriture", "Le partage accorde Modifier ou Contrôle total à un groupe large ET le NTFS de sa racine accorde l'écriture à un groupe large : aucune barrière ne limite l'écriture.", "Restreindre le NTFS de la racine du partage à des groupes métiers."),
        new("ACL-021", Severity.Medium, "Hygiène", "SID orphelin dans les droits d'un partage", "Les droits de partage contiennent un SID non résolu (compte ou groupe supprimé).", "Nettoyer les droits de partage."),
        new("ACL-022", Severity.Info, "Conception", "Partage imbriqué", "Un partage est un sous-dossier d'un autre partage : le même dossier est accessible par deux chemins réseau avec des droits de partage différents.", "Vérifier que les droits de partage des deux chemins sont cohérents."),
        new("ACL-023", Severity.Low, "Conception", "Compte utilisateur dans les droits d'un partage", "Un compte utilisateur est nommé dans les droits de partage (au lieu d'un groupe).", "Utiliser des groupes ; pour un compte à privilèges ou partagé, supprimer l'entrée."),
        new("ACL-024", Severity.Info, "Collecte", "Droits de partage illisibles", "Les droits du partage n'ont pas pu être lus (droits d'administrateur du serveur requis) : l'accès réseau est calculé sans eux.", "Relancer avec un compte administrateur du serveur de fichiers."),
        new("ACL-030", Severity.Low, "Hygiène", "Groupe vide utilisé dans une ACL", "Un groupe sans membre accorde des droits : ACE inutile ou groupe en attente.", "Supprimer l'ACE ou alimenter le groupe."),
        new("ACL-031", Severity.Low, "Conception", "Imbrication de groupes profonde ou circulaire", "La chaîne d'imbrication compte 4 groupes ou plus ou forme une boucle : les accès réels deviennent difficiles à comprendre.", "Aplatir l'imbrication (AGDLP : un seul niveau GG → DL)."),
        new("ACL-032", Severity.Info, "Collecte", "Appartenance inconnue", "Les membres de ce groupe n'ont pas pu être lus (groupe local distant sans droits d'administration, groupe d'un autre domaine) : les accès passant par lui sont marqués « ambigus ».", "Relancer avec un compte habilité, ou vérifier manuellement."),
        new("ACL-040", Severity.Info, "Collecte", "Analyse incomplète", "L'analyse a été interrompue, limitée par la profondeur, ou a rencontré des erreurs.", "Consulter le journal de collecte ; augmenter la profondeur si nécessaire."),
    ];

    private readonly SnapshotIndex _index;
    private readonly TokenBuilder _tokens;
    private readonly Dictionary<string, bool> _privileged = new(StringComparer.OrdinalIgnoreCase);

    public RuleEngine(SnapshotIndex index, TokenBuilder tokens) { _index = index; _tokens = tokens; }

    /// <summary>Vrai si l'identité est administrative ou membre (même indirect) d'un groupe d'administration.</summary>
    public bool IsPrivileged(string sid)
    {
        if (_privileged.TryGetValue(sid, out var v)) return v;
        var p = _index.Principal(sid);
        v = WellKnownSids.IsAdministrative(sid) || p?.AdminCount == true;
        if (!v && p is not null && p.Kind is PrincipalKind.User or PrincipalKind.Group or PrincipalKind.Computer)
        {
            var t = _tokens.Build(sid);
            v = t.Sids.Any(s => s != sid && (s == WellKnownSids.Administrators || (Sid.DomainOf(s) is not null && Sid.Rid(s) is WellKnownSids.RidDomainAdmins or WellKnownSids.RidEnterpriseAdmins or WellKnownSids.RidSchemaAdmins)));
        }
        _privileged[sid] = v;
        return v;
    }

    private PrincipalKind KindOf(string sid) => _index.Principal(sid)?.Kind ?? WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown;

    private bool IsOrphan(string sid)
    {
        var p = _index.Principal(sid);
        return p?.Orphan == true || (p is null && Sid.DomainOf(sid) is not null && WellKnownSids.NameOf(sid) is null);
    }

    /// <summary>Exécute toutes les règles.</summary>
    public List<Finding> Run()
    {
        var acc = Catalog.ToDictionary(r => r.Id, _ => new List<FindingItem>());
        var counts = Catalog.ToDictionary(r => r.Id, _ => 0);
        void Add(string rule, FindingItem item) { counts[rule]++; if (acc[rule].Count < MaxItems) acc[rule].Add(item); }

        var usedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var id = 0; id < _index.Count; id++)
        {
            var f = _index.Folder(id);
            if ((f.Flags & (NodeFlags.ListDenied | NodeFlags.SecurityUnreadable)) != 0 && (f.Flags & NodeFlags.ReparsePoint) == 0)
                Add("ACL-010", new(id, null, null, (f.Flags & NodeFlags.SecurityUnreadable) != 0 ? "Autorisations illisibles" : "Contenu non listable"));
            var sd = _index.Descriptor(id);
            if (sd is null) continue;
            if (!sd.DaclPresent) { Add("ACL-001", new(id, null, null, "DACL nulle")); continue; }
            if (sd.Protected && id != 0) Add("ACL-007", new(id, null, null, "Héritage désactivé"));
            if (!AccessEngine.IsCanonical(sd)) Add("ACL-009", new(id, null, null, "Ordre des ACE non canonique"));
            if (sd.Owner is { } owner && _index.Depth(id) <= 2 && KindOf(owner) == PrincipalKind.User && !IsPrivileged(owner))
                Add("ACL-011", new(id, null, owner, "Propriétaire : " + _index.NameOf(owner)));
            foreach (var a in sd.Aces)
            {
                if (a.IsConditional) Add("ACL-012", new(id, null, a.Sid, "ACE conditionnelle pour " + _index.NameOf(a.Sid)));
                if (a.IsInherited || a.Kind == AceKind.Other) continue;
                var kind = KindOf(a.Sid);
                if (kind is PrincipalKind.Group or PrincipalKind.LocalGroup or PrincipalKind.Foreign) usedGroups.Add(a.Sid);
                var m = Rights.MapGeneric(a.Mask);
                var who = _index.NameOf(a.Sid);
                if (a.IsDeny) { Add("ACL-008", new(id, null, a.Sid, $"Refus : {who} — {Rights.Summary(a.Mask)}")); continue; }
                if (IsOrphan(a.Sid)) Add("ACL-005", new(id, null, a.Sid, $"SID orphelin {a.Sid} — {Rights.Summary(a.Mask)}"));
                if (WellKnownSids.IsBroad(a.Sid) && (m & FileRights.AnyWrite) != 0)
                    Add("ACL-002", new(id, null, a.Sid, $"{who} : {Rights.Summary(a.Mask)} ({Rights.AppliesTo(a.Flags)})"));
                else if ((m & (FileRights.WriteDac | FileRights.WriteOwner)) != 0 && !IsPrivileged(a.Sid) && !WellKnownSids.IsBroad(a.Sid) && a.Sid != WellKnownSids.CreatorOwner)
                    Add("ACL-003", new(id, null, a.Sid, $"{who} : {Rights.Summary(a.Mask)}"));
                if (kind == PrincipalKind.User)
                {
                    if (IsPrivileged(a.Sid)) Add("ACL-006", new(id, null, a.Sid, $"{who} (compte à privilèges) : {Rights.Summary(a.Mask)}"));
                    else Add("ACL-004", new(id, null, a.Sid, $"{who} : {Rights.Summary(a.Mask)}"));
                }
            }
        }

        foreach (var s in _index.Snapshot.Shares)
        {
            if (s.NestedIn is not null) Add("ACL-022", new(s.RootFolderId, s.Name, null, $"{s.Unc} est inclus dans le partage {s.NestedIn}"));
            if (s.Security is null) { if (s.Kind == ShareKind.Disk && !s.Special) Add("ACL-024", new(s.RootFolderId, s.Name, null, s.SecurityError ?? "Droits illisibles")); continue; }
            var broadWriteShare = false;
            foreach (var a in s.Security.Aces.Where(a => a.IsAllow))
            {
                if (IsOrphan(a.Sid)) Add("ACL-021", new(s.RootFolderId, s.Name, a.Sid, $"{s.Name} : SID orphelin {a.Sid}"));
                if (KindOf(a.Sid) == PrincipalKind.User)
                    Add(IsPrivileged(a.Sid) ? "ACL-006" : "ACL-023", new(s.RootFolderId, s.Name, a.Sid, $"Partage {s.Name} : {_index.NameOf(a.Sid)} — {Rights.ShareLabel(a.Mask)}"));
                if (WellKnownSids.IsBroad(a.Sid) && (Rights.MapGeneric(a.Mask) & (FileRights.AddFile | FileRights.Delete)) != 0) broadWriteShare = true;
            }
            if (broadWriteShare && s.RootFolderId is int root && _index.Descriptor(root) is { } rsd
                && rsd.Aces.Any(a => a.IsAllow && !a.IsInheritOnly && WellKnownSids.IsBroad(a.Sid) && (Rights.MapGeneric(a.Mask) & (FileRights.AddFile | FileRights.AddSubdirectory | FileRights.Delete)) != 0))
                Add("ACL-020", new(root, s.Name, null, $"{s.Unc} : partage et NTFS de la racine ouverts en écriture à un groupe large"));
        }

        foreach (var g in usedGroups)
        {
            var p = _index.Principal(g);
            if (p is null) continue;
            if (p.Members is null) { Add("ACL-032", new(null, null, g, $"{p.Name} : {p.MembersError ?? "membres non lus"}")); continue; }
            if (p.Members.Count == 0 && WellKnownSids.KindOf(g) is null && Sid.Rid(g) is not (WellKnownSids.RidDomainUsers or WellKnownSids.RidDomainComputers))
                Add("ACL-030", new(null, null, g, $"{p.Name} n'a aucun membre"));
            var depth = NestingDepth(g, [], out var cycle);
            if (cycle) Add("ACL-031", new(null, null, g, $"{p.Name} : boucle d'imbrication"));
            else if (depth >= 3) Add("ACL-031", new(null, null, g, $"{p.Name} : chaîne de {depth + 1} groupes imbriqués"));
        }

        var m0 = _index.Snapshot.Manifest;
        var depthLimited = _index.Snapshot.Folders.Count(f => (f.Flags & NodeFlags.DepthLimit) != 0);
        if (m0.Truncated) Add("ACL-040", new(null, null, null, "Analyse interrompue avant la fin (annulation ou limite de nœuds)"));
        if (depthLimited > 0) Add("ACL-040", new(null, null, null, $"{depthLimited} dossier(s) au-delà de la profondeur maximale ({m0.Options.MaxDepth}) non analysés"));
        if (_index.Snapshot.Errors.Count > 0) Add("ACL-040", new(null, null, null, $"{_index.Snapshot.Errors.Count} erreur(s) de collecte (voir le journal)"));

        return Catalog.Where(r => counts[r.Id] > 0).Select(r => new Finding
        {
            RuleId = r.Id, Severity = r.Severity, Category = r.Category, Title = r.Title, Description = r.Description,
            Recommendation = r.Recommendation, Count = counts[r.Id], Items = acc[r.Id],
        }).OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId).ToList();
    }

    /// <summary>Profondeur maximale d'imbrication sous un groupe (membres groupes), avec détection de boucle.</summary>
    public int NestingDepth(string group, HashSet<string> stack, out bool cycle)
    {
        cycle = false;
        var p = _index.Principal(group);
        if (p?.Members is null) return 0;
        if (!stack.Add(group)) { cycle = true; return 0; }
        var max = 0;
        foreach (var m in p.Members)
        {
            var mp = _index.Principal(m);
            if (mp?.Kind is not (PrincipalKind.Group or PrincipalKind.LocalGroup)) continue;
            var d = NestingDepth(m, stack, out var c) + 1;
            if (c) { cycle = true; stack.Remove(group); return d; }
            max = Math.Max(max, d);
            if (max > 20) break;
        }
        stack.Remove(group);
        return max;
    }
}
