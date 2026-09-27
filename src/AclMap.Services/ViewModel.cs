using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Services;

/// <summary>Résumé d'un descripteur pour les filtres de l'arbre.</summary>
public sealed record SdSummary(int Id, bool Protected, int Explicit, bool Deny, bool Orphan, bool NullDacl, bool NonCanonical, string? Owner);

/// <summary>Identité pour les listes de l'interface.</summary>
public sealed record PrincipalRow
{
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Scope { get; init; } = "";
    public string? DisplayName { get; init; }
    public string? Dn { get; init; }
    public string? Description { get; init; }
    public bool Disabled { get; init; }
    public bool Orphan { get; init; }
    public bool Privileged { get; init; }
    public int? MemberCount { get; init; }
    public bool MembersKnown { get; init; }
    public int ExplicitFolders { get; init; }
}

/// <summary>ACE décodée pour l'affichage.</summary>
public sealed record AceRow(int Index, string Kind, string Sid, string Name, string PrincipalKind, string Mask, string Level, string Rights, List<string> Details,
    string AppliesTo, bool Inherited, bool InheritOnly, string? OriginPath, int? OriginFolderId, bool Orphan, string Sddl);

/// <summary>Partage pour l'affichage.</summary>
public sealed record ShareRow(string Name, string Unc, string? LocalPath, string Kind, bool Special, string? Remark, int? RootFolderId, string? NestedIn,
    bool RightsKnown, string? RightsError, List<AceRow> Aces, string? Sddl);

/// <summary>Données envoyées au visualiseur à l'ouverture d'un instantané.</summary>
public sealed record SnapshotView
{
    public SnapshotManifest Manifest { get; init; } = new();
    public string? FilePath { get; init; }
    public IReadOnlyList<FolderNode> Folders { get; init; } = [];
    public IReadOnlyList<SdSummary> Descriptors { get; init; } = [];
    public IReadOnlyList<PrincipalRow> Principals { get; init; } = [];
    public IReadOnlyList<ShareRow> Shares { get; init; } = [];
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public IReadOnlyList<AccessPathOption> AccessPaths { get; init; } = [];
    public string DefaultAccessPath { get; init; } = "ntfs";
    public IReadOnlyList<CollectionError> Errors { get; init; } = [];
    public Dictionary<string, int> Stats { get; init; } = [];
}

/// <summary>Détail d'un dossier.</summary>
public sealed record FolderDetail(int Id, string Path, string Name, int Flags, NamedSid? Owner, bool Protected, bool DaclPresent, bool Canonical, string? Sddl,
    List<AceRow> Aces, int Children, int Descendants, List<string> ShareRoots, List<FindingRef> Findings);

public sealed record FindingRef(string RuleId, string Severity, string Title, string Detail);

/// <summary>Détail d'une identité.</summary>
public sealed record PrincipalDetail(PrincipalRow Info, List<PrincipalRow> Members, string? MembersError, List<PrincipalRow> Parents, List<NamedSid> AllGroups,
    int TransitiveUsers, List<PrincipalRow> TransitiveUserSample, List<ExplicitAceRef> Aces, int AceTotal, int NestingDepth, bool NestingCycle, List<FindingRef> Findings, List<string> Notes);

public sealed record ExplicitAceRef(int FolderId, string Path, string Rights, string Level, bool Deny, bool InheritOnly, string AppliesTo);

/// <summary>Construit les vues envoyées à l'interface.</summary>
public static class ViewModel
{
    /// <summary>Vue complète d'un instantané.</summary>
    public static SnapshotView Build(AnalysisSession s)
    {
        var idx = s.Index;
        var snap = idx.Snapshot;
        var sds = snap.Descriptors.Select(d => new SdSummary(d.Id, d.Protected, d.Aces.Count(a => !a.IsInherited), d.Aces.Any(a => a.IsDeny),
            d.Aces.Any(a => IsOrphan(s, a.Sid)), !d.DaclPresent, !AccessEngine.IsCanonical(d), d.Owner)).ToList();
        var principals = idx.Principals.Select(p => Row(s, p)).OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        // identités présentes dans les ACL mais inconnues de la collecte
        var known = principals.Select(p => p.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var sid in s.SidsWithExplicitAces.Where(x => !known.Contains(x)))
            principals.Add(Row(s, new PrincipalInfo { Sid = sid, Name = idx.NameOf(sid), Kind = WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown, Orphan = IsOrphan(s, sid) }));
        var folders = snap.Folders;
        var stats = new Dictionary<string, int>
        {
            ["folders"] = folders.Count(f => (f.Flags & NodeFlags.File) == 0),
            ["files"] = folders.Count(f => (f.Flags & NodeFlags.File) != 0),
            ["descriptors"] = snap.Descriptors.Count,
            ["protected"] = folders.Count(f => f.Id > 0 && idx.Descriptor(f.Id)?.Protected == true),
            ["explicitAces"] = folders.Sum(f => idx.Descriptor(f.Id)?.Aces.Count(a => !a.IsInherited) ?? 0),
            ["foldersWithExplicit"] = folders.Count(f => idx.Descriptor(f.Id)?.Aces.Any(a => !a.IsInherited) == true),
            ["inaccessible"] = folders.Count(f => (f.Flags & (NodeFlags.ListDenied | NodeFlags.SecurityUnreadable)) != 0),
            ["principals"] = principals.Count,
            ["groups"] = principals.Count(p => p.Kind is "Group" or "LocalGroup"),
            ["users"] = principals.Count(p => p.Kind == "User"),
            ["orphans"] = principals.Count(p => p.Orphan),
            ["shares"] = snap.Shares.Count(x => x.Kind == ShareKind.Disk),
            ["errors"] = snap.Errors.Count,
            ["reparse"] = folders.Count(f => (f.Flags & NodeFlags.ReparsePoint) != 0),
            ["maxDepth"] = idx.Count == 0 ? 0 : Enumerable.Range(0, idx.Count).Max(idx.Depth),
        };
        return new SnapshotView
        {
            Manifest = snap.Manifest, FilePath = s.FilePath, Folders = folders, Descriptors = sds, Principals = principals,
            Shares = snap.Shares.Select(x => Share(s, x)).ToList(), Findings = s.Findings, AccessPaths = s.AccessPaths(),
            DefaultAccessPath = s.DefaultAccessPath(), Errors = snap.Errors.Take(2000).ToList(), Stats = stats,
        };
    }

    private static bool IsOrphan(AnalysisSession s, string sid)
    {
        var p = s.Index.Principal(sid);
        return p?.Orphan == true || (p is null && Sid.DomainOf(sid) is not null && WellKnownSids.NameOf(sid) is null);
    }

    /// <summary>Ligne d'identité.</summary>
    public static PrincipalRow Row(AnalysisSession s, PrincipalInfo p) => new()
    {
        Sid = p.Sid, Name = string.IsNullOrEmpty(p.Name) ? s.Index.NameOf(p.Sid) : p.Name, Kind = p.Kind.ToString(), Scope = p.Scope.ToString(),
        DisplayName = p.DisplayName, Dn = p.DistinguishedName, Description = p.Description, Disabled = p.Disabled == true, Orphan = p.Orphan || IsOrphan(s, p.Sid),
        Privileged = !p.Orphan && s.Rules.IsPrivileged(p.Sid), MemberCount = p.Members?.Count, MembersKnown = p.Members is not null,
        ExplicitFolders = s.ExplicitAces(p.Sid).Select(x => x.Folder).Distinct().Count(),
    };

    /// <summary>Ligne d'ACE (avec origine pour une ACE héritée si <paramref name="folderId"/> est fourni).</summary>
    public static AceRow Ace(AnalysisSession s, int index, AceInfo a, int? folderId, bool share = false)
    {
        string? origin = null; int? originId = null;
        if (folderId is int f && a.IsInherited)
        {
            var o = InheritanceTracer.Find(s.Index, f, a);
            originId = o.FolderId;
            origin = o.FolderId is int oid ? s.Index.FullPath(oid) + (o.Certain ? "" : " (probable)") : "au-dessus de la racine analysée";
        }
        var kind = a.Kind switch { AceKind.Allow => "Autoriser", AceKind.Deny => "Refuser", AceKind.AllowCallback => "Autoriser (conditionnelle)", AceKind.DenyCallback => "Refuser (conditionnelle)", _ => "Autre" };
        return new AceRow(index, kind, a.Sid, s.Index.NameOf(a.Sid), s.KindName(a.Sid), "0x" + a.Mask.ToString("x8"), share ? Rights.ShareLabel(a.Mask) : Rights.LevelLabel(Rights.LevelOf(a.Mask)),
            share ? Rights.ShareLabel(a.Mask) : Rights.Summary(a.Mask), Rights.Describe(a.Mask).ToList(), share ? "Partage" : Rights.AppliesTo(a.Flags), a.IsInherited, a.IsInheritOnly,
            origin, originId, IsOrphan(s, a.Sid), Sddl.FormatAce(a));
    }

    private static ShareRow Share(AnalysisSession s, ShareInfo x) => new(x.Name, x.Unc, x.LocalPath, x.Kind.ToString(), x.Special, x.Remark, x.RootFolderId, x.NestedIn,
        x.Security is not null, x.SecurityError, x.Security?.Aces.Select((a, i) => Ace(s, i, a, null, share: true)).ToList() ?? [], x.Security?.Sddl);

    /// <summary>Détail d'un dossier.</summary>
    public static FolderDetail Folder(AnalysisSession s, int id)
    {
        var idx = s.Index;
        if (id < 0 || id >= idx.Count) throw new ArgumentOutOfRangeException(nameof(id));
        var f = idx.Folder(id);
        var sd = idx.Descriptor(id);
        var shares = idx.Snapshot.Shares.Where(x => x.RootFolderId == id).Select(x => x.Unc).ToList();
        var findings = s.Findings.SelectMany(fi => fi.Items.Where(i => i.FolderId == id).Select(i => new FindingRef(fi.RuleId, fi.Severity.ToString(), fi.Title, i.Detail))).ToList();
        return new FolderDetail(id, idx.FullPath(id), f.Name, (int)f.Flags,
            sd?.Owner is null ? null : new NamedSid(sd.Owner, idx.NameOf(sd.Owner), s.KindName(sd.Owner)), sd?.Protected == true, sd?.DaclPresent ?? true,
            sd is null || AccessEngine.IsCanonical(sd), sd?.Sddl, sd?.Aces.Select((a, i) => Ace(s, i, a, id)).ToList() ?? [],
            idx.Children(id).Count, idx.Descendants(id).Count(), shares, findings);
    }

    /// <summary>Détail d'une identité.</summary>
    public static PrincipalDetail Principal(AnalysisSession s, string sid)
    {
        var idx = s.Index;
        var p = idx.Principal(sid) ?? new PrincipalInfo { Sid = sid, Name = idx.NameOf(sid), Kind = WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown, Orphan = IsOrphan(s, sid) };
        var members = p.Members?.Select(m => Row(s, idx.Principal(m) ?? new PrincipalInfo { Sid = m, Name = idx.NameOf(m), Kind = WellKnownSids.KindOf(m) ?? PrincipalKind.Unknown }))
            .OrderBy(r => r.Kind).ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList() ?? [];
        var parents = s.Tokens.DirectParents(sid).Select(g => Row(s, idx.Principal(g)!)).OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var token = s.Tokens.Build(sid);
        var all = token.Sids.Where(x => x != sid).Select(x => new NamedSid(x, idx.NameOf(x), s.KindName(x))).OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        // utilisateurs membres (transitifs)
        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { sid };
        var q = new Queue<string>([sid]);
        while (q.Count > 0)
        {
            var g = q.Dequeue();
            foreach (var m in idx.Principal(g)?.Members ?? [])
            {
                var mp = idx.Principal(m);
                if (mp?.Kind is PrincipalKind.User) users.Add(m);
                if (mp?.Kind is PrincipalKind.Group or PrincipalKind.LocalGroup or PrincipalKind.WellKnown && seen.Add(m)) q.Enqueue(m);
            }
        }
        var aces = s.ExplicitAces(sid);
        var depth = s.Rules.NestingDepth(sid, [], out var cycle);
        var findings = s.Findings.SelectMany(fi => fi.Items.Where(i => string.Equals(i.Sid, sid, StringComparison.OrdinalIgnoreCase)).Select(i => new FindingRef(fi.RuleId, fi.Severity.ToString(), fi.Title, i.Detail))).Take(200).ToList();
        return new PrincipalDetail(Row(s, p), members, p.MembersError, parents, all, users.Count,
            users.Take(500).Select(u => Row(s, idx.Principal(u)!)).OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList(),
            aces.Take(1000).Select(x => new ExplicitAceRef(x.Folder, idx.FullPath(x.Folder), Rights.Summary(x.Ace.Mask), Rights.LevelLabel(Rights.LevelOf(x.Ace.Mask)), x.Ace.IsDeny, x.Ace.IsInheritOnly, Rights.AppliesTo(x.Ace.Flags))).ToList(),
            aces.Count, depth, cycle, findings, token.Notes);
    }
}
