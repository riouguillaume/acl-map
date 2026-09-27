using AclMap.ACL.Access;
using AclMap.ACL.Rules;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Services;

/// <summary>Chemin d'accès proposé pour la carte de droits : NTFS seul, ou via un partage.</summary>
/// <param name="Id">« ntfs » ou nom du partage.</param>
/// <param name="Label">Libellé.</param>
/// <param name="RootFolderId">Racine du partage dans l'instantané.</param>
/// <param name="ShareRightsKnown">Droits du partage lus.</param>
public sealed record AccessPathOption(string Id, string Label, int? RootFolderId, bool ShareRightsKnown);

/// <summary>
/// Instantané chargé et prêt à l'analyse : index, jetons, constats, caches d'accès. Toutes les requêtes de
/// l'interface (carte de droits, explication, « qui a accès ») passent par cette classe.
/// </summary>
public sealed class AnalysisSession
{
    private readonly Dictionary<string, List<(int Folder, AceInfo Ace)>> _explicitBySid = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string, int), AccessResult> _sdCache = [];

    public SnapshotIndex Index { get; }
    public TokenBuilder Tokens { get; }
    public RuleEngine Rules { get; }
    public IReadOnlyList<Finding> Findings { get; }
    public string? FilePath { get; }

    /// <summary>Charge l'instantané et exécute les règles.</summary>
    public AnalysisSession(AclSnapshot snapshot, string? filePath = null)
    {
        Index = new SnapshotIndex(snapshot);
        Tokens = new TokenBuilder(Index);
        Rules = new RuleEngine(Index, Tokens);
        Findings = Rules.Run();
        FilePath = filePath;
        for (var id = 0; id < Index.Count; id++)
        {
            var sd = Index.Descriptor(id);
            if (sd is null) continue;
            foreach (var a in sd.Aces.Where(a => !a.IsInherited && a.Kind != AceKind.Other))
            {
                if (!_explicitBySid.TryGetValue(a.Sid, out var l)) _explicitBySid[a.Sid] = l = [];
                l.Add((id, a));
            }
        }
    }

    /// <summary>Charge un fichier .aclmap.</summary>
    public static AnalysisSession Open(string path) => new(SnapshotArchive.Load(path), path);

    /// <summary>Dossiers où l'identité a une ACE explicite.</summary>
    public IReadOnlyList<(int Folder, AceInfo Ace)> ExplicitAces(string sid) => _explicitBySid.TryGetValue(sid, out var l) ? l : [];

    /// <summary>Identités ayant au moins une ACE explicite.</summary>
    public IEnumerable<string> SidsWithExplicitAces => _explicitBySid.Keys;

    /// <summary>Chemins d'accès proposés.</summary>
    public IReadOnlyList<AccessPathOption> AccessPaths()
    {
        var list = new List<AccessPathOption> { new("ntfs", "NTFS seul (accès local ou droits de partage ignorés)", 0, true) };
        foreach (var s in Index.Snapshot.Shares.Where(s => s.Kind == ShareKind.Disk && s.RootFolderId is not null).OrderBy(s => s.RootFolderId))
            list.Add(new(s.Name, $"Via le partage {s.Unc}", s.RootFolderId, s.Security is not null));
        return list;
    }

    /// <summary>Chemin d'accès par défaut : le partage analysé s'il est connu, sinon NTFS seul.</summary>
    public string DefaultAccessPath()
    {
        var m = Index.Snapshot.Manifest.ShareName;
        return m is not null && Index.Snapshot.Shares.Any(s => s.Name.Equals(m, StringComparison.OrdinalIgnoreCase) && s.RootFolderId is not null) ? m : "ntfs";
    }

    private ShareInfo? ShareFor(string? pathId) =>
        pathId is null or "ntfs" ? null : Index.Snapshot.Shares.FirstOrDefault(s => s.Name.Equals(pathId, StringComparison.OrdinalIgnoreCase) && s.RootFolderId is not null)
        ?? throw new ArgumentException($"Partage inconnu dans cet instantané : {pathId}");

    private AccessResult Ntfs(int folderId, Token t)
    {
        var sdId = Index.Folder(folderId).SdId;
        if (sdId < 0) return AccessResult.Unknown;
        var key = (t.PrincipalSid + (t.Sids.Contains(WellKnownSids.Everyone) ? "+i" : ""), sdId);
        if (_sdCache.TryGetValue(key, out var r)) return r;
        r = AccessEngine.Evaluate(Index.DescriptorById(sdId), t);
        if (_sdCache.Count > 2_000_000) _sdCache.Clear();
        _sdCache[key] = r;
        return r;
    }

    private static AccessResult ShareAccess(ShareInfo s, Token t) => s.Security is null ? AccessResult.Unknown : AccessEngine.Evaluate(s.Security, t);

    /// <summary>Carte de droits d'une identité : niveau et précisions pour chaque dossier.</summary>
    public AccessMap ComputeMap(string sid, string? accessPath, bool includeImplicitForGroup = false)
    {
        var t = Tokens.Build(sid, includeImplicitForGroup);
        var share = ShareFor(accessPath);
        var n = Index.Count;
        var levels = new byte[n];
        var flags = new byte[n];
        HashSet<int>? inside = null;
        AccessResult shareResult = default;
        if (share is not null)
        {
            inside = [share.RootFolderId!.Value, .. Index.Descendants(share.RootFolderId.Value)];
            shareResult = ShareAccess(share, t);
        }
        var counts = new int[8];
        int ambiguous = 0, denied = 0, canChange = 0, unknown = 0;
        for (var i = 0; i < n; i++)
        {
            if (inside is not null && !inside.Contains(i)) { flags[i] = (byte)AccessFlags.OutsideShare; continue; }
            var r = Ntfs(i, t);
            if (share is not null) r = AccessEngine.Combine(r, shareResult);
            levels[i] = (byte)r.Level;
            flags[i] = (byte)r.Flags;
            counts[(int)r.Level]++;
            if ((r.Flags & AccessFlags.Ambiguous) != 0) ambiguous++;
            if ((r.Flags & AccessFlags.Denied) != 0) denied++;
            if ((r.Flags & AccessFlags.CanChangePermissions) != 0) canChange++;
            if ((r.Flags & AccessFlags.Unknown) != 0) unknown++;
        }
        var notes = new List<string>(t.Notes);
        if (share?.Security is null && share is not null) notes.Add("Droits du partage illisibles : l'accès réseau est calculé avec le NTFS seul (marqué ambigu).");
        if (t.GroupMode && !includeImplicitForGroup) notes.Add("Mode groupe : seuls les droits accordés via ce groupe (et ses groupes parents) sont comptés.");
        return new AccessMap
        {
            Sid = sid, Name = Index.NameOf(sid), GroupMode = t.GroupMode, AccessPath = accessPath ?? "ntfs",
            Levels = Convert.ToBase64String(levels), Flags = Convert.ToBase64String(flags),
            Counts = counts, Ambiguous = ambiguous, Denied = denied, CanChangePermissions = canChange, Unknown = unknown,
            ShareLevel = share is null ? null : Rights.LevelLabel(shareResult.Level),
            Groups = t.Sids.Where(s => s != sid).Select(s => new NamedSid(s, Index.NameOf(s), KindName(s))).OrderBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase).ToList(),
            Notes = notes,
        };
    }

    /// <summary>Explication détaillée de l'accès d'une identité à un dossier.</summary>
    public Explanation Explain(string sid, int folderId, string? accessPath, bool includeImplicitForGroup = false)
    {
        if (folderId < 0 || folderId >= Index.Count) throw new ArgumentOutOfRangeException(nameof(folderId));
        var t = Tokens.Build(sid, includeImplicitForGroup);
        var sd = Index.Descriptor(folderId);
        var contribs = new List<AceContribution>();
        var ntfs = AccessEngine.Evaluate(sd, t, contribs);
        var share = ShareFor(accessPath);
        var shareContribs = new List<AceContribution>();
        AccessResult? shareRes = null;
        var outside = false;
        if (share is not null)
        {
            outside = folderId != share.RootFolderId && !IsUnder(folderId, share.RootFolderId!.Value);
            shareRes = share.Security is null ? AccessResult.Unknown : AccessEngine.Evaluate(share.Security, t, shareContribs);
        }
        var final = share is null ? ntfs : outside ? new AccessResult(0, 0, AccessLevel.None, AccessFlags.OutsideShare) : AccessEngine.Combine(ntfs, shareRes!.Value);
        return new Explanation
        {
            Sid = sid, Name = Index.NameOf(sid), FolderId = folderId, Path = Index.FullPath(folderId),
            Ntfs = Describe(ntfs), Share = shareRes is null ? null : Describe(shareRes.Value), Final = Describe(final),
            ShareName = share?.Name, OutsideShare = outside,
            Owner = sd?.Owner is null ? null : new NamedSid(sd.Owner, Index.NameOf(sd.Owner), KindName(sd.Owner)),
            OwnerIsPrincipal = sd?.Owner is not null && t.Contains(sd.Owner),
            Aces = contribs.Select(c => ToRow(folderId, c)).ToList(),
            ShareAces = shareContribs.Select(c => ToRow(null, c)).ToList(),
            Notes = t.Notes,
        };
    }

    private bool IsUnder(int id, int root) { for (var p = Index.Parent(id); p >= 0; p = Index.Parent(p)) if (p == root) return true; return false; }

    private static ResultDto Describe(AccessResult r) => new(Rights.LevelLabel(r.Level), (int)r.Level, (int)r.Flags,
        Rights.Describe(r.Granted).ToList(), Rights.Describe(r.Denied).ToList());

    private ExplainRow ToRow(int? folderId, AceContribution c)
    {
        int? origin = null; var certain = true;
        if (folderId is int f && c.Ace.IsInherited) { var o = InheritanceTracer.Find(Index, f, c.Ace); origin = o.FolderId; certain = o.Certain; }
        return new ExplainRow
        {
            Index = c.Index, Sid = c.Ace.Sid, Name = Index.NameOf(c.Ace.Sid), Kind = c.Ace.Kind.ToString(),
            Rights = folderId is null ? Rights.ShareLabel(c.Ace.Mask) : Rights.Summary(c.Ace.Mask), AppliesTo = Rights.AppliesTo(c.Ace.Flags),
            Inherited = c.Ace.IsInherited, OriginFolderId = origin, OriginPath = origin is int o2 ? Index.FullPath(o2) : (c.Ace.IsInherited ? "au-dessus de la racine analysée" : null),
            OriginCertain = certain, Effect = c.Effect.ToString(), Bits = Rights.Describe(c.Bits).ToList(), Note = c.Note,
            Path = c.MembershipPath.Select(s => s == Token.Implicit ? new NamedSid(s, "(SID implicite du jeton réseau)", "implicit") : new NamedSid(s, Index.NameOf(s), KindName(s))).ToList(),
        };
    }

    /// <summary>Libellé de nature d'une identité.</summary>
    public string KindName(string sid) => (Index.Principal(sid)?.Kind ?? WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown).ToString();

    /// <summary>Graphe « identité → groupes → dossiers » des droits posés explicitement.</summary>
    public PrincipalGraph Graph(string sid, int maxFolders = 120, bool includeImplicitForGroup = false)
    {
        var t = Tokens.Build(sid, includeImplicitForGroup);
        var nodes = new Dictionary<string, GraphNode>();
        var edges = new List<GraphEdge>();
        nodes[sid] = new GraphNode(sid, Index.NameOf(sid), "principal", KindName(sid), null);
        var bearing = t.Sids.Where(s => ExplicitAces(s).Count > 0).ToList();
        var needed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in bearing) foreach (var p in t.PathTo(s)) needed.Add(p);
        foreach (var s in needed)
        {
            if (s == sid) continue;
            nodes[s] = new GraphNode(s, s == Token.Implicit ? "Jeton réseau (SID implicites)" : Index.NameOf(s), s == Token.Implicit ? "implicit" : "group", s == Token.Implicit ? "implicit" : KindName(s), null);
        }
        foreach (var s in needed)
        {
            if (s == Token.Implicit) { edges.Add(new GraphEdge(sid, s, "jeton réseau", "member")); continue; }
            if (!t.Via.TryGetValue(s, out var via) || via is null) continue;
            edges.Add(new GraphEdge(via, s, "membre de", "member"));
        }
        var folderAces = bearing.SelectMany(s => ExplicitAces(s).Select(x => (Sid: s, x.Folder, x.Ace)))
            .OrderBy(x => Index.Depth(x.Folder)).ThenBy(x => x.Folder).ToList();
        var folders = folderAces.Select(x => x.Folder).Distinct().Take(maxFolders).ToHashSet();
        foreach (var x in folderAces.Where(x => folders.Contains(x.Folder)))
        {
            var fid = "F" + x.Folder;
            if (!nodes.ContainsKey(fid)) nodes[fid] = new GraphNode(fid, x.Folder == 0 ? Index.FullPath(0) : Index.Folder(x.Folder).Name, "folder", "folder", x.Folder);
            edges.Add(new GraphEdge(x.Sid, fid, (x.Ace.IsDeny ? "Refus : " : "") + Rights.Summary(x.Ace.Mask), x.Ace.IsDeny ? "deny" : x.Ace.IsInheritOnly ? "inheritOnly" : "allow"));
        }
        return new PrincipalGraph(nodes.Values.ToList(), edges, folderAces.Select(x => x.Folder).Distinct().Count(), folders.Count);
    }

    /// <summary>« Qui a accès à ce dossier ? » : utilisateurs connus de l'instantané et leur niveau effectif.</summary>
    public WhoHasAccess WhoHasAccess(int folderId, string? accessPath, int maxUsers = 5000)
    {
        var share = ShareFor(accessPath);
        var users = Index.Principals.Where(p => p.Kind is PrincipalKind.User && !p.Orphan).Take(maxUsers).ToList();
        var rows = new List<AccessRow>();
        foreach (var u in users)
        {
            var t = Tokens.Build(u.Sid);
            var r = Ntfs(folderId, t);
            if (share is not null) r = AccessEngine.Combine(r, ShareAccess(share, t));
            if (r.Level == AccessLevel.None && (r.Flags & AccessFlags.Ambiguous) == 0) continue;
            rows.Add(new AccessRow(u.Sid, u.Name, u.DisplayName, u.Disabled == true, (int)r.Level, Rights.LevelLabel(r.Level), (int)r.Flags, Rules.IsPrivileged(u.Sid)));
        }
        var sd = Index.Descriptor(folderId);
        var entries = sd?.Aces.Where(a => a.Kind != AceKind.Other && !a.IsInheritOnly).Select(a => new AclEntrySummary(a.Sid, Index.NameOf(a.Sid), KindName(a.Sid), a.IsDeny, Rights.Summary(a.Mask),
            Index.Principal(a.Sid)?.Members is { } mem ? mem.Count : null)).ToList() ?? [];
        var broad = sd?.Aces.Any(a => a.IsAllow && !a.IsInheritOnly && WellKnownSids.IsBroad(a.Sid)) == true;
        return new WhoHasAccess(folderId, Index.FullPath(folderId), rows.OrderByDescending(r => r.Level).ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList(),
            entries, users.Count, broad);
    }
}
