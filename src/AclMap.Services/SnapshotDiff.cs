using AclMap.Core.Security;
using AclMap.Models.Security;

namespace AclMap.Services;

/// <summary>Changement d'ACL sur un dossier présent dans les deux instantanés.</summary>
public sealed record FolderChange(string Path, int? FolderId, List<string> Added, List<string> Removed, bool? ProtectionChanged, string? OwnerBefore, string? OwnerAfter);

/// <summary>Résultat de la comparaison de deux instantanés.</summary>
public sealed record DiffResult
{
    public string OldCreated { get; init; } = "";
    public string NewCreated { get; init; } = "";
    public string OldRoot { get; init; } = "";
    public string NewRoot { get; init; } = "";
    public bool SameRoot { get; init; }
    public int AddedCount { get; init; }
    public int RemovedCount { get; init; }
    public int ChangedCount { get; init; }
    public List<string> AddedFolders { get; init; } = [];
    public List<string> RemovedFolders { get; init; } = [];
    public List<FolderChange> Changed { get; init; } = [];
    public List<string> ShareChanges { get; init; } = [];
    public List<string> NewFindings { get; init; } = [];
    public List<string> ResolvedFindings { get; init; } = [];
}

/// <summary>Compare deux instantanés (par chemin relatif, ACE explicites, héritage et propriétaire).</summary>
public static class SnapshotDiff
{
    private const int MaxList = 2000;

    public static DiffResult Compare(AnalysisSession older, AnalysisSession newer)
    {
        var o = older.Index; var n = newer.Index;
        var oldPaths = Enumerable.Range(0, o.Count).ToDictionary(o.RelativePath, i => i, StringComparer.OrdinalIgnoreCase);
        var newPaths = Enumerable.Range(0, n.Count).ToDictionary(n.RelativePath, i => i, StringComparer.OrdinalIgnoreCase);
        var added = newPaths.Keys.Where(k => !oldPaths.ContainsKey(k)).OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();
        var removed = oldPaths.Keys.Where(k => !newPaths.ContainsKey(k)).OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();
        var changed = new List<FolderChange>();
        var changedCount = 0;
        foreach (var (rel, ni) in newPaths.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!oldPaths.TryGetValue(rel, out var oi)) continue;
            var a = o.Descriptor(oi); var b = n.Descriptor(ni);
            if (a is null || b is null) continue;
            string Fmt(SnapshotIndexWrapper w, AceInfo x) => $"{(x.IsDeny ? "Refus" : "Autorisation")} {w.Name(x.Sid)} : {Rights.Summary(x.Mask)} ({Rights.AppliesTo(x.Flags)})";
            var ea = a.Aces.Where(x => !x.IsInherited).Select(Sddl.FormatAce).ToHashSet();
            var eb = b.Aces.Where(x => !x.IsInherited).Select(Sddl.FormatAce).ToHashSet();
            var add = b.Aces.Where(x => !x.IsInherited && !ea.Contains(Sddl.FormatAce(x))).Select(x => Fmt(new(n), x)).ToList();
            var rem = a.Aces.Where(x => !x.IsInherited && !eb.Contains(Sddl.FormatAce(x))).Select(x => Fmt(new(o), x)).ToList();
            var prot = a.Protected != b.Protected ? b.Protected : (bool?)null;
            var owner = !string.Equals(a.Owner, b.Owner, StringComparison.OrdinalIgnoreCase);
            if (add.Count == 0 && rem.Count == 0 && prot is null && !owner) continue;
            changedCount++;
            if (changed.Count < MaxList)
                changed.Add(new FolderChange(n.FullPath(ni), ni, add, rem, prot, owner && a.Owner is not null ? o.NameOf(a.Owner) : null, owner && b.Owner is not null ? n.NameOf(b.Owner) : null));
        }
        var shareChanges = new List<string>();
        var os = older.Index.Snapshot.Shares.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        var ns = newer.Index.Snapshot.Shares.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var k in ns.Keys.Except(os.Keys, StringComparer.OrdinalIgnoreCase)) shareChanges.Add($"Nouveau partage : {ns[k].Unc}");
        foreach (var k in os.Keys.Except(ns.Keys, StringComparer.OrdinalIgnoreCase)) shareChanges.Add($"Partage supprimé : {os[k].Unc}");
        foreach (var k in ns.Keys.Intersect(os.Keys, StringComparer.OrdinalIgnoreCase))
            if (!string.Equals(os[k].Security?.Sddl, ns[k].Security?.Sddl, StringComparison.Ordinal) && os[k].Security is not null && ns[k].Security is not null)
                shareChanges.Add($"Droits de partage modifiés : {ns[k].Unc}");
        static HashSet<string> Keys(AnalysisSession s) => s.Findings.SelectMany(f => f.Items.Select(i => $"{f.RuleId} — {f.Title} — {(i.FolderId is int id ? s.Index.RelativePath(id) + " : " : "")}{i.Detail}")).ToHashSet();
        var fo = Keys(older); var fn = Keys(newer);
        return new DiffResult
        {
            OldCreated = older.Index.Snapshot.Manifest.CreatedUtc.ToString("u"), NewCreated = newer.Index.Snapshot.Manifest.CreatedUtc.ToString("u"),
            OldRoot = older.Index.Snapshot.Manifest.RootPath, NewRoot = newer.Index.Snapshot.Manifest.RootPath,
            SameRoot = string.Equals(older.Index.Snapshot.Manifest.RootPath, newer.Index.Snapshot.Manifest.RootPath, StringComparison.OrdinalIgnoreCase),
            AddedCount = added.Count, RemovedCount = removed.Count, ChangedCount = changedCount,
            AddedFolders = added.Take(MaxList).ToList(), RemovedFolders = removed.Take(MaxList).ToList(), Changed = changed, ShareChanges = shareChanges,
            NewFindings = fn.Except(fo).Order().Take(MaxList).ToList(), ResolvedFindings = fo.Except(fn).Order().Take(MaxList).ToList(),
        };
    }

    private readonly struct SnapshotIndexWrapper(AclMap.Core.Snapshot.SnapshotIndex i)
    {
        public string Name(string sid) => i.NameOf(sid);
    }
}
