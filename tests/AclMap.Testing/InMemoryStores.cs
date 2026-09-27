using AclMap.Models.Security;
using AclMap.Operations;
using AclMap.Services;

namespace AclMap.Testing;

/// <summary>ACL « réelles » simulées en mémoire (tests et hôte de développement).</summary>
public sealed class InMemoryAclStore(AnalysisSession s) : IAclStore
{
    public readonly Dictionary<string, SecurityDescriptorInfo> Live = Enumerable.Range(0, s.Index.Count).Where(i => s.Index.Descriptor(i) is not null)
        .ToDictionary(s.Index.FullPath, i => s.Index.Descriptor(i)!, StringComparer.OrdinalIgnoreCase);
    public int Writes;

    public SecurityDescriptorInfo Read(string path) => Live.TryGetValue(path, out var v) ? v : throw new FileNotFoundException("Dossier introuvable : " + path);

    public void WriteDacl(string path, IReadOnlyList<AceInfo> aces, bool protectedDacl)
    {
        Writes++;
        var cur = Read(path);
        Live[path] = PlanBuilder.WithAces(cur, [.. aces, .. cur.Aces.Where(a => a.IsInherited)]);
    }
}

/// <summary>Annuaire simulé en mémoire (tests et hôte de développement).</summary>
public sealed class InMemoryDirectory : IDirectoryStore
{
    public readonly Dictionary<string, (string Sid, string Dn)> ByName = new(StringComparer.OrdinalIgnoreCase);
    public readonly HashSet<(string, string)> Membership = [];
    public readonly Dictionary<string, string> SidToDn = new(StringComparer.OrdinalIgnoreCase);
    private int _next = 9000;

    public InMemoryDirectory(AnalysisSession s)
    {
        foreach (var p in s.Index.Principals.Where(p => p.SamAccountName is not null && p.DistinguishedName is not null)) { ByName[p.SamAccountName!] = (p.Sid, p.DistinguishedName!); SidToDn[p.Sid] = p.DistinguishedName!; }
        foreach (var p in s.Index.Principals.Where(p => p.Members is not null && p.DistinguishedName is not null)) foreach (var m in p.Members!) Membership.Add((p.DistinguishedName!, m));
    }

    public (string Sid, string Dn)? Find(PrincipalRef r) =>
        r.Sid is not null ? (SidToDn.TryGetValue(r.Sid, out var dn) ? (r.Sid, dn) : null) : ByName.TryGetValue(r.Name.Split('\\').Last(), out var v) ? v : null;
    public bool IsMember(string groupDn, string memberSid) => Membership.Contains((groupDn, memberSid));
    public void AddMember(string groupDn, string memberDn) => Membership.Add((groupDn, SidToDn.First(k => k.Value == memberDn).Key));
    public void RemoveMember(string groupDn, string memberDn) => Membership.Remove((groupDn, SidToDn.First(k => k.Value == memberDn).Key));
    public (string Sid, string Dn) CreateGroup(string ouDn, string name, string scope, string? description)
    {
        var r = (LabSnapshotFactory.Rid(_next++), $"CN={name},{ouDn}");
        ByName[name] = r; SidToDn[r.Item1] = r.Item2;
        return r;
    }
    public void DeleteGroup(string dn) { var k = ByName.First(x => x.Value.Dn == dn).Key; ByName.Remove(k); }
}
