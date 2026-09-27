using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Analysis;
using AclMap.Models.Snapshot;
using AclMap.Services;
using AclMap.Testing;
using L = AclMap.Testing.LabSnapshotFactory;

namespace AclMap.Tests;

public class LabScenarioTests
{
    private static readonly AnalysisSession S = new(L.Create());

    private static int F(string rel) => S.Index.FindRelative(rel) ?? throw new Xunit.Sdk.XunitException("dossier absent : " + rel);

    private static AccessLevel Level(AccessMap m, int id) => (AccessLevel)Convert.FromBase64String(m.Levels)[id];
    private static AccessFlags Flags(AccessMap m, int id) => (AccessFlags)Convert.FromBase64String(m.Flags)[id];

    [Fact]
    public void Descriptors_are_deduplicated()
    {
        Assert.True(S.Index.Snapshot.Descriptors.Count < S.Index.Count / 3, $"{S.Index.Snapshot.Descriptors.Count} descripteurs pour {S.Index.Count} dossiers");
    }

    [Fact]
    public void All_expected_rules_fire()
    {
        var ids = S.Findings.Select(f => f.RuleId).ToHashSet();
        foreach (var r in new[] { "ACL-002", "ACL-003", "ACL-004", "ACL-005", "ACL-006", "ACL-007", "ACL-008", "ACL-009", "ACL-010", "ACL-011", "ACL-012",
                     "ACL-020", "ACL-021", "ACL-022", "ACL-023", "ACL-024", "ACL-030", "ACL-031", "ACL-032", "ACL-040" })
            Assert.True(ids.Contains(r), "règle absente : " + r);
        Assert.DoesNotContain("ACL-001", ids);
        // les constats sont triés par gravité
        Assert.Equal(S.Findings.OrderByDescending(f => f.Severity).Select(f => f.RuleId), S.Findings.Select(f => f.RuleId));
    }

    [Fact]
    public void Prestataire_is_privileged_and_flagged()
    {
        Assert.True(S.Rules.IsPrivileged(L.Prestataire));
        Assert.False(S.Rules.IsPrivileged(L.Alice));
        var f = S.Findings.Single(x => x.RuleId == "ACL-006");
        Assert.Contains(f.Items, i => i.Sid == L.Prestataire && i.FolderId == F("Direction"));
        Assert.Contains(f.Items, i => i.Sid == L.Prestataire && i.Share == "Archives");
    }

    [Fact]
    public void Broad_write_findings_point_to_origin_folders_only()
    {
        var f = S.Findings.Single(x => x.RuleId == "ACL-002");
        Assert.Equal(new[] { F("Commercial\\Prospects"), F("Scan") }.Order(), f.Items.Select(i => i.FolderId!.Value).Order());
        Assert.Contains(S.Findings, x => x.RuleId == "ACL-020" && x.Items.Any(i => i.Share == "Scan"));
    }

    [Fact]
    public void Alice_map_matches_expected_access()
    {
        var m = S.ComputeMap(L.Alice, "ntfs");
        Assert.Equal(AccessLevel.Modify, Level(m, F("Compta")));
        Assert.Equal(AccessLevel.Modify, Level(m, F("Compta\\2025\\Clôture")));
        Assert.Equal(AccessLevel.None, Level(m, F("RH")));
        Assert.True((Flags(m, F("RH\\Paie")) & AccessFlags.Unknown) != 0);
        Assert.Equal(AccessLevel.Modify, Level(m, F("Commun")));
        Assert.Equal(AccessLevel.ReadExecute, Level(m, 0));
        Assert.Equal(AccessLevel.Modify, Level(m, F("Commercial\\Prospects")));   // Tout le monde : Modification
        Assert.False(m.GroupMode);
    }

    [Fact]
    public void Bruno_is_denied_on_cloture_and_emma_ambiguous_on_contrats()
    {
        var b = S.ComputeMap(L.Bruno, "ntfs");
        var id = F("Compta\\2025\\Clôture");
        Assert.True((Flags(b, id) & AccessFlags.Denied) != 0);
        Assert.Equal(AccessLevel.ReadExecute, Level(b, id));
        var e = S.ComputeMap(L.Emma, "ntfs");
        Assert.True((Flags(e, F("Commercial\\Contrats")) & AccessFlags.Ambiguous) != 0);
        // IT : groupe étranger au contenu inconnu → ambigu pour tout le monde
        Assert.True((Flags(e, F("IT")) & AccessFlags.Ambiguous) != 0);
    }

    [Fact]
    public void Share_path_restricts_to_share_subtree_and_intersects()
    {
        var m = S.ComputeMap(L.Alice, "Scan");
        Assert.True((Flags(m, F("Compta")) & AccessFlags.OutsideShare) != 0);
        Assert.Equal(AccessLevel.Modify, Level(m, F("Scan")));
        var paths = S.AccessPaths();
        Assert.Contains(paths, p => p.Id == "Scan");
        Assert.Contains(paths, p => p.Id == "Compta$" && !p.ShareRightsKnown);
        Assert.Equal("Donnees", S.DefaultAccessPath());
        var viaCompta = S.ComputeMap(L.Alice, "Compta$");
        Assert.True((Flags(viaCompta, F("Compta")) & AccessFlags.Ambiguous) != 0);
    }

    [Fact]
    public void Group_mode_counts_only_rights_through_the_group()
    {
        var m = S.ComputeMap(L.GgCompta, "ntfs");
        Assert.True(m.GroupMode);
        Assert.Equal(AccessLevel.Modify, Level(m, F("Compta")));
        Assert.Equal(AccessLevel.None, Level(m, F("Commun")));   // Commun est ouvert via Utilisateurs du domaine, pas via GG_Compta
    }

    [Fact]
    public void Explain_shows_chain_and_inheritance_origin()
    {
        var x = S.Explain(L.Alice, F("Compta\\2025"), "ntfs");
        var grant = x.Aces.Single(a => a.Effect == "Grants" && a.Sid == L.DlComptaRw);
        Assert.Equal([L.Alice, L.GgCompta, L.DlComptaRw], grant.Path.Select(p => p.Sid));
        Assert.True(grant.Inherited);
        Assert.Equal(F("Compta"), grant.OriginFolderId);
        Assert.Equal("Modification", x.Final.Label);
        var viaShare = S.Explain(L.Alice, F("Compta"), "Donnees");
        Assert.NotNull(viaShare.Share);
        Assert.Equal("Contrôle total", viaShare.Share!.Label);
    }

    [Fact]
    public void Deep_nesting_is_resolved_and_reported()
    {
        var m = S.ComputeMap(L.Emma, "ntfs");
        Assert.True(Level(m, F("Commercial")) >= AccessLevel.Read);
        Assert.Equal(3, S.Rules.NestingDepth(L.GlNiv1, [], out var cycle));
        Assert.False(cycle);
    }

    [Fact]
    public void Graph_links_principal_groups_and_folders()
    {
        var g = S.Graph(L.Alice);
        Assert.Contains(g.Nodes, n => n.Id == L.DlComptaRw);
        Assert.Contains(g.Edges, e => e.Source == L.GgCompta && e.Target == L.DlComptaRw);
        Assert.Contains(g.Edges, e => e.Source == L.DlComptaRw && e.Target == "F" + F("Compta"));
        Assert.Contains(g.Edges, e => e.Source == L.Alice && e.Target == "F" + F("Compta\\Archives"));
    }

    [Fact]
    public void Who_has_access_lists_users()
    {
        var w = S.WhoHasAccess(F("Compta"), "ntfs");
        Assert.Contains(w.Users, u => u.Sid == L.Alice && u.Level == (int)AccessLevel.Modify);
        Assert.Contains(w.Users, u => u.Sid == L.David && u.Level == (int)AccessLevel.ReadExecute);
        Assert.DoesNotContain(w.Users, u => u.Sid == L.Chloe);
        Assert.Contains(w.Users, u => u.Sid == L.Prestataire && u.Privileged);   // admin du domaine → BUILTIN\Administrateurs
    }

    [Fact]
    public void View_model_and_details()
    {
        var v = ViewModel.Build(S);
        Assert.Equal(S.Index.Count, v.Folders.Count);
        Assert.Equal(3, v.Stats["protected"]);
        Assert.Equal(1, v.Stats["inaccessible"]);
        var d = ViewModel.Folder(S, F("Direction"));
        Assert.True(d.Protected);
        Assert.Contains(d.Aces, a => a.Orphan);
        Assert.Contains(d.Findings, f => f.RuleId == "ACL-006");
        var p = ViewModel.Principal(S, L.DlComptaRw);
        Assert.Equal(2, p.TransitiveUsers);
        Assert.Contains(p.Members, m => m.Sid == L.GgCompta);
        Assert.NotEmpty(p.Aces);
    }

    [Fact]
    public void Archive_roundtrip_and_tamper_detection()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var file = Path.Combine(dir.FullName, "lab.aclmap");
            var saved = SnapshotArchive.Save(L.Create(), file);
            Assert.Equal(5, saved.Manifest.Parts.Count);
            var back = SnapshotArchive.Load(file);
            Assert.Equal(saved.Folders.Count, back.Folders.Count);
            Assert.Equal(saved.Descriptors.Select(d => d.Sddl), back.Descriptors.Select(d => d.Sddl));
            Assert.Equal(saved.Manifest.FolderCount, new AnalysisSession(back).Index.Snapshot.Folders.Count(f => (f.Flags & NodeFlags.File) == 0));
            // altération d'une partie
            var bad = Path.Combine(dir.FullName, "bad.aclmap");
            using (var src = System.IO.Compression.ZipFile.OpenRead(file))
            using (var dst = System.IO.Compression.ZipFile.Open(bad, System.IO.Compression.ZipArchiveMode.Create))
                foreach (var e in src.Entries)
                {
                    using var i = e.Open(); using var ms = new MemoryStream(); i.CopyTo(ms);
                    var bytes = ms.ToArray();
                    if (e.Name == "folders.json") bytes = System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(bytes).Replace("Compta", "Compte"));
                    using var o = dst.CreateEntry(e.FullName).Open(); o.Write(bytes);
                }
            var ex = Assert.Throws<InvalidDataException>(() => SnapshotArchive.Load(bad));
            Assert.Contains("SHA-256", ex.Message);
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public void Diff_detects_acl_changes_and_new_findings()
    {
        var older = L.Create();
        var descs = older.Descriptors.ToList();
        var dirId = new SnapshotIndex(older).FindRelative("Direction")!.Value;
        var sdId = older.Folders[dirId].SdId;
        var d = descs[sdId];
        descs[sdId] = d with { Aces = d.Aces.Where(a => a.Sid != L.Prestataire).ToList() };
        var old = older with { Descriptors = descs, Folders = older.Folders.Where(f => f.Name != "Livrables" || f.ParentId != new SnapshotIndex(older).FindRelative("Projets\\Projet-020")).ToList() };
        // reconstruit des identifiants contigus pour l'ancien instantané
        var map = old.Folders.Select((f, i) => (f.Id, i)).ToDictionary(x => x.Id, x => x.i);
        old = old with { Folders = old.Folders.Select((f, i) => f with { Id = i, ParentId = f.ParentId < 0 ? -1 : map[f.ParentId] }).ToList() };
        var diff = SnapshotDiff.Compare(new AnalysisSession(old), S);
        Assert.Equal(1, diff.AddedCount);
        Assert.Contains(diff.Changed, c => c.Path.EndsWith("Direction") && c.Added.Any(a => a.Contains("prestataire")));
        Assert.Contains(diff.NewFindings, f => f.StartsWith("ACL-006"));
        Assert.True(diff.SameRoot);
    }
}
