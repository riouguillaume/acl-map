using AclMap.Core.Security;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Operations;
using AclMap.Services;
using AclMap.Testing;
using L = AclMap.Testing.LabSnapshotFactory;

namespace AclMap.Tests;

public class OperationsTests
{
    private static readonly AnalysisSession S = new(L.Create());
    private static int F(string rel) => S.Index.FindRelative(rel)!.Value;

    [Fact]
    public void Add_ace_is_inserted_canonically_and_merged()
    {
        var sd = S.Index.Descriptor(F("Compta\\2025\\Clôture"))!;
        var after = PlanBuilder.AddAce(sd.Aces, L.GgRh, new AceSpec(new PrincipalRef(L.GgRh, "GG_RH"), AccessLevel.Read, "ThisFolderSubfoldersFiles"), out var changed);
        Assert.True(changed);
        Assert.Equal(AceKind.Deny, after[0].Kind);          // refus explicite en tête
        Assert.Equal(L.GgRh, after[1].Sid);                  // puis autorisation explicite
        Assert.True(after.Skip(2).All(a => a.IsInherited));  // puis héritées
        var again = PlanBuilder.AddAce(after, L.GgRh, new AceSpec(new PrincipalRef(L.GgRh, "GG_RH"), AccessLevel.Read, "ThisFolderSubfoldersFiles"), out var changed2);
        Assert.False(changed2);
        Assert.Equal(after.Count, again.Count);
    }

    [Fact]
    public void Affected_count_stops_at_protected_children()
    {
        var flags = Rights.FlagsFor("ThisFolderSubfoldersFiles");
        var root = PlanBuilder.Affected(S, 0, flags);
        var total = S.Index.Count;
        var protectedBranches = new[] { "Compta", "RH", "Direction" }.Sum(r => 1 + S.Index.Descendants(F(r)).Count());
        Assert.Equal(total - protectedBranches - 1 /* jonction */, root);
        Assert.Equal(1, PlanBuilder.Affected(S, 0, Rights.FlagsFor("ThisFolderOnly")));
    }

    [Fact]
    public void Plan_add_ace_warns_for_broad_write()
    {
        var op = PlanBuilder.PlanAddAce(S, F("Commun"), new AceSpec(new PrincipalRef(WellKnownSids.Everyone, "Tout le monde"), AccessLevel.Modify, "ThisFolderSubfoldersFiles"));
        Assert.Contains(op.Warnings, w => w.Contains("écriture à tous"));
        Assert.NotEqual(op.BeforeSddl, op.AfterSddl);
        Assert.True(op.AffectedObjects >= 1);
        Assert.Throws<ArgumentException>(() => PlanBuilder.PlanAddAce(S, F("RH\\Paie"), new AceSpec(new PrincipalRef(L.GgRh, "GG_RH"), AccessLevel.Read, "ThisFolderOnly")));
        Assert.Throws<ArgumentException>(() => PlanBuilder.PlanAddAce(S, F("Commercial\\Contrats"), new AceSpec(new PrincipalRef(L.GgRh, "GG_RH"), AccessLevel.Read, "ThisFolderOnly")));
    }

    [Fact]
    public void Plan_remove_rejects_inherited_and_warns_on_admins()
    {
        var sd = S.Index.Descriptor(F("Compta\\2025"))!;
        Assert.Throws<ArgumentException>(() => PlanBuilder.PlanRemoveAce(S, F("Compta\\2025"), 0));
        var direction = S.Index.Descriptor(F("Direction"))!;
        var ix = direction.Aces.ToList().FindIndex(a => a.Sid == WellKnownSids.Administrators);
        var op = PlanBuilder.PlanRemoveAce(S, F("Direction"), ix);
        Assert.Empty(op.Warnings);   // SYSTEM garde le contrôle total
        Assert.NotNull(sd);
    }

    [Fact]
    public void Agdlp_plan_creates_groups_nests_and_sets_aces()
    {
        var plan = PlanBuilder.PlanAgdlp(S, new PlanBuilder.AgdlpRequest(F("Commun"), "Qualité", "Donnees", "Qualite", true, true, "OU=Groupes,DC=contoso,DC=local",
            [new PrincipalRef(L.Chloe, "CONTOSO\\chloe.bernard")]));
        var kinds = plan.Operations.Select(o => o.Kind).ToList();
        Assert.Equal([OperationKind.CreateGroup, OperationKind.CreateGroup, OperationKind.AddAce, OperationKind.AddGroupMember, OperationKind.CreateGroup, OperationKind.AddAce, OperationKind.AddGroupMember], kinds);
        Assert.Equal("GG_Qualite", plan.Operations[0].Group!.Name);
        Assert.Equal("DL_Donnees-Qualite_RW", plan.Operations[1].Group!.Name);
        Assert.Equal("DL_Donnees-Qualite_RO", plan.Operations[4].Group!.Name);
        Assert.Throws<ArgumentException>(() => PlanBuilder.PlanCreateGroup("bad/name", "Global", "OU=x,DC=c", null));
    }

    [Fact]
    public void Executor_dry_run_writes_nothing_then_applies_and_restores()
    {
        var acl = new InMemoryAclStore(S); var dir = new InMemoryDirectory(S);
        var tmp = Directory.CreateTempSubdirectory();
        try
        {
            var plan = PlanBuilder.PlanAgdlp(S, new PlanBuilder.AgdlpRequest(F("Commun"), "Qualité", "Donnees", "Qualite", true, false, "OU=Groupes,DC=contoso,DC=local",
                [new PrincipalRef(L.Chloe, "CONTOSO\\chloe.bernard")]));
            var exec = new PlanExecutor(acl, dir, tmp.FullName);
            var dry = exec.Execute(plan, dryRun: true);
            Assert.All(dry, r => Assert.True(r.Success, r.Message));
            Assert.Equal(0, acl.Writes);
            Assert.False(dir.ByName.ContainsKey("GG_Qualite"));

            var res = exec.Execute(plan, dryRun: false);
            Assert.All(res, r => Assert.True(r.Success, r.Message));
            var path = S.Index.FullPath(F("Commun"));
            var dl = dir.ByName["DL_Donnees-Qualite_RW"];
            Assert.Contains(acl.Live[path].Aces, a => a.Sid == dl.Sid && !a.IsInherited);
            Assert.True(dir.IsMember(dl.Dn, dir.ByName["GG_Qualite"].Sid));
            Assert.True(dir.IsMember(dir.ByName["GG_Qualite"].Dn, L.Chloe));

            // restauration de l'ACE
            var backup = res.Single(r => r.BackupFile is not null && plan.Operations.First(o => o.Id == r.OperationId).Kind == OperationKind.AddAce).BackupFile!;
            var rec = System.Text.Json.JsonSerializer.Deserialize<BackupRecord>(File.ReadAllText(backup), AclMap.Core.Snapshot.AclMapJson.Options)!;
            exec.Restore(rec, dryRun: false);
            Assert.DoesNotContain(acl.Live[path].Aces, a => a.Sid == dl.Sid);
        }
        finally { tmp.Delete(true); }
    }

    [Fact]
    public void Executor_refuses_when_live_acl_changed()
    {
        var acl = new InMemoryAclStore(S); var dir = new InMemoryDirectory(S);
        var tmp = Directory.CreateTempSubdirectory();
        try
        {
            var op = PlanBuilder.PlanAddAce(S, F("Commun"), new AceSpec(new PrincipalRef(L.GgRh, "GG_RH"), AccessLevel.Read, "ThisFolderSubfoldersFiles"));
            var path = op.Path!;
            acl.Live[path] = PlanBuilder.WithAces(acl.Live[path], [new AceInfo(AceKind.Allow, L.Gilles, FileRights.FullControl, 0), .. acl.Live[path].Aces]);
            var res = new PlanExecutor(acl, dir, tmp.FullName).Execute(new OperationPlan { Operations = [op] }, dryRun: false);
            Assert.False(res.Single().Success);
            Assert.Contains("a changé", res.Single().Message);
            Assert.Equal(0, acl.Writes);
        }
        finally { tmp.Delete(true); }
    }

    [Fact]
    public void Membership_plan_detects_noop()
    {
        var op = PlanBuilder.PlanMembership(S, new PrincipalRef(L.GgCompta, "GG_Compta"), new PrincipalRef(L.Alice, "alice"), add: true);
        Assert.True(op.NoOp);
        var op2 = PlanBuilder.PlanMembership(S, new PrincipalRef(L.GgCompta, "GG_Compta"), new PrincipalRef(L.Chloe, "chloe"), add: true);
        Assert.False(op2.NoOp);
        Assert.Contains(op2.Warnings, w => w.Contains("prochaine ouverture de session"));
    }

    [Theory]
    [InlineData("Qualité & Sécurité", "Qualite-Securite")]
    [InlineData("  RH / Paie ", "RH-Paie")]
    public void Slug(string input, string expected) => Assert.Equal(expected, PlanBuilder.Slug(input));
}
