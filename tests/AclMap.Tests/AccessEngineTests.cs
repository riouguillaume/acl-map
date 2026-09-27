using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Tests;

public class AccessEngineTests
{
    private const string Dom = "S-1-5-21-1-2-3";
    private static readonly string User = Dom + "-1101", Group = Dom + "-2001", Parent = Dom + "-2002";

    private static (TokenBuilder, SnapshotIndex) Build(params PrincipalInfo[] extra)
    {
        var principals = new List<PrincipalInfo>
        {
            new() { Sid = User, Name = "C\\u", Kind = PrincipalKind.User, PrimaryGroupRid = 513 },
            new() { Sid = Group, Name = "C\\g", Kind = PrincipalKind.Group, Members = [User] },
            new() { Sid = Parent, Name = "C\\p", Kind = PrincipalKind.Group, Members = [Group] },
        };
        principals.AddRange(extra);
        var idx = new SnapshotIndex(new AclSnapshot { Folders = [new FolderNode(0, -1, "\\\\s\\x", -1, 0)], Principals = principals });
        return (new TokenBuilder(idx), idx);
    }

    private static SecurityDescriptorInfo Sd(string dacl, string owner = "BA") => Sddl.Parse($"O:{owner}{dacl}");

    [Fact]
    public void Token_contains_nested_groups_primary_group_and_implicit_sids()
    {
        var (b, _) = Build();
        var t = b.Build(User);
        Assert.Contains(Group, t.Sids);
        Assert.Contains(Parent, t.Sids);
        Assert.Contains(Dom + "-513", t.Sids);
        Assert.Contains(WellKnownSids.Everyone, t.Sids);
        Assert.Contains(WellKnownSids.AuthenticatedUsers, t.Sids);
        Assert.Equal([User, Group, Parent], t.PathTo(Parent));
        Assert.Equal([Token.Implicit, WellKnownSids.Everyone], t.PathTo(WellKnownSids.Everyone));
    }

    [Fact]
    public void Group_token_has_no_implicit_sids()
    {
        var (b, _) = Build();
        var t = b.Build(Group);
        Assert.True(t.GroupMode);
        Assert.Contains(Parent, t.Sids);
        Assert.DoesNotContain(WellKnownSids.Everyone, t.Sids);
    }

    [Fact]
    public void Cycles_do_not_hang()
    {
        var a = Dom + "-3001"; var c = Dom + "-3002";
        var (b, _) = Build(new PrincipalInfo { Sid = a, Kind = PrincipalKind.Group, Members = [c, User] }, new PrincipalInfo { Sid = c, Kind = PrincipalKind.Group, Members = [a] });
        var t = b.Build(User);
        Assert.Contains(a, t.Sids); Assert.Contains(c, t.Sids);
    }

    [Fact]
    public void Allow_through_nested_group()
    {
        var (b, _) = Build();
        var r = AccessEngine.Evaluate(Sd($"D:(A;OICI;0x1301bf;;;{Parent})"), b.Build(User));
        Assert.Equal(AccessLevel.Modify, r.Level);
    }

    [Fact]
    public void Deny_before_allow_wins_and_is_flagged()
    {
        var (b, _) = Build();
        var r = AccessEngine.Evaluate(Sd($"D:(D;;0x10000;;;{User})(A;OICI;FA;;;{Group})"), b.Build(User));
        Assert.True((r.Flags & AccessFlags.Denied) != 0);
        Assert.Equal(0u, r.Granted & FileRights.Delete);
        Assert.Equal(AccessLevel.Write, r.Level);
    }

    [Fact]
    public void Allow_before_deny_non_canonical_keeps_access()
    {
        var (b, _) = Build();
        var sd = Sd($"D:(A;OICI;FA;;;{Group})(D;;0x10000;;;{User})");
        var r = AccessEngine.Evaluate(sd, b.Build(User));
        Assert.Equal(AccessLevel.Full, r.Level);
        Assert.False(AccessEngine.IsCanonical(sd));
    }

    [Fact]
    public void Inherit_only_is_ignored_on_the_folder_itself()
    {
        var (b, _) = Build();
        Assert.Equal(AccessLevel.None, AccessEngine.Evaluate(Sd($"D:(A;OICIIO;FA;;;{User})"), b.Build(User)).Level);
    }

    [Fact]
    public void Owner_gets_read_and_change_permissions_unless_owner_rights()
    {
        var (b, _) = Build();
        var r = AccessEngine.Evaluate(Sd("D:(A;;FA;;;SY)", owner: User), b.Build(User));
        Assert.True((r.Flags & AccessFlags.AsOwner) != 0);
        Assert.True((r.Flags & AccessFlags.CanChangePermissions) != 0);
        var r2 = AccessEngine.Evaluate(Sd("D:(A;;0x120089;;;OW)", owner: User), b.Build(User));
        Assert.Equal(0u, r2.Granted & FileRights.WriteDac);
        Assert.Equal(AccessLevel.Read, r2.Level);
    }

    [Fact]
    public void Null_dacl_is_full_control()
    {
        var (b, _) = Build();
        var r = AccessEngine.Evaluate(Sddl.Parse("O:BAD:NO_ACCESS_CONTROL"), b.Build(User));
        Assert.Equal(AccessLevel.Full, r.Level);
        Assert.True((r.Flags & AccessFlags.NullDacl) != 0);
    }

    [Fact]
    public void Conditional_and_unknown_membership_are_ambiguous()
    {
        var unknown = Dom + "-4000";
        var (b, _) = Build(new PrincipalInfo { Sid = unknown, Kind = PrincipalKind.Group, Members = null });
        var t = b.Build(User);
        Assert.True((AccessEngine.Evaluate(Sd($"D:(XA;OICI;FA;;;{User})"), t).Flags & AccessFlags.Ambiguous) != 0);
        var r = AccessEngine.Evaluate(Sd($"D:(A;OICI;FA;;;{unknown})"), t);
        Assert.True((r.Flags & AccessFlags.Ambiguous) != 0);
        Assert.Equal(AccessLevel.None, r.Level);
    }

    [Fact]
    public void Network_access_is_the_intersection_with_share_rights()
    {
        var (b, _) = Build();
        var t = b.Build(User);
        var ntfs = AccessEngine.Evaluate(Sd($"D:(A;OICI;FA;;;{Group})"), t);
        var share = AccessEngine.Evaluate(Sd("D:(A;;0x1200a9;;;WD)"), t);
        Assert.Equal(AccessLevel.ReadExecute, AccessEngine.Combine(ntfs, share).Level);
        Assert.Equal(0, (int)(AccessEngine.Combine(ntfs, share).Flags & AccessFlags.CanChangePermissions));
    }

    [Fact]
    public void Explanation_lists_contributions()
    {
        var (b, _) = Build();
        var list = new List<AceContribution>();
        AccessEngine.Evaluate(Sd($"D:(D;;0x10000;;;{User})(A;OICI;0x1301bf;;;{Parent})(A;OICI;0x1301bf;;;{Group})"), b.Build(User), list);
        Assert.Equal([AceEffect.Denies, AceEffect.Grants, AceEffect.NoEffect], list.Select(c => c.Effect));
        Assert.Equal([User, Group, Parent], list[1].MembershipPath);
    }
}
