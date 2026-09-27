using AclMap.Core.Security;
using AclMap.Models.Analysis;
using AclMap.Models.Security;

namespace AclMap.Tests;

public class SecurityCodecTests
{
    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-1105")]
    public void Sid_binary_roundtrip(string sid)
    {
        var bin = Sid.ToBinary(sid);
        Assert.Equal(sid, Sid.Read(bin, 0, out var len));
        Assert.Equal(bin.Length, len);
    }

    [Fact]
    public void Sid_helpers()
    {
        Assert.False(Sid.IsValid("S-1-5-abc"));
        Assert.False(Sid.IsValid("S-1-5-21-99999999999"));
        Assert.Equal("S-1-5-21-1-2-3", Sid.DomainOf("S-1-5-21-1-2-3-1105"));
        Assert.Equal(1105u, Sid.Rid("S-1-5-21-1-2-3-1105"));
        Assert.Null(Sid.DomainOf("S-1-5-32-544"));
        Assert.Equal(@"\01\01\00\00\00\00\00\01\00\00\00\00", Sid.ToLdapFilterValue("S-1-1-0"));
    }

    [Fact]
    public void Descriptor_binary_roundtrip_keeps_everything()
    {
        var sd = Sddl.Parse("O:BAG:SYD:PAI(D;OICI;0x10000;;;S-1-5-21-1-2-3-1102)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;S-1-5-21-1-2-3-513)(A;OICIID;0x1301bf;;;AU)");
        var bin = SecurityDescriptorCodec.Build(sd);
        var back = SecurityDescriptorCodec.Parse(bin);
        Assert.Equal(sd.Sddl, back.Sddl);
        Assert.True(back.Protected);
        Assert.Equal("S-1-5-32-544", back.Owner);
        Assert.Equal(5, back.Aces.Count);
        Assert.True(back.Aces[4].IsInherited);
        Assert.True(back.Aces[2].IsInheritOnly);
        Assert.Equal(AceKind.Deny, back.Aces[0].Kind);
    }

    [Fact]
    public void Null_dacl_roundtrip()
    {
        var sd = Sddl.Parse("O:BAD:NO_ACCESS_CONTROL");
        Assert.False(sd.DaclPresent);
        Assert.False(SecurityDescriptorCodec.Parse(SecurityDescriptorCodec.Build(sd)).DaclPresent);
    }

    [Fact]
    public void Sddl_rejects_garbage()
    {
        Assert.Throws<FormatException>(() => Sddl.Parse("D:(Z;;FA;;;WD)"));
        Assert.Throws<FormatException>(() => Sddl.Parse("D:(A;OX;FA;;;WD)"));
        Assert.Throws<FormatException>(() => Sddl.Parse("D:(A;;FA;;;DA)"));
        Assert.Throws<FormatException>(() => SecurityDescriptorCodec.Parse(new byte[] { 1, 0, 4, 0 }));
    }

    [Theory]
    [InlineData(0x001F01FFu, AccessLevel.Full)]
    [InlineData(0x001301BFu, AccessLevel.Modify)]
    [InlineData(0x0012019Fu, AccessLevel.Write)]
    [InlineData(0x001200A9u, AccessLevel.ReadExecute)]
    [InlineData(0x00120089u, AccessLevel.Read)]
    [InlineData(0x00000001u, AccessLevel.List)]
    [InlineData(0x00000020u, AccessLevel.Special)]
    [InlineData(0x10000000u, AccessLevel.Full)]
    [InlineData(0xA0000000u, AccessLevel.ReadExecute)]
    [InlineData(0x00100000u, AccessLevel.None)]
    public void Levels(uint mask, AccessLevel expected) => Assert.Equal(expected, Rights.LevelOf(mask));

    [Fact]
    public void Summaries_and_scopes()
    {
        Assert.Equal("Modification", Rights.Summary(FileRights.Modify));
        Assert.StartsWith("Modification + ", Rights.Summary(FileRights.Modify | FileRights.WriteDac));
        Assert.StartsWith("Spécial", Rights.Summary(FileRights.Delete));
        Assert.Equal("Ce dossier, les sous-dossiers et les fichiers", Rights.AppliesTo(AceFlags.ObjectInherit | AceFlags.ContainerInherit));
        Assert.Equal("Les sous-dossiers uniquement", Rights.AppliesTo(AceFlags.ContainerInherit | AceFlags.InheritOnly));
        Assert.EndsWith("(un seul niveau)", Rights.AppliesTo(AceFlags.ContainerInherit | AceFlags.NoPropagateInherit));
        Assert.Equal("Lecture", Rights.ShareLabel(FileRights.ShareRead));
        Assert.Equal("Modifier", Rights.ShareLabel(FileRights.ShareChange));
    }
}
