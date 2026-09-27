namespace AclMap.Models.Snapshot;

/// <summary>Nature d'une identité.</summary>
public enum PrincipalKind { User, Group, Computer, WellKnown, LocalGroup, LocalUser, Capability, Foreign, Unknown }

/// <summary>Étendue d'un groupe AD.</summary>
public enum GroupScope { None, DomainLocal, Global, Universal, Local }

/// <summary>
/// Identité rencontrée dans une ACL ou dans une appartenance de groupe. Les membres directs des groupes sont
/// renseignés pour permettre le calcul hors ligne des jetons (qui appartient à quoi).
/// </summary>
public sealed record PrincipalInfo
{
    public string Sid { get; init; } = "";
    /// <summary>Nom affiché : DOMAINE\nom, ou nom connu.</summary>
    public string Name { get; init; } = "";
    public PrincipalKind Kind { get; init; } = PrincipalKind.Unknown;
    public GroupScope Scope { get; init; }
    public string? DistinguishedName { get; init; }
    public string? SamAccountName { get; init; }
    public string? DisplayName { get; init; }
    public string? Description { get; init; }
    /// <summary>Compte désactivé.</summary>
    public bool? Disabled { get; init; }
    /// <summary>adminCount = 1 (compte ou groupe protégé par AdminSDHolder).</summary>
    public bool AdminCount { get; init; }
    /// <summary>RID du groupe principal (utilisateurs, ordinateurs).</summary>
    public int? PrimaryGroupRid { get; init; }
    /// <summary>SID non résolu (compte ou groupe supprimé).</summary>
    public bool Orphan { get; init; }
    /// <summary>Membres directs (SID) pour un groupe ; null si l'appartenance n'a pas pu être lue.</summary>
    public IReadOnlyList<string>? Members { get; init; }
    /// <summary>Raison pour laquelle les membres sont inconnus ou incomplets.</summary>
    public string? MembersError { get; init; }
}
