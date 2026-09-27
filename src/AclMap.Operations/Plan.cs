using AclMap.Models.Analysis;

namespace AclMap.Operations;

/// <summary>Nature d'une opération d'écriture.</summary>
public enum OperationKind { AddAce, RemoveAce, CreateGroup, AddGroupMember, RemoveGroupMember }

/// <summary>Référence à une identité : SID connu, ou nom d'un groupe créé par une opération précédente du même plan.</summary>
/// <param name="Sid">SID (null si le groupe est créé par le plan).</param>
/// <param name="Name">Nom affiché / sAMAccountName.</param>
/// <param name="Dn">DistinguishedName si connu.</param>
public sealed record PrincipalRef(string? Sid, string Name, string? Dn = null)
{
    /// <summary>Vrai si l'identité sera créée par le plan.</summary>
    public bool CreatedByPlan => Sid is null;
}

/// <summary>ACE à ajouter.</summary>
/// <param name="Principal">Identité.</param>
/// <param name="Level">Niveau (Contrôle total, Modification…).</param>
/// <param name="Scope">Portée (ThisFolderSubfoldersFiles, ThisFolderOnly…).</param>
/// <param name="Deny">Refus au lieu d'autorisation.</param>
public sealed record AceSpec(PrincipalRef Principal, AccessLevel Level, string Scope, bool Deny = false);

/// <summary>ACE à retirer (identifiée par son contenu exact, pas par sa position).</summary>
public sealed record AceRemoval(string Kind, string Sid, uint Mask, byte Flags, string Label);

/// <summary>Opération planifiée, avec l'état avant/après et l'impact.</summary>
public sealed record PlannedOperation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public OperationKind Kind { get; init; }
    /// <summary>Libellé de l'opération (« Ajouter DL_Donnees-Compta_RW (Modification) sur \\FS01\Donnees\Compta »).</summary>
    public string Description { get; init; } = "";
    /// <summary>Cible : chemin (ACL) ou groupe (appartenance).</summary>
    public string Target { get; init; } = "";
    // --- ACL ---
    public string? Path { get; init; }
    public AceSpec? Ace { get; init; }
    public AceRemoval? Removal { get; init; }
    public string? BeforeSddl { get; init; }
    public string? AfterSddl { get; init; }
    public List<string> Before { get; init; } = [];
    public List<string> After { get; init; } = [];
    /// <summary>Objets de l'instantané touchés (dossier + descendants qui héritent).</summary>
    public int AffectedObjects { get; init; }
    // --- Groupes ---
    public PrincipalRef? Group { get; init; }
    public PrincipalRef? Member { get; init; }
    public string? OuDn { get; init; }
    public string? GroupScope { get; init; }
    public string? GroupDescription { get; init; }
    public List<string> Warnings { get; init; } = [];
    /// <summary>Vrai si l'opération ne change rien (déjà en place).</summary>
    public bool NoOp { get; init; }
}

/// <summary>Plan d'écriture soumis à confirmation. Il ne contient aucun secret.</summary>
public sealed record OperationPlan
{
    public string PlanId { get; init; } = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public string Title { get; init; } = "";
    public string? Domain { get; init; }
    public string? DomainController { get; init; }
    public string? SnapshotRoot { get; init; }
    public List<PlannedOperation> Operations { get; init; } = [];
    public List<string> Warnings { get; init; } = [];
}

/// <summary>Résultat d'une opération exécutée (ou vérifiée en Dry Run).</summary>
public sealed record OperationResult(string OperationId, bool Success, bool Skipped, string Message, string? BackupFile);

/// <summary>Sauvegarde permettant d'annuler une opération.</summary>
public sealed record BackupRecord
{
    public string PlanId { get; init; } = "";
    public string OperationId { get; init; } = "";
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;
    public OperationKind Kind { get; init; }
    public string Target { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary>ACL avant modification (restaurée telle quelle).</summary>
    public string? BeforeSddl { get; init; }
    public string? AfterSddl { get; init; }
    /// <summary>Groupe et membre concernés (appartenance), ou groupe créé.</summary>
    public string? GroupDn { get; init; }
    public string? GroupSid { get; init; }
    public string? MemberSid { get; init; }
    public string? MemberDn { get; init; }
}
