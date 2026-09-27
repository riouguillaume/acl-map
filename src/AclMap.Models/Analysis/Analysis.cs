namespace AclMap.Models.Analysis;

/// <summary>Gravité d'un constat.</summary>
public enum Severity { Info, Low, Medium, High, Critical }

/// <summary>Niveau d'accès lisible, dans l'ordre croissant.</summary>
public enum AccessLevel : byte
{
    None = 0,
    /// <summary>Droits partiels ne correspondant à aucun niveau standard (ex. parcours seul).</summary>
    Special = 1,
    /// <summary>Lister le dossier.</summary>
    List = 2,
    Read = 3,
    ReadExecute = 4,
    /// <summary>Lecture + écriture (sans suppression).</summary>
    Write = 5,
    Modify = 6,
    Full = 7,
}

/// <summary>Précisions sur un accès effectif.</summary>
[Flags]
public enum AccessFlags : byte
{
    None = 0,
    /// <summary>Un refus a retiré des droits.</summary>
    Denied = 1,
    /// <summary>Peut modifier les autorisations (WRITE_DAC) ou s'approprier l'objet.</summary>
    CanChangePermissions = 2,
    /// <summary>Calcul ambigu (ACE conditionnelle, appartenance inconnue, principal étranger…).</summary>
    Ambiguous = 4,
    /// <summary>Accès obtenu (en partie) comme propriétaire.</summary>
    AsOwner = 8,
    /// <summary>Descripteur illisible : accès inconnu.</summary>
    Unknown = 16,
    /// <summary>DACL nulle.</summary>
    NullDacl = 32,
    /// <summary>Hors du partage choisi (inaccessible par ce chemin réseau).</summary>
    OutsideShare = 64,
}

/// <summary>Élément concerné par un constat.</summary>
/// <param name="FolderId">Dossier (null si le constat porte sur un partage ou un principal).</param>
/// <param name="Share">Partage.</param>
/// <param name="Sid">Identité.</param>
/// <param name="Detail">Précision lisible.</param>
public sealed record FindingItem(int? FolderId, string? Share, string? Sid, string Detail);

/// <summary>Constat d'une règle ACL-*.</summary>
public sealed record Finding
{
    public string RuleId { get; init; } = "";
    public Severity Severity { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public string Category { get; init; } = "";
    /// <summary>Nombre total d'éléments (les listes peuvent être tronquées).</summary>
    public int Count { get; init; }
    public IReadOnlyList<FindingItem> Items { get; init; } = [];
}
