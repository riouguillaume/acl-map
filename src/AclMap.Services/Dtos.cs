namespace AclMap.Services;

/// <summary>Identité nommée.</summary>
public sealed record NamedSid(string Sid, string Name, string Kind);

/// <summary>Carte de droits (tableaux encodés en base64 : un octet par dossier).</summary>
public sealed record AccessMap
{
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public bool GroupMode { get; init; }
    public string AccessPath { get; init; } = "ntfs";
    /// <summary>Niveau (AccessLevel) par dossier.</summary>
    public string Levels { get; init; } = "";
    /// <summary>Précisions (AccessFlags) par dossier.</summary>
    public string Flags { get; init; } = "";
    public int[] Counts { get; init; } = [];
    public int Ambiguous { get; init; }
    public int Denied { get; init; }
    public int CanChangePermissions { get; init; }
    public int Unknown { get; init; }
    public string? ShareLevel { get; init; }
    public IReadOnlyList<NamedSid> Groups { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>Résultat lisible.</summary>
public sealed record ResultDto(string Label, int Level, int Flags, List<string> Granted, List<string> Denied);

/// <summary>Ligne d'explication (une ACE).</summary>
public sealed record ExplainRow
{
    public int Index { get; init; }
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Rights { get; init; } = "";
    public string AppliesTo { get; init; } = "";
    public bool Inherited { get; init; }
    public int? OriginFolderId { get; init; }
    public string? OriginPath { get; init; }
    public bool OriginCertain { get; init; }
    public string Effect { get; init; } = "";
    public List<string> Bits { get; init; } = [];
    public string Note { get; init; } = "";
    public List<NamedSid> Path { get; init; } = [];
}

/// <summary>Explication complète.</summary>
public sealed record Explanation
{
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public int FolderId { get; init; }
    public string Path { get; init; } = "";
    public ResultDto Ntfs { get; init; } = null!;
    public ResultDto? Share { get; init; }
    public ResultDto Final { get; init; } = null!;
    public string? ShareName { get; init; }
    public bool OutsideShare { get; init; }
    public NamedSid? Owner { get; init; }
    public bool OwnerIsPrincipal { get; init; }
    public List<ExplainRow> Aces { get; init; } = [];
    public List<ExplainRow> ShareAces { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];
}

public sealed record GraphNode(string Id, string Label, string Type, string Kind, int? FolderId);
public sealed record GraphEdge(string Source, string Target, string Label, string Type);
/// <summary>Graphe d'origine des droits.</summary>
public sealed record PrincipalGraph(List<GraphNode> Nodes, List<GraphEdge> Edges, int FolderTotal, int FolderShown);

public sealed record AccessRow(string Sid, string Name, string? DisplayName, bool Disabled, int Level, string LevelLabel, int Flags, bool Privileged);
public sealed record AclEntrySummary(string Sid, string Name, string Kind, bool Deny, string Rights, int? MemberCount);
/// <summary>Vue inverse : qui a accès à un dossier.</summary>
public sealed record WhoHasAccess(int FolderId, string Path, List<AccessRow> Users, List<AclEntrySummary> Entries, int UsersEvaluated, bool BroadGroupPresent);
