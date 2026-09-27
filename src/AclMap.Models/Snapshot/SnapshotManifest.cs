namespace AclMap.Models.Snapshot;

/// <summary>Options d'analyse.</summary>
public sealed record ScanOptions
{
    /// <summary>Profondeur maximale (0 = racine seule).</summary>
    public int MaxDepth { get; init; } = 12;
    public bool IncludeFiles { get; init; }
    /// <summary>Requêtes simultanées vers le serveur de fichiers.</summary>
    public int Parallelism { get; init; } = 8;
    /// <summary>Mode sauvegarde : lecture avec SeBackupPrivilege (sans takeown).</summary>
    public bool BackupMode { get; init; }
    public bool IncludePrintShares { get; init; }
    public bool IncludeSpecialShares { get; init; }
    /// <summary>Garde-fou : nombre maximal de nœuds.</summary>
    public int MaxNodes { get; init; } = 1_000_000;
    /// <summary>Développer les groupes AD et locaux présents dans les ACL.</summary>
    public bool ExpandGroups { get; init; } = true;
}

/// <summary>Domaine de rattachement.</summary>
public sealed record DomainRef(string? DnsName, string? NetbiosName, string? Sid, string? DomainController);

/// <summary>En-tête d'un instantané .aclmap.</summary>
public sealed record SnapshotManifest
{
    public const string CurrentFormat = "aclmap/1";
    public string Format { get; init; } = CurrentFormat;
    public string ToolVersion { get; init; } = "";
    public DateTimeOffset CreatedUtc { get; init; }
    /// <summary>Chemin analysé (UNC ou local).</summary>
    public string RootPath { get; init; } = "";
    /// <summary>Serveur de fichiers.</summary>
    public string? Server { get; init; }
    /// <summary>Partage analysé (si la racine est un partage ou un de ses sous-dossiers).</summary>
    public string? ShareName { get; init; }
    /// <summary>Chemin local sur le serveur correspondant à la racine (si connu).</summary>
    public string? RootLocalPath { get; init; }
    public DomainRef? Domain { get; init; }
    /// <summary>Compte de collecte (DOMAINE\compte).</summary>
    public string? CollectedBy { get; init; }
    public string? CollectedBySid { get; init; }
    public string? Machine { get; init; }
    public ScanOptions Options { get; init; } = new();
    public int FolderCount { get; init; }
    public int FileCount { get; init; }
    public int DescriptorCount { get; init; }
    public int ErrorCount { get; init; }
    public long DurationMs { get; init; }
    /// <summary>Vrai si l'analyse a été interrompue (annulation, garde-fou).</summary>
    public bool Truncated { get; init; }
    /// <summary>Empreintes SHA-256 des parties de l'archive.</summary>
    public Dictionary<string, string> Parts { get; init; } = [];
}

/// <summary>Instantané complet en mémoire.</summary>
public sealed record AclSnapshot
{
    public SnapshotManifest Manifest { get; init; } = new();
    public IReadOnlyList<FolderNode> Folders { get; init; } = [];
    public IReadOnlyList<Security.SecurityDescriptorInfo> Descriptors { get; init; } = [];
    public IReadOnlyList<PrincipalInfo> Principals { get; init; } = [];
    public IReadOnlyList<ShareInfo> Shares { get; init; } = [];
    public IReadOnlyList<CollectionError> Errors { get; init; } = [];
}
