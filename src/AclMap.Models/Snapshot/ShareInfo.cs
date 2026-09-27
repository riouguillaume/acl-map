using AclMap.Models.Security;

namespace AclMap.Models.Snapshot;

/// <summary>Type de partage (NetShareEnum, champ shi_type).</summary>
public enum ShareKind { Disk, Print, Device, Ipc, Other }

/// <summary>Partage SMB d'un serveur de fichiers.</summary>
public sealed record ShareInfo
{
    public string Server { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>Chemin local sur le serveur (ex. D:\Administration), ou nom de la file pour une imprimante.</summary>
    public string? LocalPath { get; init; }
    public ShareKind Kind { get; init; }
    /// <summary>Partage spécial (C$, ADMIN$, IPC$…).</summary>
    public bool Special { get; init; }
    public string? Remark { get; init; }
    /// <summary>Droits de partage (null si illisibles : droits d'administrateur du serveur requis).</summary>
    public SecurityDescriptorInfo? Security { get; init; }
    /// <summary>Raison de l'illisibilité des droits.</summary>
    public string? SecurityError { get; init; }
    /// <summary>Dossier de l'instantané correspondant à la racine du partage (null si hors analyse).</summary>
    public int? RootFolderId { get; init; }
    /// <summary>Partage parent quand ce partage est un sous-dossier d'un autre partage.</summary>
    public string? NestedIn { get; init; }

    /// <summary>Chemin UNC du partage.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string Unc => $@"\\{Server}\{Name}";
}
