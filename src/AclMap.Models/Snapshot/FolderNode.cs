namespace AclMap.Models.Snapshot;

/// <summary>État d'un nœud de l'arborescence analysée.</summary>
[Flags]
public enum NodeFlags
{
    None = 0,
    /// <summary>Fichier (analyse des fichiers activée).</summary>
    File = 1,
    /// <summary>Point de jonction / lien symbolique : signalé, jamais suivi.</summary>
    ReparsePoint = 2,
    /// <summary>Contenu non listable (accès refusé).</summary>
    ListDenied = 4,
    /// <summary>Descripteur de sécurité illisible.</summary>
    SecurityUnreadable = 8,
    /// <summary>Chemin de 260 caractères ou plus.</summary>
    LongPath = 16,
    /// <summary>Profondeur maximale atteinte : sous-dossiers non analysés.</summary>
    DepthLimit = 32,
    /// <summary>Lu grâce au mode sauvegarde (SeBackupPrivilege).</summary>
    ReadWithBackup = 64,
    /// <summary>Autre erreur de lecture.</summary>
    Error = 128,
}

/// <summary>
/// Dossier (ou fichier) de l'arborescence. Le chemin complet se reconstitue par les parents ; le descripteur de
/// sécurité est référencé par <see cref="SdId"/> (-1 si illisible).
/// </summary>
/// <param name="Id">Identifiant (0 = racine analysée).</param>
/// <param name="ParentId">Parent (-1 pour la racine).</param>
/// <param name="Name">Nom (chemin complet pour la racine).</param>
/// <param name="SdId">Descripteur de sécurité, ou -1.</param>
/// <param name="Flags">État.</param>
public sealed record FolderNode(int Id, int ParentId, string Name, int SdId, NodeFlags Flags);
