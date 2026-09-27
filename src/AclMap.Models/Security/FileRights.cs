namespace AclMap.Models.Security;

/// <summary>Droits d'accès des fichiers et dossiers (winnt.h), et combinaisons affichées par l'Explorateur Windows.</summary>
public static class FileRights
{
    public const uint ListDirectory = 0x0001;      // lire les données / lister le dossier
    public const uint AddFile = 0x0002;            // écrire les données / créer des fichiers
    public const uint AddSubdirectory = 0x0004;    // ajouter des données / créer des dossiers
    public const uint ReadEa = 0x0008;
    public const uint WriteEa = 0x0010;
    public const uint Traverse = 0x0020;           // exécuter / parcourir
    public const uint DeleteChild = 0x0040;
    public const uint ReadAttributes = 0x0080;
    public const uint WriteAttributes = 0x0100;
    public const uint Delete = 0x00010000;
    public const uint ReadControl = 0x00020000;    // lire les autorisations
    public const uint WriteDac = 0x00040000;       // modifier les autorisations
    public const uint WriteOwner = 0x00080000;     // appropriation
    public const uint Synchronize = 0x00100000;
    public const uint AccessSystemSecurity = 0x01000000;
    public const uint GenericAll = 0x10000000;
    public const uint GenericExecute = 0x20000000;
    public const uint GenericWrite = 0x40000000;
    public const uint GenericRead = 0x80000000;

    /// <summary>Contrôle total.</summary>
    public const uint FullControl = 0x001F01FF;
    /// <summary>Modification.</summary>
    public const uint Modify = 0x001301BF;
    /// <summary>Lecture et exécution (= « Afficher le contenu du dossier » pour un dossier).</summary>
    public const uint ReadAndExecute = 0x001200A9;
    /// <summary>Lecture.</summary>
    public const uint Read = 0x00120089;
    /// <summary>Écriture.</summary>
    public const uint Write = 0x00100116;
    /// <summary>FILE_GENERIC_READ.</summary>
    public const uint FileGenericRead = 0x00120089;
    /// <summary>FILE_GENERIC_WRITE.</summary>
    public const uint FileGenericWrite = 0x00120116;
    /// <summary>FILE_GENERIC_EXECUTE.</summary>
    public const uint FileGenericExecute = 0x001200A0;
    /// <summary>Bits d'écriture « de données » (création, écriture, ajout, suppression).</summary>
    public const uint AnyWrite = AddFile | AddSubdirectory | WriteEa | WriteAttributes | Delete | DeleteChild | WriteDac | WriteOwner;

    /// <summary>Droits de partage « Contrôle total ».</summary>
    public const uint ShareFull = 0x001F01FF;
    /// <summary>Droits de partage « Modifier ».</summary>
    public const uint ShareChange = 0x001301BF;
    /// <summary>Droits de partage « Lire ».</summary>
    public const uint ShareRead = 0x001200A9;
}
