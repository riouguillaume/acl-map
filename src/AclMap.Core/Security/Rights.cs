using AclMap.Models.Analysis;
using AclMap.Models.Security;

namespace AclMap.Core.Security;

/// <summary>Traduction des masques d'accès en niveaux et textes lisibles (termes de l'Explorateur Windows).</summary>
public static class Rights
{
    /// <summary>Convertit les droits génériques (GENERIC_*) en droits spécifiques aux fichiers.</summary>
    public static uint MapGeneric(uint mask)
    {
        var m = mask & 0x0FFFFFFF;
        if ((mask & FileRights.GenericRead) != 0) m |= FileRights.FileGenericRead;
        if ((mask & FileRights.GenericWrite) != 0) m |= FileRights.FileGenericWrite;
        if ((mask & FileRights.GenericExecute) != 0) m |= FileRights.FileGenericExecute;
        if ((mask & FileRights.GenericAll) != 0) m |= FileRights.FullControl;
        return m & ~FileRights.AccessSystemSecurity;
    }

    private static bool Has(uint m, uint r) => (m & r) == r;

    /// <summary>Niveau standard le plus élevé entièrement contenu dans le masque.</summary>
    public static AccessLevel LevelOf(uint mask)
    {
        var m = MapGeneric(mask) | FileRights.Synchronize; // SYNCHRONIZE n'est jamais déterminant
        if (Has(m, FileRights.FullControl)) return AccessLevel.Full;
        if (Has(m, FileRights.Modify)) return AccessLevel.Modify;
        if (Has(m, FileRights.Read | FileRights.Write)) return AccessLevel.Write;
        if (Has(m, FileRights.ReadAndExecute)) return AccessLevel.ReadExecute;
        if (Has(m, FileRights.Read)) return AccessLevel.Read;
        if ((m & FileRights.ListDirectory) != 0) return AccessLevel.List;
        return (MapGeneric(mask) & ~FileRights.Synchronize) != 0 ? AccessLevel.Special : AccessLevel.None;
    }

    /// <summary>Libellé français d'un niveau.</summary>
    public static string LevelLabel(AccessLevel l) => l switch
    {
        AccessLevel.Full => "Contrôle total",
        AccessLevel.Modify => "Modification",
        AccessLevel.Write => "Lecture et écriture",
        AccessLevel.ReadExecute => "Lecture et exécution",
        AccessLevel.Read => "Lecture",
        AccessLevel.List => "Liste du dossier",
        AccessLevel.Special => "Autorisations spéciales",
        _ => "Aucun accès",
    };

    /// <summary>Libellé court (matrices, CSV).</summary>
    public static string LevelShort(AccessLevel l) => l switch
    {
        AccessLevel.Full => "CT", AccessLevel.Modify => "M", AccessLevel.Write => "LE", AccessLevel.ReadExecute => "LX",
        AccessLevel.Read => "L", AccessLevel.List => "Li", AccessLevel.Special => "S", _ => "",
    };

    /// <summary>Libellé d'un masque de partage.</summary>
    public static string ShareLabel(uint mask)
    {
        var m = MapGeneric(mask) | FileRights.Synchronize;
        if (Has(m, FileRights.ShareFull)) return "Contrôle total";
        if (Has(m, FileRights.ShareChange)) return "Modifier";
        if (Has(m, FileRights.ShareRead)) return "Lecture";
        return "Spécial (0x" + mask.ToString("x") + ")";
    }

    private static readonly (uint Bit, string Label)[] Bits =
    [
        (FileRights.ListDirectory, "Lister le dossier / lire les données"),
        (FileRights.AddFile, "Créer des fichiers / écrire des données"),
        (FileRights.AddSubdirectory, "Créer des dossiers / ajouter des données"),
        (FileRights.ReadEa, "Lire les attributs étendus"),
        (FileRights.WriteEa, "Écrire les attributs étendus"),
        (FileRights.Traverse, "Parcourir le dossier / exécuter"),
        (FileRights.DeleteChild, "Supprimer les sous-dossiers et fichiers"),
        (FileRights.ReadAttributes, "Lire les attributs"),
        (FileRights.WriteAttributes, "Écrire les attributs"),
        (FileRights.Delete, "Supprimer"),
        (FileRights.ReadControl, "Lire les autorisations"),
        (FileRights.WriteDac, "Modifier les autorisations"),
        (FileRights.WriteOwner, "Appropriation"),
    ];

    /// <summary>Détail des droits élémentaires d'un masque.</summary>
    public static IReadOnlyList<string> Describe(uint mask)
    {
        var m = MapGeneric(mask);
        return Bits.Where(b => (m & b.Bit) != 0).Select(b => b.Label).ToList();
    }

    /// <summary>Résumé d'un masque : niveau standard, ou « Spécial : … ».</summary>
    public static string Summary(uint mask)
    {
        var l = LevelOf(mask);
        var m = MapGeneric(mask) | FileRights.Synchronize;
        var std = l switch
        {
            AccessLevel.Full => FileRights.FullControl, AccessLevel.Modify => FileRights.Modify, AccessLevel.Write => FileRights.Read | FileRights.Write,
            AccessLevel.ReadExecute => FileRights.ReadAndExecute, AccessLevel.Read => FileRights.Read, _ => 0u,
        };
        if (std != 0 && (m & ~std) == 0) return LevelLabel(l);
        if (l is AccessLevel.None) return LevelLabel(l);
        var extra = Describe(m & ~std);
        return std == 0 ? "Spécial : " + string.Join(", ", Describe(m)) : LevelLabel(l) + " + " + string.Join(", ", extra);
    }

    /// <summary>« S'applique à » d'une ACE, comme dans l'onglet Sécurité avancée.</summary>
    public static string AppliesTo(AceFlags f)
    {
        var oi = (f & AceFlags.ObjectInherit) != 0;
        var ci = (f & AceFlags.ContainerInherit) != 0;
        var io = (f & AceFlags.InheritOnly) != 0;
        var s = (oi, ci, io) switch
        {
            (true, true, false) => "Ce dossier, les sous-dossiers et les fichiers",
            (false, true, false) => "Ce dossier et les sous-dossiers",
            (true, false, false) => "Ce dossier et les fichiers",
            (true, true, true) => "Les sous-dossiers et les fichiers uniquement",
            (false, true, true) => "Les sous-dossiers uniquement",
            (true, false, true) => "Les fichiers uniquement",
            _ => "Ce dossier seulement",
        };
        return (f & AceFlags.NoPropagateInherit) != 0 && (oi || ci) ? s + " (un seul niveau)" : s;
    }

    /// <summary>Drapeaux correspondant à une portée choisie dans l'interface.</summary>
    public static AceFlags FlagsFor(string scope) => scope switch
    {
        "ThisFolderSubfoldersFiles" => AceFlags.ObjectInherit | AceFlags.ContainerInherit,
        "ThisFolderSubfolders" => AceFlags.ContainerInherit,
        "ThisFolderFiles" => AceFlags.ObjectInherit,
        "SubfoldersFiles" => AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly,
        "SubfoldersOnly" => AceFlags.ContainerInherit | AceFlags.InheritOnly,
        "FilesOnly" => AceFlags.ObjectInherit | AceFlags.InheritOnly,
        "ThisFolderOnly" => AceFlags.None,
        _ => throw new ArgumentException($"Portée inconnue : {scope}", nameof(scope)),
    };

    /// <summary>Masque d'un niveau choisi dans l'interface.</summary>
    public static uint MaskFor(AccessLevel level) => level switch
    {
        AccessLevel.Full => FileRights.FullControl,
        AccessLevel.Modify => FileRights.Modify,
        AccessLevel.Write => FileRights.Read | FileRights.Write,
        AccessLevel.ReadExecute => FileRights.ReadAndExecute,
        AccessLevel.Read => FileRights.Read,
        AccessLevel.List => FileRights.ReadAndExecute,
        _ => throw new ArgumentException("Niveau non attribuable.", nameof(level)),
    };
}
