namespace AclMap.FileSystem;

/// <summary>Sous-dossier proposé par le sélecteur de chemin.</summary>
public sealed record BrowseEntry(string Name, bool Reparse);

/// <summary>Parcours d'un niveau d'arborescence pour le sélecteur de chemin de l'interface.</summary>
public static class FolderBrowser
{
    /// <summary>Sous-dossiers directs.</summary>
    /// <exception cref="System.ComponentModel.Win32Exception">Dossier inaccessible.</exception>
    public static List<BrowseEntry> List(string path)
    {
        using var h = SecurityReader.Open(path, Native.FILE_LIST_DIRECTORY, false, out var err);
        if (h.IsInvalid) throw new System.ComponentModel.Win32Exception(err, SecurityReader.Describe(err));
        return SecurityReader.List(h).Where(e => e.IsDirectory).OrderBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(e => new BrowseEntry(e.Name, e.IsReparsePoint)).ToList();
    }
}
