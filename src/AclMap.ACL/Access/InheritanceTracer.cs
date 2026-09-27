using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Security;

namespace AclMap.ACL.Access;

/// <summary>Retrouve le dossier d'origine d'une ACE héritée (meilleur effort, à partir des ancêtres analysés).</summary>
public static class InheritanceTracer
{
    /// <summary>Résultat : dossier d'origine, ou null si l'ACE vient d'au-dessus de la racine analysée.</summary>
    /// <param name="FolderId">Dossier portant l'ACE explicite.</param>
    /// <param name="Certain">Faux si plusieurs ACE comparables rendent l'attribution incertaine.</param>
    public sealed record Origin(int? FolderId, bool Certain);

    /// <summary>Cherche l'ancêtre le plus proche portant la même ACE en explicite et transmissible.</summary>
    public static Origin Find(SnapshotIndex index, int folderId, AceInfo ace)
    {
        if (!ace.IsInherited) return new(folderId, true);
        var target = Rights.MapGeneric(ace.Mask);
        for (var p = index.Parent(folderId); p >= 0; p = index.Parent(p))
        {
            var sd = index.Descriptor(p);
            if (sd is null) return new(null, false);
            var candidates = sd.Aces.Where(a => a.Kind == ace.Kind && a.Sid.Equals(ace.Sid, StringComparison.OrdinalIgnoreCase)
                && (a.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) != 0).ToList();
            var explicitMatch = candidates.FirstOrDefault(a => !a.IsInherited && Rights.MapGeneric(a.Mask) == target);
            if (explicitMatch is not null) return new(p, candidates.Count(a => !a.IsInherited) == 1);
            if (!candidates.Any(a => a.IsInherited)) return new(p, false); // l'ACE a changé de forme (générique, CREATOR OWNER…)
            if (sd.Protected) return new(null, false);
        }
        return new(null, true);
    }
}
