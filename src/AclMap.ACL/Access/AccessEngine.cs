using AclMap.Core.Security;
using AclMap.Models.Analysis;
using AclMap.Models.Security;

namespace AclMap.ACL.Access;

/// <summary>Résultat d'une évaluation d'accès.</summary>
/// <param name="Granted">Droits accordés (masque spécifique, génériques convertis).</param>
/// <param name="Denied">Droits retirés par un refus.</param>
/// <param name="Level">Niveau lisible.</param>
/// <param name="Flags">Précisions (refus, ambiguïté, propriétaire…).</param>
public readonly record struct AccessResult(uint Granted, uint Denied, AccessLevel Level, AccessFlags Flags)
{
    /// <summary>Accès inconnu (descripteur illisible).</summary>
    public static readonly AccessResult Unknown = new(0, 0, AccessLevel.None, AccessFlags.Unknown);
}

/// <summary>Rôle d'une ACE dans une évaluation.</summary>
public enum AceEffect { NotApplicable, InheritOnly, Grants, Denies, NoEffect, Conditional, Uncertain }

/// <summary>Contribution d'une ACE au résultat (explication).</summary>
public sealed record AceContribution(int Index, AceInfo Ace, AceEffect Effect, uint Bits, IReadOnlyList<string> MembershipPath, string Note);

/// <summary>
/// Moteur d'accès effectif NTFS / partage. Il reproduit l'évaluation de Windows pour MAXIMUM_ALLOWED :
/// les ACE sont lues dans l'ordre ; pour chaque droit, la première ACE applicable (autorisation ou refus) l'emporte.
/// Les ACE « héritage seulement » sont ignorées, les droits génériques convertis, et le propriétaire reçoit
/// implicitement « Lire » et « Modifier les autorisations » sauf ACE DROITS DU PROPRIÉTAIRE.
/// </summary>
public static class AccessEngine
{
    private const uint OwnerImplicit = FileRights.ReadControl | FileRights.WriteDac;

    /// <summary>Évalue un descripteur pour un jeton.</summary>
    public static AccessResult Evaluate(SecurityDescriptorInfo? sd, Token token) => Evaluate(sd, token, null);

    /// <summary>Évalue en collectant éventuellement l'explication ACE par ACE.</summary>
    public static AccessResult Evaluate(SecurityDescriptorInfo? sd, Token token, List<AceContribution>? explain)
    {
        if (sd is null) return AccessResult.Unknown;
        if (!sd.DaclPresent) return new(FileRights.FullControl, 0, AccessLevel.Full, AccessFlags.NullDacl | AccessFlags.CanChangePermissions);
        uint granted = 0, denied = 0;
        var flags = AccessFlags.None;
        var isOwner = sd.Owner is not null && token.Contains(sd.Owner);
        var ownerRightsAce = sd.Aces.Any(a => !a.IsInheritOnly && a.Sid.Equals(WellKnownSids.OwnerRights, StringComparison.OrdinalIgnoreCase));
        for (var i = 0; i < sd.Aces.Count; i++)
        {
            var a = sd.Aces[i];
            if (a.Kind == AceKind.Other) { explain?.Add(new(i, a, AceEffect.NotApplicable, 0, [], "Type d'ACE sans effet sur un dossier.")); continue; }
            var matchSid = a.Sid.Equals(WellKnownSids.OwnerRights, StringComparison.OrdinalIgnoreCase) ? (isOwner ? sd.Owner! : null) : a.Sid;
            var matched = matchSid is not null && token.Contains(matchSid);
            if (a.IsInheritOnly)
            {
                if (matched) explain?.Add(new(i, a, AceEffect.InheritOnly, 0, token.PathTo(matchSid!), "Modèle d'héritage : s'applique aux sous-dossiers/fichiers, pas à ce dossier."));
                continue;
            }
            if (!matched)
            {
                if (token.Uncertain.Contains(a.Sid))
                {
                    flags |= AccessFlags.Ambiguous;
                    explain?.Add(new(i, a, AceEffect.Uncertain, 0, [], "Appartenance à ce groupe inconnue : l'identité en fait peut-être partie."));
                }
                continue;
            }
            var path = token.PathTo(matchSid!);
            if (a.IsConditional)
            {
                flags |= AccessFlags.Ambiguous;
                explain?.Add(new(i, a, AceEffect.Conditional, 0, path, "ACE conditionnelle (revendications, DAC) : effet non calculable hors ligne."));
                continue;
            }
            var m = Rights.MapGeneric(a.Mask);
            if (a.IsAllow)
            {
                var add = m & ~denied & ~granted;
                granted |= m & ~denied;
                explain?.Add(new(i, a, add != 0 ? AceEffect.Grants : AceEffect.NoEffect, add, path, add != 0 ? "" : "Droits déjà accordés ou refusés par une ACE précédente."));
            }
            else
            {
                var rem = m & ~granted & ~denied;
                denied |= m & ~granted;
                if (rem != 0) flags |= AccessFlags.Denied;
                explain?.Add(new(i, a, rem != 0 ? AceEffect.Denies : AceEffect.NoEffect, rem, path, rem != 0 ? "" : "Refus sans effet : droits déjà accordés par une ACE précédente (ordre non canonique)."));
            }
        }
        if (isOwner && !ownerRightsAce)
        {
            var add = OwnerImplicit & ~denied & ~granted;
            if (add != 0) { granted |= add; flags |= AccessFlags.AsOwner; }
        }
        if ((granted & (FileRights.WriteDac | FileRights.WriteOwner)) != 0) flags |= AccessFlags.CanChangePermissions;
        return new(granted, denied, Rights.LevelOf(granted), flags);
    }

    /// <summary>Combine l'accès NTFS et l'accès au partage : c'est l'intersection qui s'applique par le réseau.</summary>
    public static AccessResult Combine(AccessResult ntfs, AccessResult share)
    {
        if ((ntfs.Flags & AccessFlags.Unknown) != 0) return ntfs;
        if ((share.Flags & AccessFlags.Unknown) != 0) return ntfs with { Flags = ntfs.Flags | AccessFlags.Ambiguous };
        var g = ntfs.Granted & share.Granted;
        var f = (ntfs.Flags | share.Flags) & ~(AccessFlags.CanChangePermissions | AccessFlags.NullDacl);
        if ((g & (FileRights.WriteDac | FileRights.WriteOwner)) != 0) f |= AccessFlags.CanChangePermissions;
        if ((ntfs.Flags & AccessFlags.NullDacl) != 0) f |= AccessFlags.NullDacl;
        return new(g, ntfs.Denied | share.Denied, Rights.LevelOf(g), f);
    }

    /// <summary>Vrai si l'ordre des ACE explicites est canonique (refus explicites, puis autorisations explicites, puis ACE héritées).</summary>
    public static bool IsCanonical(SecurityDescriptorInfo sd)
    {
        var seenInherited = false; var seenAllow = false;
        foreach (var a in sd.Aces)
        {
            if (a.IsInherited) { seenInherited = true; continue; }
            if (seenInherited) return false;
            if (a.IsAllow) seenAllow = true;
            else if (a.IsDeny && seenAllow) return false;
        }
        return true;
    }
}
