using System.Text.Json.Serialization;

namespace AclMap.Models.Security;

/// <summary>Type d'une entrée de contrôle d'accès (ACE) NTFS ou de partage.</summary>
public enum AceKind
{
    /// <summary>ACCESS_ALLOWED_ACE (type 0).</summary>
    Allow = 0,
    /// <summary>ACCESS_DENIED_ACE (type 1).</summary>
    Deny = 1,
    /// <summary>ACCESS_ALLOWED_CALLBACK_ACE (type 9) : ACE conditionnelle (DAC, claims).</summary>
    AllowCallback = 9,
    /// <summary>ACCESS_DENIED_CALLBACK_ACE (type 10) : ACE conditionnelle.</summary>
    DenyCallback = 10,
    /// <summary>Autre type (objet, audit, étiquette…) : conservé mais ignoré par le calcul d'accès.</summary>
    Other = 255,
}

/// <summary>Drapeaux d'héritage d'une ACE (octet AceFlags).</summary>
[Flags]
public enum AceFlags : byte
{
    None = 0,
    /// <summary>OI : hérité par les fichiers.</summary>
    ObjectInherit = 0x01,
    /// <summary>CI : hérité par les sous-dossiers.</summary>
    ContainerInherit = 0x02,
    /// <summary>NP : ne se propage qu'au niveau suivant.</summary>
    NoPropagateInherit = 0x04,
    /// <summary>IO : ne s'applique pas à l'objet lui-même (modèle d'héritage seulement).</summary>
    InheritOnly = 0x08,
    /// <summary>ID : ACE héritée d'un parent.</summary>
    Inherited = 0x10,
}

/// <summary>
/// Entrée de contrôle d'accès décodée. <see cref="Mask"/> est le masque brut tel qu'il est stocké (droits génériques
/// éventuels non convertis) ; la conversion est faite par le moteur d'accès.
/// </summary>
/// <param name="Kind">Type (autorisation, refus, conditionnelle…).</param>
/// <param name="Sid">SID de l'identité (forme S-1-…).</param>
/// <param name="Mask">Masque d'accès brut.</param>
/// <param name="Flags">Drapeaux d'héritage.</param>
/// <param name="RawType">Type binaire d'origine (utile pour <see cref="AceKind.Other"/>).</param>
public sealed record AceInfo(AceKind Kind, string Sid, uint Mask, AceFlags Flags, byte RawType = 0)
{
    /// <summary>Vrai si l'ACE est héritée d'un dossier parent.</summary>
    [JsonIgnore]
    public bool IsInherited => (Flags & AceFlags.Inherited) != 0;

    /// <summary>Vrai si l'ACE ne s'applique pas au dossier lui-même.</summary>
    [JsonIgnore]
    public bool IsInheritOnly => (Flags & AceFlags.InheritOnly) != 0;

    /// <summary>Vrai pour une autorisation (simple ou conditionnelle).</summary>
    [JsonIgnore]
    public bool IsAllow => Kind is AceKind.Allow or AceKind.AllowCallback;

    /// <summary>Vrai pour un refus (simple ou conditionnel).</summary>
    [JsonIgnore]
    public bool IsDeny => Kind is AceKind.Deny or AceKind.DenyCallback;

    /// <summary>Vrai pour une ACE conditionnelle (le calcul exact dépend des revendications du jeton).</summary>
    [JsonIgnore]
    public bool IsConditional => Kind is AceKind.AllowCallback or AceKind.DenyCallback;
}
