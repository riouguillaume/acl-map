using System.Text.Json.Serialization;

namespace AclMap.Models.Security;

/// <summary>
/// Descripteur de sécurité décodé (propriétaire, groupe, DACL). Dans un instantané, chaque descripteur distinct
/// n'est stocké qu'une fois et les dossiers y font référence par <see cref="Id"/>.
/// </summary>
public sealed record SecurityDescriptorInfo
{
    /// <summary>Identifiant dans l'instantané.</summary>
    public int Id { get; init; }

    /// <summary>SID du propriétaire (null si non lu).</summary>
    public string? Owner { get; init; }

    /// <summary>SID du groupe principal (sans effet sur NTFS, conservé pour la fidélité du SDDL).</summary>
    public string? Group { get; init; }

    /// <summary>Champ Control brut (SE_DACL_PRESENT, SE_DACL_PROTECTED…).</summary>
    public ushort Control { get; init; }

    /// <summary>Faux si la DACL est absente (DACL nulle : accès total pour tous).</summary>
    public bool DaclPresent { get; init; } = true;

    /// <summary>Entrées de la DACL, dans l'ordre d'évaluation.</summary>
    public IReadOnlyList<AceInfo> Aces { get; init; } = [];

    /// <summary>Vrai si l'héritage est désactivé sur l'objet (SE_DACL_PROTECTED).</summary>
    [JsonIgnore]
    public bool Protected => (Control & SdControl.DaclProtected) != 0;

    /// <summary>Représentation SDDL normalisée (SID complets, masques hexadécimaux).</summary>
    public string Sddl { get; init; } = "";
}

/// <summary>Bits du champ Control d'un descripteur de sécurité.</summary>
public static class SdControl
{
    public const ushort OwnerDefaulted = 0x0001;
    public const ushort GroupDefaulted = 0x0002;
    public const ushort DaclPresent = 0x0004;
    public const ushort DaclDefaulted = 0x0008;
    public const ushort SaclPresent = 0x0010;
    public const ushort DaclAutoInheritReq = 0x0100;
    public const ushort DaclAutoInherited = 0x0400;
    public const ushort DaclProtected = 0x1000;
    public const ushort SelfRelative = 0x8000;
}
