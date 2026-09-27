using System.Net;
using System.Text.RegularExpressions;

namespace AclMap.Core.Validation;

/// <summary>Validation des saisies (profils, chemins). Messages en français, prêts à afficher.</summary>
public static partial class InputValidator
{
    [GeneratedRegex(@"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")]
    private static partial Regex FqdnRegex();

    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9-]{0,14})$")]
    private static partial Regex NetbiosRegex();

    [GeneratedRegex(@"^[^\\/:*?""<>|@\s][^\\/:*?""<>|@]{0,63}\\[^\\/:*?""<>|@\[\]+=;,]{1,104}$")]
    private static partial Regex DownLevelRegex();

    [GeneratedRegex(@"^[^\\/:*?""<>|@\s]{1,104}@[A-Za-z0-9.-]{1,253}$")]
    private static partial Regex UpnRegex();

    [GeneratedRegex(@"^[^\\/:*?""<>|\x00-\x1F]+$")]
    private static partial Regex SegmentRegex();

    /// <summary>Nom de domaine DNS (FQDN).</summary>
    public static string? Domain(string? v) =>
        string.IsNullOrWhiteSpace(v) ? "Le nom du domaine est obligatoire (ex. contoso.local)."
        : FqdnRegex().IsMatch(v.Trim()) ? null : "Nom de domaine invalide : saisissez le FQDN (ex. contoso.local).";

    /// <summary>Serveur : nom NetBIOS, FQDN ou adresse IP.</summary>
    public static string? Server(string? v, bool required = true)
    {
        if (string.IsNullOrWhiteSpace(v)) return required ? "Le nom du serveur est obligatoire (ex. FS01.contoso.local)." : null;
        var s = v.Trim();
        if (IPAddress.TryParse(s, out _) || FqdnRegex().IsMatch(s) || NetbiosRegex().IsMatch(s)) return null;
        return "Nom de serveur invalide : nom court (FS01), FQDN (FS01.contoso.local) ou adresse IP.";
    }

    /// <summary>Compte DOMAINE\compte ou UPN.</summary>
    public static string? Account(string? v) =>
        string.IsNullOrWhiteSpace(v) ? "Le compte est obligatoire (ex. CONTOSO\\audit ou audit@contoso.local)."
        : DownLevelRegex().IsMatch(v.Trim()) || UpnRegex().IsMatch(v.Trim()) ? null
        : "Compte invalide : utilisez DOMAINE\\compte ou compte@domaine.";

    /// <summary>Chemin UNC \\serveur\partage[\dossier…].</summary>
    public static string? Unc(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "Le chemin est obligatoire (ex. \\\\FS01\\Donnees).";
        var p = v.Trim().TrimEnd('\\');
        if (!p.StartsWith(@"\\", StringComparison.Ordinal) || p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal))
            return "Chemin réseau attendu : \\\\serveur\\partage\\dossier.";
        var parts = p[2..].Split('\\');
        if (parts.Length < 2) return "Indiquez au moins le serveur et le partage : \\\\serveur\\partage.";
        if (Server(parts[0]) is not null) return "Nom de serveur invalide dans le chemin.";
        if (parts.Skip(1).Any(s => s.Length == 0 || s is "." or ".." || !SegmentRegex().IsMatch(s))) return "Le chemin contient un nom de dossier invalide.";
        return null;
    }

    /// <summary>Chemin local absolu (C:\… ) ou UNC.</summary>
    public static string? ScanPath(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "Le chemin est obligatoire.";
        var p = v.Trim();
        if (p.StartsWith(@"\\", StringComparison.Ordinal)) return Unc(p);
        if (p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\')
            return p[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries).Any(s => s is "." or ".." || !SegmentRegex().IsMatch(s)) ? "Le chemin contient un nom de dossier invalide." : null;
        return "Chemin invalide : \\\\serveur\\partage\\dossier ou D:\\dossier.";
    }

    /// <summary>Dossier de sortie : chemin absolu local ou UNC.</summary>
    public static string? OutputFolder(string? v) =>
        string.IsNullOrWhiteSpace(v) ? null : ScanPath(v) is null ? null : "Dossier de sortie invalide : chemin complet attendu (ex. D:\\Audits\\Contoso).";

    /// <summary>Nom de groupe AD (sAMAccountName).</summary>
    public static string? GroupName(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "Le nom du groupe est obligatoire.";
        var s = v.Trim();
        if (s.Length > 64) return "Nom de groupe trop long (64 caractères maximum).";
        if (s.IndexOfAny(['"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@']) >= 0 || s.EndsWith('.')) return "Le nom du groupe contient un caractère interdit (\" / \\ [ ] : ; | = , + * ? < > @).";
        return null;
    }

    /// <summary>Découpe un chemin UNC en (serveur, partage, reste).</summary>
    public static (string Server, string Share, string SubPath)? SplitUnc(string unc)
    {
        if (Unc(unc) is not null) return null;
        var parts = unc.Trim().TrimEnd('\\')[2..].Split('\\');
        return (parts[0], parts[1], string.Join('\\', parts.Skip(2)));
    }
}
