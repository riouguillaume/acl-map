using System.Text.Json;
using System.Text.Json.Serialization;
using AclMap.Core.Validation;
using AclMap.Models.Snapshot;

namespace AclMap.Hosting;

/// <summary>Mode de connexion.</summary>
public enum ConnectionMode
{
    /// <summary>Session Windows actuelle.</summary>
    CurrentUser,
    /// <summary>Autre compte du domaine (« runas /netonly »), mot de passe demandé et gardé en mémoire le temps de la session.</summary>
    AlternateAccount,
}

/// <summary>Serveur de fichiers d'un profil.</summary>
public sealed record FileServerEntry
{
    public string Server { get; init; } = "";
    public List<string> Favorites { get; init => field = value ?? []; } = [];
    public bool IncludePrintShares { get; init; }
    public bool IncludeSpecialShares { get; init; }
}

/// <summary>Profil de domaine : domaine, contrôleur, compte, serveurs de fichiers. Aucun mot de passe.</summary>
public sealed record DomainProfile
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Name { get; init; } = "";
    public string? DomainName { get; init; }
    public string? DomainController { get; init; }
    public ConnectionMode ConnectionMode { get; init; } = ConnectionMode.CurrentUser;
    public string? AccountName { get; init; }
    public List<FileServerEntry> FileServers { get; init => field = value ?? []; } = [];
    public string? OutputFolder { get; init; }
    /// <summary>Compte délégué pour les modifications (vide = compte de connexion).</summary>
    public string? WriteAccountName { get; init; }
    /// <summary>OU de destination des groupes créés.</summary>
    public string? GroupsOu { get; init; }
    public DateTimeOffset? LastCollectedUtc { get; init; }
    public string? LastSnapshotPath { get; init; }
    public string? LastPath { get; init; }

    /// <summary>Contrôles de saisie (liste vide = profil valide).</summary>
    public Dictionary<string, string> Validate()
    {
        var e = new Dictionary<string, string>();
        if (string.IsNullOrWhiteSpace(Name)) e["name"] = "Donnez un nom au profil (ex. Contoso – production).";
        if (ConnectionMode == ConnectionMode.AlternateAccount || !string.IsNullOrWhiteSpace(DomainName))
            if (InputValidator.Domain(DomainName) is { } d) e["domainName"] = d;
        if (InputValidator.Server(DomainController, required: false) is { } dc) e["domainController"] = dc;
        if (ConnectionMode == ConnectionMode.AlternateAccount && InputValidator.Account(AccountName) is { } a) e["accountName"] = a;
        if (!string.IsNullOrWhiteSpace(WriteAccountName) && InputValidator.Account(WriteAccountName) is { } w) e["writeAccountName"] = w;
        if (InputValidator.OutputFolder(OutputFolder) is { } o) e["outputFolder"] = o;
        for (var i = 0; i < FileServers.Count; i++)
        {
            if (InputValidator.Server(FileServers[i].Server) is { } s) e[$"servers.{i}"] = s;
            foreach (var f in FileServers[i].Favorites) if (InputValidator.ScanPath(f) is { } fe) { e[$"servers.{i}.favorites"] = fe; break; }
        }
        if (FileServers.Select(f => f.Server.Trim()).GroupBy(s => s, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1)) e["servers"] = "Un serveur figure deux fois.";
        return e;
    }

    /// <summary>Profil nettoyé (espaces).</summary>
    public DomainProfile Normalize() => this with
    {
        Name = Name.Trim(), DomainName = Blank(DomainName), DomainController = Blank(DomainController), AccountName = Blank(AccountName),
        WriteAccountName = Blank(WriteAccountName), OutputFolder = Blank(OutputFolder), GroupsOu = Blank(GroupsOu),
        FileServers = FileServers.Where(f => !string.IsNullOrWhiteSpace(f.Server)).Select(f => f with { Server = f.Server.Trim(), Favorites = f.Favorites.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() }).ToList(),
    };

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}

/// <summary>Paramètres de l'application (aucun secret).</summary>
public sealed record AppSettings
{
    public List<DomainProfile> Profiles { get; init => field = value ?? []; } = [];
    public string? ActiveProfileId { get; init; }
    public bool QuickConnectDone { get; init; }
    /// <summary>Modifications autorisées (désactivé par défaut : lecture seule).</summary>
    public bool WriteEnabled { get; init; }
    public string GgTemplate { get; init; } = "GG_{Metier}";
    public string DlTemplate { get; init; } = "DL_{Partage}-{Dossier}_{Droit}";
    public ScanOptions DefaultScan { get; init; } = new();
    public string? BackupFolder { get; init; }
    public List<string> RecentSnapshots { get; init => field = value ?? []; } = [];

    [JsonIgnore]
    public DomainProfile? ActiveProfile => Profiles.FirstOrDefault(p => p.Id == ActiveProfileId) ?? Profiles.FirstOrDefault();
}

/// <summary>Lecture / écriture de %APPDATA%\AclMap\settings.json.</summary>
public sealed class SettingsStore(string path)
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, Converters = { new JsonStringEnumConverter() },
    };

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AclMap", "settings.json");

    public AppSettings Load()
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Options) ?? new() : new(); }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return new(); }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Options));
        File.Move(tmp, path, overwrite: true);
    }
}
