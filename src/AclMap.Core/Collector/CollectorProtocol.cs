using AclMap.Models.Snapshot;

namespace AclMap.Core.Collector;

/// <summary>
/// Requête transmise au collecteur (fichier JSON passé par --request). Elle ne contient jamais de mot de passe :
/// en mode « autre compte », le collecteur est lancé en « runas /netonly » par l'application.
/// </summary>
public sealed record CollectorRequest
{
    /// <summary>scan, browse, shares, servers, test, search, ous, apply, restore, authz.</summary>
    public string Verb { get; init; } = "";
    public string? Path { get; init; }
    public string? Server { get; init; }
    public List<string>? Servers { get; init; }
    public string? Domain { get; init; }
    public string? DomainController { get; init; }
    /// <summary>Compte réseau utilisé (information, pour identifier le compte de collecte dans l'instantané).</summary>
    public string? AccountName { get; init; }
    public string? OutputFolder { get; init; }
    public ScanOptions? Scan { get; init; }
    public string? Text { get; init; }
    public string? Kind { get; init; }
    public string? Sid { get; init; }
    public string? PlanFile { get; init; }
    public string? BackupFile { get; init; }
    public string? BackupFolder { get; init; }
    public bool DryRun { get; init; }
}

/// <summary>Noms des événements écrits par le collecteur (une ligne JSON par événement).</summary>
public static class CollectorEvents
{
    public const string Progress = "progress", Log = "log", Result = "result", Error = "error", OperationResult = "opResult";
    /// <summary>Suffixe du fichier dont la présence demande l'arrêt propre (instantané partiel enregistré).</summary>
    public const string CancelSuffix = ".cancel";
}
