using System.Security;
using System.Text.Json;
using AclMap.Core.Collector;

namespace AclMap.Hosting;

/// <summary>Canal vers l'interface web (WebView2 : PostWebMessageAsJson).</summary>
public interface IHostBridge
{
    void Post(string json);
}

/// <summary>Boîtes de dialogue Windows.</summary>
public interface IDialogService
{
    /// <summary>Choix d'un instantané .aclmap à ouvrir.</summary>
    string? OpenSnapshot(string title);
    /// <summary>Choix d'un fichier de destination.</summary>
    string? SaveFile(string suggestedName, string filter);
    /// <summary>Choix d'un dossier.</summary>
    string? PickFolder(string? initial);
}

/// <summary>
/// Identifiants réseau pour « runas /netonly ». Le mot de passe reste un <see cref="SecureString"/> : jamais écrit,
/// journalisé, ni transmis à la page web.
/// </summary>
public sealed record NetCredential(string Account, SecureString Password)
{
    /// <summary>(utilisateur, domaine) ; domaine null pour un UPN.</summary>
    public (string User, string? Domain) Split()
    {
        var i = Account.IndexOf('\\');
        return i > 0 ? (Account[(i + 1)..], Account[..i]) : (Account, null);
    }
}

/// <summary>Demande de mot de passe dans une fenêtre Windows (jamais dans la page web).</summary>
public interface ICredentialPrompt
{
    /// <param name="account">Compte.</param>
    /// <param name="target">Domaine / serveur affichés.</param>
    /// <param name="purpose">Usage (lecture, modification).</param>
    /// <returns>Mot de passe, ou null si annulé.</returns>
    SecureString? PromptPassword(string account, string target, string purpose);
}

/// <summary>Processus lancé (normal ou « runas /netonly »).</summary>
public interface IRunningProcess : IDisposable
{
    Task<int> WaitForExitAsync(CancellationToken ct);
    bool HasExited { get; }
    void Kill();
}

/// <summary>Lanceur de processus.</summary>
public interface IProcessLauncher
{
    IRunningProcess Start(string exe, string arguments, NetCredential? credential);
}

/// <summary>État du poste.</summary>
public interface ISystemInfo
{
    bool IsDomainJoined { get; }
    string? JoinedDomain { get; }
    string MachineName { get; }
    string CurrentUser { get; }
    string? WebView2Version { get; }
    string? DotNetVersion { get; }
}

/// <summary>Issue d'une exécution du collecteur.</summary>
/// <param name="ExitCode">Code de sortie.</param>
/// <param name="Result">Données de l'événement « result » (null si absent).</param>
/// <param name="Error">Message de l'événement « error » (null si absent).</param>
public sealed record CollectorOutcome(int ExitCode, JsonElement? Result, string? Error)
{
    public bool Ok => Error is null && Result is not null;
}

/// <summary>Exécute le collecteur avec une requête.</summary>
public interface ICollectorRunner
{
    /// <param name="request">Requête (sans secret).</param>
    /// <param name="credential">Identifiants réseau éventuels.</param>
    /// <param name="onEvent">Chaque événement reçu (progression, journal, résultat d'opération).</param>
    /// <param name="ct">Annulation : arrêt propre demandé, puis arrêt forcé.</param>
    Task<CollectorOutcome> RunAsync(CollectorRequest request, NetCredential? credential, Action<JsonElement> onEvent, CancellationToken ct);
}
