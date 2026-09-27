using System.Text.Encodings.Web;
using System.Text.Json;

namespace AclMap.Logging;

/// <summary>Entrée du journal des opérations.</summary>
/// <param name="Timestamp">Horodatage (UTC).</param>
/// <param name="Level">info, warning, error, audit.</param>
/// <param name="Event">Événement (scan.start, plan.apply…).</param>
/// <param name="Message">Message lisible.</param>
/// <param name="Data">Données structurées (jamais de secret).</param>
/// <param name="CorrelationId">Identifiant de l'opération.</param>
public sealed record LogEntry(DateTimeOffset Timestamp, string Level, string Event, string Message, Dictionary<string, string?>? Data, string? CorrelationId);

/// <summary>
/// Journal structuré JSON Lines (un fichier par jour dans %LOCALAPPDATA%\AclMap\logs). Écriture sûre entre
/// threads ; aucun mot de passe ni secret n'y est jamais écrit (les appelants ne transmettent que des métadonnées).
/// </summary>
public sealed class OperationLog(string folder)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private readonly Lock _gate = new();

    /// <summary>Dossier par défaut.</summary>
    public static string DefaultFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AclMap", "logs");

    public string Folder => folder;

    /// <summary>Ajoute une entrée.</summary>
    public LogEntry Write(string level, string evt, string message, Dictionary<string, string?>? data = null, string? correlationId = null)
    {
        var e = new LogEntry(DateTimeOffset.UtcNow, level, evt, message, data, correlationId);
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(folder);
                File.AppendAllText(Path.Combine(folder, $"aclmap-{e.Timestamp:yyyyMMdd}.jsonl"), JsonSerializer.Serialize(e, Json) + "\n");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* le journal ne doit jamais bloquer l'outil */ }
        return e;
    }

    /// <summary>Dernières entrées (tous fichiers, plus récentes en premier).</summary>
    public List<LogEntry> Recent(int max = 500)
    {
        var list = new List<LogEntry>();
        if (!Directory.Exists(folder)) return list;
        foreach (var file in Directory.GetFiles(folder, "aclmap-*.jsonl").OrderDescending())
        {
            string[] lines;
            try { lines = File.ReadAllLines(file); } catch (IOException) { continue; }
            for (var i = lines.Length - 1; i >= 0 && list.Count < max; i--)
            {
                try { if (JsonSerializer.Deserialize<LogEntry>(lines[i], Json) is { } e) list.Add(e); } catch (JsonException) { }
            }
            if (list.Count >= max) break;
        }
        return list;
    }
}
