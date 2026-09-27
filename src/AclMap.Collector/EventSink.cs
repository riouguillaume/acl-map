using System.Text;
using System.Text.Json;
using AclMap.Core.Collector;
using AclMap.Core.Snapshot;

namespace AclMap.Collector;

/// <summary>Écrit les événements : fichier JSON Lines (mode application) ou console (mode ligne de commande).</summary>
public sealed class EventSink(string? file)
{
    private readonly Lock _gate = new();
    private static readonly UTF8Encoding Utf8 = new(false);

    public bool Console => file is null;

    private void Write(object o)
    {
        lock (_gate)
        {
            if (file is null) return;
            File.AppendAllText(file, JsonSerializer.Serialize(o, AclMapJson.Options) + "\n", Utf8);
        }
    }

    public void Progress(string stage, string message, int current = 0, int total = 0)
    {
        if (file is null)
        {
            // Console redirigée (tâche planifiée, journal) : une ligne par événement ; sinon mise à jour sur place.
            if (System.Console.IsErrorRedirected) { System.Console.Error.WriteLine($"[{stage}] {message}"); return; }
            System.Console.Error.Write($"\r[{stage}] {message}".PadRight(Math.Min(Width() - 1, 160)));
            return;
        }
        Write(new { type = CollectorEvents.Progress, stage, message, current, total });
    }

    private static int Width()
    {
        try { return System.Console.BufferWidth > 20 ? System.Console.BufferWidth : 120; }
        catch (IOException) { return 120; }
    }

    public void Log(string level, string message)
    {
        if (file is null) { System.Console.Error.WriteLine($"\n{(level == "warning" ? "ATTENTION" : level.ToUpperInvariant())} : {message}"); return; }
        Write(new { type = CollectorEvents.Log, level, message });
    }

    public void Result(object data)
    {
        if (file is null) { System.Console.WriteLine(); System.Console.WriteLine(JsonSerializer.Serialize(data, AclMapJson.Indented)); return; }
        Write(new { type = CollectorEvents.Result, data });
    }

    public void Error(string message, int code = 0)
    {
        if (file is null) { System.Console.Error.WriteLine($"\nERREUR : {message}"); return; }
        Write(new { type = CollectorEvents.Error, message, code });
    }

    public void OperationResult(object data)
    {
        if (file is null) { System.Console.WriteLine(JsonSerializer.Serialize(data, AclMapJson.Options)); return; }
        Write(new { type = CollectorEvents.OperationResult, data });
    }
}
