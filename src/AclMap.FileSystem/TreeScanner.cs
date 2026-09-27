using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Channels;
using AclMap.Core.Security;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.FileSystem;

/// <summary>Progression de l'analyse.</summary>
/// <param name="Processed">Dossiers traités.</param>
/// <param name="Pending">Dossiers en attente.</param>
/// <param name="Errors">Erreurs.</param>
/// <param name="Current">Dernier chemin traité.</param>
public readonly record struct ScanProgress(int Processed, int Pending, int Errors, string Current);

/// <summary>Résultat brut d'une analyse d'arborescence.</summary>
public sealed record ScanResult(List<FolderNode> Nodes, List<SecurityDescriptorInfo> Descriptors, List<CollectionError> Errors, bool Truncated, bool BackupPrivilegeEnabled, long DurationMs);

/// <summary>
/// Analyse parallèle d'une arborescence : un handle par dossier (sémantique de sauvegarde) sert à lire à la fois
/// l'ACL et la liste des entrées. Les descripteurs identiques sont dédupliqués ; les points de jonction sont
/// signalés sans être suivis ; aucun dossier inaccessible n'est ignoré silencieusement.
/// </summary>
public sealed class TreeScanner(ScanOptions options)
{
    private sealed record Work(int Id, int ParentId, string Name, string Path, int Depth, bool IsFile, bool IsReparse);

    private readonly ConcurrentDictionary<int, FolderNode> _nodes = new();
    private readonly ConcurrentDictionary<string, int> _sdByHash = new();
    private readonly ConcurrentDictionary<int, SecurityDescriptorInfo> _sds = new();
    private readonly ConcurrentQueue<CollectionError> _errors = new();
    private int _nextId, _nextSd, _processed, _pending, _errorCount, _truncated;

    /// <summary>Analyse l'arborescence.</summary>
    /// <param name="rootPath">Chemin UNC ou local.</param>
    /// <param name="progress">Progression (facultatif).</param>
    /// <param name="ct">Annulation : l'instantané est alors marqué incomplet.</param>
    public async Task<ScanResult> ScanAsync(string rootPath, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var backup = options.BackupMode && Privileges.Enable("SeBackupPrivilege");
        if (options.BackupMode && !backup) AddError("scan", rootPath, 1300, "Mode sauvegarde demandé mais le privilège SeBackupPrivilege n'est pas détenu (session non élevée ou compte hors « Opérateurs de sauvegarde ») : lecture normale.");
        using (var probe = SecurityReader.Open(rootPath, Native.READ_CONTROL, false, out var perr))
        {
            if (probe.IsInvalid && perr != Native.ERROR_ACCESS_DENIED)
                throw new Win32Exception(perr, $"Impossible d'ouvrir {rootPath} : {SecurityReader.Describe(perr)}");
        }
        var channel = Channel.CreateUnbounded<Work>();
        var lastPath = rootPath;
        _nextId = 1;
        Interlocked.Increment(ref _pending);
        channel.Writer.TryWrite(new Work(0, -1, rootPath.TrimEnd('\\') + (rootPath.EndsWith(":\\", StringComparison.Ordinal) ? "\\" : ""), rootPath, 0, false, false));
        using var timer = progress is null ? null : new Timer(_ => progress.Report(new(Volatile.Read(ref _processed), Volatile.Read(ref _pending), Volatile.Read(ref _errorCount), lastPath)), null, 500, 500);
        var workers = Enumerable.Range(0, Math.Clamp(options.Parallelism, 1, 64)).Select(_ => Task.Run(async () =>
        {
            await foreach (var w in channel.Reader.ReadAllAsync(CancellationToken.None))
            {
                try
                {
                    if (ct.IsCancellationRequested || Volatile.Read(ref _truncated) == 2) Placeholder(w);
                    else { Process(w, channel.Writer); lastPath = w.Path; }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    AddError("scan", w.Path, 0, "Erreur inattendue : " + ex.Message);
                    _nodes.TryAdd(w.Id, new FolderNode(w.Id, w.ParentId, w.Name, -1, NodeFlags.Error));
                }
                Interlocked.Increment(ref _processed);
                if (Interlocked.Decrement(ref _pending) == 0) channel.Writer.TryComplete();
            }
        }, CancellationToken.None)).ToArray();
        await Task.WhenAll(workers).ConfigureAwait(false);
        progress?.Report(new(_processed, 0, _errorCount, rootPath));
        var nodes = Enumerable.Range(0, _nextId).Select(i => _nodes.TryGetValue(i, out var n) ? n : new FolderNode(i, 0, "?", -1, NodeFlags.Error)).ToList();
        var descs = _sds.Values.OrderBy(d => d.Id).ToList();
        return new ScanResult(nodes, descs, [.. _errors], ct.IsCancellationRequested || _truncated != 0, backup, sw.ElapsedMilliseconds);
    }

    private void Placeholder(Work w)
    {
        Interlocked.CompareExchange(ref _truncated, 1, 0);
        _nodes.TryAdd(w.Id, new FolderNode(w.Id, w.ParentId, w.Name, -1, NodeFlags.DepthLimit | (w.IsFile ? NodeFlags.File : 0)));
    }

    private void AddError(string stage, string? target, int code, string message)
    {
        if (Interlocked.Increment(ref _errorCount) <= 20_000) _errors.Enqueue(new CollectionError(stage, target, code, message));
    }

    private int StoreSd(byte[] bytes, string path)
    {
        var key = Convert.ToBase64String(SHA256.HashData(bytes));
        if (_sdByHash.TryGetValue(key, out var id)) return id;
        SecurityDescriptorInfo info;
        try { info = SecurityDescriptorCodec.Parse(bytes); }
        catch (FormatException ex) { AddError("security", path, 0, "Descripteur illisible : " + ex.Message); return -1; }
        return _sdByHash.GetOrAdd(key, _ =>
        {
            var nid = Interlocked.Increment(ref _nextSd) - 1;
            _sds[nid] = info with { Id = nid };
            return nid;
        });
    }

    private void Process(Work w, ChannelWriter<Work> writer)
    {
        var flags = w.Path.Length >= 260 ? NodeFlags.LongPath : NodeFlags.None;
        if (w.IsFile) flags |= NodeFlags.File;
        if (w.IsReparse) flags |= NodeFlags.ReparsePoint;
        var sdId = -1;
        if (w.IsFile)
        {
            var b = SecurityReader.ReadFileSecurity(w.Path, out var fe);
            if (b is not null) sdId = StoreSd(b, w.Path);
            else { flags |= NodeFlags.SecurityUnreadable; AddError("security", w.Path, fe, SecurityReader.Describe(fe)); }
            _nodes[w.Id] = new FolderNode(w.Id, w.ParentId, w.Name, sdId, flags);
            return;
        }
        // Dossier : un handle pour l'ACL et la liste ; repli si l'un des deux droits manque.
        var wantList = !w.IsReparse;
        var h = SecurityReader.Open(w.Path, Native.READ_CONTROL | (wantList ? Native.FILE_LIST_DIRECTORY : 0), w.IsReparse, out var err);
        var canList = wantList && !h.IsInvalid;
        if (h.IsInvalid && err == Native.ERROR_ACCESS_DENIED)
        {
            h.Dispose();
            h = SecurityReader.Open(w.Path, Native.READ_CONTROL, w.IsReparse, out var err2);
            if (h.IsInvalid)
            {
                h.Dispose();
                h = wantList ? SecurityReader.Open(w.Path, Native.FILE_LIST_DIRECTORY, false, out _) : h;
                canList = wantList && !h.IsInvalid;
                flags |= NodeFlags.SecurityUnreadable;
                if (!canList) flags |= NodeFlags.ListDenied;
                AddError("scan", w.Path, err2, canList ? "Autorisations illisibles : " + SecurityReader.Describe(err2) : "Ni la liste ni les autorisations ne sont lisibles : " + SecurityReader.Describe(err2));
            }
            else if (wantList) { flags |= NodeFlags.ListDenied; canList = false; AddError("scan", w.Path, err, "Contenu non listable : " + SecurityReader.Describe(err)); }
        }
        else if (h.IsInvalid)
        {
            flags |= NodeFlags.Error | NodeFlags.SecurityUnreadable | NodeFlags.ListDenied;
            AddError("scan", w.Path, err, SecurityReader.Describe(err));
        }
        using (h)
        {
            if (!h.IsInvalid && (flags & NodeFlags.SecurityUnreadable) == 0)
            {
                var bytes = SecurityReader.ReadSecurity(h, out var se);
                if (bytes is not null) sdId = StoreSd(bytes, w.Path);
                else { flags |= NodeFlags.SecurityUnreadable; AddError("security", w.Path, se, "Autorisations illisibles : " + SecurityReader.Describe(se)); }
            }
            if (canList && !h.IsInvalid)
            {
                List<SecurityReader.Entry> entries;
                try { entries = SecurityReader.List(h); }
                catch (Win32Exception ex) { flags |= NodeFlags.ListDenied; AddError("scan", w.Path, ex.NativeErrorCode, "Contenu non listable : " + SecurityReader.Describe(ex.NativeErrorCode)); entries = []; }
                if (w.Depth >= options.MaxDepth)
                {
                    if (entries.Any(e => e.IsDirectory)) flags |= NodeFlags.DepthLimit;
                }
                else
                {
                    foreach (var e in entries.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        if (!e.IsDirectory && !options.IncludeFiles) continue;
                        var id = Interlocked.Increment(ref _nextId) - 1;
                        if (id >= options.MaxNodes)
                        {
                            Interlocked.Decrement(ref _nextId);
                            if (Interlocked.Exchange(ref _truncated, 2) != 2) AddError("scan", w.Path, 0, $"Limite de {options.MaxNodes:N0} éléments atteinte : analyse interrompue.");
                            break;
                        }
                        Interlocked.Increment(ref _pending);
                        writer.TryWrite(new Work(id, w.Id, e.Name, w.Path.TrimEnd('\\') + "\\" + e.Name, w.Depth + 1, !e.IsDirectory, e.IsReparsePoint));
                    }
                }
            }
        }
        _nodes[w.Id] = new FolderNode(w.Id, w.ParentId, w.Name, sdId, flags);
    }
}
