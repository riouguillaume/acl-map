using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using AclMap.Core.Collector;
using AclMap.Core.Snapshot;
using AclMap.Core.Validation;
using AclMap.Export;
using AclMap.Logging;
using AclMap.Models.Analysis;
using AclMap.Models.Snapshot;
using AclMap.Operations;
using AclMap.Services;

namespace AclMap.Hosting;

/// <summary>
/// Contrôleur de l'application : reçoit les messages de l'interface web, pilote le collecteur, garde l'instantané
/// ouvert et prépare les plans d'écriture. Il ne dépend d'aucune API graphique : il est testé avec des doublures.
/// Règles de sécurité : lecture seule par défaut ; écriture seulement si activée, avec plan, Dry Run et confirmation
/// explicite ; mots de passe demandés dans une fenêtre Windows, gardés en mémoire (SecureString) et jamais envoyés à la page.
/// </summary>
public sealed class AppController
{
    public const string ConfirmWord = "APPLIQUER";

    private readonly IHostBridge _bridge;
    private readonly IDialogService _dialogs;
    private readonly ICollectorRunner _collector;
    private readonly ICredentialPrompt _prompt;
    private readonly ISystemInfo _system;
    private readonly SettingsStore _store;
    private readonly OperationLog _log;
    private readonly string _dataFolder;
    private readonly string? _initialSnapshot;
    private readonly ConcurrentDictionary<string, NetCredential> _sessionCredentials = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, OperationPlan> _plans = new();
    private AppSettings _settings;
    private AnalysisSession? _session;
    private CancellationTokenSource? _scanCts;
    private readonly Lock _gate = new();

    public AppController(IHostBridge bridge, IDialogService dialogs, ICollectorRunner collector, ICredentialPrompt prompt, ISystemInfo system,
        SettingsStore store, OperationLog log, string dataFolder, string? initialSnapshot = null)
    {
        _bridge = bridge; _dialogs = dialogs; _collector = collector; _prompt = prompt; _system = system; _store = store; _log = log;
        _dataFolder = dataFolder; _initialSnapshot = initialSnapshot;
        _settings = store.Load();
    }

    /// <summary>Session d'analyse ouverte (tests).</summary>
    public AnalysisSession? Session => _session;

    /// <summary>Paramètres courants (tests).</summary>
    public AppSettings Settings => _settings;

    private string PlansFolder => Path.Combine(_dataFolder, "plans");
    private string BackupFolder => _settings.BackupFolder ?? Path.Combine(_dataFolder, "backups");

    private void Send(string type, object? data = null)
    {
        var node = data is null ? new JsonObject() : JsonSerializer.SerializeToNode(data, AclMapJson.Options) as JsonObject ?? new JsonObject { ["data"] = JsonSerializer.SerializeToNode(data, AclMapJson.Options) };
        node["type"] = type;
        _bridge.Post(node.ToJsonString(AclMapJson.Options));
    }

    private void SendError(string message, string? context = null) => Send("error", new { message, context });

    /// <summary>Traite un message de l'interface.</summary>
    public async Task HandleAsync(string json)
    {
        JsonElement m;
        try { m = JsonDocument.Parse(json).RootElement; if (m.ValueKind == JsonValueKind.String) m = JsonDocument.Parse(m.GetString()!).RootElement; }
        catch (JsonException) { SendError("Message illisible."); return; }
        var type = Str(m, "type") ?? "";
        try
        {
            switch (type)
            {
                case "ready": Ready(); break;
                case "getSettings": SendSettings(); break;
                case "saveProfile": SaveProfile(m); break;
                case "deleteProfile": UpdateSettings(s => s with { Profiles = s.Profiles.Where(p => p.Id != Str(m, "id")).ToList() }); SendSettings(); break;
                case "setActiveProfile": UpdateSettings(s => s with { ActiveProfileId = Str(m, "id") }); SendSettings(); break;
                case "quickConnectDone": UpdateSettings(s => s with { QuickConnectDone = true }); SendSettings(); break;
                case "saveSettings": SaveAppSettings(m); break;
                case "forgetCredentials": _sessionCredentials.Clear(); Send("info", new { message = "Mots de passe de la session oubliés." }); break;
                case "testConnection": await TestConnection(m); break;
                case "discoverServers": await CollectorQuery(m, "servers", "servers", new CollectorRequest { Verb = "servers" }); break;
                case "listShares": await CollectorQuery(m, "shares", "shares", new CollectorRequest { Verb = "shares", Server = Str(m, "server") }); break;
                case "browse": await CollectorQuery(m, "browse", "browse", new CollectorRequest { Verb = "browse", Path = Str(m, "path") }); break;
                case "searchDirectory": await CollectorQuery(m, "search", "directorySearch", new CollectorRequest { Verb = "search", Text = Str(m, "text"), Kind = Str(m, "kind") }); break;
                case "listOus": await CollectorQuery(m, "ous", "ous", new CollectorRequest { Verb = "ous" }); break;
                case "pickOutputFolder": Send("folderPicked", new { field = Str(m, "field"), path = _dialogs.PickFolder(Str(m, "initial")) }); break;
                case "scan": await Scan(m); break;
                case "cancelScan": _scanCts?.Cancel(); break;
                case "openSnapshot": { var f = _dialogs.OpenSnapshot("Ouvrir un instantané ACL Map"); if (f is not null) await Task.Run(() => OpenFile(f)); break; }
                case "openFile": { var f = Str(m, "path") ?? ""; await Task.Run(() => OpenFile(f)); break; }
                case "openProfileSnapshot": { var p = _settings.Profiles.FirstOrDefault(x => x.Id == Str(m, "id")); if (p?.LastSnapshotPath is { } f) OpenFile(f); else SendError("Aucun instantané pour ce domaine."); break; }
                case "folder": await Heavy(s => Send("folder", ViewModel.Folder(s, Int(m, "id")))); break;
                case "principal": await Heavy(s => Send("principal", ViewModel.Principal(s, Str(m, "sid") ?? ""))); break;
                case "accessMap": await Heavy(s => Send("accessMap", s.ComputeMap(Str(m, "sid") ?? "", Str(m, "path"), Bool(m, "implicit")))); break;
                case "explain": await Heavy(s => Send("explain", s.Explain(Str(m, "sid") ?? "", Int(m, "folderId"), Str(m, "path"), Bool(m, "implicit")))); break;
                case "graph": await Heavy(s => Send("graph", s.Graph(Str(m, "sid") ?? "", 120, Bool(m, "implicit")))); break;
                case "whoHasAccess": await Heavy(s => Send("whoHasAccess", s.WhoHasAccess(Int(m, "folderId"), Str(m, "path")))); break;
                case "compare": Compare(); break;
                case "export": Export(m); break;
                case "getLog": Send("log", new { entries = _log.Recent(500), folder = _log.Folder }); break;
                case "authz": await Authz(m); break;
                case "planAddAce": RequireSession(s => StorePlan(Single(s, PlanBuilder.PlanAddAce(s, Int(m, "folderId"), new AceSpec(Ref(m, "principal"), Enum.Parse<AccessLevel>(Str(m, "level") ?? "Read"), Str(m, "scope") ?? "ThisFolderSubfoldersFiles", Bool(m, "deny")))))); break;
                case "planRemoveAce": RequireSession(s => StorePlan(Single(s, PlanBuilder.PlanRemoveAce(s, Int(m, "folderId"), Int(m, "index"))))); break;
                case "planMembership": StorePlan(Single(_session, PlanBuilder.PlanMembership(_session, Ref(m, "group"), Ref(m, "member"), Bool(m, "add")))); break;
                case "planCreateGroup": StorePlan(Single(_session, PlanBuilder.PlanCreateGroup(Str(m, "name") ?? "", Str(m, "scope") ?? "Global", Str(m, "ou") ?? "", Str(m, "description")))); break;
                case "planAgdlp": RequireSession(s => StorePlan(PlanAgdlp(s, m))); break;
                case "applyPlan": await ApplyPlan(m); break;
                case "listBackups": ListBackups(); break;
                case "restoreBackup": await Restore(m); break;
                default: SendError($"Message inconnu : {type}"); break;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or InvalidDataException or IOException or UnauthorizedAccessException or FormatException or KeyNotFoundException or System.ComponentModel.Win32Exception)
        {
            SendError(ex.Message, type);
        }
    }

    // ---------------------------------------------------------------- paramètres

    private void Ready()
    {
        Send("init", new
        {
            version = typeof(AppController).Assembly.GetName().Version?.ToString(3),
            system = new { joined = _system.IsDomainJoined, domain = _system.JoinedDomain, machine = _system.MachineName, user = _system.CurrentUser, webView2 = _system.WebView2Version, dotnet = _system.DotNetVersion },
            confirmWord = ConfirmWord,
        });
        SendSettings();
        if (_initialSnapshot is not null) OpenFile(_initialSnapshot);
    }

    private void SendSettings() => Send("settings", new { settings = _settings, sessionCredentials = _sessionCredentials.Keys.ToList() });

    private void UpdateSettings(Func<AppSettings, AppSettings> f)
    {
        lock (_gate) { _settings = f(_settings); _store.Save(_settings); }
    }

    private void SaveProfile(JsonElement m)
    {
        var p = (JsonSerializer.Deserialize<DomainProfile>(m.GetProperty("profile").GetRawText(), AclMapJson.Options) ?? throw new ArgumentException("Profil vide.")).Normalize();
        var errors = p.Validate();
        if (errors.Count > 0) { Send("validation", new { context = "profile", errors }); return; }
        UpdateSettings(s =>
        {
            var existing = s.Profiles.FirstOrDefault(x => x.Id == p.Id);
            var merged = existing is null ? p : p with { LastCollectedUtc = existing.LastCollectedUtc, LastSnapshotPath = existing.LastSnapshotPath, LastPath = p.LastPath ?? existing.LastPath };
            var list = s.Profiles.Where(x => x.Id != p.Id).Append(merged).OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
            return s with { Profiles = list, ActiveProfileId = Bool(m, "activate") || s.ActiveProfileId is null ? p.Id : s.ActiveProfileId };
        });
        _log.Write("info", "profile.save", $"Profil enregistré : {p.Name}", new() { ["domain"] = p.DomainName, ["dc"] = p.DomainController, ["mode"] = p.ConnectionMode.ToString() });
        Send("profileSaved", new { id = p.Id });
        SendSettings();
    }

    private void SaveAppSettings(JsonElement m)
    {
        var scan = m.TryGetProperty("defaultScan", out var ds) ? JsonSerializer.Deserialize<ScanOptions>(ds.GetRawText(), AclMapJson.Options) : null;
        var gg = Str(m, "ggTemplate"); var dl = Str(m, "dlTemplate");
        if (gg is not null && !gg.Contains("{Metier}", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Le modèle de groupe global doit contenir {Metier}.");
        if (dl is not null && !dl.Contains("{Droit}", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Le modèle de groupe domaine local doit contenir {Droit}.");
        if (scan is not null && (scan.MaxDepth is < 0 or > 64 || scan.Parallelism is < 1 or > 64)) throw new ArgumentException("Profondeur (0–64) ou parallélisme (1–64) invalide.");
        var backup = Str(m, "backupFolder");
        if (!string.IsNullOrWhiteSpace(backup) && InputValidator.OutputFolder(backup) is { } be) throw new ArgumentException(be);
        var wasWrite = _settings.WriteEnabled;
        UpdateSettings(s => s with
        {
            WriteEnabled = m.TryGetProperty("writeEnabled", out var w) ? w.GetBoolean() : s.WriteEnabled,
            GgTemplate = gg ?? s.GgTemplate, DlTemplate = dl ?? s.DlTemplate, DefaultScan = scan ?? s.DefaultScan,
            BackupFolder = m.TryGetProperty("backupFolder", out _) ? (string.IsNullOrWhiteSpace(backup) ? null : backup) : s.BackupFolder,
        });
        if (wasWrite != _settings.WriteEnabled) _log.Write("audit", "settings.write", _settings.WriteEnabled ? "Modifications autorisées dans ACL Map." : "Retour en lecture seule.");
        SendSettings();
    }

    // ---------------------------------------------------------------- collecteur

    private DomainProfile ProfileFrom(JsonElement m)
    {
        if (m.TryGetProperty("profile", out var p) && p.ValueKind == JsonValueKind.Object)
            return (JsonSerializer.Deserialize<DomainProfile>(p.GetRawText(), AclMapJson.Options) ?? throw new ArgumentException("Profil vide.")).Normalize();
        var id = Str(m, "profileId");
        return (id is null ? _settings.ActiveProfile : _settings.Profiles.FirstOrDefault(x => x.Id == id))
            ?? throw new InvalidOperationException("Aucun domaine configuré : ajoutez-en un (Quick Connect ou Paramètres › Domaines).");
    }

    private NetCredential? Credential(DomainProfile p, bool write, bool forcePrompt = false)
    {
        var account = write && !string.IsNullOrWhiteSpace(p.WriteAccountName) ? p.WriteAccountName! : p.AccountName;
        if (!write && p.ConnectionMode == ConnectionMode.CurrentUser) return null;
        if (write && p.ConnectionMode == ConnectionMode.CurrentUser && string.IsNullOrWhiteSpace(p.WriteAccountName)) return null;
        if (string.IsNullOrWhiteSpace(account)) throw new InvalidOperationException("Compte non renseigné dans le profil.");
        var key = $"{p.Id}|{account}";
        if (!write && !forcePrompt && _sessionCredentials.TryGetValue(key, out var cached)) return cached;
        var target = p.DomainController ?? p.DomainName ?? "";
        var pwd = _prompt.PromptPassword(account, target, write ? "Modification (compte délégué) — le mot de passe n'est pas mémorisé" : "Lecture seule — mémorisé en mémoire jusqu'à la fermeture d'ACL Map")
            ?? throw new OperationCanceledException("Saisie du mot de passe annulée.");
        var cred = new NetCredential(account, pwd);
        if (!write) _sessionCredentials[key] = cred;
        return cred;
    }

    private CollectorRequest Enrich(CollectorRequest r, DomainProfile p, bool write) => r with
    {
        Domain = r.Domain ?? p.DomainName, DomainController = r.DomainController ?? p.DomainController,
        AccountName = write ? (p.WriteAccountName ?? p.AccountName) : (p.ConnectionMode == ConnectionMode.AlternateAccount ? p.AccountName : null),
    };

    private async Task<CollectorOutcome> RunCollector(DomainProfile p, CollectorRequest r, bool write, Action<JsonElement>? onEvent = null, CancellationToken ct = default)
    {
        NetCredential? cred;
        try { cred = Credential(p, write); }
        catch (OperationCanceledException) { return new CollectorOutcome(2, null, "Saisie du mot de passe annulée."); }
        var outcome = await _collector.RunAsync(Enrich(r, p, write), cred, onEvent ?? (_ => { }), ct).ConfigureAwait(false);
        // Mot de passe refusé : on l'oublie pour qu'il soit redemandé
        if (!outcome.Ok && cred is not null && outcome.Error is { } e && (e.Contains("1326", StringComparison.Ordinal) || e.Contains("Identifiants refusés", StringComparison.Ordinal)))
            _sessionCredentials.TryRemove($"{p.Id}|{cred.Account}", out _);
        return outcome;
    }

    private async Task CollectorQuery(JsonElement m, string verb, string replyType, CollectorRequest request)
    {
        var p = ProfileFrom(m);
        var o = await RunCollector(p, request, write: false).ConfigureAwait(false);
        if (o.Ok) Send(replyType, new { requestId = Str(m, "requestId"), ok = true, data = o.Result });
        else Send(replyType, new { requestId = Str(m, "requestId"), ok = false, error = o.Error });
    }

    private async Task TestConnection(JsonElement m)
    {
        var p = ProfileFrom(m);
        var errors = p.Validate();
        errors.Remove("name");
        if (errors.Count > 0) { Send("validation", new { context = "test", errors }); return; }
        _log.Write("info", "connection.test", $"Test de connexion : {p.DomainController ?? p.DomainName ?? "domaine du poste"}", new() { ["account"] = p.AccountName });
        var o = await RunCollector(p, new CollectorRequest { Verb = "test", Servers = p.FileServers.Select(f => f.Server).ToList() }, false, e => Progress(e, "test")).ConfigureAwait(false);
        Send("testResult", new { ok = o.Ok && AllChecksOk(o.Result), data = o.Result, error = o.Error });
    }

    private static bool AllChecksOk(JsonElement? r) =>
        r is { } e && e.TryGetProperty("checks", out var c) && c.EnumerateArray().All(x => !x.TryGetProperty("ok", out var ok) || ok.GetBoolean());

    private void Progress(JsonElement e, string context)
    {
        var t = Str(e, "type");
        if (t == CollectorEvents.Progress) Send("progress", new { context, stage = Str(e, "stage"), message = Str(e, "message"), current = IntOr(e, "current"), total = IntOr(e, "total") });
        else if (t == CollectorEvents.Log) Send("collectorLog", new { context, level = Str(e, "level"), message = Str(e, "message") });
    }

    private async Task Scan(JsonElement m)
    {
        var p = ProfileFrom(m);
        var path = Str(m, "path")?.Trim() ?? "";
        if (InputValidator.ScanPath(path) is { } err) { Send("validation", new { context = "scan", errors = new Dictionary<string, string> { ["path"] = err } }); return; }
        var options = m.TryGetProperty("options", out var o) && o.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<ScanOptions>(o.GetRawText(), AclMapJson.Options) ?? _settings.DefaultScan : _settings.DefaultScan;
        var srv = InputValidator.SplitUnc(path)?.Server;
        var fs = p.FileServers.FirstOrDefault(f => srv is not null && (f.Server.Equals(srv, StringComparison.OrdinalIgnoreCase) || f.Server.Split('.')[0].Equals(srv.Split('.')[0], StringComparison.OrdinalIgnoreCase)));
        if (fs is not null) options = options with { IncludePrintShares = fs.IncludePrintShares, IncludeSpecialShares = fs.IncludeSpecialShares };
        lock (_gate)
        {
            if (_scanCts is not null) throw new InvalidOperationException("Une analyse est déjà en cours.");
            _scanCts = new CancellationTokenSource();
        }
        var ct = _scanCts.Token;
        var output = p.OutputFolder ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "AclMap");
        var corr = Guid.NewGuid().ToString("N")[..8];
        _log.Write("info", "scan.start", $"Analyse de {path}", new() { ["path"] = path, ["profile"] = p.Name, ["depth"] = options.MaxDepth.ToString(), ["backupMode"] = options.BackupMode.ToString() }, corr);
        Send("scanStarted", new { path });
        try
        {
            var r = await RunCollector(p, new CollectorRequest { Verb = "scan", Path = path, OutputFolder = output, Scan = options }, false, e => Progress(e, "scan"), ct).ConfigureAwait(false);
            if (!r.Ok || r.Result is not { } res)
            {
                _log.Write("error", "scan.error", r.Error ?? "Échec de l'analyse", new() { ["path"] = path }, corr);
                Send("scanError", new { message = r.Error ?? "Échec de l'analyse." });
                return;
            }
            var file = Str(res, "path")!;
            _log.Write("info", "scan.done", $"Analyse terminée : {IntOr(res, "folders"):N0} dossiers, {IntOr(res, "errors")} erreur(s)", new() { ["file"] = file, ["truncated"] = Str(res, "truncated") }, corr);
            UpdateSettings(s => s with
            {
                Profiles = s.Profiles.Select(x => x.Id == p.Id ? x with { LastCollectedUtc = DateTimeOffset.UtcNow, LastSnapshotPath = file, LastPath = path } : x).ToList(),
            });
            Send("scanDone", new { file, data = res });
            OpenFile(file);
            SendSettings();
        }
        finally { lock (_gate) { _scanCts?.Dispose(); _scanCts = null; } }
    }

    // ---------------------------------------------------------------- instantanés

    private void OpenFile(string file)
    {
        if (!File.Exists(file)) throw new FileNotFoundException($"Instantané introuvable : {file}");
        var s = AnalysisSession.Open(file);
        _session = s;
        _plans.Clear();
        UpdateSettings(x => x with { RecentSnapshots = x.RecentSnapshots.Where(r => !r.Equals(file, StringComparison.OrdinalIgnoreCase)).Prepend(file).Take(10).ToList() });
        _log.Write("info", "snapshot.open", $"Instantané ouvert : {Path.GetFileName(file)}", new() { ["file"] = file, ["root"] = s.Index.Snapshot.Manifest.RootPath });
        Send("snapshot", ViewModel.Build(s));
    }

    private readonly SemaphoreSlim _sessionLock = new(1, 1);

    private void RequireSession(Action<AnalysisSession> a)
    {
        var s = _session ?? throw new InvalidOperationException("Aucun instantané ouvert : lancez une analyse ou ouvrez un fichier .aclmap.");
        _sessionLock.Wait();
        try { a(s); } finally { _sessionLock.Release(); }
    }

    /// <summary>Calcul lourd hors du thread de l'interface (les caches de la session sont protégés par un verrou).</summary>
    private Task Heavy(Action<AnalysisSession> a) => Task.Run(() => RequireSession(a));

    private void Compare()
    {
        var s = _session ?? throw new InvalidOperationException("Ouvrez d'abord l'instantané le plus récent.");
        var f = _dialogs.OpenSnapshot("Choisir l'instantané de référence (plus ancien)");
        if (f is null) return;
        var older = AnalysisSession.Open(f);
        var (a, b) = older.Index.Snapshot.Manifest.CreatedUtc <= s.Index.Snapshot.Manifest.CreatedUtc ? (older, s) : (s, older);
        Send("diff", SnapshotDiff.Compare(a, b));
    }

    private void Export(JsonElement m)
    {
        var s = _session ?? throw new InvalidOperationException("Aucun instantané ouvert.");
        var kind = Enum.Parse<ExportKind>(Str(m, "kind") ?? "Html");
        var name = Exporters.SuggestedName(s, kind);
        var filter = kind switch { ExportKind.Json => "JSON (*.json)|*.json", ExportKind.Html => "Page HTML (*.html)|*.html", _ => "CSV (*.csv)|*.csv" };
        var target = _dialogs.SaveFile(name, filter);
        if (target is null) return;
        using (var fs = File.Create(target)) Exporters.Write(s, kind, fs, Str(m, "sid"), Str(m, "path"));
        _log.Write("info", "export", $"Export {kind} : {Path.GetFileName(target)}", new() { ["file"] = target });
        Send("exported", new { file = target, kind = kind.ToString() });
    }

    private async Task Authz(JsonElement m)
    {
        var s = _session ?? throw new InvalidOperationException("Aucun instantané ouvert.");
        var path = s.Index.FullPath(Int(m, "folderId"));
        var p = ProfileFrom(m);
        var o = await RunCollector(p, new CollectorRequest { Verb = "authz", Path = path, Sid = Str(m, "sid") }, false).ConfigureAwait(false);
        Send("authz", new { ok = o.Ok, data = o.Result, error = o.Error, folderId = Int(m, "folderId"), sid = Str(m, "sid") });
    }

    // ---------------------------------------------------------------- écriture contrôlée

    private static OperationPlan Single(AnalysisSession? s, PlannedOperation op) => new()
    {
        Title = op.Description, Domain = s?.Index.Snapshot.Manifest.Domain?.DnsName, SnapshotRoot = s?.Index.Snapshot.Manifest.RootPath, Operations = [op],
    };

    private OperationPlan PlanAgdlp(AnalysisSession s, JsonElement m)
    {
        var members = m.TryGetProperty("members", out var mm) && mm.ValueKind == JsonValueKind.Array ? mm.EnumerateArray().Select(RefOf).ToList() : [];
        var existingGg = m.TryGetProperty("existingGg", out var eg) && eg.ValueKind == JsonValueKind.Object ? RefOf(eg) : null;
        var ou = Str(m, "ou") ?? _settings.ActiveProfile?.GroupsOu ?? "";
        return PlanBuilder.PlanAgdlp(s, new PlanBuilder.AgdlpRequest(Int(m, "folderId"), Str(m, "metier") ?? "", Str(m, "shareLabel") ?? "", Str(m, "folderLabel") ?? "",
            Bool(m, "readWrite"), Bool(m, "readOnly"), ou, members, _settings.GgTemplate, _settings.DlTemplate, existingGg));
    }

    private void StorePlan(OperationPlan plan)
    {
        Directory.CreateDirectory(PlansFolder);
        File.WriteAllText(Path.Combine(PlansFolder, plan.PlanId + ".json"), JsonSerializer.Serialize(plan, AclMapJson.Indented));
        _plans[plan.PlanId] = plan;
        _log.Write("info", "plan.create", plan.Title, new() { ["planId"] = plan.PlanId, ["operations"] = plan.Operations.Count.ToString() }, plan.PlanId);
        Send("plan", new { plan, writeEnabled = _settings.WriteEnabled, confirmWord = ConfirmWord });
    }

    private async Task ApplyPlan(JsonElement m)
    {
        var id = Str(m, "planId") ?? "";
        if (!_plans.TryGetValue(id, out var plan)) throw new InvalidOperationException("Plan inconnu ou expiré : préparez de nouveau la modification.");
        var dry = Bool(m, "dryRun");
        if (!dry)
        {
            if (!_settings.WriteEnabled) throw new InvalidOperationException("Les modifications sont désactivées (Paramètres › Modifications). ACL Map est en lecture seule.");
            if (!string.Equals(Str(m, "confirm"), ConfirmWord, StringComparison.Ordinal)) throw new InvalidOperationException($"Confirmation requise : saisissez {ConfirmWord}.");
        }
        var p = ProfileFrom(m);
        var planFile = Path.Combine(PlansFolder, plan.PlanId + ".json");
        _log.Write("audit", dry ? "plan.dryrun" : "plan.apply", (dry ? "Dry Run : " : "Application : ") + plan.Title,
            new() { ["planId"] = plan.PlanId, ["account"] = p.WriteAccountName ?? p.AccountName ?? _system.CurrentUser, ["operations"] = plan.Operations.Count.ToString() }, plan.PlanId);
        Send("applyStarted", new { planId = id, dryRun = dry });
        var o = await RunCollector(p, new CollectorRequest { Verb = "apply", PlanFile = planFile, DryRun = dry, BackupFolder = BackupFolder }, write: !dry, e =>
        {
            if (Str(e, "type") == CollectorEvents.OperationResult && e.TryGetProperty("data", out var d))
            {
                Send("opResult", new { planId = id, dryRun = dry, result = d });
                if (!dry) _log.Write(d.TryGetProperty("success", out var ok) && ok.GetBoolean() ? "audit" : "error", "operation", Str(d, "message") ?? "", new() { ["operationId"] = Str(d, "operationId"), ["backup"] = Str(d, "backupFile") }, id);
            }
            else Progress(e, "apply");
        }).ConfigureAwait(false);
        var success = o.Result is { } r && r.TryGetProperty("success", out var sflag) && sflag.GetBoolean();
        _log.Write(success ? "audit" : "error", dry ? "plan.dryrun.done" : "plan.apply.done", success ? (dry ? "Dry Run réussi" : "Plan appliqué") : (o.Error ?? "Échec"), new() { ["planId"] = id }, id);
        Send("applyDone", new { planId = id, dryRun = dry, success, data = o.Result, error = o.Error });
    }

    private void ListBackups()
    {
        var list = new List<object>();
        if (Directory.Exists(BackupFolder))
            foreach (var f in Directory.GetFiles(BackupFolder, "*.backup.json").OrderByDescending(File.GetLastWriteTimeUtc).Take(500))
            {
                try
                {
                    var b = JsonSerializer.Deserialize<BackupRecord>(File.ReadAllText(f), AclMapJson.Options);
                    if (b is not null) list.Add(new { file = f, b.PlanId, b.TimestampUtc, kind = b.Kind.ToString(), b.Target, b.Description });
                }
                catch (JsonException) { }
            }
        Send("backups", new { folder = BackupFolder, items = list });
    }

    private async Task Restore(JsonElement m)
    {
        var file = Str(m, "file") ?? "";
        if (!File.Exists(file) || !Path.GetFullPath(file).StartsWith(Path.GetFullPath(BackupFolder), StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Sauvegarde introuvable.");
        var dry = Bool(m, "dryRun");
        if (!dry)
        {
            if (!_settings.WriteEnabled) throw new InvalidOperationException("Les modifications sont désactivées (Paramètres › Modifications).");
            if (!string.Equals(Str(m, "confirm"), ConfirmWord, StringComparison.Ordinal)) throw new InvalidOperationException($"Confirmation requise : saisissez {ConfirmWord}.");
        }
        var p = ProfileFrom(m);
        _log.Write("audit", dry ? "restore.dryrun" : "restore", $"Restauration : {Path.GetFileName(file)}", new() { ["file"] = file });
        var o = await RunCollector(p, new CollectorRequest { Verb = "restore", BackupFile = file, DryRun = dry }, write: !dry).ConfigureAwait(false);
        _log.Write(o.Ok ? "audit" : "error", "restore.done", o.Ok ? Str(o.Result!.Value, "message") ?? "" : o.Error ?? "Échec", new() { ["file"] = file });
        Send("restoreDone", new { file, dryRun = dry, ok = o.Ok, data = o.Result, error = o.Error });
    }

    // ---------------------------------------------------------------- utilitaires

    private static PrincipalRef Ref(JsonElement m, string prop) => m.TryGetProperty(prop, out var p) && p.ValueKind == JsonValueKind.Object ? RefOf(p) : throw new ArgumentException($"Identité manquante ({prop}).");

    private static PrincipalRef RefOf(JsonElement p) => new(Str(p, "sid"), Str(p, "name") ?? Str(p, "sid") ?? throw new ArgumentException("Identité sans nom."), Str(p, "dn"));

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ValueKind switch { JsonValueKind.String => v.GetString(), JsonValueKind.Null or JsonValueKind.Undefined => null, _ => v.GetRawText() } : null;

    private static int Int(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : throw new ArgumentException($"Paramètre numérique manquant : {name}");

    private static int IntOr(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : 0;

    private static bool Bool(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}
