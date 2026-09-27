using System.Net.WebSockets;
using System.Security;
using System.Text;
using System.Text.Json;
using AclMap.Core.Collector;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Hosting;
using AclMap.Logging;
using AclMap.Models.Snapshot;
using AclMap.Operations;
using AclMap.Services;
using AclMap.Testing;
using Microsoft.Extensions.FileProviders;

// Hôte de développement ACL Map : sert l'interface et relie la page (WebSocket) au vrai AppController,
// avec un collecteur, des boîtes de dialogue et un poste Windows simulés.
//   dotnet run --project tools/AclMap.DevHost -- [--port 5180] [--preset configured|empty] [--make-sample samples/demo.aclmap]
var argsList = args.ToList();
string Arg(string name, string def) { var i = argsList.IndexOf(name); return i >= 0 && i + 1 < argsList.Count ? argsList[i + 1] : def; }
if (argsList.Contains("--make-sample"))
{
    var target = Arg("--make-sample", "samples/demo.aclmap");
    SnapshotArchive.Save(LabSnapshotFactory.Create(), target);
    Console.WriteLine("Échantillon : " + Path.GetFullPath(target));
    return;
}
if (argsList.Contains("--make-plan"))
{
    // --make-plan <instantané> <chemin relatif> <sid> <niveau> <plan.json> : plan d'ajout d'ACE (tests d'écriture sous Wine)
    var i = argsList.IndexOf("--make-plan");
    var s = AnalysisSession.Open(argsList[i + 1]);
    var folder = s.Index.FindRelative(argsList[i + 2]) ?? throw new ArgumentException("dossier absent");
    var op = PlanBuilder.PlanAddAce(s, folder, new AceSpec(new PrincipalRef(argsList[i + 3], argsList[i + 3]), Enum.Parse<AclMap.Models.Analysis.AccessLevel>(argsList[i + 4]), "ThisFolderSubfoldersFiles"));
    File.WriteAllText(argsList[i + 5], JsonSerializer.Serialize(new OperationPlan { Title = op.Description, Operations = [op] }, AclMapJson.Indented));
    Console.WriteLine(op.Description); Console.WriteLine("avant : " + op.BeforeSddl); Console.WriteLine("après : " + op.AfterSddl);
    return;
}
var port = int.Parse(Arg("--port", "5180"));
var preset = Arg("--preset", "empty");
var root = Path.Combine(Path.GetTempPath(), "aclmap-dev-" + port);
if (Directory.Exists(root)) Directory.Delete(root, true);
Directory.CreateDirectory(root);
var viewer = Path.GetFullPath(Arg("--viewer", Path.Combine(AppContext.BaseDirectory, "../../../../../src/AclMap.UI/Assets/Viewer")));

var store = new SettingsStore(Path.Combine(root, "settings.json"));
if (preset == "configured")
{
    store.Save(new AppSettings
    {
        QuickConnectDone = true, ActiveProfileId = "p1",
        Profiles = [new DomainProfile { Id = "p1", Name = "Contoso – production", DomainName = "contoso.local", DomainController = "DC01.contoso.local", ConnectionMode = ConnectionMode.AlternateAccount, AccountName = @"CONTOSO\audit",
            FileServers = [new FileServerEntry { Server = "FS01.contoso.local", Favorites = [@"\\FS01.contoso.local\Donnees"] }], GroupsOu = "OU=Groupes,DC=contoso,DC=local", OutputFolder = @"D:\Audits\Contoso" }],
    });
}

var builder = WebApplication.CreateBuilder();
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
builder.Logging.SetMinimumLevel(LogLevel.Warning);
var app = builder.Build();
app.UseWebSockets();
app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = new PhysicalFileProvider(viewer) });
app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(viewer), OnPrepareResponse = c => c.Context.Response.Headers.CacheControl = "no-store" });
app.Map("/ws", async ctx =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
    var bridge = new WsBridge(ws);
    var fake = new FakeCollector(root);
    var controller = new AppController(bridge, new FakeDialogs(root, fake), fake, new FakePrompt(), new FakeSystem(), store, new OperationLog(Path.Combine(root, "logs")), root);
    var buffer = new byte[1 << 20];
    var sb = new StringBuilder();
    while (ws.State == WebSocketState.Open)
    {
        var r = await ws.ReceiveAsync(buffer, CancellationToken.None);
        if (r.MessageType == WebSocketMessageType.Close) break;
        sb.Append(Encoding.UTF8.GetString(buffer, 0, r.Count));
        if (!r.EndOfMessage) continue;
        var text = sb.ToString(); sb.Clear();
        _ = Task.Run(async () =>
        {
            try { await controller.HandleAsync(text); }
            catch (Exception ex) { bridge.Post(JsonSerializer.Serialize(new { type = "error", message = ex.Message })); }
        });
    }
});
Console.WriteLine($"ACL Map (développement) : http://127.0.0.1:{port}/  — interface : {viewer}");
app.Run();

sealed class WsBridge(WebSocket ws) : IHostBridge
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    public void Post(string json)
    {
        _gate.Wait();
        try { ws.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (WebSocketException) { }
        finally { _gate.Release(); }
    }
}

sealed class FakePrompt : ICredentialPrompt
{
    public SecureString? PromptPassword(string account, string target, string purpose) { var s = new SecureString(); foreach (var c in "x") s.AppendChar(c); s.MakeReadOnly(); return s; }
}

sealed class FakeSystem : ISystemInfo
{
    public bool IsDomainJoined => true;
    public string? JoinedDomain => "contoso.local";
    public string MachineName => "ADMIN01";
    public string CurrentUser => @"CONTOSO\audit";
    public string? WebView2Version => "140.0 (simulé)";
    public string? DotNetVersion => "10.0 (simulé)";
}

sealed class FakeDialogs(string root, FakeCollector fake) : IDialogService
{
    public string? OpenSnapshot(string title) => title.Contains("référence") ? fake.OlderSnapshot() : fake.DemoSnapshot();
    public string? SaveFile(string suggestedName, string filter) { Directory.CreateDirectory(Path.Combine(root, "exports")); return Path.Combine(root, "exports", suggestedName); }
    public string? PickFolder(string? initial) => @"D:\Audits\Contoso";
}

/// <summary>Collecteur simulé : répond à chaque verbe à partir de l'instantané de démonstration.</summary>
sealed class FakeCollector(string root) : ICollectorRunner
{
    private AnalysisSession? _lab;
    private InMemoryAclStore? _acl;
    private InMemoryDirectory? _dir;
    private AnalysisSession Lab => _lab ??= new AnalysisSession(LabSnapshotFactory.Create());

    public string DemoSnapshot()
    {
        var f = Path.Combine(root, "demo.aclmap");
        if (!File.Exists(f)) SnapshotArchive.Save(LabSnapshotFactory.Create() with { }, f);
        return f;
    }

    public string OlderSnapshot()
    {
        var f = Path.Combine(root, "older.aclmap");
        var s = LabSnapshotFactory.Create();
        var idx = new SnapshotIndex(s);
        var dir = idx.FindRelative("Direction")!.Value;
        var descs = s.Descriptors.ToList();
        var d = descs[s.Folders[dir].SdId];
        descs[s.Folders[dir].SdId] = d with { Aces = d.Aces.Where(a => a.Sid != LabSnapshotFactory.Prestataire).ToList() };
        SnapshotArchive.Save(s with { Descriptors = descs, Manifest = s.Manifest with { CreatedUtc = s.Manifest.CreatedUtc.AddDays(-30) } }, f);
        return f;
    }

    private static JsonElement J(object o) => JsonSerializer.SerializeToElement(o, AclMapJson.Options);

    public async Task<CollectorOutcome> RunAsync(CollectorRequest r, NetCredential? credential, Action<JsonElement> onEvent, CancellationToken ct)
    {
        await Task.Delay(150, CancellationToken.None);
        void Progress(string stage, string msg, int cur = 0, int total = 0) => onEvent(J(new { type = "progress", stage, message = msg, current = cur, total }));
        switch (r.Verb)
        {
            case "test":
                Progress("test", "Connexion à l'annuaire…");
                if ((r.DomainController ?? "").Contains("injoignable", StringComparison.OrdinalIgnoreCase))
                    return new(0, J(new { checks = new[] { new { name = "Annuaire (LDAP 389)", ok = false, message = "Contrôleur de domaine injoignable (LDAP 389) : vérifiez le nom, le DNS et le pare-feu." } } }), null);
                return new(0, J(new
                {
                    domain = new { dns = "contoso.local", netbios = "CONTOSO", sid = LabSnapshotFactory.D, dc = "DC01.contoso.local" },
                    account = new { name = r.AccountName ?? @"CONTOSO\audit", sid = LabSnapshotFactory.Rid(1500), tokenGroups = 7 },
                    checks = new object[]
                    {
                        new { name = "Annuaire (LDAP 389)", ok = true, message = "Domaine contoso.local (CONTOSO), contrôleur DC01.contoso.local" },
                        new { name = "Compte et groupes (tokenGroups)", ok = true, message = $"{r.AccountName ?? @"CONTOSO\audit"} : 7 groupe(s) transitif(s)" },
                    }.Concat((r.Servers ?? []).Select(s => (object)new { name = $"Partages de {s} (SMB 445)", ok = true, message = "4 partage(s) ; droits de partage lisibles pour 3." })).ToArray(),
                }), null);
            case "servers":
                return new(0, J(new { domain = "contoso.local", servers = new[] { new { name = "FS01.contoso.local", os = "Windows Server 2022 Standard" }, new { name = "FS02.contoso.local", os = "Windows Server 2019 Standard" } } }), null);
            case "shares":
                return new(0, J(new
                {
                    server = r.Server,
                    shares = Lab.Index.Snapshot.Shares.Select(s => (object)new { name = s.Name, unc = $@"\\{r.Server}\{s.Name}", localPath = s.LocalPath, kind = "Disk", special = false, remark = s.Remark, rightsKnown = s.Security is not null, rightsError = s.SecurityError,
                        rights = s.Security?.Aces.Select(a => new { sid = a.Sid, name = Lab.Index.NameOf(a.Sid), deny = a.IsDeny, rights = Rights.ShareLabel(a.Mask) }) })
                        .Append(new { name = "IMC2010_Atelier", unc = $@"\\{r.Server}\IMC2010_Atelier", localPath = "IMC2010_Atelier,LocalsplOnly", kind = "Print", special = false, remark = (string?)null, rightsKnown = false, rightsError = (string?)null, rights = (IEnumerable<object>?)null }),
                }), null);
            case "browse":
            {
                var p = r.Path ?? "";
                var parts = p.TrimStart('\\').Split('\\');
                var rel = string.Join('\\', parts.Skip(2));
                var id = Lab.Index.FindRelative(rel);
                if (id is null) return new(1, null, "Chemin réseau introuvable (53)");
                return new(0, J(new { path = p, folders = Lab.Index.Children(id.Value).Select(c => new { name = Lab.Index.Folder(c).Name, reparse = (Lab.Index.Folder(c).Flags & NodeFlags.ReparsePoint) != 0 }) }), null);
            }
            case "search":
            {
                var q = (r.Text ?? "").ToLowerInvariant();
                var items = Lab.Index.Principals.Where(p => p.SamAccountName is not null && (p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || (p.DisplayName ?? "").Contains(q, StringComparison.OrdinalIgnoreCase)))
                    .Select(p => new { sid = p.Sid, name = p.Name, kind = p.Kind.ToString(), scope = p.Scope.ToString(), dn = p.DistinguishedName, displayName = p.DisplayName, disabled = p.Disabled });
                items = items.Append(new { sid = LabSnapshotFactory.Rid(1601), name = @"CONTOSO\helene.garnier", kind = "User", scope = "None", dn = (string?)"CN=Hélène Garnier,OU=Utilisateurs,DC=contoso,DC=local", displayName = (string?)"Hélène Garnier", disabled = (bool?)false })
                    .Where(x => x.name.Contains(q, StringComparison.OrdinalIgnoreCase) || (x.displayName ?? "").Contains(q, StringComparison.OrdinalIgnoreCase));
                return new(0, J(new { items }), null);
            }
            case "ous":
                return new(0, J(new { ous = new[] { "OU=Groupes,DC=contoso,DC=local", "OU=Utilisateurs,DC=contoso,DC=local", "OU=Serveurs,DC=contoso,DC=local" } }), null);
            case "scan":
            {
                for (var i = 1; i <= 5; i++)
                {
                    if (ct.IsCancellationRequested) break;
                    Progress("scan", $"{i * 12} dossiers analysés, {60 - i * 12} en attente, 0 erreur(s)", i * 12, 60);
                    await Task.Delay(200, CancellationToken.None);
                }
                onEvent(J(new { type = "log", level = "warning", message = @"Autorisations illisibles : Accès refusé (5) — \\FS01.contoso.local\Donnees\RH\Paie" }));
                if ((r.Path ?? "").Contains("Inexistant", StringComparison.OrdinalIgnoreCase)) return new(1, null, @"Impossible d'ouvrir \\FS01\Inexistant : Nom réseau introuvable (67)");
                var dir = Path.Combine(root, "snapshots");
                var file = Path.Combine(dir, $"AclMap-FS01-Donnees-{DateTime.Now:yyyyMMdd-HHmmss}.aclmap");
                var snap = LabSnapshotFactory.Create();
                SnapshotArchive.Save(snap with { Manifest = snap.Manifest with { CreatedUtc = DateTimeOffset.UtcNow, Truncated = ct.IsCancellationRequested, CollectedBy = r.AccountName ?? @"CONTOSO\audit" } }, file);
                return new(0, J(new { path = file, folders = snap.Folders.Count, descriptors = snap.Descriptors.Count, principals = snap.Principals.Count, errors = 1, truncated = ct.IsCancellationRequested, durationMs = 1000 }), null);
            }
            case "authz":
                return new(0, J(new { path = r.Path, sid = r.Sid, mask = "0x001301bf", level = "Modification", details = Array.Empty<string>() }), null);
            case "apply":
            {
                var plan = JsonSerializer.Deserialize<OperationPlan>(File.ReadAllText(r.PlanFile!), AclMapJson.Options)!;
                _acl ??= new InMemoryAclStore(Lab); _dir ??= new InMemoryDirectory(Lab);
                var exec = new PlanExecutor(_acl, _dir, r.BackupFolder ?? Path.Combine(root, "backups"));
                var results = exec.Execute(plan, r.DryRun, res => onEvent(J(new { type = "opResult", data = res })));
                var ok = results.All(x => x.Success) && results.Count == plan.Operations.Count;
                return new(ok ? 0 : 3, J(new { planId = plan.PlanId, dryRun = r.DryRun, success = ok, results }), null);
            }
            case "restore":
            {
                _acl ??= new InMemoryAclStore(Lab); _dir ??= new InMemoryDirectory(Lab);
                var rec = JsonSerializer.Deserialize<BackupRecord>(File.ReadAllText(r.BackupFile!), AclMapJson.Options)!;
                var msg = new PlanExecutor(_acl, _dir, Path.Combine(root, "backups")).Restore(rec, r.DryRun);
                return new(0, J(new { backup = r.BackupFile, dryRun = r.DryRun, message = msg }), null);
            }
            default:
                return new(64, null, "Verbe inconnu : " + r.Verb);
        }
    }
}
