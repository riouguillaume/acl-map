using System.Security;
using System.Text.Json;
using AclMap.Core.Collector;
using AclMap.Core.Snapshot;
using AclMap.Hosting;
using AclMap.Logging;
using AclMap.Testing;

namespace AclMap.Tests;

public sealed class HostingTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory();
    public void Dispose() => _dir.Delete(true);

    private sealed class Bridge : IHostBridge
    {
        public readonly List<JsonElement> Messages = [];
        public readonly List<string> Raw = [];
        public void Post(string json) { lock (Messages) { Raw.Add(json); Messages.Add(JsonDocument.Parse(json).RootElement.Clone()); } }
        public JsonElement Last(string type) => Messages.Last(m => m.GetProperty("type").GetString() == type);
        public bool Has(string type) => Messages.Any(m => m.GetProperty("type").GetString() == type);
    }

    private sealed class Prompt : ICredentialPrompt
    {
        public int Calls;
        public SecureString? PromptPassword(string account, string target, string purpose)
        {
            Calls++;
            var s = new SecureString(); foreach (var c in "S3cr3t!Pwd") s.AppendChar(c); s.MakeReadOnly(); return s;
        }
    }

    private sealed class Sys : ISystemInfo
    {
        public bool IsDomainJoined => false; public string? JoinedDomain => null; public string MachineName => "ADMIN01";
        public string CurrentUser => @"ADMIN01\tech"; public string? WebView2Version => "1"; public string? DotNetVersion => "10";
    }

    private sealed class Dialogs(string file) : IDialogService
    {
        public string? OpenSnapshot(string title) => file;
        public string? SaveFile(string suggestedName, string filter) => Path.Combine(Path.GetDirectoryName(file)!, suggestedName);
        public string? PickFolder(string? initial) => null;
    }

    private sealed class Collector(string dir) : ICollectorRunner
    {
        public readonly List<(CollectorRequest Req, NetCredential? Cred)> Calls = [];
        public Task<CollectorOutcome> RunAsync(CollectorRequest r, NetCredential? c, Action<JsonElement> onEvent, CancellationToken ct)
        {
            Calls.Add((r, c));
            onEvent(JsonSerializer.SerializeToElement(new { type = "progress", stage = "scan", message = "x", current = 1, total = 2 }));
            if (r.Verb == "scan")
            {
                var f = Path.Combine(dir, "scan.aclmap");
                SnapshotArchive.Save(LabSnapshotFactory.Create(), f);
                return Task.FromResult(new CollectorOutcome(0, JsonSerializer.SerializeToElement(new { path = f, folders = 10, errors = 0 }), null));
            }
            if (r.Verb == "apply") return Task.FromResult(new CollectorOutcome(0, JsonSerializer.SerializeToElement(new { success = true, results = Array.Empty<object>() }), null));
            return Task.FromResult(new CollectorOutcome(0, JsonSerializer.SerializeToElement(new { checks = new[] { new { name = "x", ok = true, message = "ok" } } }), null));
        }
    }

    private (AppController, Bridge, Prompt, Collector) Create()
    {
        var snap = Path.Combine(_dir.FullName, "lab.aclmap");
        SnapshotArchive.Save(LabSnapshotFactory.Create(), snap);
        var b = new Bridge(); var p = new Prompt(); var c = new Collector(_dir.FullName);
        var store = new SettingsStore(Path.Combine(_dir.FullName, "settings.json"));
        store.Save(new AppSettings
        {
            ActiveProfileId = "p", QuickConnectDone = true,
            Profiles = [new DomainProfile { Id = "p", Name = "Contoso", DomainName = "contoso.local", DomainController = "DC01", ConnectionMode = ConnectionMode.AlternateAccount, AccountName = @"CONTOSO\audit", WriteAccountName = @"CONTOSO\adm-acl" }],
        });
        return (new AppController(b, new Dialogs(snap), c, p, new Sys(), store, new OperationLog(Path.Combine(_dir.FullName, "logs")), _dir.FullName), b, p, c);
    }

    private static string Msg(object o) => JsonSerializer.Serialize(o);

    [Fact]
    public async Task Ready_sends_init_and_settings_without_secrets()
    {
        var (ctl, b, _, _) = Create();
        await ctl.HandleAsync(Msg(new { type = "ready" }));
        Assert.True(b.Has("init"));
        Assert.Equal("Contoso", b.Last("settings").GetProperty("settings").GetProperty("profiles")[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task Invalid_profile_is_rejected_with_field_errors()
    {
        var (ctl, b, _, _) = Create();
        await ctl.HandleAsync(Msg(new { type = "saveProfile", profile = new { name = "", domainName = "contoso", connectionMode = "AlternateAccount", accountName = "audit", fileServers = new[] { new { server = "FS 01" } } } }));
        var errs = b.Last("validation").GetProperty("errors");
        Assert.True(errs.TryGetProperty("name", out _));
        Assert.True(errs.TryGetProperty("domainName", out _));
        Assert.True(errs.TryGetProperty("accountName", out _));
        Assert.True(errs.TryGetProperty("servers.0", out _));
    }

    [Fact]
    public async Task Read_password_is_prompted_once_per_session_and_never_sent_to_the_page()
    {
        var (ctl, b, p, c) = Create();
        await ctl.HandleAsync(Msg(new { type = "listShares", server = "FS01" }));
        await ctl.HandleAsync(Msg(new { type = "browse", path = @"\\FS01\Donnees" }));
        Assert.Equal(1, p.Calls);
        Assert.All(c.Calls, x => Assert.Equal(@"CONTOSO\audit", x.Cred!.Account));
        Assert.DoesNotContain(b.Raw, r => r.Contains("S3cr3t", StringComparison.Ordinal));
        Assert.All(Directory.GetFiles(_dir.FullName, "*", SearchOption.AllDirectories).Where(f => !f.EndsWith(".aclmap")), f => Assert.DoesNotContain("S3cr3t", File.ReadAllText(f)));
    }

    [Fact]
    public async Task Scan_runs_collector_then_opens_snapshot_and_updates_profile()
    {
        var (ctl, b, _, c) = Create();
        await ctl.HandleAsync(Msg(new { type = "scan", path = @"\\FS01\Donnees" }));
        Assert.True(b.Has("scanStarted") && b.Has("scanDone") && b.Has("snapshot") && b.Has("progress"));
        Assert.Equal("scan", c.Calls.Single().Req.Verb);
        Assert.Equal("contoso.local", c.Calls.Single().Req.Domain);
        Assert.NotNull(ctl.Settings.Profiles[0].LastSnapshotPath);
        await ctl.HandleAsync(Msg(new { type = "scan", path = "pas un chemin" }));
        Assert.Equal("scan", b.Last("validation").GetProperty("context").GetString());
    }

    [Fact]
    public async Task Writes_require_enabling_confirmation_and_the_delegated_account()
    {
        var (ctl, b, p, c) = Create();
        await ctl.HandleAsync(Msg(new { type = "openSnapshot" }));
        var commun = ctl.Session!.Index.FindRelative("Commun")!.Value;
        await ctl.HandleAsync(Msg(new { type = "planAddAce", folderId = commun, principal = new { sid = LabSnapshotFactory.GgRh, name = "GG_RH" }, level = "Read", scope = "ThisFolderSubfoldersFiles" }));
        var planId = b.Last("plan").GetProperty("plan").GetProperty("planId").GetString();
        Assert.False(b.Last("plan").GetProperty("writeEnabled").GetBoolean());

        await ctl.HandleAsync(Msg(new { type = "applyPlan", planId, dryRun = false, confirm = "APPLIQUER" }));
        Assert.Contains("lecture seule", b.Last("error").GetProperty("message").GetString());
        Assert.DoesNotContain(c.Calls, x => x.Req.Verb == "apply");

        await ctl.HandleAsync(Msg(new { type = "applyPlan", planId, dryRun = true }));
        var dry = c.Calls.Single(x => x.Req.Verb == "apply");
        Assert.True(dry.Req.DryRun);
        Assert.Equal(@"CONTOSO\audit", dry.Cred!.Account);   // Dry Run : compte de lecture

        await ctl.HandleAsync(Msg(new { type = "saveSettings", writeEnabled = true }));
        await ctl.HandleAsync(Msg(new { type = "applyPlan", planId, dryRun = false, confirm = "oui" }));
        Assert.Contains("APPLIQUER", b.Last("error").GetProperty("message").GetString());

        var before = p.Calls;
        await ctl.HandleAsync(Msg(new { type = "applyPlan", planId, dryRun = false, confirm = "APPLIQUER" }));
        var real = c.Calls.Last();
        Assert.False(real.Req.DryRun);
        Assert.Equal(@"CONTOSO\adm-acl", real.Cred!.Account);  // compte délégué, redemandé
        Assert.Equal(before + 1, p.Calls);
        Assert.True(b.Last("applyDone").GetProperty("success").GetBoolean());
        var log = new OperationLog(Path.Combine(_dir.FullName, "logs")).Recent();
        Assert.Contains(log, e => e.Event == "plan.apply" && e.Level == "audit");
        Assert.True(File.Exists(real.Req.PlanFile));
    }

    [Fact]
    public async Task Queries_and_exports_work_on_the_open_snapshot()
    {
        var (ctl, b, _, _) = Create();
        await ctl.HandleAsync(Msg(new { type = "folder", id = 0 }));
        Assert.Contains("Aucun instantané", b.Last("error").GetProperty("message").GetString());
        await ctl.HandleAsync(Msg(new { type = "openSnapshot" }));
        await ctl.HandleAsync(Msg(new { type = "accessMap", sid = LabSnapshotFactory.Alice, path = "Donnees" }));
        Assert.Equal("Donnees", b.Last("accessMap").GetProperty("accessPath").GetString());
        await ctl.HandleAsync(Msg(new { type = "explain", sid = LabSnapshotFactory.Alice, folderId = 2, path = "ntfs" }));
        Assert.True(b.Has("explain"));
        await ctl.HandleAsync(Msg(new { type = "export", kind = "Html" }));
        Assert.True(File.Exists(b.Last("exported").GetProperty("file").GetString()));
        await ctl.HandleAsync(Msg(new { type = "compare" }));
        Assert.Equal(0, b.Last("diff").GetProperty("changedCount").GetInt32());
    }
}
