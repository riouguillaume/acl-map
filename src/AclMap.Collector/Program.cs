using System.ComponentModel;
using System.Text.Json;
using AclMap.ActiveDirectory;
using AclMap.Collector;
using AclMap.Core.Collector;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Core.Validation;
using AclMap.FileSystem;
using AclMap.Models.Snapshot;
using AclMap.Operations;
using AclMap.Shares;

// Collecteur ACL Map.
//  Mode application : AclMap.Collector.exe --request <requête.json> --events <événements.jsonl>
//  Mode ligne de commande (serveur de fichiers, tâche planifiée) :
//    AclMap.Collector.exe scan \\FS01\Donnees [--out D:\Audits] [--depth 12] [--files] [--parallel 8] [--backup] [--dc DC01.contoso.local] [--domain contoso.local]
//    AclMap.Collector.exe shares FS01 | test | servers | help

Console.OutputEncoding = System.Text.Encoding.UTF8;
CollectorRequest request;
string? eventsFile = null;
try
{
    (request, eventsFile) = Cli.Parse(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine("ERREUR : " + ex.Message);
    Console.Error.WriteLine(Cli.Help);
    return 64;
}
if (request.Verb == "help") { Console.WriteLine(Cli.Help); return 0; }

var events = new EventSink(eventsFile);
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
if (eventsFile is not null)
{
    // Arrêt propre demandé par l'application : présence du fichier <événements>.cancel
    _ = Task.Run(async () =>
    {
        while (!cts.IsCancellationRequested)
        {
            if (File.Exists(eventsFile + CollectorEvents.CancelSuffix)) { cts.Cancel(); break; }
            await Task.Delay(400).ConfigureAwait(false);
        }
    });
}

try
{
    switch (request.Verb)
    {
        case "scan": await new ScanPipeline(request, events).RunAsync(cts.Token); break;
        case "browse": Verbs.Browse(request, events); break;
        case "shares": Verbs.Shares(request, events); break;
        case "servers": Verbs.Servers(request, events); break;
        case "test": Verbs.Test(request, events); break;
        case "search": Verbs.Search(request, events); break;
        case "ous": Verbs.Ous(request, events); break;
        case "authz": Verbs.Authz(request, events); break;
        case "apply": return Verbs.Apply(request, events);
        case "restore": Verbs.Restore(request, events); break;
        default: events.Error($"Verbe inconnu : {request.Verb}"); return 64;
    }
    return 0;
}
catch (OperationCanceledException) { events.Error("Opération annulée."); return 2; }
catch (Exception ex) when (ex is not OutOfMemoryException)
{
    var code = ex is Win32Exception w ? w.NativeErrorCode : 0;
    if (Environment.GetEnvironmentVariable("ACLMAP_DEBUG") == "1") Console.Error.WriteLine(ex.ToString());
    events.Error(ex is System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException ? LdapDirectory.Explain(ex) : ex.Message, code);
    return 1;
}

/// <summary>Analyse de la ligne de commande.</summary>
internal static class Cli
{
    public const string Help = """
ACL Map — collecteur (lecture seule)
  AclMap.Collector.exe scan <\\serveur\partage\dossier | D:\dossier> [options]
      --out <dossier>      dossier de sortie (défaut : Documents\AclMap)
      --depth <n>          profondeur maximale (défaut 12)
      --files              analyser aussi les fichiers
      --parallel <n>       requêtes simultanées (défaut 8)
      --backup             mode sauvegarde (SeBackupPrivilege, sans takeown)
      --domain <fqdn>      domaine ;  --dc <serveur> contrôleur de domaine
  AclMap.Collector.exe shares <serveur>
  AclMap.Collector.exe test [--domain <fqdn>] [--dc <serveur>] [--server <serveur>]
  AclMap.Collector.exe servers [--domain <fqdn>] [--dc <serveur>]
""";

    public static (CollectorRequest, string?) Parse(string[] args)
    {
        if (args.Length == 0) return (new CollectorRequest { Verb = "help" }, null);
        var named = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("--", StringComparison.Ordinal))
            {
                var key = args[i][2..];
                var flag = key is "files" or "backup" or "dry-run" or "print";
                named[key] = flag ? "1" : (i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Valeur manquante pour --{key}"));
            }
            else positional.Add(args[i]);
        }
        if (named.TryGetValue("request", out var reqFile))
        {
            var r = JsonSerializer.Deserialize<CollectorRequest>(File.ReadAllText(reqFile!), AclMapJson.Options) ?? throw new ArgumentException("Requête vide.");
            return (r, named.GetValueOrDefault("events"));
        }
        var verb = positional.FirstOrDefault()?.ToLowerInvariant() ?? "help";
        int Int(string k, int def) => named.TryGetValue(k, out var v) ? (int.TryParse(v, out var n) && n > 0 ? n : throw new ArgumentException($"--{k} : nombre attendu")) : def;
        var req = new CollectorRequest
        {
            Verb = verb, Path = verb == "scan" ? positional.ElementAtOrDefault(1) : null,
            Server = verb == "shares" ? positional.ElementAtOrDefault(1) : named.GetValueOrDefault("server"),
            Servers = named.GetValueOrDefault("server") is { } s ? [s] : null,
            Domain = named.GetValueOrDefault("domain"), DomainController = named.GetValueOrDefault("dc"), OutputFolder = named.GetValueOrDefault("out"),
            Scan = new ScanOptions { MaxDepth = Int("depth", 12), Parallelism = Int("parallel", 8), IncludeFiles = named.ContainsKey("files"), BackupMode = named.ContainsKey("backup"), IncludePrintShares = named.ContainsKey("print") },
        };
        if (verb == "scan" && req.Path is null) throw new ArgumentException("Chemin à analyser manquant.");
        if (verb == "shares" && req.Server is null) throw new ArgumentException("Serveur manquant.");
        return (req, null);
    }
}

/// <summary>Verbes courts (lecture seule, sauf apply/restore).</summary>
internal static class Verbs
{
    public static void Browse(CollectorRequest r, EventSink e)
    {
        var path = r.Path ?? throw new ArgumentException("Chemin manquant.");
        if (InputValidator.ScanPath(path) is { } err) throw new ArgumentException(err);
        var list = FolderBrowser.List(path);
        e.Result(new { path, folders = list.Select(f => new { name = f.Name, reparse = f.Reparse }) });
    }

    private static object ShareDto(ShareInfo s, Func<string, string> name) => new
    {
        name = s.Name, unc = s.Unc, localPath = s.LocalPath, kind = s.Kind.ToString(), special = s.Special, remark = s.Remark,
        rightsKnown = s.Security is not null, rightsError = s.SecurityError,
        rights = s.Security?.Aces.Select(a => new { sid = a.Sid, name = name(a.Sid), deny = a.IsDeny, rights = Rights.ShareLabel(a.Mask) }),
    };

    public static void Shares(CollectorRequest r, EventSink e)
    {
        var server = Targets.PreferFqdn(r.Server ?? throw new ArgumentException("Serveur manquant."));
        if (InputValidator.Server(server) is { } err) throw new ArgumentException(err);
        var shares = ShareReader.List(server);
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string Name(string sid) => names.TryGetValue(sid, out var n) ? n : names[sid] = WellKnownSids.NameOf(sid) ?? WindowsAccounts.Resolve(server, sid).Name;
        e.Result(new { server, shares = shares.Where(s => s.Kind != ShareKind.Ipc).Select(s => ShareDto(s, Name)) });
    }

    public static void Servers(CollectorRequest r, EventSink e)
    {
        using var ldap = Targets.Connect(r.DomainController, r.Domain);
        e.Result(new { domain = ldap.Domain.DnsName, servers = ldap.Servers().Select(s => new { name = s.Name, os = s.OperatingSystem }) });
    }

    public static void Search(CollectorRequest r, EventSink e)
    {
        var text = r.Text?.Trim() ?? "";
        if (text.Length < 2) throw new ArgumentException("Saisissez au moins 2 caractères.");
        using var ldap = Targets.Connect(r.DomainController, r.Domain);
        e.Result(new { items = ldap.Search(text, r.Kind ?? "any").Select(p => new { sid = p.Sid, name = p.Name, kind = p.Kind.ToString(), scope = p.Scope.ToString(), dn = p.DistinguishedName, displayName = p.DisplayName, disabled = p.Disabled }) });
    }

    public static void Ous(CollectorRequest r, EventSink e)
    {
        using var ldap = Targets.Connect(r.DomainController, r.Domain);
        e.Result(new { ous = ldap.OrganizationalUnits() });
    }

    public static void Test(CollectorRequest r, EventSink e)
    {
        var checks = new List<object>();
        object? domain = null; object? account = null;
        e.Progress("test", "Connexion à l'annuaire…");
        try
        {
            using var ldap = Targets.Connect(r.DomainController, r.Domain);
            var d = ldap.Domain;
            domain = new { dns = d.DnsName, netbios = d.NetbiosName, sid = d.Sid, dc = d.DomainController };
            checks.Add(new { name = "Annuaire (LDAP 389)", ok = true, message = $"Domaine {d.DnsName} ({d.NetbiosName}), contrôleur {d.DomainController}" });
            var accountName = r.AccountName ?? Targets.CurrentUser().Name;
            var found = ((IDirectoryStore)ldap).Find(new PrincipalRef(null, accountName.Split('\\').Last().Split('@')[0]));
            if (found is { } f)
            {
                var n = ldap.TokenGroupCount(f.Sid);
                account = new { name = accountName, sid = f.Sid, tokenGroups = n };
                checks.Add(new { name = "Compte et groupes (tokenGroups)", ok = true, message = $"{accountName} : {n} groupe(s) transitif(s)" });
            }
            else checks.Add(new { name = "Compte et groupes (tokenGroups)", ok = false, message = $"Compte {accountName} introuvable dans {d.DnsName}." });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            checks.Add(new { name = "Annuaire (LDAP 389)", ok = false, message = LdapDirectory.Explain(ex) + " Pistes : DNS du domaine, ports 53/88/389, heure synchronisée, identifiants." });
        }
        foreach (var srv in (r.Servers ?? []).Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            var server = Targets.PreferFqdn(srv.Trim());
            e.Progress("test", $"Serveur {server}…");
            try
            {
                var shares = ShareReader.List(server).Where(s => s.Kind == ShareKind.Disk && !s.Special).ToList();
                var readable = shares.Count(s => s.Security is not null);
                checks.Add(new { name = $"Partages de {server} (SMB 445)", ok = true, message = $"{shares.Count} partage(s) ; droits de partage lisibles pour {readable}." + (readable < shares.Count ? " Les droits de partage exigent d'être administrateur du serveur." : "") });
                var first = shares.FirstOrDefault();
                if (first is not null)
                {
                    try
                    {
                        using var h = SecurityReader.Open(first.Unc, 0x20000, false, out var err);
                        var ok = !h.IsInvalid && SecurityReader.ReadSecurity(h, out err) is not null;
                        checks.Add(new { name = $"ACL de {first.Unc}", ok, message = ok ? "Autorisations lisibles." : "Autorisations illisibles : " + SecurityReader.Describe(err) });
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException) { checks.Add(new { name = $"ACL de {first.Unc}", ok = false, message = ex.Message }); }
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                checks.Add(new { name = $"Partages de {server} (SMB 445)", ok = false, message = ex.Message + " Pistes : nom du serveur, port 445, identifiants (erreur 1219 : une connexion SMB existe déjà avec un autre compte)." });
            }
        }
        var backup = Privileges.Enable("SeBackupPrivilege");
        checks.Add(new { name = "Mode sauvegarde (SeBackupPrivilege)", ok = true, message = backup ? "Disponible sur ce poste." : "Non disponible dans cette session (facultatif)." });
        e.Result(new { domain, account, checks });
    }

    public static void Authz(CollectorRequest r, EventSink e)
    {
        var path = r.Path ?? throw new ArgumentException("Chemin manquant.");
        var sid = r.Sid ?? throw new ArgumentException("SID manquant.");
        using var h = SecurityReader.Open(path, 0x20000, false, out var err);
        if (h.IsInvalid) throw new Win32Exception(err, "Lecture de l'ACL impossible : " + SecurityReader.Describe(err));
        var sd = SecurityReader.ReadSecurity(h, out err) ?? throw new Win32Exception(err, "Lecture de l'ACL impossible : " + SecurityReader.Describe(err));
        var mask = AuthzCheck.MaximumAllowed(sid, sd);
        e.Result(new { path, sid, mask = "0x" + mask.ToString("x8"), level = Rights.LevelLabel(Rights.LevelOf(mask)), details = Rights.Describe(mask) });
    }

    private static PlanExecutor Executor(CollectorRequest r, out LdapDirectory? ldap)
    {
        ldap = null;
        try { ldap = Targets.Connect(r.DomainController, r.Domain); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { ldap = null; _ = ex; }
        var folder = r.BackupFolder ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AclMap", "backups");
        return new PlanExecutor(new WindowsAclStore(), (IDirectoryStore?)ldap ?? new NoDirectory(), folder);
    }

    public static int Apply(CollectorRequest r, EventSink e)
    {
        var plan = JsonSerializer.Deserialize<OperationPlan>(File.ReadAllText(r.PlanFile ?? throw new ArgumentException("Plan manquant.")), AclMapJson.Options)
            ?? throw new ArgumentException("Plan illisible.");
        var exec = Executor(r, out var ldap);
        using (ldap)
        {
            var results = exec.Execute(plan, r.DryRun, res => e.OperationResult(res));
            var ok = results.All(x => x.Success) && results.Count == plan.Operations.Count;
            e.Result(new { planId = plan.PlanId, dryRun = r.DryRun, success = ok, results });
            return ok ? 0 : 3;
        }
    }

    public static void Restore(CollectorRequest r, EventSink e)
    {
        var rec = JsonSerializer.Deserialize<BackupRecord>(File.ReadAllText(r.BackupFile ?? throw new ArgumentException("Sauvegarde manquante.")), AclMapJson.Options)
            ?? throw new ArgumentException("Sauvegarde illisible.");
        var exec = Executor(r, out var ldap);
        using (ldap) e.Result(new { backup = r.BackupFile, dryRun = r.DryRun, message = exec.Restore(rec, r.DryRun) });
    }

    /// <summary>Annuaire indisponible : seules les opérations sur les ACL restent possibles.</summary>
    private sealed class NoDirectory : IDirectoryStore
    {
        private static InvalidOperationException Fail() => new("Annuaire injoignable : opération sur les groupes impossible.");
        public (string Sid, string Dn)? Find(PrincipalRef reference) => reference.Sid is not null ? (reference.Sid, reference.Dn ?? reference.Name) : throw Fail();
        public bool IsMember(string groupDn, string memberSid) => throw Fail();
        public void AddMember(string groupDn, string memberDn) => throw Fail();
        public void RemoveMember(string groupDn, string memberDn) => throw Fail();
        public (string Sid, string Dn) CreateGroup(string ouDn, string name, string scope, string? description) => throw Fail();
        public void DeleteGroup(string dn) => throw Fail();
    }
}
