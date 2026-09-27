using System.Diagnostics;
using System.Globalization;
using AclMap.ActiveDirectory;
using AclMap.Core.Collector;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Core.Validation;
using AclMap.FileSystem;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;
using AclMap.Shares;

namespace AclMap.Collector;

/// <summary>
/// Analyse complète (lecture seule) : partages du serveur, arborescence et ACL, résolution des identités,
/// développement des groupes AD et locaux, puis enregistrement de l'instantané .aclmap.
/// </summary>
public sealed class ScanPipeline(CollectorRequest req, EventSink events)
{
    private const int MaxPrincipals = 250_000;
    private readonly List<CollectionError> _errors = [];

    public async Task<string> RunAsync(CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var path = (req.Path ?? "").Trim();
        if (InputValidator.ScanPath(path) is { } perr) throw new ArgumentException(perr);
        path = path.TrimEnd('\\');
        if (path.Length == 2 && path[1] == ':') path += "\\";
        var options = req.Scan ?? new ScanOptions();
        var unc = InputValidator.SplitUnc(path);
        var server = unc?.Server ?? Environment.MachineName;
        var serverFqdn = Targets.PreferFqdn(server);

        // 1. Partages
        events.Progress("shares", $"Lecture des partages de {server}…");
        List<ShareInfo> shares = [];
        try { shares = ShareReader.List(server); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { AddError("shares", server, ex, "Partages non lus : " + ex.Message); }
        shares = shares.Where(s => (s.Kind == ShareKind.Disk || (options.IncludePrintShares && s.Kind == ShareKind.Print)) && (options.IncludeSpecialShares || !s.Special) && s.Kind != ShareKind.Ipc)
            .Select(s => s with { Server = serverFqdn }).ToList();
        string? shareName = null, rootLocal = null;
        if (unc is { } u)
        {
            var sh = shares.FirstOrDefault(s => s.Name.Equals(u.Share, StringComparison.OrdinalIgnoreCase));
            shareName = sh?.Name ?? u.Share;
            if (sh?.LocalPath is { Length: > 0 } lp) rootLocal = u.SubPath.Length == 0 ? lp : lp.TrimEnd('\\') + "\\" + u.SubPath;
        }
        else
        {
            rootLocal = path;
            shareName = shares.Where(s => s.LocalPath is not null && s.LocalPath.TrimEnd('\\').Equals(path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)).Select(s => s.Name).FirstOrDefault();
        }

        // 2. Arborescence
        events.Progress("scan", $"Analyse de {path}…");
        var scanner = new TreeScanner(options);
        var progress = new Progress<ScanProgress>(p => events.Progress("scan", $"{p.Processed:N0} dossiers analysés, {p.Pending:N0} en attente, {p.Errors:N0} erreur(s) — {Short(p.Current)}", p.Processed, p.Processed + p.Pending));
        var scan = await scanner.ScanAsync(path, progress, ct).ConfigureAwait(false);
        _errors.AddRange(scan.Errors);

        var draft = new AclSnapshot
        {
            Manifest = new SnapshotManifest { RootPath = path, RootLocalPath = rootLocal },
            Folders = scan.Nodes, Descriptors = scan.Descriptors,
        };
        var index = new SnapshotIndex(draft);
        shares = ShareReader.Link(shares, index.FindLocal);

        // 3. Identités
        events.Progress("identities", "Résolution des identités…");
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in scan.Descriptors) { if (d.Owner is not null) sids.Add(d.Owner); foreach (var a in d.Aces) sids.Add(a.Sid); }
        foreach (var s in shares) foreach (var a in s.Security?.Aces ?? []) sids.Add(a.Sid);
        sids.RemoveWhere(s => s == "S-1-0-0");

        LdapDirectory? ldap = null;
        DomainInfo? domain = null;
        try
        {
            ldap = Targets.Connect(req.DomainController, req.Domain);
            domain = ldap.Domain;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            AddError("ldap", req.DomainController ?? req.Domain, ex, "Annuaire injoignable : les groupes ne seront pas développés. " + LdapDirectory.Explain(ex));
            ldap?.Dispose(); ldap = null;
        }

        var principals = new Dictionary<string, PrincipalInfo>(StringComparer.OrdinalIgnoreCase);
        ResolveInto(principals, sids, ldap, domain, serverFqdn);

        // Groupes locaux du serveur
        if (options.ExpandGroups)
        {
            try
            {
                foreach (var g in WindowsAccounts.LocalGroups(serverFqdn))
                {
                    if (principals.TryGetValue(g.Sid, out var existing)) principals[g.Sid] = existing with { Kind = PrincipalKind.LocalGroup, Scope = GroupScope.Local, Members = g.Members, MembersError = g.MembersError, Description = g.Description };
                    else if (g.Sid.StartsWith("S-1-5-32-", StringComparison.Ordinal) || sids.Contains(g.Sid)) principals[g.Sid] = g;
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                AddError("localgroups", serverFqdn, ex, "Groupes locaux du serveur non lus (droits d'administrateur requis) : les accès via BUILTIN\\… seront marqués ambigus. " + ex.Message);
                foreach (var k in principals.Keys.Where(k => principals[k].Kind == PrincipalKind.LocalGroup).ToList())
                    principals[k] = principals[k] with { Members = null, MembersError = "Groupe local du serveur : membres non lus." };
            }

            // 4. Développement des groupes (AD et locaux)
            events.Progress("groups", "Développement des groupes…");
            var queue = new Queue<string>(principals.Values.Where(p => p.Kind is PrincipalKind.Group or PrincipalKind.LocalGroup).Select(p => p.Sid));
            var done = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var n = 0;
            while (queue.Count > 0 && principals.Count < MaxPrincipals && !ct.IsCancellationRequested)
            {
                var gsid = queue.Dequeue();
                if (!done.Add(gsid) || !principals.TryGetValue(gsid, out var g)) continue;
                if (++n % 20 == 0) events.Progress("groups", $"Développement des groupes : {n:N0} traités, {principals.Count:N0} identités", n, n + queue.Count);
                List<string> memberSids;
                if (g.Kind == PrincipalKind.Group && g.DistinguishedName is not null && ldap is not null && Sid.DomainOf(g.Sid) == domain?.Sid)
                {
                    try
                    {
                        var members = ldap.Members(g);
                        foreach (var m in members) principals.TryAdd(m.Sid, m);
                        memberSids = members.Select(m => m.Sid).ToList();
                        principals[gsid] = g with { Members = memberSids };
                    }
                    catch (Exception ex) when (ex is System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException)
                    {
                        principals[gsid] = g with { Members = null, MembersError = LdapDirectory.Explain(ex) };
                        continue;
                    }
                }
                else if (g.Kind == PrincipalKind.LocalGroup && g.Members is not null) memberSids = g.Members.ToList();
                else
                {
                    if (g.Members is null && g.MembersError is null)
                        principals[gsid] = g with { MembersError = Sid.DomainOf(g.Sid) != domain?.Sid ? "Groupe d'un autre domaine : membres non lus." : "Membres non lus (annuaire injoignable)." };
                    continue;
                }
                var unknown = memberSids.Where(s => !principals.ContainsKey(s)).ToList();
                if (unknown.Count > 0) ResolveInto(principals, unknown, ldap, domain, serverFqdn);
                foreach (var m in memberSids) if (principals.TryGetValue(m, out var mp) && mp.Kind is PrincipalKind.Group or PrincipalKind.LocalGroup && !done.Contains(m)) queue.Enqueue(m);
            }
            if (principals.Count >= MaxPrincipals) AddError("groups", null, null, $"Limite de {MaxPrincipals:N0} identités atteinte : développement des groupes interrompu.");
        }

        // Compte de collecte
        var (who, whoSid) = Targets.CurrentUser();
        if (!string.IsNullOrWhiteSpace(req.AccountName))
        {
            who = req.AccountName!;
            whoSid = null;
            try
            {
                if (ldap is not null && ((AclMap.Operations.IDirectoryStore)ldap).Find(new AclMap.Operations.PrincipalRef(null, who.Split('\\').Last().Split('@')[0])) is { } f) whoSid = f.Sid;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { }
        }

        var manifest = new SnapshotManifest
        {
            ToolVersion = typeof(ScanPipeline).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
            CreatedUtc = DateTimeOffset.UtcNow, RootPath = path, Server = serverFqdn, ShareName = shareName, RootLocalPath = rootLocal,
            Domain = domain is null ? (req.Domain is null ? null : new DomainRef(req.Domain, null, null, req.DomainController)) : new DomainRef(domain.DnsName, domain.NetbiosName, domain.Sid, domain.DomainController),
            CollectedBy = who, CollectedBySid = whoSid, Machine = Environment.MachineName, Options = options with { BackupMode = scan.BackupPrivilegeEnabled },
            DurationMs = sw.ElapsedMilliseconds, Truncated = scan.Truncated,
        };
        ldap?.Dispose();
        var snapshot = draft with { Manifest = manifest, Principals = principals.Values.OrderBy(p => p.Sid, StringComparer.Ordinal).ToList(), Shares = shares, Errors = _errors };

        events.Progress("save", "Enregistrement de l'instantané…");
        var folder = string.IsNullOrWhiteSpace(req.OutputFolder) ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "AclMap") : req.OutputFolder!;
        var name = $"AclMap-{Safe(server)}-{Safe(shareName ?? Path.GetFileName(path.TrimEnd('\\')))}-{DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}{SnapshotArchive.Extension}";
        var file = Path.Combine(folder, name);
        var saved = SnapshotArchive.Save(snapshot, file);
        events.Result(new
        {
            path = file, folders = saved.Manifest.FolderCount, files = saved.Manifest.FileCount, descriptors = saved.Manifest.DescriptorCount,
            principals = snapshot.Principals.Count, errors = saved.Manifest.ErrorCount, truncated = saved.Manifest.Truncated, durationMs = sw.ElapsedMilliseconds,
        });
        return file;
    }

    private static string Short(string p) => p.Length > 90 ? "…" + p[^88..] : p;

    private static string Safe(string s) => string.Concat(s.Select(c => Path.GetInvalidFileNameChars().Contains(c) || c is '$' or ' ' ? '_' : c));

    private void AddError(string stage, string? target, Exception? ex, string message)
    {
        var code = ex is System.ComponentModel.Win32Exception w ? w.NativeErrorCode : 0;
        _errors.Add(new CollectionError(stage, target, code, message));
        events.Log("warning", message);
    }

    private static void ResolveInto(Dictionary<string, PrincipalInfo> principals, IEnumerable<string> sids, LdapDirectory? ldap, DomainInfo? domain, string server)
    {
        var list = sids.Where(s => !principals.ContainsKey(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ldap is not null && domain is not null)
        {
            try { foreach (var (k, v) in ldap.Resolve(list.Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal)))) principals[k] = v; }
            catch (Exception ex) when (ex is System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException) { }
        }
        foreach (var s in list.Where(s => !principals.ContainsKey(s)))
        {
            var wk = WellKnownSids.NameOf(s);
            var kind = WellKnownSids.KindOf(s);
            WindowsAccounts.Lookup? look = null;
            if (wk is null || kind is null)
            {
                try { look = WindowsAccounts.Resolve(server, s); } catch (FormatException) { continue; }
            }
            var orphan = look?.Orphan == true && (domain is null || Sid.DomainOf(s) == domain.Sid || look.Kind == PrincipalKind.Unknown);
            principals[s] = new PrincipalInfo
            {
                Sid = s, Name = wk ?? look?.Name ?? s, Kind = kind ?? (orphan ? PrincipalKind.Unknown : look?.Kind ?? PrincipalKind.Unknown),
                Orphan = orphan, Scope = kind == PrincipalKind.LocalGroup ? GroupScope.Local : GroupScope.None,
                // Groupe d'un autre domaine (approbation) : membres inconnus
                MembersError = look?.Kind == PrincipalKind.Group && domain is not null && Sid.DomainOf(s) != domain.Sid ? "Groupe d'un autre domaine : membres non lus." : null,
            } is var p && p.Kind == PrincipalKind.Group && domain is not null && Sid.DomainOf(s) != domain.Sid ? p with { Kind = PrincipalKind.Foreign } : p;
        }
    }
}
