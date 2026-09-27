using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Text;
using AclMap.Core.Security;
using AclMap.Models.Snapshot;
using AclMap.Operations;

namespace AclMap.ActiveDirectory;

/// <summary>Informations de domaine lues dans le RootDSE et la partition de configuration.</summary>
public sealed record DomainInfo(string DnsName, string? NetbiosName, string Sid, string DefaultNamingContext, string DomainController);

/// <summary>Serveur proposé par la découverte AD.</summary>
public sealed record ServerCandidate(string Name, string? OperatingSystem);

/// <summary>
/// Accès LDAP à l'annuaire (System.DirectoryServices.Protocols, authentification Negotiate avec signature et
/// chiffrement). En mode « autre compte », le processus tourne en « runas /netonly » : l'authentification réseau
/// utilise alors ce compte sans qu'aucun mot de passe ne transite par ACL Map.
/// </summary>
public sealed class LdapDirectory : IDirectoryStore, IDisposable
{
    private static readonly string[] PrincipalAttrs = ["objectSid", "objectClass", "sAMAccountName", "distinguishedName", "groupType", "userAccountControl", "adminCount", "primaryGroupID", "displayName", "description"];
    private readonly LdapConnection _conn;
    private DomainInfo? _domain;

    /// <summary>Se connecte au contrôleur (ou au domaine).</summary>
    /// <param name="server">Contrôleur de domaine ou nom DNS du domaine.</param>
    public LdapDirectory(string server)
    {
        _conn = new LdapConnection(new LdapDirectoryIdentifier(server, 389, false, false)) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(90) };
        _conn.SessionOptions.ProtocolVersion = 3;
        _conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        _conn.SessionOptions.Signing = true;
        _conn.SessionOptions.Sealing = true;
        _conn.Bind();
        Server = server;
    }

    public string Server { get; }

    public void Dispose() => _conn.Dispose();

    /// <summary>Domaine de la connexion.</summary>
    public DomainInfo Domain => _domain ??= LoadDomain();

    private DomainInfo LoadDomain()
    {
        var root = (SearchResponse)_conn.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext", "configurationNamingContext", "dnsHostName"));
        var e = root.Entries[0];
        var dnc = Str(e, "defaultNamingContext") ?? throw new InvalidOperationException("RootDSE sans defaultNamingContext.");
        var cfg = Str(e, "configurationNamingContext");
        var dc = Str(e, "dnsHostName") ?? Server;
        var dom = (SearchResponse)_conn.SendRequest(new SearchRequest(dnc, "(objectClass=*)", SearchScope.Base, "objectSid"));
        var sid = SidOf(dom.Entries[0]) ?? throw new InvalidOperationException("SID du domaine illisible.");
        string? netbios = null; string dns = string.Join('.', dnc.Split(',').Select(p => p.Trim()).Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(p => p[3..]));
        if (cfg is not null)
        {
            try
            {
                var cr = (SearchResponse)_conn.SendRequest(new SearchRequest("CN=Partitions," + cfg, $"(&(objectClass=crossRef)(nCName={Escape(dnc)}))", SearchScope.OneLevel, "nETBIOSName", "dnsRoot"));
                if (cr.Entries.Count > 0) { netbios = Str(cr.Entries[0], "nETBIOSName"); dns = Str(cr.Entries[0], "dnsRoot") ?? dns; }
            }
            catch (DirectoryOperationException) { }
        }
        return new DomainInfo(dns, netbios, sid, dnc, dc);
    }

    /// <summary>Échappement d'une valeur de filtre LDAP (RFC 4515).</summary>
    public static string Escape(string v)
    {
        var sb = new StringBuilder();
        foreach (var c in v) sb.Append(c switch { '\\' => @"\5c", '*' => @"\2a", '(' => @"\28", ')' => @"\29", '\0' => @"\00", _ => c.ToString() });
        return sb.ToString();
    }

    private static string? Str(SearchResultEntry e, string attr) => e.Attributes.Contains(attr) && e.Attributes[attr].Count > 0 ? e.Attributes[attr][0] as string ?? Encoding.UTF8.GetString((byte[])e.Attributes[attr][0]) : null;

    private static string? SidOf(SearchResultEntry e)
    {
        if (!e.Attributes.Contains("objectSid")) return null;
        var v = e.Attributes["objectSid"].GetValues(typeof(byte[]));
        return v.Length > 0 ? Sid.Read((byte[])v[0], 0, out _) : null;
    }

    private IEnumerable<SearchResultEntry> Paged(string baseDn, string filter, SearchScope scope, string[] attrs, int max = int.MaxValue)
    {
        var req = new SearchRequest(baseDn, filter, scope, attrs);
        var page = new PageResultRequestControl(500);
        req.Controls.Add(page);
        var n = 0;
        while (true)
        {
            var resp = (SearchResponse)_conn.SendRequest(req);
            foreach (SearchResultEntry e in resp.Entries) { if (n++ >= max) yield break; yield return e; }
            var pr = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
            if (pr is null || pr.Cookie.Length == 0) yield break;
            page.Cookie = pr.Cookie;
        }
    }

    /// <summary>Convertit une entrée LDAP en identité.</summary>
    public PrincipalInfo ToPrincipal(SearchResultEntry e)
    {
        var sid = SidOf(e) ?? "";
        var classes = e.Attributes.Contains("objectClass") ? e.Attributes["objectClass"].GetValues(typeof(string)).Cast<string>().ToArray() : [];
        var sam = Str(e, "sAMAccountName");
        var uac = int.TryParse(Str(e, "userAccountControl"), CultureInfo.InvariantCulture, out var u) ? u : 0;
        var gt = int.TryParse(Str(e, "groupType"), CultureInfo.InvariantCulture, out var g) ? g : 0;
        var kind = classes.Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase) ? PrincipalKind.Foreign
            : classes.Contains("computer", StringComparer.OrdinalIgnoreCase) ? PrincipalKind.Computer
            : classes.Contains("group", StringComparer.OrdinalIgnoreCase) ? PrincipalKind.Group
            : classes.Contains("user", StringComparer.OrdinalIgnoreCase) ? PrincipalKind.User : PrincipalKind.Unknown;
        var scope = kind != PrincipalKind.Group ? GroupScope.None : (gt & 0x2) != 0 ? GroupScope.Global : (gt & 0x4) != 0 ? GroupScope.DomainLocal : (gt & 0x8) != 0 ? GroupScope.Universal : (gt & 0x1) != 0 ? GroupScope.Local : GroupScope.None;
        var netbios = Domain.NetbiosName ?? Domain.DnsName.Split('.')[0].ToUpperInvariant();
        return new PrincipalInfo
        {
            Sid = sid, Kind = kind, Scope = scope, DistinguishedName = e.DistinguishedName, SamAccountName = sam,
            Name = sam is null ? (WellKnownSids.NameOf(sid) ?? e.DistinguishedName) : $"{netbios}\\{sam}",
            DisplayName = Str(e, "displayName"), Description = Str(e, "description"),
            Disabled = kind is PrincipalKind.User or PrincipalKind.Computer ? (uac & 0x2) != 0 : null,
            AdminCount = Str(e, "adminCount") == "1",
            PrimaryGroupRid = int.TryParse(Str(e, "primaryGroupID"), CultureInfo.InvariantCulture, out var pg) ? pg : null,
        };
    }

    /// <summary>Résout des SID par lots (les SID absents ne sont pas renvoyés).</summary>
    public Dictionary<string, PrincipalInfo> Resolve(IEnumerable<string> sids)
    {
        var result = new Dictionary<string, PrincipalInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var batch in sids.Where(Sid.IsValid).Distinct(StringComparer.OrdinalIgnoreCase).Chunk(40))
        {
            var filter = "(|" + string.Concat(batch.Select(s => $"(objectSid={Sid.ToLdapFilterValue(s)})")) + ")";
            foreach (var e in Paged(Domain.DefaultNamingContext, filter, SearchScope.Subtree, PrincipalAttrs))
            {
                var p = ToPrincipal(e);
                if (p.Sid.Length > 0) result[p.Sid] = p;
            }
        }
        return result;
    }

    /// <summary>Membres directs d'un groupe (y compris ceux dont c'est le groupe principal).</summary>
    public List<PrincipalInfo> Members(PrincipalInfo group, int max = 50_000)
    {
        var list = Paged(Domain.DefaultNamingContext, $"(memberOf={Escape(group.DistinguishedName!)})", SearchScope.Subtree, PrincipalAttrs, max).Select(ToPrincipal).ToList();
        var rid = Sid.Rid(group.Sid);
        if (rid is not null && Sid.DomainOf(group.Sid) == Domain.Sid)
            list.AddRange(Paged(Domain.DefaultNamingContext, $"(primaryGroupID={rid})", SearchScope.Subtree, PrincipalAttrs, max).Select(ToPrincipal));
        return list.DistinctBy(p => p.Sid, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Recherche d'identités (résolution ambiguë ANR : nom, prénom, sAMAccountName…).</summary>
    public List<PrincipalInfo> Search(string text, string kind, int max = 50)
    {
        var k = kind switch { "user" => "(objectCategory=person)", "group" => "(objectCategory=group)", _ => "(|(objectCategory=person)(objectCategory=group))" };
        return Paged(Domain.DefaultNamingContext, $"(&{k}(anr={Escape(text.Trim())}))", SearchScope.Subtree, PrincipalAttrs, max).Select(ToPrincipal).ToList();
    }

    /// <summary>Serveurs du domaine (ordinateurs dont le système contient « Server »).</summary>
    public List<ServerCandidate> Servers(int max = 500) =>
        Paged(Domain.DefaultNamingContext, "(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", SearchScope.Subtree, ["dNSHostName", "name", "operatingSystem"], max)
            .Select(e => new ServerCandidate(Str(e, "dNSHostName") ?? Str(e, "name") ?? e.DistinguishedName, Str(e, "operatingSystem"))).OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Unités d'organisation (destination des groupes créés).</summary>
    public List<string> OrganizationalUnits(int max = 5000) =>
        Paged(Domain.DefaultNamingContext, "(|(objectClass=organizationalUnit)(objectClass=container))", SearchScope.Subtree, ["distinguishedName"], max)
            .Select(e => e.DistinguishedName).Where(d => !d.Contains("CN=System,", StringComparison.OrdinalIgnoreCase) && !d.StartsWith("CN=ForeignSecurityPrincipals", StringComparison.OrdinalIgnoreCase))
            .OrderBy(d => string.Join(",", d.Split(',').Reverse()), StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Nombre de groupes du jeton (tokenGroups) d'un compte, pour le test de connexion.</summary>
    public int TokenGroupCount(string sid)
    {
        var r = (SearchResponse)_conn.SendRequest(new SearchRequest($"<SID={sid}>", "(objectClass=*)", SearchScope.Base, "tokenGroups"));
        return r.Entries.Count == 0 || !r.Entries[0].Attributes.Contains("tokenGroups") ? 0 : r.Entries[0].Attributes["tokenGroups"].Count;
    }

    // ----- IDirectoryStore : écriture (verbe « apply » uniquement) -----

    (string Sid, string Dn)? IDirectoryStore.Find(PrincipalRef reference)
    {
        var filter = reference.Sid is not null ? $"(objectSid={Sid.ToLdapFilterValue(reference.Sid)})" : $"(sAMAccountName={Escape(reference.Name.Split('\\').Last())})";
        var e = Paged(Domain.DefaultNamingContext, filter, SearchScope.Subtree, ["objectSid"], 1).FirstOrDefault();
        return e is null ? null : (SidOf(e)!, e.DistinguishedName);
    }

    /// <inheritdoc/>
    public bool IsMember(string groupDn, string memberSid) =>
        Paged(Domain.DefaultNamingContext, $"(&(objectSid={Sid.ToLdapFilterValue(memberSid)})(memberOf={Escape(groupDn)}))", SearchScope.Subtree, ["objectSid"], 1).Any();

    /// <inheritdoc/>
    public void AddMember(string groupDn, string memberDn) => _conn.SendRequest(new ModifyRequest(groupDn, DirectoryAttributeOperation.Add, "member", memberDn));

    /// <inheritdoc/>
    public void RemoveMember(string groupDn, string memberDn) => _conn.SendRequest(new ModifyRequest(groupDn, DirectoryAttributeOperation.Delete, "member", memberDn));

    /// <inheritdoc/>
    public (string Sid, string Dn) CreateGroup(string ouDn, string name, string scope, string? description)
    {
        var dn = $"CN={PlanBuilder.EscapeRdn(name)},{ouDn}";
        var type = scope switch { "Global" => unchecked((int)0x80000002), "DomainLocal" => unchecked((int)0x80000004), _ => unchecked((int)0x80000008) };
        var req = new AddRequest(dn, new DirectoryAttribute("objectClass", "group"), new DirectoryAttribute("sAMAccountName", name),
            new DirectoryAttribute("groupType", type.ToString(CultureInfo.InvariantCulture)));
        if (!string.IsNullOrWhiteSpace(description)) req.Attributes.Add(new DirectoryAttribute("description", description));
        _conn.SendRequest(req);
        var r = (SearchResponse)_conn.SendRequest(new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "objectSid"));
        return (SidOf(r.Entries[0])!, dn);
    }

    /// <inheritdoc/>
    public void DeleteGroup(string dn)
    {
        var r = (SearchResponse)_conn.SendRequest(new SearchRequest(dn, "(objectClass=group)", SearchScope.Base, "member"));
        if (r.Entries.Count > 0 && r.Entries[0].Attributes.Contains("member") && r.Entries[0].Attributes["member"].Count > 0)
            throw new InvalidOperationException("Le groupe n'est pas vide : suppression refusée (retirez d'abord ses membres).");
        _conn.SendRequest(new DeleteRequest(dn));
    }

    /// <summary>Réponse lisible d'une erreur LDAP.</summary>
    public static string Explain(Exception ex) => ex switch
    {
        LdapException { ErrorCode: 81 } => "Contrôleur de domaine injoignable (LDAP 389) : vérifiez le nom, le DNS et le pare-feu.",
        LdapException { ErrorCode: 49 } => "Identifiants refusés par le contrôleur de domaine.",
        LdapException l => $"Erreur LDAP {l.ErrorCode} : {l.Message}",
        DirectoryOperationException d when d.Response?.ResultCode == ResultCode.InsufficientAccessRights => "Droits insuffisants dans l'annuaire pour cette opération.",
        DirectoryOperationException d => $"Opération LDAP refusée ({d.Response?.ResultCode}) : {d.Message}",
        _ => ex.Message,
    };
}
