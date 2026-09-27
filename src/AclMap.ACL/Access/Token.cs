using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Snapshot;

namespace AclMap.ACL.Access;

/// <summary>
/// Jeton d'accès reconstitué hors ligne : l'identité, tous les groupes qui la contiennent (directement ou par
/// imbrication) et les SID implicites. <see cref="Via"/> garde, pour chaque SID du jeton, l'identité par laquelle
/// il a été atteint : c'est ce qui permet d'expliquer « d'où vient le droit ».
/// </summary>
public sealed class Token
{
    internal Token(string principalSid, bool groupMode) { PrincipalSid = principalSid; GroupMode = groupMode; }

    /// <summary>Identité analysée.</summary>
    public string PrincipalSid { get; }

    /// <summary>Vrai si l'identité est un groupe : on calcule « les droits accordés par ce groupe ».</summary>
    public bool GroupMode { get; }

    /// <summary>SID présents dans le jeton.</summary>
    public HashSet<string> Sids { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>SID du jeton → identité par laquelle il a été ajouté (null pour l'identité elle-même, « implicit » pour les SID implicites).</summary>
    public Dictionary<string, string?> Via { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Groupes dont l'appartenance est inconnue (membres illisibles, groupe étranger) : l'identité y est peut-être.</summary>
    public HashSet<string> Uncertain { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Hypothèses faites pendant la construction (affichées à l'utilisateur).</summary>
    public List<string> Notes { get; } = [];

    /// <summary>Marqueur de SID implicite dans <see cref="Via"/>.</summary>
    public const string Implicit = "implicit";

    /// <summary>Vrai si le SID est dans le jeton.</summary>
    public bool Contains(string sid) => Sids.Contains(sid);

    /// <summary>Chaîne d'appartenance de l'identité jusqu'à <paramref name="sid"/> (identité en premier).</summary>
    public IReadOnlyList<string> PathTo(string sid)
    {
        var path = new List<string>();
        var cur = sid;
        var guard = 0;
        while (cur is not null && guard++ < 64)
        {
            path.Add(cur);
            if (!Via.TryGetValue(cur, out var next) || next is null || next == Implicit) { if (next == Implicit) path.Add(Implicit); break; }
            cur = next;
        }
        path.Reverse();
        return path;
    }
}

/// <summary>Construit les jetons à partir des appartenances collectées dans l'instantané.</summary>
public sealed class TokenBuilder
{
    private readonly SnapshotIndex _index;
    private readonly Dictionary<string, List<string>> _memberOf = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _unknownGroups = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Token> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Crée le constructeur (index inverse des appartenances).</summary>
    public TokenBuilder(SnapshotIndex index)
    {
        _index = index;
        foreach (var p in index.Principals)
        {
            if (p.Members is { } members)
                foreach (var m in members) { if (!_memberOf.TryGetValue(m, out var l)) _memberOf[m] = l = []; l.Add(p.Sid); }
            else if (p.Kind is PrincipalKind.Group or PrincipalKind.LocalGroup || p.Kind == PrincipalKind.Foreign)
                _unknownGroups.Add(p.Sid);
        }
    }

    /// <summary>Groupes directs contenant <paramref name="sid"/>.</summary>
    public IReadOnlyList<string> DirectParents(string sid) => _memberOf.TryGetValue(sid, out var l) ? l : [];

    /// <summary>Groupes dont les membres sont inconnus.</summary>
    public IReadOnlySet<string> UnknownGroups => _unknownGroups;

    /// <summary>Jeton (mis en cache) d'une identité.</summary>
    /// <param name="sid">SID de l'utilisateur ou du groupe.</param>
    /// <param name="includeImplicit">Pour un groupe : ajouter aussi les SID implicites d'un utilisateur réseau.</param>
    public Token Build(string sid, bool includeImplicit = false)
    {
        var key = sid + "|" + includeImplicit;
        if (_cache.TryGetValue(key, out var cached)) return cached;
        var p = _index.Principal(sid);
        var kind = p?.Kind ?? WellKnownSids.KindOf(sid) ?? PrincipalKind.Unknown;
        var groupMode = kind is PrincipalKind.Group or PrincipalKind.LocalGroup or PrincipalKind.WellKnown or PrincipalKind.Capability;
        var t = new Token(sid, groupMode);
        var queue = new Queue<string>();
        void Add(string s, string? via) { if (t.Sids.Add(s)) { t.Via[s] = via; queue.Enqueue(s); } }
        Add(sid, null);
        if (!groupMode || includeImplicit)
        {
            foreach (var s in WellKnownSids.ImplicitNetworkSids) Add(s, Token.Implicit);
            if (kind is PrincipalKind.User or PrincipalKind.Computer or PrincipalKind.Unknown && Sid.DomainOf(sid) is { } dom && !groupMode)
            {
                var rid = p?.PrimaryGroupRid;
                if (rid is null)
                {
                    rid = kind == PrincipalKind.Computer ? (int)WellKnownSids.RidDomainComputers : (int)WellKnownSids.RidDomainUsers;
                    t.Notes.Add($"Groupe principal non collecté : {(rid == 513 ? "Utilisateurs du domaine" : "Ordinateurs du domaine")} supposé.");
                }
                Add($"{dom}-{rid}", sid);
            }
        }
        while (queue.Count > 0)
        {
            var s = queue.Dequeue();
            if (_memberOf.TryGetValue(s, out var parents)) foreach (var g in parents) Add(g, s);
        }
        foreach (var g in _unknownGroups) if (!t.Sids.Contains(g)) t.Uncertain.Add(g);
        if (p is null && !groupMode) t.Notes.Add("Identité absente de l'instantané : seuls ses SID implicites sont connus.");
        if (p?.Kind == PrincipalKind.Foreign) t.Notes.Add("Principal d'un autre domaine : ses groupes dans son domaine d'origine ne sont pas connus.");
        _cache[key] = t;
        return t;
    }
}
