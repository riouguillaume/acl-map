using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Core.Snapshot;

/// <summary>
/// Index en mémoire d'un instantané : enfants, chemins, profondeur, descripteurs et identités par clé.
/// Construit une fois au chargement ; toutes les analyses s'appuient dessus.
/// </summary>
public sealed class SnapshotIndex
{
    private readonly int[] _parent;
    private readonly int[][] _children;
    private readonly int[] _depth;
    private readonly Dictionary<int, SecurityDescriptorInfo> _sd;
    private readonly Dictionary<string, PrincipalInfo> _principals;
    private readonly Dictionary<string, int> _byRelative;

    /// <summary>Instantané indexé.</summary>
    public AclSnapshot Snapshot { get; }

    /// <summary>Crée l'index.</summary>
    /// <exception cref="InvalidDataException">Identifiants incohérents.</exception>
    public SnapshotIndex(AclSnapshot snapshot)
    {
        Snapshot = snapshot;
        var n = snapshot.Folders.Count;
        _parent = new int[n];
        _depth = new int[n];
        var kids = new List<int>?[n];
        for (var i = 0; i < n; i++)
        {
            var f = snapshot.Folders[i];
            if (f.Id != i) throw new InvalidDataException($"Instantané incohérent : dossier {i} a l'identifiant {f.Id}.");
            if (i > 0 && (f.ParentId < 0 || f.ParentId >= i)) throw new InvalidDataException($"Instantané incohérent : parent invalide pour le dossier {i}.");
            _parent[i] = f.ParentId;
            if (i > 0) { (kids[f.ParentId] ??= []).Add(i); _depth[i] = _depth[f.ParentId] + 1; }
        }
        _children = kids.Select(k => k?.ToArray() ?? []).ToArray();
        _sd = snapshot.Descriptors.ToDictionary(d => d.Id);
        _principals = new Dictionary<string, PrincipalInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in snapshot.Principals) _principals[p.Sid] = p;
        _byRelative = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < n; i++) _byRelative[RelativePath(i)] = i;
    }

    public int Count => _parent.Length;
    public FolderNode Folder(int id) => Snapshot.Folders[id];
    public int Parent(int id) => _parent[id];
    public IReadOnlyList<int> Children(int id) => _children[id];
    public int Depth(int id) => _depth[id];

    /// <summary>Descripteur d'un dossier (null si illisible).</summary>
    public SecurityDescriptorInfo? Descriptor(int folderId)
    {
        var sd = Snapshot.Folders[folderId].SdId;
        return sd >= 0 && _sd.TryGetValue(sd, out var d) ? d : null;
    }

    public SecurityDescriptorInfo? DescriptorById(int sdId) => _sd.GetValueOrDefault(sdId);

    public PrincipalInfo? Principal(string sid) => _principals.GetValueOrDefault(sid);

    public IEnumerable<PrincipalInfo> Principals => _principals.Values;

    /// <summary>Chemin relatif à la racine (« » pour la racine, « Compta\2025 » sinon).</summary>
    public string RelativePath(int id)
    {
        if (id == 0) return "";
        var parts = new List<string>();
        for (var c = id; c > 0; c = _parent[c]) parts.Add(Snapshot.Folders[c].Name);
        parts.Reverse();
        return string.Join('\\', parts);
    }

    /// <summary>Chemin complet (racine analysée + chemin relatif).</summary>
    public string FullPath(int id)
    {
        var rel = RelativePath(id);
        var root = Snapshot.Manifest.RootPath.TrimEnd('\\');
        return rel.Length == 0 ? Snapshot.Manifest.RootPath : root + "\\" + rel;
    }

    /// <summary>Dossier correspondant à un chemin relatif, ou null.</summary>
    public int? FindRelative(string relative) => _byRelative.TryGetValue(relative.Trim('\\'), out var id) ? id : null;

    /// <summary>Dossier correspondant à un chemin local du serveur (ex. D:\Administration\Scan), ou null.</summary>
    public int? FindLocal(string localPath)
    {
        var root = Snapshot.Manifest.RootLocalPath;
        if (string.IsNullOrEmpty(root)) return null;
        var r = root.TrimEnd('\\');
        var p = localPath.TrimEnd('\\');
        if (p.Equals(r, StringComparison.OrdinalIgnoreCase)) return 0;
        if (!p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)) return null;
        return FindRelative(p[(r.Length + 1)..]);
    }

    /// <summary>Tous les descendants (parcours en largeur), sans le dossier lui-même.</summary>
    public IEnumerable<int> Descendants(int id)
    {
        var q = new Queue<int>(_children[id]);
        while (q.Count > 0)
        {
            var c = q.Dequeue();
            yield return c;
            foreach (var k in _children[c]) q.Enqueue(k);
        }
    }

    /// <summary>Nom affichable d'un SID.</summary>
    public string NameOf(string sid) =>
        Principal(sid)?.Name is { Length: > 0 } n ? n : Security.WellKnownSids.NameOf(sid) ?? sid;
}
