using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;

namespace AclMap.Core.Snapshot;

/// <summary>
/// Fichier .aclmap : archive zip contenant manifest.json et les parties (folders, descriptors, principals, shares,
/// errors). Chaque partie est vérifiée par son empreinte SHA-256 à la lecture.
/// </summary>
public static class SnapshotArchive
{
    /// <summary>Extension des instantanés.</summary>
    public const string Extension = ".aclmap";

    private static readonly string[] PartNames = ["folders.json", "descriptors.json", "principals.json", "shares.json", "errors.json"];

    /// <summary>Écrit l'instantané (le manifeste est complété avec les empreintes et les compteurs).</summary>
    /// <param name="snapshot">Instantané.</param>
    /// <param name="path">Fichier de destination.</param>
    /// <returns>Instantané avec manifeste final.</returns>
    public static AclSnapshot Save(AclSnapshot snapshot, string path)
    {
        var parts = new Dictionary<string, byte[]>
        {
            ["folders.json"] = JsonSerializer.SerializeToUtf8Bytes(snapshot.Folders, AclMapJson.Options),
            ["descriptors.json"] = JsonSerializer.SerializeToUtf8Bytes(snapshot.Descriptors, AclMapJson.Options),
            ["principals.json"] = JsonSerializer.SerializeToUtf8Bytes(snapshot.Principals, AclMapJson.Options),
            ["shares.json"] = JsonSerializer.SerializeToUtf8Bytes(snapshot.Shares, AclMapJson.Options),
            ["errors.json"] = JsonSerializer.SerializeToUtf8Bytes(snapshot.Errors, AclMapJson.Options),
        };
        var manifest = snapshot.Manifest with
        {
            Parts = parts.ToDictionary(p => p.Key, p => Convert.ToHexStringLower(SHA256.HashData(p.Value))),
            FolderCount = snapshot.Folders.Count(f => (f.Flags & NodeFlags.File) == 0),
            FileCount = snapshot.Folders.Count(f => (f.Flags & NodeFlags.File) != 0),
            DescriptorCount = snapshot.Descriptors.Count,
            ErrorCount = snapshot.Errors.Count,
        };
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        using (var fs = File.Create(tmp))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            Write(zip, "manifest.json", JsonSerializer.SerializeToUtf8Bytes(manifest, AclMapJson.Indented));
            foreach (var p in parts) Write(zip, p.Key, p.Value);
        }
        File.Move(tmp, path, overwrite: true);
        return snapshot with { Manifest = manifest };
    }

    private static void Write(ZipArchive zip, string name, byte[] data)
    {
        var e = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var s = e.Open();
        s.Write(data);
    }

    /// <summary>Lit et vérifie un instantané.</summary>
    /// <exception cref="InvalidDataException">Fichier invalide, format inconnu ou empreinte incorrecte.</exception>
    public static AclSnapshot Load(string path)
    {
        using var fs = File.OpenRead(path);
        return Load(fs);
    }

    /// <summary>Lit et vérifie un instantané depuis un flux.</summary>
    /// <exception cref="InvalidDataException">Fichier invalide.</exception>
    public static AclSnapshot Load(Stream stream)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        byte[] Read(string name)
        {
            var e = zip.GetEntry(name) ?? throw new InvalidDataException($"Instantané incomplet : {name} absent.");
            if (e.Length > 2L * 1024 * 1024 * 1024) throw new InvalidDataException($"Partie trop volumineuse : {name}.");
            using var s = e.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }
        SnapshotManifest manifest;
        try { manifest = JsonSerializer.Deserialize<SnapshotManifest>(Read("manifest.json"), AclMapJson.Options) ?? throw new InvalidDataException("Manifeste vide."); }
        catch (JsonException ex) { throw new InvalidDataException("Manifeste illisible : " + ex.Message, ex); }
        if (!manifest.Format.StartsWith("aclmap/", StringComparison.Ordinal)) throw new InvalidDataException($"Format inconnu : {manifest.Format}");
        var data = new Dictionary<string, byte[]>();
        foreach (var name in PartNames)
        {
            var bytes = Read(name);
            if (manifest.Parts.TryGetValue(name, out var expected) && !string.Equals(expected, Convert.ToHexStringLower(SHA256.HashData(bytes)), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Empreinte SHA-256 incorrecte pour {name} : l'instantané a été modifié ou est corrompu.");
            data[name] = bytes;
        }
        try
        {
            return new AclSnapshot
            {
                Manifest = manifest,
                Folders = JsonSerializer.Deserialize<List<FolderNode>>(data["folders.json"], AclMapJson.Options) ?? [],
                Descriptors = JsonSerializer.Deserialize<List<SecurityDescriptorInfo>>(data["descriptors.json"], AclMapJson.Options) ?? [],
                Principals = JsonSerializer.Deserialize<List<PrincipalInfo>>(data["principals.json"], AclMapJson.Options) ?? [],
                Shares = JsonSerializer.Deserialize<List<ShareInfo>>(data["shares.json"], AclMapJson.Options) ?? [],
                Errors = JsonSerializer.Deserialize<List<CollectionError>>(data["errors.json"], AclMapJson.Options) ?? [],
            };
        }
        catch (JsonException ex) { throw new InvalidDataException("Instantané illisible : " + ex.Message, ex); }
    }
}
