using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Analysis;
using AclMap.Models.Snapshot;
using AclMap.Services;

namespace AclMap.Export;

/// <summary>Types d'export proposés.</summary>
public enum ExportKind { AclCsv, FindingsCsv, SharesCsv, PrincipalsCsv, AccessCsv, Json, Html }

/// <summary>
/// Exports CSV (séparateur « ; », UTF-8 avec BOM : ouverture directe dans Excel en français), JSON et rapport HTML
/// autonome (tableau de bord, constats, partages, matrice d'accès).
/// </summary>
public static class Exporters
{
    /// <summary>Nom de fichier proposé.</summary>
    public static string SuggestedName(AnalysisSession s, ExportKind kind)
    {
        var root = s.Index.Snapshot.Manifest.RootPath.Trim('\\').Replace('\\', '_').Replace(':', '_').Replace('$', '_');
        var stamp = s.Index.Snapshot.Manifest.CreatedUtc.ToLocalTime().ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture);
        return kind switch
        {
            ExportKind.AclCsv => $"AclMap-ACL-{root}-{stamp}.csv",
            ExportKind.FindingsCsv => $"AclMap-Constats-{root}-{stamp}.csv",
            ExportKind.SharesCsv => $"AclMap-Partages-{root}-{stamp}.csv",
            ExportKind.PrincipalsCsv => $"AclMap-Identites-{root}-{stamp}.csv",
            ExportKind.AccessCsv => $"AclMap-CarteDeDroits-{root}-{stamp}.csv",
            ExportKind.Json => $"AclMap-{root}-{stamp}.json",
            _ => $"AclMap-Rapport-{root}-{stamp}.html",
        };
    }

    /// <summary>Écrit l'export demandé.</summary>
    /// <param name="accessSid">Identité (export de carte de droits).</param>
    /// <param name="accessPath">Chemin d'accès (export de carte de droits).</param>
    public static void Write(AnalysisSession s, ExportKind kind, Stream output, string? accessSid = null, string? accessPath = null)
    {
        switch (kind)
        {
            case ExportKind.AclCsv: Csv(output, AclRows(s)); break;
            case ExportKind.FindingsCsv: Csv(output, FindingRows(s)); break;
            case ExportKind.SharesCsv: Csv(output, ShareRows(s)); break;
            case ExportKind.PrincipalsCsv: Csv(output, PrincipalRows(s)); break;
            case ExportKind.AccessCsv: Csv(output, AccessRows(s, accessSid ?? throw new ArgumentException("Identité requise."), accessPath)); break;
            case ExportKind.Json: JsonSerializer.Serialize(output, ViewModel.Build(s), AclMapJson.Indented); break;
            case ExportKind.Html: var bytes = new UTF8Encoding(false).GetBytes(HtmlReport(s)); output.Write(bytes); break;
        }
    }

    private static string Esc(string? v)
    {
        v ??= "";
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@') v = "'" + v;   // pas d'injection de formule dans Excel
        return v.IndexOfAny([';', '"', '\n', '\r']) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }

    private static void Csv(Stream output, IEnumerable<string[]> rows)
    {
        using var w = new StreamWriter(output, new UTF8Encoding(true), leaveOpen: true);
        foreach (var r in rows) w.WriteLine(string.Join(';', r.Select(Esc)));
    }

    private static IEnumerable<string[]> AclRows(AnalysisSession s)
    {
        var idx = s.Index;
        yield return ["Chemin", "Propriétaire", "Héritage", "Identité", "SID", "Nature", "Type", "Droits", "Niveau", "Origine", "S'applique à", "Masque"];
        for (var id = 0; id < idx.Count; id++)
        {
            var sd = idx.Descriptor(id);
            var path = idx.FullPath(id);
            if (sd is null) { yield return [path, "", "", "", "", "", "", "Autorisations illisibles", "", "", "", ""]; continue; }
            var owner = sd.Owner is null ? "" : idx.NameOf(sd.Owner);
            var inh = sd.Protected ? "Désactivé" : "Activé";
            foreach (var a in sd.Aces)
                yield return [path, owner, inh, idx.NameOf(a.Sid), a.Sid, s.KindName(a.Sid), a.IsDeny ? "Refuser" : "Autoriser", Rights.Summary(a.Mask),
                    Rights.LevelLabel(Rights.LevelOf(a.Mask)), a.IsInherited ? "Héritée" : "Explicite", Rights.AppliesTo(a.Flags), "0x" + a.Mask.ToString("x8")];
        }
    }

    private static IEnumerable<string[]> FindingRows(AnalysisSession s)
    {
        yield return ["Règle", "Gravité", "Catégorie", "Titre", "Chemin / partage", "Identité", "Détail", "Recommandation"];
        foreach (var f in s.Findings)
            foreach (var i in f.Items)
                yield return [f.RuleId, SeverityLabel(f.Severity), f.Category, f.Title, i.FolderId is int id ? s.Index.FullPath(id) : i.Share ?? "", i.Sid is null ? "" : s.Index.NameOf(i.Sid), i.Detail, f.Recommendation];
    }

    private static IEnumerable<string[]> ShareRows(AnalysisSession s)
    {
        yield return ["Partage", "Chemin local", "Type", "Identité", "SID", "Type d'accès", "Droits", "Imbriqué dans"];
        foreach (var x in s.Index.Snapshot.Shares)
        {
            if (x.Security is null) { yield return [x.Unc, x.LocalPath ?? "", x.Kind.ToString(), "", "", "", x.SecurityError ?? "Droits illisibles", x.NestedIn ?? ""]; continue; }
            foreach (var a in x.Security.Aces)
                yield return [x.Unc, x.LocalPath ?? "", x.Kind.ToString(), s.Index.NameOf(a.Sid), a.Sid, a.IsDeny ? "Refuser" : "Autoriser", Rights.ShareLabel(a.Mask), x.NestedIn ?? ""];
        }
    }

    private static IEnumerable<string[]> PrincipalRows(AnalysisSession s)
    {
        yield return ["Identité", "SID", "Nature", "Étendue", "Privilégié", "Orphelin", "Désactivé", "Membres directs", "Dossiers avec ACE explicite", "DN", "Membres"];
        foreach (var p in s.Index.Principals.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var r = ViewModel.Row(s, p);
            yield return [r.Name, r.Sid, r.Kind, r.Scope, r.Privileged ? "Oui" : "", r.Orphan ? "Oui" : "", r.Disabled ? "Oui" : "", r.MembersKnown ? r.MemberCount?.ToString(CultureInfo.InvariantCulture) ?? "" : (p.Kind is PrincipalKind.Group or PrincipalKind.LocalGroup ? "inconnu" : ""),
                r.ExplicitFolders.ToString(CultureInfo.InvariantCulture), r.Dn ?? "", p.Members is null ? "" : string.Join(", ", p.Members.Take(200).Select(s.Index.NameOf))];
        }
    }

    private static IEnumerable<string[]> AccessRows(AnalysisSession s, string sid, string? accessPath)
    {
        var map = s.ComputeMap(sid, accessPath);
        var levels = Convert.FromBase64String(map.Levels);
        var flags = Convert.FromBase64String(map.Flags);
        yield return ["Identité", "Chemin d'accès", "Chemin", "Niveau", "Refus", "Peut modifier les autorisations", "Ambigu", "Inconnu"];
        for (var i = 0; i < levels.Length; i++)
        {
            var f = (AccessFlags)flags[i];
            if ((f & AccessFlags.OutsideShare) != 0) continue;
            yield return [map.Name, accessPath ?? "ntfs", s.Index.FullPath(i), Rights.LevelLabel((AccessLevel)levels[i]), Has(f, AccessFlags.Denied), Has(f, AccessFlags.CanChangePermissions), Has(f, AccessFlags.Ambiguous), Has(f, AccessFlags.Unknown)];
        }
        static string Has(AccessFlags f, AccessFlags b) => (f & b) != 0 ? "Oui" : "";
    }

    /// <summary>Libellé de gravité.</summary>
    public static string SeverityLabel(Severity s) => s switch { Severity.Critical => "Critique", Severity.High => "Élevée", Severity.Medium => "Moyenne", Severity.Low => "Faible", _ => "Info" };

    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// <summary>Rapport HTML autonome.</summary>
    public static string HtmlReport(AnalysisSession s)
    {
        var v = ViewModel.Build(s);
        var m = v.Manifest;
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ACL Map — rapport</title>
<style>
:root{--bg:#f6f7f9;--s:#fff;--s2:#f1f3f6;--b:#e1e4ea;--t:#1d2330;--m:#5b6475;--a:#2457c5;--crit:#b42318;--high:#c4540a;--med:#9a6b00;--low:#2f6fb3;--info:#5b6475}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--s:#181d26;--s2:#1f2530;--b:#2a313d;--t:#e6e9ef;--m:#a3acbb;--a:#7aa2ff;--crit:#ff8a80;--high:#ffa94d;--med:#f5c451;--low:#74b0ff;--info:#a3acbb}}
body{margin:0;font:14px/1.45 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--t)}main{max-width:1500px;margin:0 auto;padding:24px}
h1{margin:0 0 4px;font-size:22px}h2{font-size:15px;text-transform:uppercase;letter-spacing:.5px;color:var(--m);margin:28px 0 10px}
.meta{color:var(--m);font-size:13px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:16px}
.k{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:12px 14px}.k b{display:block;font-size:26px}.k span{color:var(--m);font-size:12.5px}
table{width:100%;border-collapse:collapse;background:var(--s);border:1px solid var(--b);border-radius:10px;overflow:hidden;font-size:13px}
th,td{padding:7px 9px;border-bottom:1px solid var(--b);text-align:left;vertical-align:top}th{background:var(--s2);font-size:11.5px;text-transform:uppercase;color:var(--m)}
.sev{font-weight:600;font-size:11.5px;padding:2px 8px;border-radius:999px;background:var(--s2)}.Critical{color:var(--crit)}.High{color:var(--high)}.Medium{color:var(--med)}.Low{color:var(--low)}.Info{color:var(--info)}
details{background:var(--s);border:1px solid var(--b);border-radius:8px;margin-bottom:8px}summary{padding:9px 12px;cursor:pointer}details div{padding:0 12px 12px}
.mx td{text-align:center;font-weight:600;font-size:12px}.mx td:first-child{text-align:left;font-weight:400}.mx th{writing-mode:vertical-rl;transform:rotate(180deg);text-align:left;white-space:nowrap;max-height:180px}
.l7{background:#b4231833}.l6{background:#c4540a33}.l5{background:#9a6b0033}.l4,.l3{background:#2f6fb326}.l2,.l1{background:#8a93a326}
@media print{body{background:#fff}details{break-inside:avoid}details:not([open]) div{display:none}}
</style></head><body><main>
""");
        sb.Append($"<h1>ACL Map — {H(m.RootPath)}</h1><div class=\"meta\">Analyse du {m.CreatedUtc.ToLocalTime():dd/MM/yyyy HH:mm} par {H(m.CollectedBy)} depuis {H(m.Machine)}")
          .Append(m.Domain?.DnsName is { } d ? $" · domaine {H(d)}" : "").Append(m.Options.BackupMode ? " · mode sauvegarde" : "").Append(m.Truncated ? " · <b>analyse incomplète</b>" : "").Append("</div>");
        sb.Append("<div class=\"kpis\">");
        void K(string label, int value) => sb.Append($"<div class=\"k\"><b>{value:N0}</b><span>{H(label)}</span></div>");
        K("dossiers", v.Stats["folders"]); K("jeux de droits distincts", v.Stats["descriptors"]); K("héritages désactivés", v.Stats["protected"]);
        K("dossiers avec ACE explicites", v.Stats["foldersWithExplicit"]); K("dossiers inaccessibles", v.Stats["inaccessible"]); K("identités", v.Stats["principals"]);
        K("SID orphelins", v.Stats["orphans"]); K("partages (disque)", v.Stats["shares"]);
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium }) K("constats " + SeverityLabel(sev).ToLowerInvariant() + "s", s.Findings.Where(f => f.Severity == sev).Sum(f => f.Count));
        sb.Append("</div>");

        sb.Append("<h2>Constats</h2>");
        foreach (var f in s.Findings)
        {
            sb.Append($"<details><summary><span class=\"sev {f.Severity}\">{SeverityLabel(f.Severity)}</span> <b>{H(f.RuleId)}</b> {H(f.Title)} — {f.Count:N0}</summary><div><p>{H(f.Description)}</p><p><b>Recommandation :</b> {H(f.Recommendation)}</p><table><tr><th>Emplacement</th><th>Détail</th></tr>");
            foreach (var i in f.Items.Take(200))
                sb.Append($"<tr><td>{H(i.FolderId is int id ? s.Index.FullPath(id) : i.Share ?? (i.Sid is null ? "" : s.Index.NameOf(i.Sid)))}</td><td>{H(i.Detail)}</td></tr>");
            if (f.Count > 200) sb.Append($"<tr><td colspan=\"2\">… et {f.Count - 200:N0} autres (export CSV des constats)</td></tr>");
            sb.Append("</table></div></details>");
        }

        sb.Append("<h2>Partages</h2><table><tr><th>Partage</th><th>Chemin local</th><th>Droits de partage</th><th>Remarque</th></tr>");
        foreach (var x in v.Shares.Where(x => x.Kind == nameof(ShareKind.Disk)))
            sb.Append($"<tr><td>{H(x.Unc)}</td><td>{H(x.LocalPath)}</td><td>{(x.RightsKnown ? string.Join("<br>", x.Aces.Select(a => H($"{a.Name} : {(a.Kind.StartsWith("Refuser") ? "refus " : "")}{a.Rights}"))) : H(x.RightsError ?? "illisibles"))}</td><td>{H(x.NestedIn is null ? x.Remark : "Imbriqué dans " + x.NestedIn)}</td></tr>");
        sb.Append("</table>");

        // Matrice d'accès : dossiers de premier niveau × identités ayant des ACE explicites (hors administration)
        var rows = new List<int> { 0 };
        rows.AddRange(s.Index.Children(0).Where(c => (s.Index.Folder(c).Flags & NodeFlags.File) == 0).Take(80));
        var cols = rows.SelectMany(r => s.Index.Descriptor(r)?.Aces.Where(a => !a.IsInheritOnly && a.IsAllow && !WellKnownSids.IsAdministrative(a.Sid)).Select(a => a.Sid) ?? [])
            .Concat(rows.SelectMany(r => s.Index.Children(r)).Take(2000).SelectMany(r => s.Index.Descriptor(r)?.Aces.Where(a => !a.IsInherited && a.IsAllow && !WellKnownSids.IsAdministrative(a.Sid)).Select(a => a.Sid) ?? []))
            .GroupBy(x => x, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).Take(30).Select(g => g.Key).ToList();
        if (cols.Count > 0)
        {
            sb.Append("<h2>Matrice d'accès (dossiers de premier niveau)</h2><p class=\"meta\">Accès NTFS effectif de chaque identité (groupes : droits accordés via le groupe). CT contrôle total, M modification, LE lecture et écriture, LX lecture et exécution, L lecture, Li liste, S spécial.</p>");
            sb.Append("<div style=\"overflow:auto\"><table class=\"mx\"><tr><th style=\"writing-mode:initial;transform:none\">Dossier</th>");
            foreach (var c in cols) sb.Append($"<th>{H(s.Index.NameOf(c))}</th>");
            sb.Append("</tr>");
            var tokens = cols.ToDictionary(c => c, c => s.Tokens.Build(c), StringComparer.OrdinalIgnoreCase);
            foreach (var r in rows)
            {
                sb.Append($"<tr><td>{H(r == 0 ? m.RootPath : s.Index.Folder(r).Name)}</td>");
                foreach (var c in cols)
                {
                    var res = AccessEngine.Evaluate(s.Index.Descriptor(r), tokens[c]);
                    sb.Append($"<td class=\"l{(int)res.Level}\">{Rights.LevelShort(res.Level)}{((res.Flags & AccessFlags.Denied) != 0 ? "*" : "")}</td>");
                }
                sb.Append("</tr>");
            }
            sb.Append("</table></div>");
        }
        if (v.Errors.Count > 0)
        {
            sb.Append("<h2>Erreurs de collecte</h2><table><tr><th>Étape</th><th>Cible</th><th>Message</th></tr>");
            foreach (var e in v.Errors.Take(300)) sb.Append($"<tr><td>{H(e.Stage)}</td><td>{H(e.Target)}</td><td>{H(e.Message)}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append($"<p class=\"meta\" style=\"margin-top:24px\">Généré par ACL Map {H(m.ToolVersion)} — lecture seule. Données sensibles : diffusion restreinte.</p></main></body></html>");
        return sb.ToString();
    }
}
