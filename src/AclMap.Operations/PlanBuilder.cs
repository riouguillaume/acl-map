using System.Globalization;
using System.Text;
using AclMap.ACL.Access;
using AclMap.Core.Security;
using AclMap.Core.Validation;
using AclMap.Models.Analysis;
using AclMap.Models.Security;
using AclMap.Models.Snapshot;
using AclMap.Services;

namespace AclMap.Operations;

/// <summary>
/// Prépare les opérations d'écriture à partir de l'instantané : calcule l'ACL avant/après, l'impact de la
/// propagation et les avertissements. Rien n'est écrit ici ; l'exécution (après confirmation) est faite par
/// <see cref="PlanExecutor"/> avec l'état réel relu sur le serveur.
/// </summary>
public static class PlanBuilder
{
    /// <summary>Applique l'ajout d'une ACE à une liste (ordre canonique, fusion avec une ACE explicite identique).</summary>
    /// <param name="aces">ACE actuelles.</param>
    /// <param name="sid">SID résolu.</param>
    /// <param name="spec">ACE demandée.</param>
    /// <param name="changed">Faux si l'ACE était déjà présente.</param>
    public static List<AceInfo> AddAce(IReadOnlyList<AceInfo> aces, string sid, AceSpec spec, out bool changed)
    {
        var mask = Rights.MaskFor(spec.Level);
        var flags = Rights.FlagsFor(spec.Scope);
        var kind = spec.Deny ? AceKind.Deny : AceKind.Allow;
        var list = aces.ToList();
        var same = list.FindIndex(a => !a.IsInherited && a.Kind == kind && a.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase) && a.Flags == flags);
        if (same >= 0)
        {
            var merged = Rights.MapGeneric(list[same].Mask) | mask;
            changed = merged != Rights.MapGeneric(list[same].Mask);
            list[same] = list[same] with { Mask = merged };
            return list;
        }
        changed = true;
        var ace = new AceInfo(kind, sid, mask, flags, (byte)kind);
        // ordre canonique : refus explicites, autorisations explicites, puis ACE héritées
        var firstInherited = list.FindIndex(a => a.IsInherited);
        if (firstInherited < 0) firstInherited = list.Count;
        if (spec.Deny)
        {
            var firstAllow = list.FindIndex(0, firstInherited, a => a.IsAllow);
            list.Insert(firstAllow < 0 ? firstInherited : firstAllow, ace);
        }
        else list.Insert(firstInherited, ace);
        return list;
    }

    /// <summary>Retire une ACE explicite identifiée par son contenu.</summary>
    public static List<AceInfo> RemoveAce(IReadOnlyList<AceInfo> aces, AceRemoval r, out bool changed)
    {
        var list = aces.ToList();
        var i = list.FindIndex(a => !a.IsInherited && a.Kind.ToString() == r.Kind && a.Sid.Equals(r.Sid, StringComparison.OrdinalIgnoreCase) && a.Mask == r.Mask && (byte)a.Flags == r.Flags);
        changed = i >= 0;
        if (changed) list.RemoveAt(i);
        return list;
    }

    /// <summary>Vrai si deux ACL sont identiques (protection et ACE, dans l'ordre).</summary>
    public static bool SameAcl(SecurityDescriptorInfo a, SecurityDescriptorInfo b) =>
        a.Protected == b.Protected && a.DaclPresent == b.DaclPresent && a.Aces.Count == b.Aces.Count &&
        a.Aces.Zip(b.Aces).All(p => p.First.Kind == p.Second.Kind && p.First.Mask == p.Second.Mask && p.First.Flags == p.Second.Flags
            && p.First.Sid.Equals(p.Second.Sid, StringComparison.OrdinalIgnoreCase));

    /// <summary>Descripteur « après » (propriétaire conservé).</summary>
    public static SecurityDescriptorInfo WithAces(SecurityDescriptorInfo sd, List<AceInfo> aces)
    {
        var n = sd with { Aces = aces };
        return n with { Sddl = Sddl.Format(n) };
    }

    /// <summary>Nombre d'objets de l'instantané auxquels la modification s'applique (dossier + héritiers).</summary>
    public static int Affected(AnalysisSession s, int folderId, AceFlags flags)
    {
        if ((flags & (AceFlags.ContainerInherit | AceFlags.ObjectInherit)) == 0) return 1;
        var count = (flags & AceFlags.InheritOnly) != 0 ? 0 : 1;
        var onlyOne = (flags & AceFlags.NoPropagateInherit) != 0;
        var q = new Queue<(int Id, int Level)>(s.Index.Children(folderId).Select(c => (c, 1)));
        while (q.Count > 0)
        {
            var (c, lvl) = q.Dequeue();
            var node = s.Index.Folder(c);
            var isFile = (node.Flags & NodeFlags.File) != 0;
            if (isFile ? (flags & AceFlags.ObjectInherit) == 0 : (flags & AceFlags.ContainerInherit) == 0 && (flags & AceFlags.ObjectInherit) == 0) continue;
            if (s.Index.Descriptor(c)?.Protected == true) continue;   // héritage désactivé : la branche n'est pas touchée
            if ((node.Flags & NodeFlags.ReparsePoint) != 0) continue;
            count++;
            if (!onlyOne && (flags & AceFlags.ContainerInherit) != 0) foreach (var k in s.Index.Children(c)) q.Enqueue((k, lvl + 1));
        }
        return count;
    }

    private static List<string> Readable(AnalysisSession s, IEnumerable<AceInfo> aces, Dictionary<string, string>? extraNames = null) =>
        aces.Select(a => $"{(a.IsDeny ? "Refuser" : "Autoriser")} · {(extraNames?.GetValueOrDefault(a.Sid) ?? s.Index.NameOf(a.Sid))} · {Rights.Summary(a.Mask)} · {Rights.AppliesTo(a.Flags)}{(a.IsInherited ? " · héritée" : "")}").ToList();

    /// <summary>Prépare l'ajout d'une ACE sur un dossier de l'instantané.</summary>
    /// <exception cref="ArgumentException">Entrée invalide.</exception>
    public static PlannedOperation PlanAddAce(AnalysisSession s, int folderId, AceSpec spec)
    {
        var sd = s.Index.Descriptor(folderId) ?? throw new ArgumentException("Les autorisations actuelles de ce dossier sont inconnues (illisibles) : impossible de préparer la modification.");
        if (!sd.DaclPresent) throw new ArgumentException("Ce dossier a une DACL nulle : rétablissez d'abord une ACL (hors ACL Map).");
        if (sd.Aces.Any(a => a.IsConditional || a.Kind == AceKind.Other)) throw new ArgumentException("L'ACL contient des ACE conditionnelles ou spéciales : ACL Map ne la réécrit pas.");
        if (spec.Level is AccessLevel.None or AccessLevel.Special) throw new ArgumentException("Niveau non attribuable.");
        _ = Rights.FlagsFor(spec.Scope);
        var sid = spec.Principal.Sid ?? "S-1-0-0";   // groupe créé par le plan : SID connu à l'exécution
        var names = new Dictionary<string, string> { [sid] = spec.Principal.Name };
        var after = AddAce(sd.Aces, sid, spec, out var changed);
        var warnings = new List<string>();
        if (spec.Principal.Sid is { } realSid)
        {
            if (WellKnownSids.IsBroad(realSid) && spec.Level >= AccessLevel.Write && !spec.Deny) warnings.Add($"{spec.Principal.Name} contient presque tous les comptes : cette ACE ouvre l'écriture à tous (voir règle ACL-002).");
            if (spec.Level == AccessLevel.Full && !spec.Deny && !s.Rules.IsPrivileged(realSid)) warnings.Add("Contrôle total pour une identité non administrative : elle pourra modifier les autorisations. « Modification » suffit en général.");
            if (s.Index.Principal(realSid)?.Kind == PrincipalKind.User) warnings.Add("Droit nominatif : préférez un groupe (modèle AGDLP) pour garder des droits auditables.");
        }
        if (spec.Deny) warnings.Add("Un refus l'emporte sur les autorisations héritées et complique l'analyse : à réserver aux besoins précis.");
        var flags = Rights.FlagsFor(spec.Scope);
        var affected = Affected(s, folderId, flags);
        var blocked = s.Index.Descendants(folderId).Count(d => s.Index.Descriptor(d)?.Protected == true);
        if (blocked > 0 && (flags & AceFlags.ContainerInherit) != 0) warnings.Add($"{blocked} sous-dossier(s) ont l'héritage désactivé : ils ne recevront pas ce droit.");
        if (affected > 10_000) warnings.Add($"La propagation va réécrire les ACL de {affected:N0} objets : prévoir une fenêtre de maintenance (plusieurs minutes possibles).");
        var path = s.Index.FullPath(folderId);
        return new PlannedOperation
        {
            Kind = OperationKind.AddAce, Path = path, Target = path, Ace = spec, NoOp = !changed,
            Description = $"{(spec.Deny ? "Refuser" : "Accorder")} « {Rights.LevelLabel(spec.Level)} » à {spec.Principal.Name} sur {path} ({Rights.AppliesTo(flags)})",
            BeforeSddl = sd.Sddl, AfterSddl = WithAces(sd, after).Sddl, Before = Readable(s, sd.Aces), After = Readable(s, after, names),
            AffectedObjects = changed ? affected : 0, Warnings = changed ? warnings : ["Cette autorisation est déjà en place : aucune modification."],
        };
    }

    /// <summary>Prépare le retrait d'une ACE explicite (par son index dans l'ACL actuelle).</summary>
    public static PlannedOperation PlanRemoveAce(AnalysisSession s, int folderId, int aceIndex)
    {
        var sd = s.Index.Descriptor(folderId) ?? throw new ArgumentException("Autorisations actuelles inconnues.");
        if (aceIndex < 0 || aceIndex >= sd.Aces.Count) throw new ArgumentException("ACE introuvable.");
        var a = sd.Aces[aceIndex];
        if (a.IsInherited) throw new ArgumentException("ACE héritée : elle se retire sur le dossier d'origine (ou en désactivant l'héritage, hors ACL Map).");
        if (a.Kind is not (AceKind.Allow or AceKind.Deny)) throw new ArgumentException("ACE conditionnelle ou spéciale : non modifiable par ACL Map.");
        var r = new AceRemoval(a.Kind.ToString(), a.Sid, a.Mask, (byte)a.Flags, $"{s.Index.NameOf(a.Sid)} : {Rights.Summary(a.Mask)}");
        var after = RemoveAce(sd.Aces, r, out _);
        var warnings = new List<string>();
        bool AdminFull(IEnumerable<AceInfo> l) => l.Any(x => x.IsAllow && !x.IsInheritOnly && (x.Sid == WellKnownSids.Administrators || x.Sid == WellKnownSids.System) && Rights.LevelOf(x.Mask) == AccessLevel.Full);
        if (AdminFull(sd.Aces) && !AdminFull(after)) warnings.Add("Après ce retrait, ni Administrateurs ni SYSTEM n'ont le contrôle total sur ce dossier.");
        if (after.All(x => x.IsInheritOnly)) warnings.Add("Après ce retrait, plus aucune ACE ne s'applique à ce dossier : il deviendra inaccessible (hors propriétaire).");
        var path = s.Index.FullPath(folderId);
        return new PlannedOperation
        {
            Kind = OperationKind.RemoveAce, Path = path, Target = path, Removal = r,
            Description = $"Retirer l'ACE « {r.Label} » ({Rights.AppliesTo(a.Flags)}) de {path}",
            BeforeSddl = sd.Sddl, AfterSddl = WithAces(sd, after).Sddl, Before = Readable(s, sd.Aces), After = Readable(s, after),
            AffectedObjects = Affected(s, folderId, a.Flags), Warnings = warnings,
        };
    }

    /// <summary>Prépare l'ajout ou le retrait d'un membre.</summary>
    public static PlannedOperation PlanMembership(AnalysisSession? s, PrincipalRef group, PrincipalRef member, bool add)
    {
        var warnings = new List<string> { "La nouvelle appartenance ne s'applique qu'à la prochaine ouverture de session (ou au renouvellement du ticket Kerberos) de l'utilisateur." };
        var before = new List<string>(); var after = new List<string>();
        var noop = false;
        if (s is not null && group.Sid is { } gs && s.Index.Principal(gs) is { Members: { } members })
        {
            before = members.Select(s.Index.NameOf).Order(StringComparer.CurrentCultureIgnoreCase).ToList();
            var present = member.Sid is not null && members.Contains(member.Sid, StringComparer.OrdinalIgnoreCase);
            noop = add == present;
            after = add ? (present ? before : before.Append(member.Name).Order(StringComparer.CurrentCultureIgnoreCase).ToList()) : before.Where(n => n != s.Index.NameOf(member.Sid ?? "")).ToList();
            if (s.Rules.IsPrivileged(gs) && add) warnings.Add($"{group.Name} est un groupe à privilèges.");
        }
        return new PlannedOperation
        {
            Kind = add ? OperationKind.AddGroupMember : OperationKind.RemoveGroupMember, Group = group, Member = member, Target = group.Name,
            Description = add ? $"Ajouter {member.Name} au groupe {group.Name}" : $"Retirer {member.Name} du groupe {group.Name}",
            Before = before, After = after, NoOp = noop, Warnings = noop ? ["Déjà dans l'état demandé : aucune modification."] : warnings,
        };
    }

    /// <summary>Prépare la création d'un groupe de sécurité.</summary>
    /// <exception cref="ArgumentException">Nom ou OU invalide.</exception>
    public static PlannedOperation PlanCreateGroup(string name, string scope, string ouDn, string? description)
    {
        if (InputValidator.GroupName(name) is { } err) throw new ArgumentException(err);
        if (scope is not ("Global" or "DomainLocal" or "Universal")) throw new ArgumentException("Étendue attendue : Global, DomainLocal ou Universal.");
        if (string.IsNullOrWhiteSpace(ouDn) || !ouDn.Contains("DC=", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Indiquez l'OU de destination (DistinguishedName, ex. OU=Groupes,DC=contoso,DC=local).");
        var label = scope switch { "Global" => "globale", "DomainLocal" => "domaine local", _ => "universelle" };
        return new PlannedOperation
        {
            Kind = OperationKind.CreateGroup, Group = new PrincipalRef(null, name.Trim(), $"CN={EscapeRdn(name.Trim())},{ouDn}"), OuDn = ouDn, GroupScope = scope,
            GroupDescription = description, Target = name.Trim(),
            Description = $"Créer le groupe de sécurité {name.Trim()} (étendue {label}) dans {ouDn}",
            After = [$"CN={name.Trim()},{ouDn}", $"Groupe de sécurité, étendue {label}", description ?? ""],
        };
    }

    /// <summary>Échappement d'une valeur de RDN LDAP.</summary>
    public static string EscapeRdn(string v)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < v.Length; i++)
        {
            var c = v[i];
            if (c is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '=' || (i == 0 && c is ' ' or '#') || (i == v.Length - 1 && c == ' ')) sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Normalise un libellé pour un nom de groupe (sans accents ni espaces).</summary>
    public static string Slug(string s)
    {
        var d = s.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder();
        foreach (var c in d)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.NonSpacingMark) continue;
            if (char.IsLetterOrDigit(c) || c is '_' or '-' or '.') sb.Append(c);
            else if (char.IsWhiteSpace(c) || c is '\\' or '/') sb.Append('-');
        }
        var r = sb.ToString();
        while (r.Contains("--", StringComparison.Ordinal)) r = r.Replace("--", "-", StringComparison.Ordinal);
        return r.Trim('-', '.');
    }

    /// <summary>Applique un modèle de nom : {Metier}, {Partage}, {Dossier}, {Droit}.</summary>
    public static string ApplyTemplate(string template, string metier, string share, string folder, string right) =>
        template.Replace("{Metier}", Slug(metier), StringComparison.OrdinalIgnoreCase).Replace("{Partage}", Slug(share), StringComparison.OrdinalIgnoreCase)
            .Replace("{Dossier}", Slug(folder), StringComparison.OrdinalIgnoreCase).Replace("{Droit}", right, StringComparison.OrdinalIgnoreCase);

    /// <summary>Paramètres de l'assistant AGDLP.</summary>
    public sealed record AgdlpRequest(int FolderId, string Metier, string ShareLabel, string FolderLabel, bool ReadWrite, bool ReadOnly, string OuDn,
        IReadOnlyList<PrincipalRef> Members, string GgTemplate = "GG_{Metier}", string DlTemplate = "DL_{Partage}-{Dossier}_{Droit}",
        PrincipalRef? ExistingGg = null);

    /// <summary>
    /// Assistant AGDLP : crée GG_Métier (global) et DL_Partage-Dossier_RW / _RO (domaine local), imbrique le GG dans le DL,
    /// pose les ACE des DL sur le dossier, puis ajoute les membres au GG.
    /// </summary>
    public static OperationPlan PlanAgdlp(AnalysisSession s, AgdlpRequest r)
    {
        if (!r.ReadWrite && !r.ReadOnly) throw new ArgumentException("Choisissez au moins un accès : lecture/écriture ou lecture seule.");
        var ops = new List<PlannedOperation>();
        var gg = r.ExistingGg ?? new PrincipalRef(null, ApplyTemplate(r.GgTemplate, r.Metier, r.ShareLabel, r.FolderLabel, ""));
        if (r.ExistingGg is null)
        {
            var existing = s.Index.Principals.FirstOrDefault(p => string.Equals(p.SamAccountName ?? p.Name.Split('\\').Last(), gg.Name, StringComparison.OrdinalIgnoreCase));
            if (existing is not null) gg = new PrincipalRef(existing.Sid, gg.Name, existing.DistinguishedName);
            else ops.Add(PlanCreateGroup(gg.Name, "Global", r.OuDn, $"Groupe métier {r.Metier}"));
        }
        foreach (var (enabled, right, level, desc) in new[] { (r.ReadWrite, "RW", AccessLevel.Modify, "modification"), (r.ReadOnly, "RO", AccessLevel.ReadExecute, "lecture") })
        {
            if (!enabled) continue;
            var dlName = ApplyTemplate(r.DlTemplate, r.Metier, r.ShareLabel, r.FolderLabel, right);
            var existing = s.Index.Principals.FirstOrDefault(p => string.Equals(p.SamAccountName ?? p.Name.Split('\\').Last(), dlName, StringComparison.OrdinalIgnoreCase));
            var dl = existing is not null ? new PrincipalRef(existing.Sid, dlName, existing.DistinguishedName) : new PrincipalRef(null, dlName);
            if (existing is null) ops.Add(PlanCreateGroup(dlName, "DomainLocal", r.OuDn, $"Accès {desc} à {s.Index.FullPath(r.FolderId)}"));
            ops.Add(PlanAddAce(s, r.FolderId, new AceSpec(dl, level, "ThisFolderSubfoldersFiles")));
            if (right == "RW" || !r.ReadWrite) ops.Add(PlanMembership(s, dl, gg, add: true));
        }
        foreach (var m in r.Members) ops.Add(PlanMembership(s, gg, m, add: true));
        return new OperationPlan
        {
            Title = $"Modèle AGDLP pour {s.Index.FullPath(r.FolderId)} ({r.Metier})", Domain = s.Index.Snapshot.Manifest.Domain?.DnsName,
            SnapshotRoot = s.Index.Snapshot.Manifest.RootPath, Operations = ops,
            Warnings = ["Les ACE sont calculées sur l'ACL de l'instantané ; à l'exécution, ACL Map relit l'ACL réelle et refuse si elle a changé depuis."],
        };
    }
}
