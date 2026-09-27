using System.Text.Json;
using AclMap.Core.Security;
using AclMap.Core.Snapshot;
using AclMap.Models.Security;

namespace AclMap.Operations;

/// <summary>Accès en lecture/écriture aux ACL réelles (implémenté par le collecteur Windows).</summary>
public interface IAclStore
{
    /// <summary>Relit le descripteur actuel.</summary>
    SecurityDescriptorInfo Read(string path);
    /// <summary>Écrit la DACL (Windows propage l'héritage aux descendants).</summary>
    void WriteDacl(string path, IReadOnlyList<AceInfo> aces, bool protectedDacl);
}

/// <summary>Accès à l'annuaire pour les groupes (implémenté en LDAP par le collecteur Windows).</summary>
public interface IDirectoryStore
{
    /// <summary>Recherche un groupe ou un compte par SID ou par sAMAccountName ; null si absent.</summary>
    (string Sid, string Dn)? Find(PrincipalRef reference);
    bool IsMember(string groupDn, string memberSid);
    void AddMember(string groupDn, string memberDn);
    void RemoveMember(string groupDn, string memberDn);
    /// <summary>Crée un groupe et renvoie (SID, DN).</summary>
    (string Sid, string Dn) CreateGroup(string ouDn, string name, string scope, string? description);
    void DeleteGroup(string dn);
}

/// <summary>
/// Exécute un plan après confirmation : pour chaque opération, relit l'état réel, vérifie qu'il correspond à
/// l'état « avant » du plan, sauvegarde, écrit, puis relit pour contrôler. En Dry Run, seules les vérifications
/// sont faites. Toute divergence arrête le plan (les opérations suivantes ne sont pas exécutées).
/// </summary>
public sealed class PlanExecutor(IAclStore acl, IDirectoryStore directory, string backupFolder)
{
    /// <summary>Exécute (ou vérifie) le plan.</summary>
    /// <param name="plan">Plan confirmé.</param>
    /// <param name="dryRun">Vérifier seulement.</param>
    /// <param name="onResult">Rappel après chaque opération.</param>
    public List<OperationResult> Execute(OperationPlan plan, bool dryRun, Action<OperationResult>? onResult = null)
    {
        var results = new List<OperationResult>();
        var created = new Dictionary<string, (string Sid, string Dn)>(StringComparer.OrdinalIgnoreCase);
        Directory.CreateDirectory(backupFolder);
        foreach (var op in plan.Operations)
        {
            OperationResult r;
            try { r = Run(plan, op, dryRun, created); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                r = new OperationResult(op.Id, false, false, ex.Message, null);
            }
            results.Add(r);
            onResult?.Invoke(r);
            if (!r.Success) break;
        }
        return results;
    }

    private (string Sid, string Dn)? Resolve(PrincipalRef p, Dictionary<string, (string Sid, string Dn)> created, bool dryRun)
    {
        if (p.Sid is null && created.TryGetValue(p.Name, out var c)) return c;
        var found = directory.Find(p);
        if (found is null && p.Sid is null && dryRun) return ("S-1-0-0", p.Dn ?? p.Name);   // sera créé par une opération précédente
        return found;
    }

    private OperationResult Run(OperationPlan plan, PlannedOperation op, bool dryRun, Dictionary<string, (string Sid, string Dn)> created)
    {
        if (op.NoOp) return new(op.Id, true, true, "Déjà en place : ignorée.", null);
        switch (op.Kind)
        {
            case OperationKind.AddAce:
            case OperationKind.RemoveAce:
            {
                var path = op.Path ?? throw new InvalidOperationException("Chemin manquant.");
                var live = acl.Read(path);
                var expected = Sddl.Parse(op.BeforeSddl ?? throw new InvalidOperationException("État « avant » manquant."));
                if (!PlanBuilder.SameAcl(live, expected))
                    return new(op.Id, false, false, "L'ACL réelle a changé depuis l'analyse : opération refusée. Relancez une analyse puis préparez de nouveau la modification.", null);
                List<AceInfo> after; bool changed;
                if (op.Kind == OperationKind.AddAce)
                {
                    var spec = op.Ace!;
                    var who = Resolve(spec.Principal, created, dryRun) ?? throw new InvalidOperationException($"Identité introuvable dans l'annuaire : {spec.Principal.Name}");
                    after = PlanBuilder.AddAce(live.Aces, who.Sid, spec, out changed);
                }
                else after = PlanBuilder.RemoveAce(live.Aces, op.Removal!, out changed);
                if (!changed) return new(op.Id, true, true, "Aucun changement nécessaire.", null);
                var explicitOnly = after.Where(a => !a.IsInherited).ToList();
                if (dryRun) return new(op.Id, true, false, $"Vérifié : ACL identique à l'analyse ; {explicitOnly.Count} ACE explicite(s) seront écrites.", null);
                var backup = SaveBackup(plan, op, new BackupRecord { PlanId = plan.PlanId, OperationId = op.Id, Kind = op.Kind, Target = path, Description = op.Description, BeforeSddl = live.Sddl, AfterSddl = PlanBuilder.WithAces(live, after).Sddl });
                acl.WriteDacl(path, explicitOnly, live.Protected);
                var check = acl.Read(path);
                var ok = explicitOnly.All(e => check.Aces.Any(a => !a.IsInherited && a.Kind == e.Kind && a.Sid.Equals(e.Sid, StringComparison.OrdinalIgnoreCase) && a.Flags == e.Flags && Rights.MapGeneric(a.Mask) == Rights.MapGeneric(e.Mask)))
                    && check.Aces.Count(a => !a.IsInherited) == explicitOnly.Count;
                return new(op.Id, ok, false, ok ? "Appliquée et vérifiée." : "Écrite, mais la relecture ne correspond pas exactement : vérifiez l'ACL (sauvegarde disponible).", backup);
            }
            case OperationKind.CreateGroup:
            {
                var g = op.Group!;
                if (directory.Find(g) is { } exists) { created[g.Name] = exists; return new(op.Id, true, true, $"Le groupe {g.Name} existe déjà : réutilisé.", null); }
                if (dryRun) return new(op.Id, true, false, $"Vérifié : {g.Name} n'existe pas encore.", null);
                var res = directory.CreateGroup(op.OuDn!, g.Name, op.GroupScope!, op.GroupDescription);
                created[g.Name] = res;
                var backup = SaveBackup(plan, op, new BackupRecord { PlanId = plan.PlanId, OperationId = op.Id, Kind = op.Kind, Target = g.Name, Description = op.Description, GroupDn = res.Dn, GroupSid = res.Sid });
                return new(op.Id, true, false, $"Groupe créé : {res.Dn}", backup);
            }
            default:
            {
                var add = op.Kind == OperationKind.AddGroupMember;
                var g = Resolve(op.Group!, created, dryRun) ?? throw new InvalidOperationException($"Groupe introuvable : {op.Group!.Name}");
                var m = Resolve(op.Member!, created, dryRun) ?? throw new InvalidOperationException($"Membre introuvable : {op.Member!.Name}");
                var isMember = g.Sid != "S-1-0-0" && m.Sid != "S-1-0-0" && directory.IsMember(g.Dn, m.Sid);
                if (isMember == add) return new(op.Id, true, true, "Déjà dans l'état demandé.", null);
                if (dryRun) return new(op.Id, true, false, $"Vérifié : {op.Member!.Name} {(add ? "n'est pas encore" : "est")} membre de {op.Group!.Name}.", null);
                var backup = SaveBackup(plan, op, new BackupRecord { PlanId = plan.PlanId, OperationId = op.Id, Kind = op.Kind, Target = op.Group!.Name, Description = op.Description, GroupDn = g.Dn, GroupSid = g.Sid, MemberSid = m.Sid, MemberDn = m.Dn });
                if (add) directory.AddMember(g.Dn, m.Dn); else directory.RemoveMember(g.Dn, m.Dn);
                var ok = directory.IsMember(g.Dn, m.Sid) == add;
                return new(op.Id, ok, false, ok ? "Appliquée et vérifiée." : "Écrite, mais la relecture ne confirme pas le changement.", backup);
            }
        }
    }

    private string SaveBackup(OperationPlan plan, PlannedOperation op, BackupRecord record)
    {
        var file = Path.Combine(backupFolder, $"{plan.PlanId}-{op.Id}.backup.json");
        File.WriteAllText(file, JsonSerializer.Serialize(record, AclMapJson.Indented));
        return file;
    }

    /// <summary>Annule une opération à partir de sa sauvegarde.</summary>
    /// <returns>Message de résultat.</returns>
    public string Restore(BackupRecord b, bool dryRun)
    {
        switch (b.Kind)
        {
            case OperationKind.AddAce:
            case OperationKind.RemoveAce:
            {
                var before = Sddl.Parse(b.BeforeSddl!);
                var live = acl.Read(b.Target);
                var expectedAfter = b.AfterSddl is null ? null : Sddl.Parse(b.AfterSddl);
                var warn = expectedAfter is not null && !PlanBuilder.SameAcl(live, expectedAfter) ? " Attention : l'ACL a encore changé depuis la modification ; ces changements seront écrasés." : "";
                if (dryRun) return "Restauration possible : l'ACL explicite d'avant la modification sera réécrite." + warn;
                acl.WriteDacl(b.Target, before.Aces.Where(a => !a.IsInherited).ToList(), before.Protected);
                return "ACL restaurée." + warn;
            }
            case OperationKind.CreateGroup:
                if (dryRun) return $"Restauration possible : suppression du groupe {b.GroupDn} (s'il est vide).";
                directory.DeleteGroup(b.GroupDn!);
                return "Groupe supprimé.";
            default:
                var wasAdd = b.Kind == OperationKind.AddGroupMember;
                if (dryRun) return wasAdd ? "Restauration possible : retrait du membre." : "Restauration possible : réintégration du membre.";
                if (wasAdd) directory.RemoveMember(b.GroupDn!, b.MemberDn!); else directory.AddMember(b.GroupDn!, b.MemberDn!);
                return "Appartenance restaurée.";
        }
    }
}
