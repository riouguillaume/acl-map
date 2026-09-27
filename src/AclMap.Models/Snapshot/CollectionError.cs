namespace AclMap.Models.Snapshot;

/// <summary>Erreur rencontrée pendant la collecte (jamais silencieuse).</summary>
/// <param name="Stage">Étape (scan, shares, ldap, localgroups…).</param>
/// <param name="Target">Chemin, partage ou SID concerné.</param>
/// <param name="Code">Code Windows ou LDAP.</param>
/// <param name="Message">Message lisible.</param>
public sealed record CollectionError(string Stage, string? Target, int Code, string Message);
