# ACL Map

Cartographie et gestion contrôlée des ACL NTFS et des partages SMB (projet AD Tools, pendant de GPO Map).
Lecture seule par défaut ; écriture uniquement après activation, avec plan, Dry Run, confirmation, sauvegarde et journal.

## Solution

| Projet | Rôle |
|---|---|
| `src/AclMap.Models` | Modèles : instantané, dossiers, descripteurs, identités, partages, constats |
| `src/AclMap.Core` | SID, codec binaire des descripteurs, SDDL, niveaux de droits, archive `.aclmap`, index, validation, protocole du collecteur |
| `src/AclMap.ACL` | Jetons (appartenances hors ligne), moteur d'accès effectif, origine de l'héritage, règles ACL-001…ACL-040 |
| `src/AclMap.Services` | Session d'analyse : carte de droits, explication, graphe, « qui a accès », vues, comparaison |
| `src/AclMap.Export` | CSV (`;`, UTF-8 BOM, anti-injection), JSON, rapport HTML |
| `src/AclMap.Operations` | Plans d'écriture (ajout/retrait d'ACE, membres, création de groupes, AGDLP) et exécution vérifiée |
| `src/AclMap.Logging` | Journal JSON Lines |
| `src/AclMap.FileSystem` | Windows : énumération par handle (sémantique de sauvegarde), lecture/écriture des ACL, chemins longs |
| `src/AclMap.Shares` | Windows : NetShareEnum / NetShareGetInfo 502, partages imbriqués |
| `src/AclMap.ActiveDirectory` | Windows : LDAP (S.DS.Protocols, signé/chiffré), groupes locaux, LookupAccountSid, AuthZ |
| `src/AclMap.Collector` | `AclMap.Collector.exe` : scan, browse, shares, servers, test, search, ous, authz, apply, restore |
| `src/AclMap.Hosting` | Contrôleur de l'application (testable), profils, lanceur « runas /netonly », exécution du collecteur |
| `src/AclMap.UI` | WPF + WebView2 (`Assets/Viewer` : interface HTML/JS, Cytoscape.js) |
| `tests/AclMap.Tests` | xUnit (81 tests) |
| `tests/AclMap.Testing` | Instantané de laboratoire « contoso.local » piégé, magasins en mémoire |
| `tests/ui` | Tests Playwright de bout en bout (50 vérifications) — `tests/ui/run-e2e.sh` |
| `tools/AclMap.DevHost` | Hôte de développement : interface dans un navigateur, Windows et collecteur simulés |
| `installer` | MSI (wixl + msibuild) : `installer/build-release.sh` |
| `lab` | `Test-AclMapPrerequis.ps1`, `New-AclMapLabTree.ps1` (arborescence d'essai piégée) |

## Construire

```bash
dotnet build AclMap.slnx
dotnet test tests/AclMap.Tests
tests/ui/run-e2e.sh                 # Playwright (Chromium)
installer/build-release.sh release  # AclMap-<version>.msi + .sha256
```

Sous Windows : Visual Studio 2026 / SDK .NET 10 ; le MSI se construit sous WSL (paquets `wixl`, `msitools`).
