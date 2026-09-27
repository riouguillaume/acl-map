#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ACL Map — crée une arborescence de TEST « piégée » pour valider l'outil sur un serveur de labo.

.DESCRIPTION
    À lancer UNIQUEMENT sur un serveur de fichiers de laboratoire. Crée (ou complète) :
      <Racine>\Commun               héritage normal + groupe métier en Modification
      <Racine>\Compta               héritage désactivé, groupe RW + RO
      <Racine>\Compta\2025\Clôture  refus explicite (suppression) pour un utilisateur
      <Racine>\Compta\Archives      droit nominatif (utilisateur) en Modification
      <Racine>\Direction            héritage désactivé + SID orphelin + compte nommé en Contrôle total
      <Racine>\Commercial\Prospects Tout le monde : Modification (ACL-002)
      <Racine>\IT\Outils            ACL non canonique (autorisation puis refus explicites)
      <Racine>\Verrouille           inaccessible aux administrateurs (propriétaire = utilisateur, ni SYSTEM ni Administrateurs)
      <Racine>\Long\…               chemin de plus de 260 caractères
      <Racine>\Boucle               jonction qui pointe vers la racine (ne doit pas être suivie)
    Et un partage imbriqué <Partage>-Scan sur <Racine>\Commun (facultatif, -CreateShares).

    Le script ne touche qu'à <Racine>. Il n'est pas utilisé par ACL Map : c'est un jeu d'essai.

.PARAMETER Root
    Dossier racine de l'essai (ex. D:\LabAclMap). Créé s'il n'existe pas.
.PARAMETER Group, ReadGroup
    Groupes (DOMAINE\groupe) utilisés pour les droits de groupe.
.PARAMETER User, OtherUser
    Comptes utilisateurs de test (DOMAINE\compte).

.EXAMPLE
    .\New-AclMapLabTree.ps1 -Root D:\LabAclMap -Group CONTOSO\GG_Compta -ReadGroup CONTOSO\GG_Direction -User CONTOSO\alice -OtherUser CONTOSO\bruno -CreateShares
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\.+')][string]$Root,
    [Parameter(Mandatory)][string]$Group,
    [Parameter(Mandatory)][string]$ReadGroup,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][string]$OtherUser,
    [switch]$CreateShares,
    [string]$ShareName = 'LabAclMap'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Dir([string]$Path) { if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }; $Path }
function Invoke-Icacls([string[]]$Arguments) {
    if ($PSCmdlet.ShouldProcess($Arguments[0], "icacls $($Arguments[1..($Arguments.Count-1)] -join ' ')")) {
        $out = & icacls.exe @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls $($Arguments -join ' ') : $out" }
    }
}

Write-Host "Arborescence de test ACL Map dans $Root" -ForegroundColor Cyan
New-Dir $Root | Out-Null
# Racine : SYSTEM, Administrateurs, CREATEUR PROPRIETAIRE, Utilisateurs du domaine en lecture (ce dossier seulement)
Invoke-Icacls @($Root, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-3-0:(OI)(CI)(IO)F', "$ReadGroup`:(RX)")

$commun = New-Dir (Join-Path $Root 'Commun')
Invoke-Icacls @($commun, '/grant', "$Group`:(OI)(CI)M")

$compta = New-Dir (Join-Path $Root 'Compta')
Invoke-Icacls @($compta, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "$Group`:(OI)(CI)M", "$ReadGroup`:(OI)(CI)RX")
$cloture = New-Dir (Join-Path $compta '2025\Clôture')
Invoke-Icacls @($cloture, '/deny', "$OtherUser`:(OI)(CI)(DE,DC)")
$archives = New-Dir (Join-Path $compta 'Archives')
Invoke-Icacls @($archives, '/grant', "$User`:(OI)(CI)M")

$direction = New-Dir (Join-Path $Root 'Direction')
# SID orphelin : SID de domaine inexistant (RID très élevé)
$domainSid = (New-Object System.Security.Principal.NTAccount($Group)).Translate([System.Security.Principal.SecurityIdentifier]).AccountDomainSid.Value
Invoke-Icacls @($direction, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "$ReadGroup`:(OI)(CI)M", "$User`:(OI)(CI)F", "*$domainSid-999999:(OI)(CI)RX")

$prospects = New-Dir (Join-Path $Root 'Commercial\Prospects')
Invoke-Icacls @($prospects, '/grant', '*S-1-1-0:(OI)(CI)M')

$outils = New-Dir (Join-Path $Root 'IT\Outils')
# ACL non canonique : Set-Acl conserve l'ordre fourni (autorisation explicite AVANT refus explicite)
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{0})(D;OICI;0x10000;;;{1})" -f `
    (New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
    (New-Object System.Security.Principal.NTAccount($OtherUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value)
$acl.SetSecurityDescriptorSddlForm($sd.GetSddlForm('All'))
if ($PSCmdlet.ShouldProcess($outils, 'ACL non canonique')) { Set-Acl -LiteralPath $outils -AclObject $acl }

$locked = New-Dir (Join-Path $Root 'Verrouille')
New-Dir (Join-Path $locked 'Secret') | Out-Null
Invoke-Icacls @($locked, '/setowner', $User)
Invoke-Icacls @($locked, '/inheritance:r', '/grant:r', "$User`:(OI)(CI)F")

$long = Join-Path $Root 'Long'
$seg = 'Dossier-au-nom-volontairement-long-pour-depasser-260-caracteres'
$p = $long
1..5 | ForEach-Object { $p = Join-Path $p "$seg-$_" }
if ($PSCmdlet.ShouldProcess($p, 'Chemin long')) { New-Item -ItemType Directory -Path ('\\?\' + $p) -Force | Out-Null }

$loop = Join-Path $Root 'Boucle'
if (-not (Test-Path -LiteralPath $loop) -and $PSCmdlet.ShouldProcess($loop, 'Jonction vers la racine')) { cmd.exe /c mklink /J "`"$loop`"" "`"$Root`"" | Out-Null }

if ($CreateShares -and $PSCmdlet.ShouldProcess($ShareName, 'Partages')) {
    if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) { New-SmbShare -Name $ShareName -Path $Root -FullAccess 'Tout le monde' | Out-Null }
    if (-not (Get-SmbShare -Name "$ShareName-Scan" -ErrorAction SilentlyContinue)) { New-SmbShare -Name "$ShareName-Scan" -Path $commun -ChangeAccess 'Tout le monde' | Out-Null }
}

Write-Host "Terminé. Analysez \\$env:COMPUTERNAME\$ShareName avec ACL Map (profondeur 8), puis relancez avec le mode sauvegarde pour lire « Verrouille »." -ForegroundColor Green
Write-Host "Résultats attendus : ACL-002 (Prospects), ACL-004 (Archives), ACL-005 (Direction), ACL-007, ACL-008 (Clôture), ACL-009 (Outils), ACL-010 (Verrouille), ACL-022 (partage imbriqué), jonction signalée, chemin long lu." -ForegroundColor Green
