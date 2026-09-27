#Requires -Version 5.1
<#
.SYNOPSIS
    ACL Map - Étape 2 : vérification des prérequis et mesure d'un échantillon (LECTURE SEULE).

.DESCRIPTION
    À lancer sur le poste d'administration qui hébergera ACL Map.
    Ne modifie rien : aucune ACL, aucun groupe, aucun fichier en dehors du rapport JSON.

    Vérifie :
      - Windows / PowerShell, runtime .NET 10 Desktop, WebView2 ;
      - poste joint au domaine, accès LDAP, lecture de tokenGroups (base du calcul d'accès effectif) ;
      - privilège SeBackupPrivilege (futur « mode sauvegarde », désactivé par défaut) ;
    Et si -Path est fourni (ex. \\FS01\Donnees) :
      - partages du serveur et droits de partage (si les droits le permettent) ;
      - échantillon d'arborescence jusqu'à -Depth : nombre de dossiers, dossiers inaccessibles,
        chemins longs, points de jonction, descripteurs de sécurité UNIQUES (taux de déduplication), durée.

.EXAMPLE
    .\Test-AclMapPrerequis.ps1
.EXAMPLE
    .\Test-AclMapPrerequis.ps1 -Path \\FS01\Donnees -Depth 4
#>
[CmdletBinding()]
param(
    [ValidatePattern('^(\\\\[^\\]+\\[^\\]+.*|[A-Za-z]:\\.*)$')]
    [string]$Path,
    [ValidateRange(1, 20)]
    [int]$Depth = 3,
    [ValidateRange(100, 500000)]
    [int]$MaxFolders = 20000,
    [string]$OutFile = (Join-Path $env:TEMP ("AclMap-prerequis-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$report = [ordered]@{ generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); computer = $env:COMPUTERNAME }

function Write-Check([string]$Label, [string]$State, [string]$Detail) {
    $color = switch ($State) { 'OK' { 'Green' } 'ATTENTION' { 'Yellow' } 'KO' { 'Red' } default { 'Gray' } }
    Write-Host ('[{0,-9}] {1}' -f $State, $Label) -ForegroundColor $color -NoNewline
    if ($Detail) { Write-Host " - $Detail" } else { Write-Host '' }
}

# --- 1. Poste -------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$report.os = @{ caption = $os.Caption; build = $os.BuildNumber; ps = $PSVersionTable.PSVersion.ToString() }
Write-Check 'Système' 'INFO' "$($os.Caption) build $($os.BuildNumber), PowerShell $($PSVersionTable.PSVersion)"

$dotnetRoot = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.WindowsDesktop.App'
$desktop = @()
if (Test-Path -LiteralPath $dotnetRoot) { $desktop = @(Get-ChildItem -LiteralPath $dotnetRoot -Directory | Select-Object -ExpandProperty Name) }
$has10 = @($desktop | Where-Object { [int]($_.Split('.')[0]) -ge 10 }).Count -gt 0
$report.dotnetDesktop = $desktop
if ($has10) { Write-Check '.NET Desktop Runtime >= 10 (x64)' 'OK' ($desktop -join ', ') }
else { Write-Check '.NET Desktop Runtime >= 10 (x64)' 'KO' 'absent : requis par ACL Map (même prérequis que GPO Map 2.2)' }

$wv2 = $null
foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
               'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
               'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}') {
    try { $v = (Get-ItemProperty -LiteralPath $k -ErrorAction Stop).pv; if ($v -and $v -ne '0.0.0.0') { $wv2 = $v; break } } catch { }
}
$report.webView2 = $wv2
if ($wv2) { Write-Check 'WebView2 Runtime' 'OK' $wv2 } else { Write-Check 'WebView2 Runtime' 'KO' 'absent' }

# --- 2. Domaine / LDAP ----------------------------------------------------------------
$report.domain = @{ joined = [bool]$cs.PartOfDomain; name = $cs.Domain }
if ($cs.PartOfDomain) {
    Write-Check 'Poste joint au domaine' 'OK' $cs.Domain
    try {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $u = [ADSI]"LDAP://<SID=$sid>"
        $u.RefreshCache([string[]]@('tokenGroups'))
        $tg = @($u.Properties['tokenGroups']).Count
        $report.domain.tokenGroups = $tg
        Write-Check 'Lecture LDAP de tokenGroups (session courante)' 'OK' "$tg groupes transitifs"
    } catch {
        $report.domain.tokenGroupsError = $_.Exception.Message
        Write-Check 'Lecture LDAP de tokenGroups' 'KO' $_.Exception.Message
    }
} else {
    Write-Check 'Poste joint au domaine' 'ATTENTION' 'hors domaine : il faudra le mode « autre compte » (comme GPO Map 2.1+)'
}

# --- 3. Privilèges --------------------------------------------------------------------
# Recherche sur la sortie brute : les en-têtes de whoami /priv changent selon la langue de Windows.
$backup = @(whoami /priv | Select-String -SimpleMatch 'SeBackupPrivilege').Count -gt 0
$report.seBackupPrivilege = $backup
if ($backup) { Write-Check 'SeBackupPrivilege' 'INFO' 'présent : le « mode sauvegarde » pourra lire les dossiers verrouillés sans takeown' }
else { Write-Check 'SeBackupPrivilege' 'INFO' 'absent (normal hors session administrateur élevée / Opérateurs de sauvegarde)' }

# --- 4. Échantillon ------------------------------------------------------------------
if ($Path) {
    $server = $null
    if ($Path -match '^\\\\([^\\]+)\\') { $server = $Matches[1] }

    if ($server) {
        try {
            $shares = @(Get-SmbShare -CimSession $server -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' })
            $report.shares = @($shares | ForEach-Object {
                $acc = @(); try { $acc = @(Get-SmbShareAccess -CimSession $server -Name $_.Name -ErrorAction Stop | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)/$($_.AccessControlType)" }) } catch { $acc = @("non lisible: $($_.Exception.Message)") }
                @{ name = $_.Name; path = $_.Path; access = $acc }
            })
            Write-Check "Partages de $server" 'OK' "$($shares.Count) partages (hors partages cachés)"
        } catch {
            Write-Check "Partages de $server" 'ATTENTION' "Get-SmbShare impossible ($($_.Exception.Message)) ; ACL Map utilisera NetShareEnum/NetShareGetInfo"
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) { Write-Check "Accès à $Path" 'KO' 'chemin introuvable ou refusé'; }
    else {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $sections = [System.Security.AccessControl.AccessControlSections]'Access, Owner'
        $sddl = New-Object 'System.Collections.Generic.Dictionary[string,int]'
        $stats = [ordered]@{ folders = 0; denied = 0; longPaths = 0; reparsePoints = 0; aclUnreadable = 0; inheritanceBroken = 0; truncated = $false }
        $queue = New-Object 'System.Collections.Generic.Queue[object]'
        $queue.Enqueue(@((New-Object IO.DirectoryInfo $Path), 0))

        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue(); $di = $item[0]; $lvl = $item[1]
            $stats.folders++
            if ($di.FullName.Length -ge 260) { $stats.longPaths++ }
            try {
                $acl = $di.GetAccessControl($sections)
                $s = $acl.GetSecurityDescriptorSddlForm($sections)
                if ($sddl.ContainsKey($s)) { $sddl[$s]++ } else { $sddl[$s] = 1 }
                if ($acl.AreAccessRulesProtected) { $stats.inheritanceBroken++ }
            } catch { $stats.aclUnreadable++ }

            if ($stats.folders -ge $MaxFolders) { $stats.truncated = $true; break }
            if ($lvl -ge $Depth) { continue }
            try {
                foreach ($child in $di.EnumerateDirectories()) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { $stats.reparsePoints++; continue }  # jamais suivis
                    $queue.Enqueue(@($child, ($lvl + 1)))
                }
            } catch [UnauthorizedAccessException] { $stats.denied++ }
              catch [IO.PathTooLongException] { $stats.longPaths++ }
              catch { $stats.denied++ }
        }
        $sw.Stop()
        $stats.uniqueDescriptors = $sddl.Count
        $stats.dedupRatio = if ($sddl.Count) { [math]::Round($stats.folders / $sddl.Count, 1) } else { 0 }
        $stats.seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        $stats.foldersPerSecond = if ($sw.Elapsed.TotalSeconds -gt 0) { [math]::Round($stats.folders / $sw.Elapsed.TotalSeconds) } else { 0 }
        $report.sample = $stats

        Write-Check "Échantillon $Path (profondeur $Depth)" 'OK' "$($stats.folders) dossiers en $($stats.seconds) s ($($stats.foldersPerSecond)/s, PowerShell)"
        Write-Check 'Descripteurs de sécurité uniques' 'INFO' "$($stats.uniqueDescriptors) (1 pour $($stats.dedupRatio) dossiers)"
        Write-Check 'Héritage rompu' 'INFO' "$($stats.inheritanceBroken)"
        $st = if ($stats.denied + $stats.aclUnreadable) { 'ATTENTION' } else { 'OK' }
        Write-Check 'Dossiers non listables / ACL illisibles' $st "$($stats.denied) / $($stats.aclUnreadable)"
        Write-Check 'Chemins >= 260 car. / jonctions ignorées' 'INFO' "$($stats.longPaths) / $($stats.reparsePoints)"
        if ($stats.truncated) { Write-Check 'Échantillon tronqué' 'INFO' "limite -MaxFolders $MaxFolders atteinte" }
    }
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Host "`nRapport : $OutFile" -ForegroundColor Cyan
