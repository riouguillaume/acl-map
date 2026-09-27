#!/usr/bin/env bash
# Construit l'installateur MSI d'ACL Map (Linux ou WSL : paquets « wixl » et « msitools »).
#   installer/build-msi.sh <dossier contenant AclMap.exe, AclMap.Collector.exe, AclMap.ico, LISEZMOI.txt> <version> <sortie.msi>
# 1) wixl compile AclMap.wxs (interface française dans ext/ui) ;
# 2) msibuild complète ce que wixl ne gère pas : page de code 1252, recherche du runtime .NET 10 Desktop (bloquant)
#    et de WebView2 (avertissement non bloquant sur la dernière page), recherches aussi en installation silencieuse,
#    raccourci bureau facultatif (DESKTOPSHORTCUT=0) et lancement d'ACL Map depuis « Terminer »
#    (action de type 226 = 34 + 192 : répertoire INSTALLDIR, asynchrone — voir le correctif GPO Map 2.2.2, erreur 2753).
set -euo pipefail
SRC="$1"; VERSION="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
wixl -a x64 --extdir ext --ext ui -D Version="$VERSION" -D Source="$SRC" -o "$OUT" AclMap.wxs
q() { msibuild "$OUT" -q "$1"; }
msibuild "$OUT" -i tables/_ForceCodepage.idt
msibuild "$OUT" -i tables/AppSearch.idt -i tables/Signature.idt -i tables/DrLocator.idt -i tables/RegLocator.idt -i tables/LaunchCondition.idt
# AppSearch et LaunchConditions sont déjà placés par wixl dans les deux séquences (installation silencieuse /qn comprise) : on le vérifie.
for seq in InstallUISequence InstallExecuteSequence; do
  seqdump="$(msiinfo export "$OUT" "$seq")"; grep -q '^AppSearch' <<<"$seqdump" || q "INSERT INTO \`$seq\` (\`Action\`, \`Sequence\`) VALUES ('AppSearch', 50)"
done
q "UPDATE \`Component\` SET \`Condition\` = 'DESKTOPSHORTCUT = \"1\"' WHERE \`Component\` = 'DesktopShortcut'"
# Avertissement WebView2 (non bloquant) affiché sur la dernière page
q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('SetWebView2Warning', 51, 'WIXUI_EXITDIALOGOPTIONALTEXT', 'WebView2 est absent de ce poste : l’interface ne s’ouvrira pas tant qu’il n’est pas installé. Le collecteur en ligne de commande fonctionne sans lui.')"
q "INSERT INTO \`InstallUISequence\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('SetWebView2Warning', 'NOT WEBVIEW2 AND NOT WEBVIEW2USER AND NOT Installed', 1010)"
# Lancement depuis « Terminer »
q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('LaunchAclMap', 226, 'INSTALLDIR', '\"[INSTALLDIR]AclMap.exe\"')"
q "INSERT INTO \`ControlEvent\` (\`Dialog_\`, \`Control_\`, \`Event\`, \`Argument\`, \`Condition\`, \`Ordering\`) VALUES ('ExitDialog', 'Finish', 'DoAction', 'LaunchAclMap', 'WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 AND NOT Installed', 1)"
q "UPDATE \`Property\` SET \`Value\` = 'WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED;WIX_SAME_VERSION_UPGRADE_DETECTED;DESKTOPSHORTCUT;SKIPDOTNETCHECK;DOTNETDESKTOP;WEBVIEW2;WEBVIEW2USER' WHERE \`Property\` = 'SecureCustomProperties'"
echo "MSI : $OUT"
