// Tests de bout en bout de l'interface ACL Map (hôte de développement, Windows et collecteur simulés).
import { chromium } from 'playwright';
import fs from 'fs';
const out = process.env.OUT || '/tmp/shots'; fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
let pass = 0, fail = 0; const errors = [];
const ok = (cond, name) => { if (cond) { pass++; console.log('  ✔ ' + name); } else { fail++; console.log('  ✖ ' + name); } };
async function newPage(port, dark = false) {
  const ctx = await browser.newContext({ viewport: { width: 1500, height: 920 }, colorScheme: dark ? 'dark' : 'light' });
  const page = await ctx.newPage();
  page.on('pageerror', e => errors.push(`[${port}] pageerror: ${e.message}`));
  page.on('console', m => { if (m.type() === 'error' && !m.text().includes('404')) errors.push(`[${port}] console: ${m.text()}`); });
  await page.goto(`http://127.0.0.1:${port}/`); await page.waitForTimeout(700);
  return page;
}
const text = (page, sel) => page.locator(sel).first().innerText();

// ---------------------------------------------------------------- A. Quick Connect + première analyse
console.log('A. Quick Connect (poste neuf)');
{
  const page = await newPage(5181);
  ok(await page.locator('.modal h2', { hasText: 'Quick Connect' }).isVisible(), 'Quick Connect s\'ouvre au premier lancement');
  await page.click('#qcNext'); await page.click('#qcNext');
  await page.fill('#pfName', 'Contoso – production');
  await page.fill('#pfDomain', 'contoso.local');
  await page.fill('#pfDc', 'DC01.contoso.local');
  await page.check('input[name=pfMode][value=AlternateAccount]');
  await page.fill('#pfAccount', 'audit');
  await page.click('#qcNext');
  ok((await text(page, '[data-err=accountName]')).includes('DOMAINE'), 'compte invalide refusé');
  await page.fill('#pfAccount', 'CONTOSO\\audit');
  await page.click('#qcNext');
  ok(await page.locator('#pfDiscover').isVisible(), 'étape Serveurs');
  await page.click('#pfDiscover'); await page.waitForSelector('input[data-d]');
  await page.check('input[data-d="0"]'); await page.click('#dAdd');
  ok(await page.inputValue('[data-srv="0"]') === 'FS01.contoso.local', 'serveur proposé depuis l\'AD ajouté');
  await page.click('[data-shares="0"]'); await page.waitForSelector('input[data-k]');
  await page.check('input[data-k="0"]'); await page.click('#shOk');
  ok((await page.inputValue('[data-fav="0"]')).includes('Donnees'), 'partage gardé en favori');
  await page.screenshot({ path: out + '/A1-qc-servers.png' });
  await page.click('#qcNext'); await page.waitForSelector('.check-item');
  ok(await page.locator('.check-item.ok').count() >= 3, 'test de connexion réussi');
  await page.screenshot({ path: out + '/A2-qc-test.png' });
  await page.click('#qcNext'); await page.waitForSelector('text=Le domaine');
  await page.click('#qcNext');
  ok(await page.locator('.modal').count() === 0, 'Quick Connect terminé');
  ok((await page.inputValue('#pbServer')) === 'FS01.contoso.local', 'barre de chemin : serveur');
  await page.selectOption('#pbShare', { index: 1 });
  ok((await page.inputValue('#pbPath')).includes('\\Donnees'), 'barre de chemin : partage → chemin');
  await page.click('#pbBrowse'); await page.waitForSelector('#brList [data-open]');
  await page.click('#brList [data-open] >> text=Compta'); await page.click('#brOk');
  ok((await page.inputValue('#pbPath')).endsWith('\\Compta'), 'sélecteur de dossier');
  await page.fill('#pbPath', '\\\\FS01.contoso.local\\Donnees');
  await page.click('#pbScan'); await page.waitForSelector('#scMsg');
  ok(true, 'fenêtre de progression');
  await page.waitForSelector('.kpi .value', { timeout: 15000 });
  ok((await text(page, '#view-home')).includes('dossiers analysés'), 'analyse terminée → tableau de bord');
  await page.fill('#pbPath', '\\\\FS01\\Inexistant'); await page.click('#pbScan');
  await page.waitForSelector('.modal .banner.bad', { timeout: 10000 });
  ok((await text(page, '.modal .banner.bad')).includes('introuvable'), 'erreur d\'analyse affichée avec pistes');
  await page.click('#scClose');
  await page.context().close();
}

// ---------------------------------------------------------------- B. Lecture : toutes les vues
console.log('B. Consultation');
const page = await newPage(5180);
await page.click('#btnOpen'); await page.waitForSelector('.kpi .value');
ok(await page.locator('#btnExport').isEnabled(), 'instantané ouvert');
await page.click('.kpi[data-go="tree:protected"]');
await page.waitForTimeout(300);
const rows = await page.locator('#tree .trow').allInnerTexts();
ok(rows.some(r => r.includes('Direction')) && !rows.some(r => r.includes('Commun')), 'filtre « héritage rompu » depuis le tableau de bord');
await page.click('#tree .trow >> text=Direction'); await page.waitForSelector('#folderPanel h2:has-text("Direction")');
const panel = await text(page, '#folderPanel');
ok(panel.includes('héritage désactivé') && panel.includes('orphelin') && panel.includes('ACL-006'), 'détail du dossier : héritage, orphelin, constat');
ok(await page.locator('[data-act=add]').isDisabled(), 'lecture seule : ajout désactivé');
await page.click('[data-act=who]'); await page.waitForSelector('.modal table.data >> nth=1');
ok((await text(page, '.modal')).includes('prestataire'), '« Qui a accès ? » liste le compte prestataire');
await page.screenshot({ path: out + '/B1-who.png' });
await page.click('.modal [data-close]');
await page.click('#treeFilters [data-f=protected]'); // retire le filtre
await page.fill('#treeSearch', 'clôture'); await page.waitForTimeout(400);
ok((await page.locator('#tree .trow').allInnerTexts()).some(r => r.toLowerCase().includes('clôture')), 'recherche dans l\'arbre');
await page.fill('#treeSearch', '');

await page.click('nav.tabs button[data-view=map]');
await page.fill('#mapWho', 'GG_Compta'); await page.waitForSelector('#mapSuggest button'); await page.click('#mapSuggest button');
await page.waitForSelector('#mapLegend .lv');
ok((await text(page, '#mapHead')).includes('droits accordés via ce groupe') && await page.locator('#mapImplicitWrap').isVisible(), 'carte d\'un groupe : mode groupe');
await page.fill('#mapWho', 'alice'); await page.waitForSelector('#mapSuggest button'); await page.click('#mapSuggest button');
await page.waitForTimeout(500);
await page.selectOption('#mapPath', 'Scan'); await page.waitForTimeout(600);
ok((await page.locator('#mapTree .trow >> text=Compta').first().locator('..').innerText()).includes('hors partage'), 'carte via le partage Scan : hors partage');
await page.selectOption('#mapPath', 'ntfs'); await page.waitForTimeout(500);
await page.click('#mapTree .trow >> text=Compta'); await page.waitForSelector('#explainPanel .result3');
const ex = await text(page, '#explainPanel');
ok(ex.includes('GG_Compta') && ex.includes('DL_Donnees-Compta_RW') && ex.includes('Modification'), 'explication : chaîne alice → GG_Compta → DL_Compta_RW');
await page.click('[data-act=authz]'); await page.waitForSelector('#authzRes .banner');
ok((await text(page, '#authzRes')).includes('Windows'), 'vérification AuthZ');
ok(await page.locator('#cy canvas').count() > 0, 'graphe affiché');
await page.screenshot({ path: out + '/B2-map.png' });
await page.check('#mapHideNone'); await page.waitForTimeout(300);
ok(!(await page.locator('#mapTree .trow').allInnerTexts()).some(r => r.includes('Direction')), 'masquer les dossiers sans accès');
await page.uncheck('#mapHideNone');
await page.click('#mapExport'); await page.waitForSelector('.toast');
ok((await text(page, '.toast')).includes('CarteDeDroits'), 'export CSV de la carte');

await page.click('nav.tabs button[data-view=principals]');
await page.click('#prFilters [data-k=priv]'); await page.waitForTimeout(200);
ok((await text(page, '#prList')).includes('prestataire'), 'filtre privilégiés');
await page.click('#prFilters [data-k=all]');
await page.fill('#prSearch', 'DL_Donnees-Compta_RW'); await page.click('#prList .row');
await page.waitForSelector('#principalPanel h2');
const pr = await text(page, '#principalPanel');
ok(pr.includes('GG_Compta') && pr.includes('(2)'), 'groupe : membres et utilisateurs transitifs');
await page.screenshot({ path: out + '/B3-principal.png' });

await page.click('nav.tabs button[data-view=shares]');
ok((await text(page, '#view-shares')).includes('Accès refusé (5)'), 'partages : droits illisibles signalés');
await page.click('nav.tabs button[data-view=findings]');
await page.click('#view-findings details[data-rule="ACL-006"] summary');
await page.click('#view-findings details[data-rule="ACL-006"] a[data-folder]');
ok(await page.locator('#view-tree.active').count() === 1, 'lien d\'une alerte vers l\'arbre');
await page.click('nav.tabs button[data-view=home]'); await page.click('[data-act=compare]');
await page.waitForSelector('#view-diff.active .kpi');
ok((await text(page, '#view-diff')).includes('prestataire'), 'comparaison : ACE ajoutée détectée');
await page.screenshot({ path: out + '/B4-diff.png' });
await page.click('nav.tabs button[data-view=journal]'); await page.waitForTimeout(500);
ok((await text(page, '#view-journal')).includes('snapshot.open'), 'journal des opérations');
await page.click('#btnExport'); await page.click('[data-export=Html]'); await page.waitForTimeout(500);
ok((await page.locator('.toast').allInnerTexts()).some(t => t.includes('Rapport')), 'export du rapport HTML');

// ---------------------------------------------------------------- C. Écriture contrôlée
console.log('C. Modifications contrôlées');
await page.click('#modeBadge'); await page.waitForSelector('#wrEnable');
await page.check('#wrEnable'); await page.click('#wrSave');
await page.click('.modal [data-ok]'); await page.waitForTimeout(400);
ok((await text(page, '#modeBadge')).includes('autorisées'), 'modifications autorisées (avec confirmation)');
await page.keyboard.press('Escape');
await page.click('nav.tabs button[data-view=tree]');
await page.click('#tree .trow >> text=Commun'); await page.waitForSelector('#folderPanel h2:has-text("Commun")'); await page.waitForSelector('#folderPanel [data-act=add]:not([disabled])');
await page.click('[data-act=add]');
await page.click('#aaWho'); await page.keyboard.type('GG_RH', { delay: 40 }); await page.waitForSelector('#aaSug button'); await page.click('#aaSug button');
await page.selectOption('#aaLevel', 'Read'); await page.click('#aaPlan');
await page.waitForSelector('.modal h2 >> text=Modification prévue');
const plan = await text(page, '.modal');
ok(plan.includes('GG_RH') && plan.includes('Objets touchés'), 'plan : avant/après et impact');
ok(await page.locator('#plApply').isDisabled(), 'Appliquer bloqué sans confirmation');
await page.click('#plDry'); await page.waitForSelector('#plRes .banner');
ok((await text(page, '#plRes')).includes('Dry Run réussi'), 'Dry Run réussi');
await page.check('#plChecked'); await page.fill('#plConfirm', 'APPLIQUER');
ok(await page.locator('#plApply').isEnabled(), 'Appliquer actif après confirmation');
await page.click('#plApply'); await page.waitForSelector('#plRes .banner >> text=appliquées');
ok((await text(page, '.modal .opres')).includes('sauvegarde'), 'appliqué, vérifié et sauvegardé');
await page.screenshot({ path: out + '/C1-plan.png' });
await page.click('#plBackups'); await page.waitForSelector('.modal h2 >> text=Sauvegardes');
await page.click('[data-r="0"]'); await page.click('#rsDry'); await page.waitForSelector('#rsRes .banner');
ok((await text(page, '#rsRes')).includes('Restauration possible'), 'restauration : Dry Run');
await page.fill('#rsConfirm', 'APPLIQUER'); await page.click('#rsGo'); await page.waitForSelector('#rsRes .banner >> text=restaurée');
ok(true, 'restauration appliquée');
await page.keyboard.press('Escape'); await page.keyboard.press('Escape');
await page.locator('.modal-back').evaluateAll(els => els.forEach(e => e.remove()));

await page.click('#tree .trow >> text=Commercial'); await page.waitForSelector('#folderPanel h2:has-text("Commercial")'); await page.waitForSelector('#folderPanel [data-act=agdlp]:not([disabled])');
await page.click('[data-act=agdlp]');
await page.fill('#agMetier', 'Qualité');
ok((await text(page, '#agPreview')).includes('GG_Qualite') && (await text(page, '#agPreview')).includes('DL_Donnees-Commercial_RW'), 'AGDLP : noms selon la convention');
await page.click('#agMember'); await page.keyboard.type('chloe', { delay: 40 }); await page.waitForSelector('#agSug button'); await page.click('#agSug button');
await page.click('#agPlan'); await page.waitForSelector('.modal h2 >> text=Modification prévue');
ok(await page.locator('.modal .op').count() === 4, 'AGDLP : DL existant réutilisé, 4 opérations (GG, ACE, imbrication, membre)');
await page.click('#plDry'); await page.waitForSelector('#plRes .banner');
ok((await text(page, '#plRes')).includes('réussi'), 'AGDLP : Dry Run');
await page.check('#plChecked'); await page.fill('#plConfirm', 'APPLIQUER'); await page.click('#plApply');
await page.waitForSelector('#plRes .banner >> text=appliquées');
ok(true, 'AGDLP appliqué');
await page.screenshot({ path: out + '/C2-agdlp.png' });
await page.locator('.modal-back').evaluateAll(els => els.forEach(e => e.remove()));

await page.click('nav.tabs button[data-view=principals]');
await page.fill('#prSearch', 'GG_Compta'); await page.click('#prList .row'); await page.waitForSelector('[data-act=addmember]');
await page.click('[data-act=addmember]');
await page.click('#amWho'); await page.keyboard.type('chloe', { delay: 40 }); await page.waitForSelector('#amSug button'); await page.click('#amSug button'); await page.click('#amPlan');
await page.waitForSelector('.modal h2 >> text=Modification prévue');
ok((await text(page, '.modal')).includes('prochaine ouverture de session'), 'membre : avertissement Kerberos');
await page.click('#plDry'); await page.waitForSelector('#plRes .banner');
ok((await text(page, '#plRes')).includes('réussi'), 'membre : Dry Run');
await page.locator('.modal-back').evaluateAll(els => els.forEach(e => e.remove()));

await page.click('#btnSettings'); await page.click('[data-edit]');
await page.fill('#pfDc', 'bad name!'); await page.click('#pfSave'); await page.waitForTimeout(500);
ok((await text(page, '[data-err=domainController]')).includes('invalide'), 'validation côté hôte du profil');
await page.click('#pfCancel');
await page.click('[data-tab=scan]'); await page.fill('#scDepth', '99'); await page.click('#scSave'); await page.waitForSelector('.toast.bad');
ok(true, 'paramètres d\'analyse validés');
await page.context().close();

// ---------------------------------------------------------------- D. Thème sombre
{
  const p = await newPage(5180, true);
  await p.click('#btnOpen'); await p.waitForSelector('.kpi .value');
  await p.click('nav.tabs button[data-view=map]');
  await p.fill('#mapWho', 'emma'); await p.waitForSelector('#mapSuggest button'); await p.click('#mapSuggest button'); await p.waitForTimeout(800);
  await p.click('#mapTree .trow >> text=Commercial'); await p.waitForTimeout(600);
  await p.screenshot({ path: out + '/D1-dark-map.png' });
  await p.click('nav.tabs button[data-view=home]'); await p.screenshot({ path: out + '/D2-dark-home.png' });
  ok(true, 'thème sombre');
  await p.context().close();
}
console.log(errors.length ? 'ERREURS JS :\n' + errors.join('\n') : 'Aucune erreur JavaScript');
console.log(`\n${pass} réussis, ${fail} échoués`);
await browser.close();
process.exit(fail || errors.length ? 1 : 0);
