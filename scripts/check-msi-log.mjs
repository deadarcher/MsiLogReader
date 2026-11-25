/**
 * Guard the MSI log reader against the logs it was built on.
 *
 * Every fixture in scripts/fixtures/msi-log is a REAL log: lab installs of small WiX packages built
 * to fail in one specific way each (a deferred EXE custom action that exits 5, a WixQuietExec
 * PowerShell that exits 3, a service that never starts, a launch condition, a blocked downgrade, a
 * second version of the same ProductCode, two installs at once), plus real Burn and MSI logs from
 * Brian's machine with the user name scrubbed. A diagnostic that names the wrong action is worse
 * than none, so each fixture pins the verdict, the exit code and the culprit.
 *
 * Run: node scripts/check-msi-log.mjs [extra-dir-of-real-logs]
 *   The optional dir is a smoke test: every log in it must parse, get a verdict, and never throw.
 */
import { readFileSync, readdirSync, statSync } from 'fs';
import { pathToFileURL, fileURLToPath } from 'url';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { buildSync } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bundle = join(tmpdir(), 'rff-msilog.mjs');
// The JS API, not `node node_modules/esbuild/bin/esbuild`: that file is a JS shim on Windows but the
// native binary on Linux, and Cloudflare's build runs on Linux. The first push of this check made
// every production build fail there while passing here (2026-11-23).
buildSync({
  entryPoints: [join(root, 'src/lib/_msiLogTestBarrel.ts')], bundle: true, format: 'esm',
  platform: 'node', logLevel: 'warning', outfile: bundle,
});
const { analyzeMsiLog, decodeLog, scavengeLog } = await import(pathToFileURL(bundle).href + '?t=' + Date.now());

let fails = 0;
const check = (name, cond, detail = '') => {
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? ' :: ' + detail : ''}`);
  if (!cond) fails++;
};
const load = (p) => analyzeMsiLog(decodeLog(readFileSync(p)));

// file -> what the reader must say about it
const EXPECT = {
  '01-ok-install.log':           { verdict: 'success', code: 0, op: 'install' },
  '02-ok-majorupgrade.log':      { verdict: 'success', code: 0, op: 'install', notable: 'WIX_UPGRADE_DETECTED' },
  '03-ok-downgrade-blocked.log': { verdict: 'failed', code: 1603, summary: /newer version/i },
  '04-ok-uninstall.log':         { verdict: 'success', code: 0, op: 'uninstall' },
  '05-cafail.log':               { verdict: 'failed', code: 1603, action: 'ConfigureThing', caExit: 5, summary: /ConfigureThing/ },
  '06-launch-fail.log':          { verdict: 'failed', code: 1603, summary: /needs RFFOK=1/ },
  '07-launch-ok.log':            { verdict: 'success', code: 0, op: 'install' },
  '08-launch-uninstall.log':     { verdict: 'success', code: 0, op: 'uninstall' },
  '09-svcfail.log':              { verdict: 'failed', code: 1603, finding: /service did not start/i },
  '10-quietexec.log':            { verdict: 'failed', code: 1603, action: 'RunSetupScript', output: /setting up license server/ },
  '11-dup-install.log':          { verdict: 'success', code: 0, op: 'install' },
  '12-dup-1638.log':             { verdict: 'failed', code: 1638, summary: /already installed/i },
  '13-dup-uninstall.log':        { verdict: 'success', code: 0, op: 'uninstall' },
  '15-ok-1618.log':              { verdict: 'failed', code: 1618, summary: /already running/i },
  // readme.txt held open with no sharing while 2.0.0 upgraded 1.0.0: the NESTED removal of 1.0.0 hits 1306.
  '21-inuse-upgrade.log':        { verdict: 'failed', code: 1603, action: 'RemoveFiles', summary: /removing the old version.*1306/i, finding: /OLD version/ },
  // A C# (DTF) custom action reading a license file that is not there, and the same action built
  // without CustomAction.config, so SFXCA cannot load the CLR at all.
  '27-dtf-exception.log':        { verdict: 'failed', code: 1603, action: 'ValidateLicense', summary: /FileNotFoundException: Could not find file/, finding: /CustomActions\.ValidateLicense/ },
  '27-dtf-noclr.log':            { verdict: 'failed', code: 1603, action: 'ValidateLicense', summary: /could not load the \.NET runtime/, finding: /0x80131700/ },
  '22-inuse-cleanup.log':       { verdict: 'failed', code: 1605, op: 'uninstall', summary: /no record of this product/ },
  'host-firefox-159.log':        { verdict: 'success', code: 0, op: 'install' },
  'host-dotnet-sdk-1618.log':    { verdict: 'failed', code: 1618 },
  'host-burn-dotnet-sdk.log':    { kind: 'burn', verdict: 'failed', summary: /dotnet_sdk_internal/, finding: /Another install was running/ },
};

const fxDir = join(root, 'scripts', 'fixtures', 'msi-log');
console.log('== fixtures ==');
for (const [file, e] of Object.entries(EXPECT)) {
  let a;
  try { a = load(join(fxDir, file)); }
  catch (err) { check(file + ' loads', false, String(err)); continue; }
  const s = a.sessions[a.focus];
  const tag = `${file}: ${a.verdict} ${s?.exitCode ?? ''} ${a.failing?.name ?? ''}`;
  check(file + ' verdict', a.verdict === e.verdict, tag);
  if (e.kind) check(file + ' kind', a.kind === e.kind, a.kind);
  if (e.code !== undefined) check(file + ' exit code', s?.exitCode === e.code, String(s?.exitCode));
  if (e.op) check(file + ' operation', s?.operation === e.op, s?.operation);
  if (e.action) check(file + ' failing action', a.failing?.name === e.action, a.failing?.name);
  if (e.caExit !== undefined) check(file + ' custom action exit', a.failing?.caExitCode === e.caExit, String(a.failing?.caExitCode));
  if (e.summary) check(file + ' summary', e.summary.test(a.summary), a.summary);
  if (e.output) check(file + ' CA output captured', a.failing?.output.some(o => e.output.test(o)), (a.failing?.output ?? []).slice(0, 3).join(' | '));
  if (e.finding) check(file + ' finding', a.findings.some(f => e.finding.test(f.headline) || e.finding.test(f.body)), a.findings.map(f => f.headline).join(' | '));
  if (e.notable) check(file + ' notable property ' + e.notable, a.notable.some(n => n.name === e.notable));
  // Every analysis must say something: a failure that renders as an empty page is the worst outcome.
  check(file + ' has a headline and summary', !!a.headline && !!a.summary);
}

console.log('\n== edge cases ==');
const junk = analyzeMsiLog('hello\nthis is not a log\n');
check('random text -> unknown, with a how-to', junk.kind === 'unknown' && /l\*v/.test(junk.summary));
const empty = analyzeMsiLog('');
check('empty file -> unknown', empty.kind === 'unknown');
// A log cut off mid-install (the deployment tool timed out and killed msiexec).
const full = readFileSync(join(fxDir, '05-cafail.log'));
const txt = decodeLog(full);
const cut = analyzeMsiLog(txt.slice(0, Math.floor(txt.length / 3)));
check('truncated log -> no result, says so', cut.verdict === 'unknown' && /without a result/.test(cut.headline), cut.headline);
// Two runs appended to one file: the failed one gets the focus.
const ok = decodeLog(readFileSync(join(fxDir, '01-ok-install.log')));
const both = analyzeMsiLog(txt + '\n' + ok);
check('appended runs -> focus on the failed run', both.sessions.length === 2 && both.focus === 0 && both.verdict === 'failed', `${both.sessions.length} runs, focus ${both.focus}`);
// The same log saved as UTF-8 (copied out of Notepad) must read the same.
const utf8 = analyzeMsiLog(decodeLog(new TextEncoder().encode(txt)));
check('UTF-8 copy reads the same as UTF-16', utf8.failing?.name === 'ConfigureThing');

console.log('\n== ConfigMgr AppEnforce.log ==');
// A real AppEnforce.log from a ConfigMgr fleet (Brian, 2026-11-24), scrubbed by rff-scratch/scrub-appenforce.mjs:
// scope id zeroed, in-house app names replaced, an ACCOUNT_CONFIG token on a command line removed.
const ae = load(join(fxDir, 'host-appenforce-configmgr.log'));
const runs = ae.appEnforce ?? [];
check('AppEnforce: recognized', ae.kind === 'appenforce', ae.kind);
check('AppEnforce: every enforcement found', runs.length === 21, String(runs.length));
check('AppEnforce: verdict failed, headline names app and code', ae.verdict === 'failed' && /Adobe Acrobat Reader .* failed with exit code 1603/.test(ae.headline), ae.headline);
check('AppEnforce: Patch My PC runs keep their command line (only "Prepared command line" is logged)',
  runs.filter(r => /Adobe/.test(r.app)).every(r => /PatchMyPC-ScriptRunner\.exe/.test(r.command ?? '')));
const wifi = runs.find(r => /OFFICEWIFI/.test(r.app));
check('AppEnforce: exit 0 then not detected = not-detected', wifi?.result === 'not-detected' && wifi.exitCode === 0, wifi?.result);
const teams = runs.find(r => /Teams/.test(r.app));
check('AppEnforce: MSIX failure keeps its HRESULT', teams?.result === 'failed' && /^0x800700B7$/i.test(teams.hresult ?? ''), teams?.hresult);
check('AppEnforce: successes are successes', runs.filter(r => r.result === 'success').length === 3, runs.filter(r => r.result === 'success').map(r => r.app).join(', '));
check('AppEnforce: an EXE wrapper failure points at its own log', ae.findings.some(f => /installer's own log/.test(f.headline)));
const aeLines = decodeLog(readFileSync(join(fxDir, 'host-appenforce-configmgr.log'))).split(/\r?\n/);
const psEnd = aeLines.findIndex(l => /App enforcement completed .*PowerShell 7/.test(l));
const ps = analyzeMsiLog(aeLines.slice(0, psEnd + 1).join('\n'));
check('AppEnforce: a failed msiexec with no /l*v says no MSI log was asked for', /PowerShell 7/.test(ps.headline) && ps.findings.some(f => /No MSI log was asked for/.test(f.headline)), ps.headline);
check('AppEnforce: has a headline and summary', !!ae.headline && !!ae.summary);
const ime = analyzeMsiLog('<![LOG[Starting]LOG]!><time="1:00:00.000+000" date="1-1-2026" component="IntuneManagementExtension" context="" type="1" thread="1" file="">\n' +
  '<![LOG[Done]LOG]!><time="1:00:01.000+000" date="1-1-2026" component="IntuneManagementExtension" context="" type="1" thread="1" file="">');
check('other CMTrace log -> unknown, names the component', ime.kind === 'unknown' && /IntuneManagementExtension/.test(ime.headline), ime.headline);

console.log('\n== look for anything useful ==');
const sc = scavengeLog('starting\nSetup failed: access denied\nProcess exited with exit code 1603\nsee C:\\Windows\\Temp\\vendor_setup.log\nmsiexec /i x.msi /qn\nfinished with 0 errors\n');
check('scavenge: exit code with its meaning', sc.codes.some(c => c.code === '1603' && /Fatal error/.test(c.meaning ?? '')), JSON.stringify(sc.codes));
check('scavenge: failure line, not "0 errors"', sc.failures.length === 1 && !sc.failures.some(f => /0 errors/.test(f.text)), sc.failures.map(f => f.text).join(' | '));
check('scavenge: other log path', sc.logs.includes('C:\\Windows\\Temp\\vendor_setup.log'), sc.logs.join(', '));
check('scavenge: command line', sc.commands.length === 1);

const extra = process.argv[2];
if (extra) {
  console.log('\n== smoke: ' + extra + ' ==');
  const walk = (d) => readdirSync(d).flatMap(n => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });
  for (const p of walk(extra).filter(p => /\.(log|txt)$/i.test(p))) {
    let a; const t0 = Date.now();
    try { a = load(p); } catch (err) { check(p, false, 'THREW ' + err); continue; }
    const s = a.sessions[a.focus];
    console.log(`  ${a.kind.padEnd(7)} ${a.verdict.padEnd(9)} ${String(s?.exitCode ?? '').padEnd(5)} ${(a.failing?.name ?? '').padEnd(22)} ${Date.now() - t0}ms  ${p.split(/[\\/]/).pop().slice(0, 70)}`);
    if (!a.headline || !a.summary) check(p + ' says something', false);
  }
}

console.log(`\n${fails ? fails + ' failure(s)' : 'all checks passed'}`);
process.exit(fails ? 1 : 0);
