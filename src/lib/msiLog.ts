// MSI log reader. Pure: text in, verdict out. No DOM, no node builtins (check-no-node-builtins).
//
// A verbose Windows Installer log (msiexec /l*v) is 5,000 to 500,000 lines and the line that
// explains the failure is rarely near the end. The well-known trick is "search for Return value 3",
// but that line names the ACTION that failed, and for a deferred custom action it names
// InstallFinalize, not the custom action. What an admin needs is the custom action, the exit code
// it returned, what it printed, and what the 1603 means in THIS log. That is what this file finds.
//
// Built against real logs: lab fixtures (a deferred EXE that exits 5, a WixQuietExec PowerShell
// that exits 3, a service that never starts, a launch condition, a blocked downgrade, a second
// version of the same ProductCode, two installs at once), plus real installs on Brian's machine
// (Firefox, the .NET SDK bundle that failed with 1618). See scripts/check-msi-log.mjs.

export type Severity = 'bad' | 'warn' | 'info';
export type Finding = { severity: Severity; headline: string; body: string };

export type MsiSession = {
  index: number;
  startLine: number;
  started?: string;
  callingProcess?: string;
  product?: string;
  version?: string;
  manufacturer?: string;
  productCode?: string;
  operation: 'install' | 'uninstall' | 'repair' | 'modify' | 'upgrade-removal' | 'unknown';
  exitCode?: number;
  verdict: 'success' | 'reboot' | 'failed' | 'cancelled' | 'unknown';
  verbose: boolean;
  /** ProductCode(s) of the older version this run upgraded (removed), when it was a major upgrade. */
  upgraded?: string;
};

export type FailingAction = {
  name: string;
  line: number;
  /** The action whose "Return value 3" Windows Installer logged. For a deferred custom action this is InstallFinalize/InstallExecute. */
  reportedBy: string;
  isCustomAction: boolean;
  /** Exit/return code the custom action itself produced, from "returned actual error code N" or Error 1722's text. */
  caExitCode?: number;
  /** For EXE custom actions: the command line, from Error 1722. For DLL ones: the DLL entry point. */
  command?: string;
  /** The exit code of the command a QuietExec-style action ran (not the action's own 1603). */
  commandExit?: number;
  /** CustomActionData passed to a deferred DLL custom action. */
  data?: string;
  entryPoint?: string;
  /** What the custom action wrote to the log while it ran (WixQuietExec output, DTF exceptions, CA logging). */
  output: string[];
};

export type MsiError = { code: number; text: string; line: number };
export type InUse = { file: string; process: string; pid?: number };

export type BurnPackage = { id: string; action: string; result: string; resultCode?: number; log?: string };
export type BurnSummary = {
  engine: string;
  bundle?: string;
  commandLine?: string;
  result?: string;
  resultCode?: number;
  packages: BurnPackage[];
  errors: { line: number; text: string }[];
};

export type MsiAnalysis = {
  kind: 'msi' | 'burn' | 'appenforce' | 'unknown';
  sessions: MsiSession[];
  /** Index into sessions of the one analyzed in detail (the last failed one, else the last). */
  focus: number;
  verdict: MsiSession['verdict'];
  headline: string;
  summary: string;
  findings: Finding[];
  failing?: FailingAction;
  errors: MsiError[];
  inUse: InUse[];
  properties: { name: string; value: string }[];
  notable: { name: string; value: string; why: string }[];
  slowest: { action: string; seconds: number }[];
  durationSeconds?: number;
  /** Lines leading up to the failure (or the end), with their 1-based line numbers. */
  context: { line: number; text: string }[];
  burn?: BurnSummary;
  /** ConfigMgr AppEnforce.log: one row per enforcement attempt, oldest first. */
  appEnforce?: AppEnforceRun[];
  lineCount: number;
};

export type AppEnforceRun = {
  app: string;
  op: 'Install' | 'Uninstall';
  line: number;
  when?: string;
  context?: string;
  contentPath?: string;
  command?: string;
  exitCode?: number;
  /** "Success", "SoftReboot", "HardReboot", "FastRetry", "Failure"... as ConfigMgr matched it; "Unmatched" for a failure. */
  matched?: string;
  /** MSIX/AppX installs report an HRESULT instead of a process exit code. */
  hresult?: string;
  detectedBefore?: boolean;
  detectedAfter?: boolean;
  seconds?: number;
  result: 'success' | 'reboot' | 'failed' | 'not-detected' | 'already' | 'unknown';
};

// ---------------------------------------------------------------------------------------------
// Decoding: Windows Installer writes UTF-16LE (with BOM) when the engine is Unicode and the log
// was opened by msiexec; Burn and some wrappers write ANSI/UTF-8. Sniff rather than trust the
// extension.
export function decodeLog(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.subarray(2));
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.subarray(2));
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8').decode(b.subarray(3));
  // No BOM: UTF-16LE text has a zero in most odd bytes.
  let zeros = 0;
  const n = Math.min(b.length, 4000);
  for (let i = 1; i < n; i += 2) if (b[i] === 0) zeros++;
  if (n > 20 && zeros > n / 4) return new TextDecoder('utf-16le').decode(b);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(b); }
  catch { return new TextDecoder('windows-1252').decode(b); }
}

// ---------------------------------------------------------------------------------------------
// What the codes mean. Exit codes are what msiexec returns; "Error NNNN" are the messages it logs.

export const EXIT_CODES: Record<number, string> = {
  0: 'Success.',
  1601: 'The Windows Installer service could not be accessed. Usually a broken or disabled msiserver service.',
  1602: 'The user cancelled the install.',
  1603: 'Fatal error during installation. This is the generic "something failed" code; the real cause is the first failing action above it.',
  1605: 'This action is only valid for products that are currently installed. Usually an uninstall of a product code that is not on this machine.',
  1612: 'The installation source for this product is not available. The cached or original MSI is gone.',
  1618: 'Another installation is already in progress. Windows Installer runs one install at a time per machine.',
  1619: 'The installation package could not be opened. Wrong path, no access to the share, or a corrupt download.',
  1620: 'The installation package could not be opened. The file is not a valid MSI.',
  1622: 'Error opening the log file. The log path is not writable.',
  1624: 'Error applying a transform. The .mst path is wrong or the transform does not match this MSI.',
  1625: 'This installation is forbidden by system policy (DisableMSI or software restriction).',
  1633: 'This installation package is not supported on this processor type. A 64-bit MSI on 32-bit Windows, or an ARM mismatch.',
  1638: 'Another version of this product is already installed. Same ProductCode, different package; the vendor did not author a major upgrade for this version.',
  1639: 'Invalid command line argument.',
  1641: 'Success, and the installer started a reboot.',
  1642: 'The upgrade patch cannot be applied: the product is missing or the version does not match.',
  1644: 'One or more customizations are not permitted by system policy.',
  1650: 'Invalid client. Usually a broken Windows Installer registration.',
  3010: 'Success, a reboot is required to finish.',
};

export const ERROR_MESSAGES: Record<number, string> = {
  1303: 'No permission to the folder it is writing to.',
  1304: 'Error writing a file. Often antivirus holding it, or the disk is full.',
  1305: 'Error reading a file from the source. The media, share or cached MSI is not readable.',
  1306: 'Another program has the file open exclusively, so Windows Installer cannot replace or remove it. Find the process (Resource Monitor > CPU > Associated Handles, or handle.exe) and close it, or deploy when nobody is signed in.',
  1308: 'A source file was not found. The CAB or the uncompressed file next to the MSI is missing.',
  1310: 'Error writing a file to a folder. Permissions, a read-only folder, or a file locked by another program.',
  1311: 'A cabinet (.cab) file was not found next to the MSI. External CABs have to sit beside it.',
  1316: 'A network error reading the source, or "the specified account already exists" (a second version of the same product).',
  1327: 'Invalid drive. A property points at a drive letter that does not exist on this machine (often a mapped drive from the packaging machine).',
  1334: 'A file in the cabinet is missing or corrupt. Usually a truncated download.',
  1335: 'The cabinet file is corrupt. Usually a truncated download or a bad copy.',
  1402: 'Could not open a registry key. Permissions on the key, or a policy lock.',
  1406: 'Could not write a registry value. Permissions on the key, or a policy lock.',
  1500: 'Another installation is in progress.',
  1603: 'A file the install needs to replace is held open by a running program.',
  1606: 'Could not access a network location.',
  1706: 'No valid source could be found. Repair or modify needs the original MSI and it is gone.',
  1708: 'Installation failed (the summary message, not the cause).',
  1714: 'The older version could not be removed. The old product\'s own uninstall failed during the upgrade, usually because its cached MSI is gone.',
  1720: 'A script custom action (VBScript/JScript) failed.',
  1721: 'A program the installer needed to run could not be started.',
  1722: 'A program run as part of the setup (an EXE custom action) returned a failure code.',
  1723: 'A DLL needed for a custom action could not be run.',
  1730: 'You must be an administrator to remove this application.',
  1904: 'A module failed to register (self-registration).',
  1911: 'Could not register a type library.',
  1920: 'A service failed to start.',
  1921: 'A service could not be stopped.',
  1922: 'A service could not be deleted.',
  1923: 'A service could not be installed. Often an account or password problem.',
  1925: 'You do not have sufficient privileges to install for all users. Run it elevated.',
  1931: 'Windows Installer could not update a protected system file.',
  1935: 'An error installing an assembly component (WinSxS or the .NET GAC).',
  2502: 'Called RunScript when not marked in progress. Usually a TEMP folder the installer cannot write.',
  2503: 'Called RunScript when not marked in progress. Usually a TEMP folder the installer cannot write.',
  2738: 'Could not access VBScript runtime for a custom action. vbscript.dll not registered, or VBScript disabled.',
  2739: 'Could not access JScript runtime for a custom action.',
  2755: 'Server returned an unexpected error opening the package. Usually the path or the MSI file itself.',
};

// Exit codes that cmd/PowerShell/common tools return from EXE custom actions; worth naming.
const WIN32: Record<number, string> = {
  1: 'Incorrect function (or just "1", the default failure code of most scripts).',
  2: 'The system cannot find the file specified.',
  3: 'The system cannot find the path specified.',
  5: 'Access is denied.',
  32: 'The file is in use by another process.',
  87: 'The parameter is incorrect.',
  1053: 'The service did not respond to the start request in time.',
  1067: 'The process terminated unexpectedly.',
  1069: 'The service did not start due to a logon failure.',
  1603: 'Fatal error during installation (a nested installer failed).',
  1618: 'Another installation is in progress.',
  183: 'Cannot create a file when that file already exists.',
};

// HRESULT 0x8007xxxx wraps a Win32 code. Burn reports MSI exit codes this way (0x80070643 = 1603).
export function hresultToWin32(h: number): number | undefined {
  return ((h >>> 16) & 0xffff) === 0x8007 ? h & 0xffff : undefined;
}

// Properties worth showing first, and why.
const NOTABLE: Record<string, string> = {
  ProductName: 'what is being installed',
  ProductVersion: 'its version',
  ProductCode: 'identifies this exact product; uninstall with msiexec /x {code}',
  UpgradeCode: 'ties versions of the product together for upgrades',
  INSTALLDIR: 'where it installs',
  INSTALLFOLDER: 'where it installs',
  INSTALLLOCATION: 'where it installs',
  TARGETDIR: 'root target folder',
  ALLUSERS: '1 = per-machine, empty = per-user, 2 = installer decides',
  Privileged: 'set when the install runs elevated',
  AdminUser: 'set when the user is an administrator',
  UILevel: '2 = silent (/qn), 3 = basic, 5 = full UI',
  REMOVE: 'features being removed (ALL = uninstall)',
  REINSTALL: 'features being repaired',
  Installed: 'set when the product was already installed before this run',
  UPGRADINGPRODUCTCODE: 'set when this run is the OLD version being removed by an upgrade',
  WIX_UPGRADE_DETECTED: 'an older version was found and will be upgraded',
  WIX_DOWNGRADE_DETECTED: 'a NEWER version is installed (WiX blocks the downgrade)',
  MsiRestartManagerSessionKey: 'Restart Manager was used to find files in use',
  REBOOT: 'reboot behavior (ReallySuppress = never reboot)',
  ReplacedInUseFiles: 'files were in use and will be replaced at reboot',
  LogonUser: 'the account running the install',
  ClientProcessId: 'the process that started msiexec',
  SourceDir: 'where the MSI was run from',
  TRANSFORMS: 'the .mst transforms applied',
  PATCH: 'patches applied',
  ARPSYSTEMCOMPONENT: '1 = hidden from Apps & Features',
  VersionNT64: 'the Windows version (64-bit)',
  WindowsBuild: 'the Windows build',
};

// Built-in standard actions. Anything else in a "Return value 3" line is a custom action
// (or an action from a WiX extension, which is also a custom action).
const STANDARD = new Set(('AppSearch BindImage CCPSearch CostFinalize CostInitialize CreateFolders CreateShortcuts ' +
  'DeleteServices DisableRollback DuplicateFiles ExecuteAction FileCost FindRelatedProducts ForceReboot ' +
  'InstallAdminPackage InstallExecute InstallExecuteAgain InstallFiles InstallFinalize InstallInitialize ' +
  'InstallODBC InstallServices InstallSFPCatalogFile InstallValidate IsolateComponents LaunchConditions ' +
  'MigrateFeatureStates MoveFiles MsiConfigureServices MsiPublishAssemblies MsiUnpublishAssemblies ' +
  'PatchFiles ProcessComponents PublishComponents PublishFeatures PublishProduct RegisterClassInfo ' +
  'RegisterComPlus RegisterExtensionInfo RegisterFonts RegisterMIMEInfo RegisterProduct RegisterProgIdInfo ' +
  'RegisterTypeLibraries RegisterUser RemoveDuplicateFiles RemoveEnvironmentStrings RemoveExistingProducts ' +
  'RemoveFiles RemoveFolders RemoveIniValues RemoveODBC RemoveRegistryValues RemoveShortcuts ResolveSource ' +
  'RMCCPSearch ScheduleReboot SelfRegModules SelfUnregModules SetODBCFolders StartServices StopServices ' +
  'UnpublishComponents UnpublishFeatures UnregisterClassInfo UnregisterComPlus UnregisterExtensionInfo ' +
  'UnregisterFonts UnregisterMIMEInfo UnregisterProgIdInfo UnregisterTypeLibraries ValidateProductID ' +
  'WriteEnvironmentStrings WriteIniValues WriteRegistryValues INSTALL ADMIN ADVERTISE ExecuteAction ' +
  'Rollback MsiUnpublishAssemblies AllocateRegistrySpace').split(/\s+/));

// ---------------------------------------------------------------------------------------------

const RX = {
  start: /^=== (?:Verbose )?logging started: ([^=]*?)\s+Build type:.*?Calling process: (.*?) ===\s*$/,
  startLoose: /^=== (?:Verbose )?logging started: (.*?)(?: ===)?\s*$/,
  msiLine: /^MSI \(([csa])\) \(([0-9A-F]{2}):([0-9A-F]{2})\) \[(\d{2}):(\d{2}):(\d{2}):(\d{3})\]: (.*)$/,
  actionStart: /^Action start (\d{1,2}):(\d{2}):(\d{2}): ([^.]+)\.\s*$/,
  actionEnd: /^Action ended (\d{1,2}):(\d{2}):(\d{2}): ([^.]+)\. Return value (\d+)\.\s*$/,
  property: /^Property\(([SCN])\): ([^=\s]+) = (.*)$/,
  errorMsg: /(?:^|-- |: )Error (\d{4})\.\s*(.*)$/,
  caActual: /CustomAction (\S+) returned actual error code (\d+)/,
  invoke: /Invoking remote custom action\. DLL: (.*?), Entrypoint: (\S+)/,
  doAction: /Doing action: (\S+)/,
  executing: /Executing op: CustomActionSchedule\(Action=([^,]+),/,
  executingData: /Executing op: CustomActionSchedule\(Action=([^,]+),.*?CustomActionData=(.*)\)\s*$/,
  finalLine: /Product Name: (.*?)\. Product Version: (.*?)\. Product Language: .*?\. Manufacturer: (.*?)\. Installation success or error status: (\d+)\./,
  finalVerb: /Windows Installer (installed|removed|reconfigured|requires a system restart|.*?) the product\.|Windows Installer (installed|removed|reconfigured) the product/,
  mainEngine: /MainEngineThread is returning (\d+)/,
  productLine: /Product: (.*?) -- (Installation|Removal|Configuration) (completed successfully|failed|operation completed successfully)\./,
  inUse: /^Info 1603\. The file (.*?) is being held in use by the following process: Name: (.*?), Id: (\d+)/,
  inUseRm: /RESTART MANAGER: Detected that application with id (\d+), friendly name '(.*?)'/,
  mutex: /Failed to grab execution mutex/,
  product2: /\*\*\*\*\*\*\* Product: (.*)$/,
};

function seconds(h: string, m: string, s: string) { return +h * 3600 + +m * 60 + +s; }

type ParsedSession = {
  s: MsiSession;
  lines: string[];
  offset: number; // 0-based index of first line in the whole file
};

export function analyzeMsiLog(text: string): MsiAnalysis {
  const all = text.replace(/\r\n?/g, '\n').split('\n');
  const lineCount = all.length;

  // Burn (WiX bootstrapper) logs: different format, different answer.
  const burnHits = all.slice(0, 200).filter(l => /^\[[0-9A-F]{4}:[0-9A-F]{4}\]\[\d{4}-\d{2}-\d{2}T/.test(l)).length;
  if (burnHits >= 3) return analyzeBurn(all);

  // ConfigMgr / Intune logs (CMTrace format). AppEnforce.log is the one people drop here for an MSI failure.
  if (all.slice(0, 50).filter(l => l.includes('<![LOG[')).length >= 2) return analyzeCmTrace(all);

  // Split into sessions. /l+ appends, and Burn chains write one log per package, but a single
  // file can still hold several runs.
  const starts: number[] = [];
  all.forEach((l, i) => { if (/^=== (?:Verbose )?logging started/.test(l)) starts.push(i); });
  const isMsi = starts.length > 0 || all.slice(0, 500).some(l => RX.msiLine.test(l) || RX.actionStart.test(l));
  if (!isMsi) return unknown(lineCount);
  if (starts.length === 0 || starts[0] > 0 && starts[0] > 50) starts.unshift(0);
  if (starts[0] !== 0 && starts[0] <= 50) starts[0] = 0;

  const parsed: ParsedSession[] = starts.map((st, idx) => {
    const end = idx + 1 < starts.length ? starts[idx + 1] : all.length;
    const lines = all.slice(st, end);
    return { s: summarizeSession(lines, idx, st), lines, offset: st };
  });

  // Focus: the last session that failed; otherwise the last one.
  let focus = parsed.length - 1;
  for (let i = parsed.length - 1; i >= 0; i--) {
    if (parsed[i].s.verdict === 'failed' || parsed[i].s.verdict === 'cancelled') { focus = i; break; }
  }
  const P = parsed[focus];
  const detail = detailSession(P);
  const sessions = parsed.map(p => p.s);

  const a: MsiAnalysis = {
    kind: 'msi', sessions, focus, lineCount,
    verdict: P.s.verdict,
    headline: '', summary: '',
    findings: detail.findings,
    failing: detail.failing,
    errors: detail.errors,
    inUse: detail.inUse,
    properties: detail.properties,
    notable: detail.notable,
    slowest: detail.slowest,
    durationSeconds: detail.duration,
    context: detail.context,
  };
  explain(a, P.s, detail);
  if (sessions.length > 1) {
    a.findings.push({
      severity: 'info',
      headline: `This file holds ${sessions.length} separate runs`,
      body: `The log was appended to (msiexec /l+ or a wrapper that reuses the file). The detail below is run ${focus + 1}` +
        (P.s.verdict === 'failed' ? ', the last one that failed.' : ', the last one.') +
        ' The list of runs is at the bottom.',
    });
  }
  return a;
}

function unknown(lineCount: number): MsiAnalysis {
  return {
    kind: 'unknown', sessions: [], focus: 0, verdict: 'unknown', lineCount,
    headline: 'This does not look like a Windows Installer log',
    summary: 'No "=== Verbose logging started" header, no "MSI (s)" lines and no "Action start" lines were found. ' +
      'Create one with msiexec /i package.msi /l*v install.log and drop that file.',
    findings: [], errors: [], inUse: [], properties: [], notable: [], slowest: [], context: [],
  };
}

function summarizeSession(lines: string[], index: number, startLine: number): MsiSession {
  const s: MsiSession = { index, startLine: startLine + 1, operation: 'unknown', verdict: 'unknown', verbose: false };
  const m = RX.start.exec(lines[0] ?? '');
  if (m) { s.started = m[1].trim().replace(/\s+/g, ' '); s.callingProcess = m[2].trim(); }
  else { const m2 = RX.startLoose.exec(lines[0] ?? ''); if (m2) s.started = m2[1].trim().replace(/\s+/g, ' '); }

  let remove = '', reinstall = '', upgrading = '', installed = false, productLineVerb = '', status: number | undefined;
  let engine: number | undefined, verdictVerb = '', cmdRemove: boolean | undefined;
  for (const l of lines) {
    if (!s.verbose && l.startsWith('MSI (')) s.verbose = true;
    let x;
    if ((x = RX.finalLine.exec(l))) {
      s.product = x[1]; s.version = x[2]; s.manufacturer = x[3]; status = +x[4];
      const v = /Windows Installer (\w+(?: a system restart)?)/.exec(l); if (v) verdictVerb = v[1];
    } else if ((x = RX.mainEngine.exec(l))) engine = +x[1];
    else if ((x = RX.productLine.exec(l))) { s.product ??= x[1]; productLineVerb = x[2] + ' ' + x[3]; }
    else if ((x = /Product Code from property table (?:before|after) transforms:\s*'(\{[^']+\})'/.exec(l))) s.productCode ??= x[1];
    // Property(N) is the NESTED run (a major upgrade removing the old version inside this one); its
    // REMOVE=ALL and UPGRADINGPRODUCTCODE describe the old product, not this run.
    else if ((x = RX.property.exec(l)) && x[1] !== 'N') {
      const [, , k, v] = x;
      if (k === 'REMOVE') remove = v;
      else if (k === 'REINSTALL') reinstall = v;
      else if (k === 'UPGRADINGPRODUCTCODE') upgrading = v;
      else if (k === 'Installed') installed = !!v;
      else if (k === 'ProductName' && !s.product) s.product = v;
      else if (k === 'ProductVersion' && !s.version) s.version = v;
      else if (k === 'Manufacturer' && !s.manufacturer) s.manufacturer = v;
      else if (k === 'ProductCode') s.productCode = v;
      else if (k === 'WIX_UPGRADE_DETECTED' || k === 'OLDPRODUCTS') s.upgraded = v;
    } else if ((x = /^MSI \(s\).*?: Command Line: (.*)$/.exec(l))) {
      // The first server command line is this run's; later ones are nested (upgrade removals).
      if (cmdRemove === undefined) cmdRemove = /\bREMOVE=ALL\b/i.test(x[1]) && !/UPGRADINGPRODUCTCODE=/.test(x[1]);
    }
  }
  // Exit code: the server status is authoritative; the client's MainEngineThread return covers
  // runs that never reached the server (1618, 1619, 1638 on the client side).
  s.exitCode = status ?? engine;
  // The engine's own words outrank properties: Firefox's MSI sets REMOVE=ALL during a normal
  // install (it wraps the setup.exe), and the log still says "Installation completed successfully".
  // msiexec /x puts REMOVE=ALL on the server command line. That is the strongest signal: the final
  // line still says "installed the product" for an /x of something that is not installed (1605).
  if (upgrading) s.operation = 'upgrade-removal';
  else if (cmdRemove) s.operation = 'uninstall';
  // 1605 only happens to maintenance runs (msiexec /x or /f) on a product that is not installed.
  else if ((status ?? engine) === 1605) s.operation = 'uninstall';
  // 1638 is a new package refused because its ProductCode is registered: the engine logs
  // "entering maintenance mode" and sets REINSTALL, but what the admin ran was an install.
  else if ((status ?? engine) === 1638) s.operation = 'install';
  else if (verdictVerb === 'removed' || /^Removal/.test(productLineVerb)) s.operation = 'uninstall';
  else if (verdictVerb === 'installed' || /^Installation/.test(productLineVerb)) s.operation = 'install';
  else if (reinstall) s.operation = 'repair';
  else if (/^ALL$/i.test(remove)) s.operation = 'uninstall';
  else if (installed || verdictVerb === 'reconfigured' || /^Configuration/.test(productLineVerb)) s.operation = remove ? 'modify' : installed ? 'modify' : 'repair';
  else if (status !== undefined || engine !== undefined) s.operation = 'install';

  const c = s.exitCode;
  if (c === 0) s.verdict = 'success';
  else if (c === 3010 || c === 1641) s.verdict = 'reboot';
  else if (c === 1602) s.verdict = 'cancelled';
  else if (c !== undefined) s.verdict = 'failed';
  else if (/completed successfully/.test(productLineVerb)) s.verdict = 'success';
  else if (/failed/.test(productLineVerb)) s.verdict = 'failed';
  // An excerpt pasted from a ticket rarely includes the result line, but a failed action is a failure.
  else if (lines.some(l => /^Action ended .*\. Return value 3\.\s*$/.test(l))) s.verdict = 'failed';
  return s;
}

type Detail = {
  findings: Finding[];
  failing?: FailingAction;
  errors: MsiError[];
  inUse: InUse[];
  properties: { name: string; value: string }[];
  notable: { name: string; value: string; why: string }[];
  slowest: { action: string; seconds: number }[];
  duration?: number;
  context: { line: number; text: string }[];
  firstFailIdx?: number;
  launchMessage?: string;
  mutex: boolean;
  downgrade: boolean;
  /** ProductCode of an older version removed inside this run (major upgrade). */
  upgradeOf?: string;
  /** The failure happened while removing that older version, not while installing the new one. */
  failedInOldRemoval?: boolean;
  serviceErrors: string[];
};

function detailSession(P: ParsedSession): Detail {
  const { lines, offset } = P;
  const ln = (i: number) => offset + i + 1;
  const d: Detail = {
    findings: [], errors: [], inUse: [], properties: [], notable: [], slowest: [], context: [],
    mutex: false, downgrade: false, serviceErrors: [],
  };

  // Properties: last value wins; server (S) over client (C).
  const props = new Map<string, { v: string; src: string }>();
  const open = new Map<string, number>(); // action -> start seconds
  const durations = new Map<string, number>();
  let firstT: number | undefined, lastT: number | undefined, dayOffset = 0, prevT = -1;
  let firstFail: number | undefined, firstFailAction = '';
  const caExit = new Map<string, { code: number; idx: number }>();
  const invoked = new Map<string, { dll: string; entry: string; idx: number }>();
  let currentCa = '';
  // Deferred actions run later, inside InstallFinalize, as "Executing op: ActionStart(Name=X)".
  // The last one before the failure is the action that was actually running.
  let execOp = '', execOpIdx = -1, failExecOp = '', failExecOpIdx = -1;
  let nestedFrom = -1, nestedDone = false;
  const caData = new Map<string, string>();

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    let x;
    if ((x = /^MSI \(s\).*?Executing op: ActionStart\(Name=([^,]+),/.exec(l))) { execOp = x[1]; execOpIdx = i; continue; }
    if ((x = RX.executingData.exec(l))) { caData.set(x[1], x[2]); currentCa = x[1]; continue; }
    if ((x = RX.property.exec(l))) {
      const [, src, k, v] = x;
      if (src === 'N') continue; // the nested (upgrade-removal) run's properties
      const prev = props.get(k);
      if (!prev || src === 'S' || prev.src !== 'S') props.set(k, { v, src });
      continue;
    }
    if ((x = RX.actionStart.exec(l))) {
      let t = seconds(x[1], x[2], x[3]);
      if (prevT >= 0 && t + dayOffset < prevT - 3600) dayOffset += 86400;
      t += dayOffset; prevT = t;
      firstT ??= t; lastT = t;
      open.set(x[4], t);
      if (!STANDARD.has(x[4])) currentCa = x[4];
      continue;
    }
    if ((x = RX.actionEnd.exec(l))) {
      let t = seconds(x[1], x[2], x[3]);
      if (prevT >= 0 && t + dayOffset < prevT - 3600) dayOffset += 86400;
      t += dayOffset; prevT = t;
      firstT ??= t; lastT = t;
      const st = open.get(x[4]);
      if (st !== undefined && x[4] !== 'INSTALL') durations.set(x[4], Math.max(durations.get(x[4]) ?? 0, t - st));
      if ((x[5] === '3' || (x[5] === '2' && x[4] !== 'INSTALL')) && firstFail === undefined) {
        firstFail = i; firstFailAction = x[4]; failExecOp = execOp; failExecOpIdx = execOpIdx;
        // Inside the nested run that removes the old version? It ends at RemoveExistingProducts' own return.
        if (nestedFrom >= 0 && !nestedDone) d.failedInOldRemoval = true;
      }
      // The nested run logs its own (skipped) RemoveExistingProducts, so its end is its own INSTALL return.
      if (x[4] === 'INSTALL' && nestedFrom >= 0 && i > nestedFrom) nestedDone = true;
      continue;
    }
    if ((x = RX.caActual.exec(l))) { caExit.set(x[1], { code: +x[2], idx: i }); continue; }
    if ((x = RX.invoke.exec(l))) {
      // The action name is on the nearest preceding "Doing action" / CustomActionSchedule line.
      let name = currentCa;
      for (let j = i; j >= Math.max(0, i - 40); j--) {
        const m = RX.executing.exec(lines[j]) ?? /Invoking remote custom action.*|Doing action: (\S+)/.exec(lines[j]);
        if (m && m[1]) { name = m[1]; break; }
      }
      if (name) invoked.set(name, { dll: x[1], entry: x[2], idx: i });
      continue;
    }
    if ((x = RX.executing.exec(l))) { currentCa = x[1]; continue; }
    if ((x = RX.inUse.exec(l))) { d.inUse.push({ file: x[1], process: x[2], pid: +x[3] }); continue; }
    if ((x = RX.inUseRm.exec(l))) {
      if (!d.inUse.some(u => u.pid === +x![1])) d.inUse.push({ file: '', process: x[2], pid: +x[1] });
      continue;
    }
    if (RX.mutex.test(l)) d.mutex = true;
    if ((x = /Command Line: UPGRADINGPRODUCTCODE=(\{[^}]+\})/.exec(l))) { d.upgradeOf = x[1]; nestedFrom = i; }
    if ((x = RX.errorMsg.exec(l))) {
      const code = +x[1];
      // "Error 1708" is the summary, not the cause; "Note: 1: 2205" style internal notes are not
      // user-facing errors and are noise in almost every log, so only "Error NNNN." counts.
      if (!d.errors.some(e => e.code === code && e.text === x![2].trim()))
        d.errors.push({ code, text: x[2].trim(), line: ln(i) });
      if (code >= 1920 && code <= 1923) d.serviceErrors.push(x[2].trim());
    }
  }
  if (lastT !== undefined && firstT !== undefined) d.duration = lastT - firstT;
  d.slowest = [...durations.entries()].filter(([, s]) => s >= 2).sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([action, seconds]) => ({ action, seconds }));

  d.downgrade = !!props.get('WIX_DOWNGRADE_DETECTED')?.v;
  d.properties = [...props.entries()].map(([name, { v }]) => ({ name, value: v })).sort((a, b) => a.name.localeCompare(b.name));
  for (const [k, why] of Object.entries(NOTABLE)) {
    const p = props.get(k);
    if (p && p.v !== '') d.notable.push({ name: k, value: p.v, why });
  }

  // The failing action. The first "Return value 3" is the one that matters; later ones are its
  // parents (INSTALL) unwinding. A deferred custom action fails inside InstallFinalize/
  // InstallExecute, so the action actually at fault is the custom action with an error code or
  // an "Error 17xx" naming it, close above that line.
  if (firstFail !== undefined) {
    d.firstFailIdx = firstFail;
    const f: FailingAction = { name: firstFailAction, reportedBy: firstFailAction, line: ln(firstFail), isCustomAction: !STANDARD.has(firstFailAction), output: [] };
    const win = Math.max(0, firstFail - 400);
    // Error 1722/1720/1721/1723 carry the action name, location and command.
    for (let j = firstFail; j >= win; j--) {
      const m = /Error (172[0-3])\..*?Action (\S+?),\s*location: (.*?),\s*command: (.*)$/.exec(lines[j]) ??
        /Error (172[0-3])\..*?Action (\S+?),\s*(.*)$/.exec(lines[j]);
      if (m) {
        f.name = m[2]; f.isCustomAction = true;
        if (m[4]) f.command = m[4].trim(); else if (m[3]) f.command = m[3].trim();
        break;
      }
    }
    if (STANDARD.has(f.name)) {
      // Deferred: the op that was executing when the script failed. Falls back to the latest custom
      // action that returned an error code.
      if (failExecOp && failExecOp !== f.name) { f.name = failExecOp; f.isCustomAction = !STANDARD.has(failExecOp); }
      else {
        let best: [string, number, number] | undefined;
        for (const [name, v] of caExit) if (v.idx <= firstFail && v.code !== 0 && (!best || v.idx > best[2])) best = [name, v.code, v.idx];
        if (best) { f.name = best[0]; f.isCustomAction = true; }
      }
    }
    const ce = caExit.get(f.name);
    if (ce && ce.idx <= firstFail) f.caExitCode = ce.code;
    const inv = invoked.get(f.name);
    if (inv) f.entryPoint = inv.entry;
    // A deferred custom action's parameters are its CustomActionData. For WixQuietExec/CAQuietExec
    // that IS the command line it ran.
    const data = caData.get(f.name);
    if (data !== undefined && !f.command && (!f.entryPoint || /QuietExec|ShellExec|Exec/i.test(f.entryPoint))) f.command = data.trim();
    else if (data !== undefined) f.data = data.trim();

    // What the custom action printed: lines between its invocation (or its Action start) and the
    // failure that are not engine lines.
    let from = inv ? inv.idx + 1 : -1;
    if (from < 0) for (let j = firstFail; j >= win; j--) if (lines[j].includes('Action start') && lines[j].includes(f.name + '.')) { from = j + 1; break; }
    if (from < 0) for (let j = firstFail; j >= win; j--) if (lines[j].includes('CustomActionSchedule(Action=' + f.name)) { from = j + 1; break; }
    if (from < 0 && failExecOpIdx >= 0 && failExecOp === f.name) from = failExecOpIdx + 1;
    if (from >= 0) {
      for (let j = from; j < firstFail && f.output.length < 40; j++) {
        const t = lines[j];
        // Engine lines are shown elsewhere; keep what the action itself wrote.
        if (!t.trim() || /^(MSI \(|Action |Property\(|CustomAction \S+ returned|Error \d{4}\.|Info \d{4}\.)/.test(t)) continue;
        f.output.push(t.trim());
      }
    }
    // WixQuietExec/CAQuietExec report the command's own exit as an HRESULT:
    // "Error 0x80070003: Command line returned an error." means the command exited 3.
    for (const o of f.output) {
      const m = /Error (0x[0-9a-fA-F]{8}): Command line returned an error/.exec(o);
      if (m) { const w = hresultToWin32(parseInt(m[1], 16)); if (w !== undefined) f.commandExit = w; break; }
    }
    d.failing = f;

    // Launch condition text (the message is logged right above LaunchConditions' return).
    if (firstFailAction === 'LaunchConditions') {
      for (let j = firstFail; j >= Math.max(0, firstFail - 30); j--) {
        const m = /^(?:MSI \(s\).*?: )?Product: .*? -- (.*)$/.exec(lines[j]) ?? /^Error \d+\.\s*(.*)$/.exec(lines[j]);
        if (m && !/Installation failed/.test(m[1])) { d.launchMessage = m[1].replace(/^Error \d+\.\s*/, '').trim(); break; }
      }
    }
  }

  // Context: the 30 lines before the failure (or the end), engine lines included.
  const at = firstFail ?? lines.length - 1;
  for (let j = Math.max(0, at - 30); j <= Math.min(lines.length - 1, at + 2); j++) {
    if (lines[j].trim()) d.context.push({ line: ln(j), text: lines[j] });
  }
  return d;
}

const fmtCode = (n: number) => n + (n > 255 || n < 0 ? ` (0x${(n >>> 0).toString(16).toUpperCase()})` : '');
const esc = (s: string) => s; // the page escapes; kept as a marker of where strings come from the log

function explain(a: MsiAnalysis, s: MsiSession, d: Detail) {
  const F = a.findings;
  const what = s.product ? `${s.product}${s.version ? ' ' + s.version : ''}` : 'This package';
  const op = s.operation === 'uninstall' ? 'uninstall' : s.operation === 'repair' ? 'repair'
    : s.operation === 'upgrade-removal' ? 'removal of the old version (during an upgrade)' : s.operation === 'modify' ? 'change' : 'install';
  const code = s.exitCode;

  if (!s.verbose) F.push({
    severity: 'info', headline: 'Not a verbose log',
    body: 'This log has no engine lines, so property values, custom action detail and timing are missing. Rerun with msiexec ... /l*v install.log for the full picture.',
  });

  if (s.verdict === 'success' || s.verdict === 'reboot') {
    a.headline = s.verdict === 'reboot' ? `The ${op} worked, and needs a reboot` : `The ${op} worked`;
    a.summary = `${esc(what)} finished with exit code ${code}. ${EXIT_CODES[code!] ?? ''}`;
    if (d.upgradeOf || s.upgraded) F.push({
      severity: 'info', headline: 'This was an upgrade',
      body: `An older version (${d.upgradeOf ?? s.upgraded}) was found and removed inside this run (RemoveExistingProducts). Its removal is logged in this same file, between the two "Command Line" lines.`,
    });
    if (d.inUse.length) F.push({
      severity: 'warn', headline: 'Some files were in use',
      body: `Windows Installer found ${d.inUse.length} program(s) holding files it needed (${d.inUse.slice(0, 3).map(u => u.process).join(', ')}). They will be replaced at the next reboot, so the new version is not fully in place until then.`,
    });
    const errs = d.errors.filter(e => e.code !== 1708);
    if (errs.length) F.push({
      severity: 'info', headline: `${errs.length} error message(s) were logged, and the ${op} still succeeded`,
      body: 'An "Error NNNN" line in a successful log is an error the installer was told to ignore (a custom action marked Return="ignore", or a retry that worked). Listed below for completeness.',
    });
    return;
  }

  if (s.verdict === 'cancelled') {
    a.headline = `The ${op} was cancelled`;
    a.summary = `Exit code 1602: the user (or a script answering a prompt) cancelled. ${d.failing ? 'The cancel came during ' + d.failing.name + '.' : ''}`;
    return;
  }

  if (s.verdict === 'unknown') {
    a.headline = 'The log ends without a result';
    a.summary = 'There is no "Installation success or error status" or "MainEngineThread is returning" line. The install was still running when this copy was taken, or the process was killed (a reboot, a timeout in the deployment tool, or Task Manager).';
    F.push({
      severity: 'warn', headline: 'No result line',
      body: 'If the deployment tool reported a timeout, this is what it looks like: msiexec never got to write its result. Look at the last actions below to see what it was doing.',
    });
    return;
  }

  // Failed.
  a.headline = code === undefined ? `The ${op} failed` : `The ${op} failed with ${code}`;
  const generic = code === undefined
    ? 'This text has a failed action but no exit code line, so it is probably an excerpt. The cause below comes from the lines it does have.'
    : EXIT_CODES[code] ?? (hresultToWin32(code) ? WIN32[hresultToWin32(code)!] : undefined) ?? 'Not a standard Windows Installer exit code.';
  const wrapper = code === undefined ? '' : ` ${code} is only the wrapper code.`;

  if (code === 1618 || d.mutex) {
    a.summary = 'Another Windows Installer operation was already running, so this one never started. Nothing was changed.';
    F.push({
      severity: 'bad', headline: 'Two installs at once',
      body: 'Windows Installer allows one install per machine. The log says "Failed to grab execution mutex": it waited and gave up. ' +
        'Usual causes: Windows Update or another deployment tool was installing at the same moment, a bundle (like a .NET or Visual C++ setup) started its own MSI, or an earlier msiexec is stuck waiting for input. ' +
        'Retry later. A deployment tool should retry 1618 on its own; it is not a package problem.',
    });
    return;
  }
  if (code === 1605) {
    a.headline = 'Nothing to remove: the product is not installed';
    a.summary = 'Windows Installer has no record of this product on this machine, so the run did nothing (exit 1605). ' +
      'Common causes: it was already removed, it was upgraded to a version with a different ProductCode, or the uninstall string targets an old code. ' +
      'If Apps & Features still lists it, that entry is orphaned registration, not an installed MSI.';
    return;
  }
  if (code === 1638) {
    a.summary = 'This exact product (same ProductCode) is already installed in a different version, and the package is not authored to upgrade it in place.';
    F.push({
      severity: 'bad', headline: 'Same ProductCode, different version',
      body: `Uninstall the installed version first (msiexec /x ${s.productCode ?? '{ProductCode}'}), or ask the vendor for a package that does a major upgrade. Nothing was changed by this run.`,
    });
    return;
  }

  const f = d.failing;
  // Before the launch-condition branch: WiX blocks a downgrade with the same LaunchConditions-style
  // error, and "downgrade" is the more useful answer.
  if (d.downgrade) {
    a.summary = 'A newer version of this product is already installed, and the package blocks downgrades. Nothing was changed.' +
      (d.launchMessage ? ` The package says: "${esc(d.launchMessage)}"` : '');
    F.push({
      severity: 'bad', headline: 'Downgrade blocked',
      body: `WIX_DOWNGRADE_DETECTED is set to ${esc(String(a.properties.find(p => p.name === 'WIX_DOWNGRADE_DETECTED')?.value ?? ''))}, the ProductCode of the newer version on this machine. Uninstall it first (msiexec /x {that code}) if you really want the older one.`,
    });
    return;
  }
  if (d.launchMessage || f?.reportedBy === 'LaunchConditions') {
    a.summary = `A launch condition blocked the ${op} before anything was changed.` + (d.launchMessage ? ` The package says: "${esc(d.launchMessage)}"` : '');
    F.push({
      severity: 'bad', headline: 'Blocked by a launch condition',
      body: 'Launch conditions are the package\'s own prerequisites (an OS version, a required program, a property that must be set on the command line). Nothing failed; the package refused. The message above is the condition it wanted.',
    });
    return;
  }
  // Managed (C#) custom actions, run by the DTF/SFXCA host. The useful line is the INNERMOST
  // exception ("TargetInvocationException ---> System.IO.FileNotFoundException: Could not find
  // file ..."), and the vendor's own frame is the first "at" line that is not framework code.
  const managed = f?.output.some(o => /^SFXCA:|Exception thrown by custom action/.test(o));
  if (f && managed) {
    const clr = f.output.find(o => /SFXCA: Failed to get requested CLR info|SFXCA: Failed to (?:load|bind)/.test(o));
    let exType = '', exMsg = '', frame = '';
    for (const o of f.output) {
      const inner = /--->\s*([\w.]+(?:Exception|Error)):\s*(.*?)(?:\s*--->.*)?$/.exec(o.split('--->').length > 2 ? '---> ' + o.split('--->').pop()!.trim() : o);
      const top = /^([\w.]+(?:Exception|Error)):\s*(.*)$/.exec(o);
      if (inner) { exType = inner[1]; exMsg = inner[2]; break; }
      if (top && !exType && !/TargetInvocationException/.test(top[1])) { exType = top[1]; exMsg = top[2]; }
    }
    frame = f.output.map(o => /^at ([\w.`<>]+)\(/.exec(o)?.[1]).find(n => n && !/^(System|Microsoft|WixToolset|MS\.Internal)\./.test(n)) ?? '';
    if (clr) {
      a.summary = `The custom action ${f.name} is written in .NET, and it never ran: the installer could not load the .NET runtime for it.${wrapper}`;
      F.push({
        severity: 'bad', headline: `Managed custom action ${f.name}: .NET did not load`,
        body: `The log says "${esc(clr.replace(/^SFXCA:\s*/, ''))}". Either the .NET Framework version the action needs is not installed (often 3.5, which is off by default on Windows 10 and 11), or the package was built without a CustomAction.config naming a supportedRuntime. Turning on .NET Framework 3.5 fixes the first; the second is the vendor's to fix.`,
      });
      F.push({ severity: 'info', headline: code === undefined ? 'No exit code in this text' : `What ${code} means`, body: generic });
      return;
    }
    if (exType) {
      a.summary = `The custom action ${f.name} (.NET code inside the package) threw ${exType}: ${esc(exMsg)} Windows Installer rolled the ${op} back.${wrapper}`;
      F.push({
        severity: 'bad', headline: `Managed custom action ${f.name} threw ${exType.split('.').pop()}`,
        body: `${esc(exMsg)}` + (frame ? ` It was thrown in ${frame}, the vendor's code.` : '') +
          (f.data ? ` The action was given: ${esc(f.data)}.` : '') +
          ' The full stack is below. The message usually names what to fix on the machine (a missing file, a service, a registry key, an account).',
      });
      F.push({ severity: 'info', headline: code === undefined ? 'No exit code in this text' : `What ${code} means`, body: generic });
      return;
    }
  }

  if (f && f.isCustomAction) {
    // The command's own exit (QuietExec) beats the action's 1603; an EXE action's exit is the action's.
    const ex = f.commandExit ?? f.caExitCode;
    const exText = ex !== undefined && WIN32[ex] && ex !== 1603
      ? ` If ${ex} is a Windows error code it means: ${WIN32[ex]} Many programs use their own codes, so check the vendor's list too.` : '';
    const how = f.command ? `It ran: ${f.command}` : f.entryPoint ? `It is a DLL custom action (entry point ${f.entryPoint}).` : '';
    const ran = f.commandExit !== undefined ? `ran a command that exited with ${fmtCode(f.commandExit)}` : `failed${ex !== undefined ? ` with exit code ${fmtCode(ex)}` : ''}`;
    a.summary = `The custom action ${f.name} ${ran}, and Windows Installer rolled the ${op} back.${wrapper}`;
    F.push({
      severity: 'bad', headline: `Custom action ${f.name} failed${ex !== undefined ? ' (exit ' + ex + ')' : ''}`,
      body: [
        'A custom action is code the vendor added to the install: a program, a script or a DLL function. Windows Installer ran it and it reported failure.',
        how, exText,
        f.output.length ? 'What it printed is below; that is usually the real reason.' :
          'It printed nothing to this log. If it is a program, look for its own log (often in %TEMP% or C:\\Windows\\Temp).',
        f.reportedBy !== f.name ? `(Windows Installer logged "Return value 3" for ${f.reportedBy}, because ${f.name} runs inside it as a deferred action.)` : '',
      ].filter(Boolean).join(' '),
    });
    if (f.entryPoint && /QuietExec/i.test(f.entryPoint)) F.push({
      severity: 'info', headline: 'WixQuietExec',
      body: 'This is the WiX helper that runs a command line silently. The command it ran and that command\'s output are in the lines below; the "Error 0x8007..." it logs is the command\'s exit code as an HRESULT (0x80070003 = exit code 3).',
    });
  } else if (f && d.serviceErrors.length) {
    a.summary = `${esc(d.serviceErrors[0].replace(/\s+Verify that.*$/, ''))} Windows Installer rolled the ${op} back.`;
  } else if (f) {
    const err = d.errors.find(e => e.code !== 1708 && e.line <= f.line);
    a.summary = `The standard action ${f.name} failed${err ? ` with Error ${err.code}: ${esc(err.text)}` : ''}, and the ${op} was rolled back.`;
  } else {
    a.summary = `${generic}`;
  }

  if (d.serviceErrors.length) F.push({
    severity: 'bad', headline: 'A service did not start',
    body: `"${esc(d.serviceErrors[0])}" Windows Installer waits for the service it installs to reach Running. If the program is not a real service, its account lacks "Log on as a service", a dependency is missing, or it crashes at start, the install fails here. The System event log (Service Control Manager, events 7000, 7009, 7023, 7038) names the reason.`,
  });

  const userErrors = d.errors.filter(e => e.code !== 1708);
  for (const e of userErrors.slice(0, 4)) {
    if (e.code >= 1920 && e.code <= 1923) continue;
    if (e.code >= 1720 && e.code <= 1723 && f?.isCustomAction) continue;
    const meaning = ERROR_MESSAGES[e.code];
    F.push({ severity: 'bad', headline: `Error ${e.code}`, body: (meaning ? meaning + ' ' : '') + `Logged: "${esc(e.text)}" (line ${e.line})` });
  }
  if (d.inUse.length) F.push({
    severity: 'warn', headline: 'Files were in use',
    body: `${d.inUse.map(u => u.process + (u.pid ? ' (' + u.pid + ')' : '')).slice(0, 5).join(', ')} held files the install needed. Close them, or deploy when nobody is signed in.`,
  });
  if (d.failedInOldRemoval) {
    a.summary = `While removing the old version (${d.upgradeOf}) during the upgrade: ` + a.summary.charAt(0).toLowerCase() + a.summary.slice(1);
    F.unshift({
      severity: 'bad', headline: 'It failed removing the OLD version',
      body: 'This was a major upgrade, and the failure is inside the nested uninstall of the version already on the machine, not in the new package. ' +
        'Fixes go to the old install: close what holds its files, repair it, or remove it first. The old version is still installed.',
    });
  }
  F.push({ severity: 'info', headline: code === undefined ? 'No exit code in this text' : `What ${code} means`, body: generic });
}

// ---------------------------------------------------------------------------------------------
// Burn bootstrapper logs: the .exe wrapper (WiX Burn) around a chain of MSIs. The answer is which
// package failed, with what code, and where ITS log is.

function analyzeBurn(all: string[]): MsiAnalysis {
  const b: BurnSummary = { engine: '', packages: [], errors: [] };
  const logs = new Map<string, string>();
  const tail = (l: string) => l.replace(/^\[[^\]]*\]\[[^\]]*\]/, '');
  all.forEach((l, i) => {
    const t = tail(l);
    let x;
    if ((x = /^i001: (Burn v[\d.]+)/.exec(t))) b.engine = x[1];
    else if ((x = /^i009: Command Line: '(.*)'$/.exec(t))) b.commandLine = x[1];
    else if ((x = /Setting string variable 'WixBundleName' to value '(.*)'/.exec(t))) b.bundle = x[1];
    else if ((x = /Initializing string variable 'BUNDLEMONIKER' to value '(.*)'/.exec(t))) b.bundle ??= x[1];
    else if ((x = /Setting string variable 'WixBundleLog_(.+?)' to value '(.*)'/.exec(t))) logs.set(x[1], x[2]);
    else if ((x = /^i319: Applied execute package: (.+?), result: (0x[0-9a-fA-F]+), restart: (\w+)/.exec(t))) {
      const code = parseInt(x[2], 16);
      b.packages.push({ id: x[1], action: 'execute', result: x[2], resultCode: code });
    } else if ((x = /^i399: Apply complete, result: (0x[0-9a-fA-F]+)/.exec(t))) { b.result = x[1]; b.resultCode = parseInt(x[1], 16); }
    else if (/^e\d{3}:/.test(t)) { if (!b.errors.some(e => e.text === t)) b.errors.push({ line: i + 1, text: t }); }
  });
  for (const p of b.packages) {
    const lg = logs.get(p.id) ?? [...logs.entries()].find(([k]) => p.id.startsWith(k) || k.startsWith(p.id))?.[1];
    if (lg) p.log = lg;
  }
  const failedPkg = b.packages.find(p => p.resultCode !== 0);
  const rc = b.resultCode ?? 0;
  const w32 = hresultToWin32(rc);
  const meaning = w32 !== undefined ? (EXIT_CODES[w32] ?? WIN32[w32]) : undefined;
  const ok = rc === 0;
  const a: MsiAnalysis = {
    kind: 'burn', sessions: [], focus: 0, lineCount: all.length,
    verdict: b.resultCode === undefined ? 'unknown' : ok ? 'success' : rc === 0x80070bc2 || w32 === 3010 ? 'reboot' : 'failed',
    headline: '', summary: '', findings: [], errors: [], inUse: [], properties: [], notable: [], slowest: [], context: [],
    burn: b,
  };
  if (b.resultCode === undefined) {
    a.headline = 'The bundle log ends without a result';
    a.summary = 'No "Apply complete" line. The bootstrapper was still running, was killed, or this run only detected and planned.';
  } else if (ok || a.verdict === 'reboot') {
    a.headline = a.verdict === 'reboot' ? 'The bundle worked, and needs a reboot' : 'The bundle worked';
    a.summary = `${b.bundle ?? 'The bundle'} applied ${b.packages.length} package(s).`;
  } else {
    a.headline = `The bundle failed with ${b.result}`;
    a.summary = `${b.bundle ?? 'The bundle'} failed` + (failedPkg ? ` at package ${failedPkg.id} (${failedPkg.result}` +
      (hresultToWin32(failedPkg.resultCode!) !== undefined ? ` = MSI exit code ${hresultToWin32(failedPkg.resultCode!)}` : '') + ')' : '') +
      '. ' + (meaning ?? '');
    a.findings.push({
      severity: 'bad', headline: 'This is the bootstrapper log, not the MSI log',
      body: 'A setup .exe built with WiX Burn installs a chain of MSIs and writes one log for itself plus one per package. The reason a package failed is in that package\'s own log' +
        (failedPkg?.log ? `: ${failedPkg.log}` : ', named after this file with _000_, _001_ ... and the package name appended.') +
        ' Drop that file here for the detail.',
    });
    if (w32 === 1618) a.findings.push({
      severity: 'bad', headline: 'Another install was running',
      body: '0x80070652 is 1618: Windows Installer was busy with another install. Burn retried and gave up. Retry when Windows Update or the other deployment has finished.',
    });
    if (w32 === 1603) a.findings.push({
      severity: 'info', headline: '0x80070643 is 1603',
      body: 'The package\'s own log will name the action that failed.',
    });
  }
  return a;
}

// ---------------------------------------------------------------------------------------------
// ConfigMgr AppEnforce.log (CMTrace format). ConfigMgr only sees what it ran and the exit code; the
// reason lives in the installer's own log. So the answer is: which deployment failed, what ran, the
// code, and where to look next. Built on a real AppEnforce.log from a ConfigMgr fleet (2026-11-24).

type CmMsg = { line: number; text: string; component: string; when?: string };

/** CMTrace messages, multi-line ones joined, each with the line it starts on. */
function cmMessages(all: string[]): CmMsg[] {
  const out: CmMsg[] = [];
  let buf: string[] | null = null, start = 0;
  all.forEach((raw, i) => {
    const l = i === 0 ? raw.replace(/^\uFEFF/, '') : raw;
    const st = l.indexOf('<![LOG[');
    if (st >= 0) { buf = [l.slice(st + 7)]; start = i + 1; }
    else if (buf) buf.push(l);
    else return;
    const joined = buf.join('\n');
    const end = /\]LOG\]!><time="([^"]*)" date="([^"]*)" component="([^"]*)"/.exec(joined);
    if (!end) return;
    const t = end[1].replace(/[+-]\d+$/, '').replace(/\.\d+$/, '');
    out.push({ line: start, text: joined.slice(0, end.index), component: end[3], when: `${end[2]} ${t}` });
    buf = null;
  });
  return out;
}

function analyzeCmTrace(all: string[]): MsiAnalysis {
  const msgs = cmMessages(all);
  const comps = new Map<string, number>();
  for (const m of msgs) comps.set(m.component, (comps.get(m.component) ?? 0) + 1);
  const top = [...comps.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown';
  if (!comps.has('AppEnforce')) {
    const u = unknown(all.length);
    u.headline = `This is a ConfigMgr or Intune log (${top}), not a Windows Installer log`;
    u.summary = 'This page reads verbose MSI logs, WiX setup logs and ConfigMgr\'s AppEnforce.log (C:\\Windows\\CCM\\Logs). ' +
      'For an app install, AppEnforce.log names the command line and its exit code.';
    return u;
  }

  const runs: AppEnforceRun[] = [];
  const ctx = new Map<AppEnforceRun, CmMsg[]>();
  let cur: AppEnforceRun | null = null;
  for (const m of msgs) {
    if (m.component !== 'AppEnforce') continue;
    const t = m.text.trim();
    let x;
    if ((x = /^\+\+\+ Starting (Install|Uninstall) enforcement for App DT "(.*?)" ApplicationDeliveryType.*?ContentPath - (.*?), Execution Context - (\w+)/.exec(t))) {
      cur = { app: x[2], op: x[1] as 'Install' | 'Uninstall', line: m.line, when: m.when, contentPath: x[3], context: x[4], result: 'unknown' };
      runs.push(cur); ctx.set(cur, []);
    }
    if (!cur) continue;
    ctx.get(cur)!.push(m);
    const ran = cur.command !== undefined || cur.hresult !== undefined;
    if (/^\+\+\+ (?:Discovered application|MSI application discovered|Application discovered)/.test(t)) {
      if (ran) cur.detectedAfter = true; else cur.detectedBefore = true;
    } else if (/^\+\+\+ (?:Application not discovered|MSI application not discovered)/.test(t)) {
      if (ran) cur.detectedAfter = false; else cur.detectedBefore = false;
    } else if ((x = /^Executing Command line: (.*?)(?: with (\w+) context)?$/.exec(t))) cur.command = x[1];
    // Some runs (Patch My PC's ScriptRunner in the real log) log only the prepared line, never "Executing".
    else if ((x = /^Prepared command line: (.*)$/.exec(t))) cur.command ??= x[1];
    else if ((x = /^Process \d+ terminated with exitcode: (-?\d+)/.exec(t))) cur.exitCode = Number(x[1]);
    else if ((x = /^Matched exit code -?\d+ to a (\w+) entry/.exec(t))) cur.matched = x[1];
    else if (/^Unmatched exit code \(-?\d+\) is considered an execution failure/.test(t)) cur.matched = 'Unmatched';
    else if ((x = /^Installation failure, error code = (0x[0-9a-fA-F]+)/.exec(t))) cur.hresult = x[1];
    else if ((x = /^\+\+\+ Enforce completed for .*Returning: ([0-9a-fA-F]{8})/.exec(t))) cur.hresult ??= '0x' + x[1];
    else if ((x = /^\+\+\+\+\+\+ App enforcement completed \((\d+) seconds\)/.exec(t))) cur.seconds = Number(x[1]);
  }

  for (const r of runs) {
    const ran = r.command !== undefined || r.hresult !== undefined;
    if (!ran && r.detectedBefore) r.result = 'already';
    else if (r.hresult && parseInt(r.hresult, 16) !== 0) r.result = 'failed';
    else if (r.matched === 'Unmatched' || r.matched === 'Failure') r.result = 'failed';
    else if (r.matched === 'SoftReboot' || r.matched === 'HardReboot') r.result = r.detectedAfter === false ? 'not-detected' : 'reboot';
    else if (r.matched === 'Success' || r.exitCode === 0) r.result = r.detectedAfter === false ? 'not-detected' : r.detectedAfter ? 'success' : 'unknown';
  }

  const bad = (r: AppEnforceRun) => r.result === 'failed' || r.result === 'not-detected';
  let focusRun = [...runs].reverse().find(bad) ?? runs[runs.length - 1];
  const a: MsiAnalysis = {
    kind: 'appenforce', sessions: [], focus: 0, lineCount: all.length, verdict: 'unknown',
    headline: '', summary: '', findings: [], errors: [], inUse: [], properties: [], notable: [], slowest: [], context: [],
    appEnforce: runs,
  };
  if (!focusRun) {
    a.headline = 'AppEnforce.log with no app enforcement in it';
    a.summary = 'No "Starting Install enforcement" line. ConfigMgr has not tried to install or remove an application on this machine since the log rolled over (it keeps the previous one as AppEnforce.lo_).';
    return a;
  }
  const r = focusRun;
  a.context = ctx.get(r)!.map(m => ({ line: m.line, text: m.text.trim().split('\n')[0] }));
  const isMsi = !!r.command && /msiexec(\.exe)?"?\s/i.test(r.command);
  const logArg = r.command ? /\s\/l[a-z*+!]*\s+("[^"]+"|\S+)/i.exec(r.command)?.[1]?.replace(/"/g, '') : undefined;
  const meaning = r.exitCode !== undefined ? (WIN32[r.exitCode] ?? EXIT_CODES[r.exitCode]) : undefined;
  const hw = r.hresult ? hresultToWin32(parseInt(r.hresult, 16)) : undefined;
  const failures = runs.filter(bad).length;

  if (r.result === 'failed') {
    a.verdict = 'failed';
    a.headline = r.hresult ? `${r.app} failed with ${r.hresult}` : `${r.app} failed with exit code ${r.exitCode}`;
    a.summary = r.hresult
      ? `ConfigMgr's ${r.op.toLowerCase()} returned ${r.hresult}` + (hw !== undefined ? ` (Win32 ${hw}: ${WIN32[hw] ?? 'see the code'})` : '') + '.'
      : `ConfigMgr ran ${r.command ?? 'the command line'} and it exited with ${r.exitCode}, which the deployment type does not list as success. ` + (meaning ?? '');
  } else if (r.result === 'not-detected') {
    a.verdict = 'failed';
    a.headline = `${r.app} ran and exited ${r.exitCode}, but ConfigMgr still can't detect it`;
    a.summary = 'The command reported success, then the detection method found nothing, so Software Center shows a failure (0x87D00324, "the application was not detected after installation completed"). ' +
      'Either the install did not do what the detection rule looks for, or the rule checks the wrong thing (a version that changed, a 32-bit path on 64-bit Windows, a per-user location for a system install).';
  } else if (r.result === 'reboot') {
    a.verdict = 'reboot';
    a.headline = `${r.app} installed and needs a restart`;
    a.summary = `Exit code ${r.exitCode} matched a ${r.matched} entry in the deployment type's return codes.`;
  } else if (r.result === 'success') {
    a.verdict = 'success';
    a.headline = `${r.app} installed`;
    a.summary = `Exit code ${r.exitCode}, and the detection method found the app afterwards.`;
  } else if (r.result === 'already') {
    a.verdict = 'success';
    a.headline = `${r.app} was already installed`;
    a.summary = 'The detection method found it before anything ran, so ConfigMgr ran nothing.';
  } else {
    a.headline = `${r.app}: the log ends before a result`;
    a.summary = 'No exit code after the command line. The install was still running, or the client restarted mid-install.';
  }
  if (failures > 1 || runs.length > 1)
    a.summary += ` This log holds ${runs.length} enforcement attempt(s), ${failures} of them failed; the table below lists them all.`;

  if (r.command) a.findings.push({
    severity: 'info', headline: 'What ConfigMgr ran',
    body: `${r.command} (${r.context === 'Any' ? 'install for system if resource is device' : r.context?.toLowerCase() ?? 'system'} context, from ${r.contentPath ?? 'the ccmcache folder'})` +
      (r.when ? `, ${r.when}` : '') + (r.seconds !== undefined ? `, ${r.seconds} s` : '') + '.',
  });
  if (r.result === 'failed' && isMsi) a.findings.push(logArg
    ? { severity: 'bad', headline: 'The MSI log is named on the command line', body: `Windows Installer wrote it to ${logArg}. Drop that file here for the action that failed.` }
    : { severity: 'bad', headline: 'No MSI log was asked for',
        body: 'The command line has no /l*v, so Windows Installer wrote no log unless the logging policy is on (then it is a MSI*.LOG in C:\\Windows\\Temp). ' +
          'Add /l*v "C:\\Windows\\Temp\\<app>.log" to the deployment type\'s command line, run it again and drop that log here. ' +
          'The Application event log (source MsiInstaller, event 11708 or 1033) also records the product and the code.' });
  else if (r.result === 'failed' && r.command && /\.(bat|cmd|ps1)"?(\s|$)/i.test(r.command)) a.findings.push({
    severity: 'bad', headline: 'The exit code came from a script',
    body: 'A script returns whatever its last command or its exit statement set. ConfigMgr does not capture its output, so make the script write its own log (for example to C:\\Windows\\Temp) and check that.',
  });
  else if (r.result === 'failed' && r.command && !r.hresult) a.findings.push({
    severity: 'bad', headline: 'The reason is in the installer\'s own log',
    body: 'ConfigMgr only sees the exit code. A setup .exe or a wrapper (PSADT, Patch My PC, a vendor bootstrapper) writes its own log, usually to C:\\Windows\\Temp or a folder named in its documentation. That log names what failed.',
  });
  if (r.hresult && hw === 183) a.findings.push({
    severity: 'bad', headline: '0x800700B7: the package is already there in another form',
    body: 'For an MSIX or AppX deployment this usually means the same package is already installed or staged (often per user, or a newer version), so the system-wide install cannot add it. Check Get-AppxPackage -AllUsers for the package name.',
  });
  return a;
}

// ---------------------------------------------------------------------------------------------
// For a file nothing above recognizes: pull out what usually helps in any install or deployment log.

export type Scavenged = {
  codes: { line: number; code: string; meaning?: string; text: string }[];
  failures: { line: number; text: string }[];
  logs: string[];
  commands: { line: number; text: string }[];
};

export function scavengeLog(text: string): Scavenged {
  const all = text.replace(/\r\n?/g, '\n').split('\n');
  const s: Scavenged = { codes: [], failures: [], logs: [], commands: [] };
  const seen = new Set<string>();
  const clip = (l: string) => l.replace(/<!\[LOG\[|\]LOG\]!>.*$/g, '').trim().slice(0, 300);
  all.forEach((raw, i) => {
    const l = clip(raw);
    if (!l) return;
    let x;
    const rx = /(?:exit ?code|exitcode|return(?:ed)? (?:value|code)|error code|result)\s*[:=]?\s*\(?(0x[0-9a-f]{8}|-?\d{1,10})\b/ig;
    while ((x = rx.exec(l))) {
      const c = x[1];
      const n = c.startsWith('0x') ? parseInt(c, 16) : Number(c);
      if (n === 0) continue;
      const w = c.startsWith('0x') ? hresultToWin32(n) : n;
      const key = c + '|' + l;
      if (s.codes.length < 40 && !seen.has(key)) {
        seen.add(key);
        s.codes.push({ line: i + 1, code: c, meaning: w !== undefined ? (WIN32[w] ?? EXIT_CODES[w]) : undefined, text: l });
      }
    }
    if (s.failures.length < 40 && /\b(error|fail(?:ed|ure|s)?|exception|denied|cannot|can't|unable|timed? ?out|not found)\b/i.test(l) &&
        !/\b0 errors?\b|no errors?\b|errorlevel 0\b/i.test(l)) s.failures.push({ line: i + 1, text: l });
    const lg = l.match(/(?:[A-Za-z]:\\|%\w+%\\|\\\\)[^"'<>|*?\r\n]*?\.log\b/gi);
    if (lg) for (const p of lg) if (!s.logs.includes(p) && s.logs.length < 20) s.logs.push(p);
    if (s.commands.length < 20 && /\b(msiexec(?:\.exe)?|setup\.exe|powershell(?:\.exe)?|cmd(?:\.exe)? \/c)\b.*\s\/\w/i.test(l)) s.commands.push({ line: i + 1, text: l });
  });
  return s;
}
