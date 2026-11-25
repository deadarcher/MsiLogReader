# MSI Log Reader

**Drop a verbose MSI log in your browser and get the step that failed.** No upload, no signup, no agent. The log is read **entirely in your browser** and never leaves your machine.

**Use it now (hosted):** https://getrff.com/msi-log/

---

## What it does

Windows Installer logs run from a few thousand lines to several hundred thousand. The usual advice is to search for "Return value 3", and for a deferred custom action the line it finds is InstallFinalize. The custom action that failed, its exit code and what it printed sit a few hundred lines above. MSI Log Reader finds them and says what they mean:

- **The failing step**, including the deferred custom action that ran inside InstallFinalize.
- **The custom action's own result:** the command line and exit code of an EXE action, the command and exit code behind a WixQuietExec action, and the innermost exception from a .NET (DTF) custom action.
- **Error messages in context:** 1306 and 1603 file locks, 1920 services, 1722 programs, launch conditions and blocked downgrades.
- **Upgrades:** whether the failure happened while removing the OLD version inside a major upgrade.
- **WiX Burn bundles:** which package in the chain failed, with its code, and where that package's own log is.
- **ConfigMgr AppEnforce.log:** every deployment in the log with its command line and exit code (or MSIX HRESULT), the "exit 0 but not detected" case, and where the real installer log is.
- **Any other log:** a "Look for anything useful anyway" button that pulls out exit and error codes, failure lines, other log paths and command lines.

## Make a verbose log

```
msiexec /i "package.msi" /qn /l*v "C:\Windows\Temp\install.log"
```

Deployment tools usually keep one already. A user install writes `MSI*.LOG` to `%TEMP%`; SYSTEM installs (Intune, ConfigMgr, GPO, most RMMs) write to `C:\Windows\Temp`.

## Checked against real logs

Every rule is pinned by a real log in [`scripts/fixtures/msi-log`](scripts/fixtures/msi-log): lab packages built to fail one way each (a deferred EXE custom action that exits 5, a WixQuietExec script that exits 3, a service that never starts, a launch condition, a blocked downgrade, a file held open during an upgrade, a .NET custom action that throws), real installs of Firefox and the .NET SDK, and a ConfigMgr AppEnforce.log with its customer names removed.

```
npm install
npm run check   # every fixture: verdict, exit code, failing action
npm run build   # static site in dist/
```

## Run it yourself

The build is plain static files. Serve `dist/` from anywhere (GitHub Pages, Cloudflare Pages, IIS, `npx serve dist`); there is no server code.

## Wrong answer?

[Open an issue](https://github.com/deadarcher/MsiLogReader/issues/new) with the verdict it gave and what really happened. Please don't attach the log unless you have removed machine and user names from it. The hosted page also has a feedback form that sends only your note and the verdict summary.

Built by [RFF](https://getrff.com), which deploys MSIs across a fleet and keeps the verbose log from every install. MIT licensed.
