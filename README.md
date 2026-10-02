# VM Patch Agent

An agent that runs on each Windows VM hosted on VMware vCenter or ESXi. When a new vulnerability is published, it works out whether **its own VM** is affected and what the fix is. It shows that on a local dashboard, and takes a vSphere snapshot once an administrator approves a fix.

> **Status: not production-ready, and not yet a patching tool.**
> Detection, prioritisation, approval, snapshots and auditing are built and tested (84 automated tests).
> **Installing the approved fixes (M4) is not built yet.** The agent has **never been run on Windows or against a real vCenter**: all testing was on macOS, with simulated Windows output and simulated snapshots.
> See [What is not done](#what-is-not-done) before deploying anywhere.

---

## Contents

- [What it does today](#what-it-does-today)
- [What is not done](#what-is-not-done)
- [How it works](#how-it-works)
- [Deciding what is vulnerable](#deciding-what-is-vulnerable)
- [Approvals, snapshots and reverting](#approvals-snapshots-and-reverting)
- [Security model](#security-model)
- [Installing on a Windows VM (manual, for a test VM)](#installing-on-a-windows-vm-manual-for-a-test-vm)
- [Configuration reference](#configuration-reference)
- [Developing](#developing)
- [Design decisions](#design-decisions)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)

---

## What it does today

| Milestone | State | What it covers |
|---|---|---|
| **M1** Inventory + dashboard | Done | Scans the VM every hour: OS build, installed hotfixes, missing updates (from the built-in Windows Update Agent) and installed programs. |
| **M2** Detect & report | Done | Pulls the MSRC, NVD and CISA KEV feeds every 2 hours. Matches CVEs to this VM and proposes a ranked list of fixes, exploited-in-the-wild first. |
| **M3** Approval + snapshot | Done | Admins sign in with Windows credentials and tick fixes. The agent then takes a vSphere snapshot. Everything is recorded in an audit log and the Windows Event Log. |
| **M4** Install + verify | **Not started** | Install the approved KBs and app upgrades, handle restarts, and verify each fix landed. |
| **M5** Rollout | **Not started** | Windows-service installer, locking down folder permissions, rolling out to the 10 VMs. |

**The only change the agent can make to a VM today is a vSphere snapshot**, and only after an approval. All PowerShell it runs is read-only.

The fix list was checked against the **live** MSRC, NVD and CISA feeds using a simulated Windows Server 2022 VM (build 20348.2700, 7-Zip 24.08, Chrome 128). The result was 6 ranked fixes. Two of them:
- Windows cumulative update KB5122882 (1,648 CVEs, 13 in CISA KEV).
- 7-Zip 24.08 → 26.02, which includes CVE-2025-0411 (in CISA KEV).

## What is not done

Read this before putting the agent on any VM you care about.

1. **No installs (M4).** Approved jobs stop at *"Snapshot taken, awaiting install"*. Patching is still manual: install the KB or upgrade the app yourself, then cancel the job and delete its snapshot.
2. **Never run on Windows.** These pieces are untested on a real machine:
   - The three PowerShell scripts.
   - Windows sign-in (`LogonUser` through JNA).
   - DPAPI password decryption.
   - Event Log writing.
   - govc against vCenter or ESXi.

   On macOS they were exercised with stubs and canned output. Expect fixes to be needed on the first real run.
3. **No installer (M5).** Running it as a Windows service, locking down folder permissions and registering the Event Log source are manual steps, described below.
4. **winget is unproven for app upgrades.** It is often missing or broken when run as the SYSTEM account, and Windows Server 2019/2022 don't include it. This must be tested on your OS versions before M4 is built on it; Chocolatey or vendor installers are the fallback.
5. **Numbers to sanity-check on a real VM.** Microsoft's recent monthly documents list far more Server 2022 CVEs than older months (643 in September 2026, against roughly 60–120). The agent counts exactly what Microsoft publishes. A **fully patched VM should show zero Windows findings**; that is the first thing to confirm.
6. **One VM at a time.** There is no central server, by design. Ten VMs means ten dashboards and ten separate approvals.

## How it works

One self-contained Java process runs on each VM, as a Windows service under LocalSystem:

```
 MSRC CVRF ─┐
 NVD 2.0  ──┼──>  FeedWatcher (2h) ──┐
 CISA KEV ──┘                        │
                                     ▼
 PowerShell (read-only) ──> InventoryCollector (1h) ──> ExposureMatcher ──> fix plan
                                                                              │
 Admin (RDP) ── http://localhost:8090 ── Windows sign-in ── ticks fixes ── Approve
                                                                              │
                                    JobService ── govc ──> vCenter/ESXi: snapshot of this VM
                                         │
                                         └──> AuditLog ──> H2 database + Windows Event Log
```

- **Storage:** an embedded H2 database under `C:\ProgramData\VmPatchAgent\db`, with the schema managed by Flyway.
- **PowerShell:** only scripts bundled inside the jar ever run. They are passed with `-EncodedCommand`, so no `.ps1` file on disk is executed.
- **Network:** outbound HTTPS to the three feeds, and to vCenter or ESXi for snapshots. Nothing listens on the network; the dashboard binds to `127.0.0.1`.

## Deciding what is vulnerable

| Source | What it answers | How it matches |
|---|---|---|
| **MSRC** CVRF API v3: the last 12 monthly documents | Which **Windows** CVEs are open | Each Microsoft fix states the Windows build that contains it, e.g. `10.0.20348.5622`. If this VM's `build.UBR` is lower, the CVE is open. This works even when WSUS hasn't approved the update. The newest cumulative update closes them all. |
| **Windows Update** scan on the VM | Which **other Microsoft** updates apply (.NET Framework, etc.) | Every security update the VM's own Windows Update scan offers becomes a fix, with the CVEs MSRC lists for that KB. |
| **NVD** CVE API 2.0 | **Third-party app** CVEs | Only for programs in the catalog (`agent.catalog.apps`). The installed version is compared with NVD's affected version ranges for that exact product, on Windows. |
| **CISA KEV** | Which CVEs are **exploited in the wild** | Moves the fix to the top, together with CVEs Microsoft marks "Exploited: Yes". |

Rules that keep the results honest:

- **The OS product is identified exactly.** Server Core and full-desktop installs are matched separately, and client SKUs by architecture. If MSRC has nothing for the VM's build, as happens with an out-of-support OS, the dashboard says so and doesn't report the VM as clean.
- **The cumulative-update note is checked.** If Windows Update offers a different cumulative update than the latest, the dashboard only says it covers the fixes when MSRC confirms it reaches the same build. Otherwise it says how many CVEs it leaves open, or that it can't be verified.
- **Apps are never guessed.** Programs not in the catalog show as *Not tracked*. Versions that can't be compared show as *Cannot assess*. Neither is ever reported as safe.
- **The MSRC index lags.** Its `/updates` list was missing 2026-Aug and 2026-Sep, so the agent also requests each recent month directly.
- **Feed traffic is kept small.** NVD is queried per catalogued product, all CVEs the first time and only changed ones after that. MSRC documents (about 20 MB each) are downloaded again only when Microsoft revises them.

**Ranking:** a fix with any exploited CVE (CISA KEV or Microsoft) comes first, then Critical (CVSS 9 or higher), then High or Important (CVSS 7 or higher), then the rest.

**App catalog (seeded):** 7-Zip, Google Chrome, Microsoft Edge, Mozilla Firefox, Firefox ESR, Notepad++, PuTTY, WinRAR and VMware Tools. To add a program, add an entry in `application.yml`. The `cpe` must be the exact NVD CPE vendor and product, with escapes, e.g. `cpe:2.3:a:notepad-plus-plus:notepad\+\+`.

## Approvals, snapshots and reverting

1. **Sign in** at `http://localhost:8090` on the VM, over RDP. Use a Windows account: `DOMAIN\user`, `user@domain`, or a local user.
   - Windows checks the password (`LogonUser`).
   - The account must be in the approver group: local Administrators by default, or a domain group set in `agent.security.approver-group-sid`.
   - After 5 failed sign-ins a name is refused for 5 minutes. Windows' own lockout policy applies too.
2. **Tick the fixes and click Approve.**
   - A fix that may restart the VM also needs **Allow restart** ticked.
   - If the fix list changed since the page loaded, the approval is refused, so an approval always matches what was on screen.
   - Only one job can be active at a time.
3. **The agent snapshots the VM** as `vpa-job-<id>`, disk-only and quiesced through VMware Tools/VSS. If the snapshot fails, the job fails and nothing else happens.
4. **The job waits** in *"Snapshot taken, awaiting install"* until M4 exists. The admin can **cancel** it and then **delete the snapshot**. Snapshots slow the VM's disk, so don't keep them for days.
5. **Revert from outside the VM.** The dashboard shows the exact vCenter steps and govc commands. When the VM comes back up, the agent sees a job still at its snapshot point and a boot time after the snapshot. It records that as `REVERT_DETECTED`.

**Audit trail:** these are all recorded, with the Windows account and time:
- sign-ins and refused sign-ins
- approvals, with the exact fixes, restart consent and CVE count
- snapshots taken, failed or deleted
- cancellations and detected reverts

They are shown on the dashboard and written to the Windows Application log under source `VmPatchAgent`. **Forward that log off the VM** with Windows Event Forwarding or a SIEM agent: a revert erases everything recorded on the VM after the snapshot, including the agent's own database.

## Security model

| Concern | Control |
|---|---|
| Network exposure | The dashboard binds to `127.0.0.1` only; admins reach it over RDP. |
| Malicious web page in the VM's browser | Requests whose `Host` is not a loopback name are refused (DNS rebinding), before any other check. State-changing requests need a same-origin `Origin` and a CSRF token. |
| Who may approve | Windows credentials plus membership of the approver group SID, on every page. Sessions expire after 15 minutes idle. |
| Tampering with scripts run as SYSTEM | Only scripts inside the jar run, passed with `-EncodedCommand`. Parameters go in environment variables, never into code. |
| vSphere credentials | A service account allowed only snapshot create/remove on this VM, with no revert permission. Its password is DPAPI-encrypted in a folder only Administrators and SYSTEM can read, and passed to govc in its environment, never on its command line. |
| Unsafe defaults | A missing reboot flag is treated as "may reboot". Approvals are refused when snapshots are unavailable. Demo sign-in refuses to start on Windows. |

Known limitation: DPAPI machine scope means any process running as an administrator on the VM can decrypt the vSphere password. The folder permissions are the real protection, so keep the vSphere role narrow.

## Installing on a Windows VM (manual, for a test VM)

Use a throwaway test VM cloned from your template first, never production. The installer (M5) does not exist yet, so these are the manual steps.

1. **Java 25** runtime on the VM. Build the jar with `./mvnw package` and copy `target/vm-patch-agent-0.1.0-SNAPSHOT.jar` over.
2. **Check the scripts by hand** from an elevated PowerShell. Each must print one line of JSON:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\system-info.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File .\wua-scan.ps1      # can take minutes
   powershell -NoProfile -ExecutionPolicy Bypass -File .\installed-apps.ps1
   ```
   The scripts are in `src/main/resources/scripts/`.
3. **Create the data folder** and lock it down to Administrators and SYSTEM:
   ```powershell
   $dir = 'C:\ProgramData\VmPatchAgent'
   New-Item -ItemType Directory -Force "$dir\secrets" | Out-Null
   icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
   ```
4. **vSphere:**
   - In vCenter, create a role allowing only *Virtual machine > Snapshot management > Create snapshot* and *Remove snapshot*. Grant it to a service account on this VM only.
   - Put `govc.exe` ([govmomi releases](https://github.com/vmware/govmomi/releases)) at `C:\Program Files\VmPatchAgent\govc.exe`.
   - Store the password:
     ```powershell
     Add-Type -AssemblyName System.Security
     $secure = Read-Host 'vSphere service account password' -AsSecureString
     $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
     $blob = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($plain), $null, 'LocalMachine')
     [IO.File]::WriteAllBytes('C:\ProgramData\VmPatchAgent\secrets\vsphere-password.dpapi', $blob)
     ```
   - Set environment variables:
     - `VPA_VSPHERE_URL`, e.g. `https://vcenter.corp.example/sdk`
     - `VPA_VSPHERE_USER`
     - `VPA_VSPHERE_VM`: this VM's inventory path, e.g. `/DC1/vm/Apps/APP01`, or `/ha-datacenter/vm/APP01` on standalone ESXi
5. **Event Log source:** `New-EventLog -LogName Application -Source VmPatchAgent`.
6. **Optional NVD API key:** `VPA_NVD_API_KEY`. Without one, NVD allows one request every 6 seconds, and the first sync takes a few minutes.
7. **Run** elevated: `java -jar vm-patch-agent-0.1.0-SNAPSHOT.jar`. Open `http://localhost:8090` on the VM.
   - The first Windows Update scan and the first feed sync can each take several minutes.
   - Until vSphere is configured, the dashboard shows findings but refuses approvals and says why.

**What to check on that test VM:**
- The OS build and KBs match what Windows Settings shows.
- A fully patched VM shows **zero** Windows findings.
- You can sign in with an admin account; a non-admin account is refused.
- Approving creates the snapshot in vCenter; deleting it removes it.
- Entries appear in the Application log.

## Configuration reference

Everything is in `src/main/resources/application.yml`. The common overrides are environment variables:

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `server.port` | `PORT` | `8090` | Dashboard port (always on 127.0.0.1) |
| `agent.data-dir` | `VPA_DATA_DIR` | `C:/ProgramData/VmPatchAgent` | Database, secrets, state |
| `agent.scripts.powershell-path` | `VPA_POWERSHELL` | Windows PowerShell 5.1 | |
| `agent.inventory.refresh-interval` | | `1h` | How often the VM is rescanned |
| `agent.feeds.refresh-interval` | | `2h` | How often feeds are checked |
| `agent.feeds.msrc.lookback-months` | | `12` | MSRC monthly documents kept |
| `agent.feeds.nvd.api-key` | `VPA_NVD_API_KEY` | none | Faster NVD sync |
| `agent.security.approver-group-sid` | | `S-1-5-32-544` | Who may sign in and approve (default: Administrators) |
| `agent.security.max-failed-sign-ins` / `lockout` | | `5` / `5m` | Sign-in throttling |
| `agent.vsphere.mode` | | `govc` | `govc`, `fake` (demo only) or `disabled` (approvals refused) |
| `agent.vsphere.url` / `username` / `vm` | `VPA_VSPHERE_URL` / `_USER` / `_VM` | none | Snapshot target |
| `agent.vsphere.govc-path` | `VPA_GOVC` | `C:/Program Files/VmPatchAgent/govc.exe` | |
| `agent.vsphere.quiesce` | | `true` | VSS-quiesced snapshot |
| `agent.vsphere.tls-ca-certs` / `insecure` | | none / `false` | vCenter certificate trust |
| `agent.catalog.apps` | | 9 apps | Third-party programs assessed via NVD |

## Developing

Requirements: Java 25. Maven comes through `./mvnw`. No Docker, Windows or network access is needed for the tests.

```bash
./mvnw test                                   # 84 tests
SPRING_PROFILES_ACTIVE=demo PORT=18090 ./mvnw spring-boot:run
```

The **demo profile** runs the whole thing on macOS or Linux:
- A canned VM inventory (`src/main/resources/demo/`).
- **Live** feeds.
- Simulated snapshots.
- Demo sign-ins: `admin`/`admin` is an approver, `viewer`/`viewer` is refused.
- Data under `target/demo-data`.

The demo authenticator refuses to start on Windows.

**What the tests cover:**
- Version and CPE range logic.
- MSRC matching against a trimmed copy of the real September 2026 document.
- The full pipeline from feeds to fix plan, with the three feeds served by a local HTTP server from real excerpts. This includes encoding of `notepad\+\+` and incremental re-syncs.
- The cumulative-update note rules.
- Sign-in, the approver group, lockout and CSRF.
- The job lifecycle: restart consent, one active job, snapshot failure, cancel and delete, and revert detection.
- govc arguments, and that the password never appears on the command line, using a stub executable.
- PowerShell process handling, using a stub executable.

## Design decisions

- **A standalone agent on each VM**, chosen over a central server. Simple to deploy and no central point of failure. The cost: no fleet view, and one approval per VM.
- **Matching is deterministic.** No language model decides what gets installed. Every finding can be traced to an MSRC fixed build, an NVD version range or a Windows Update offer.
- **The Windows build is the source of truth for OS CVEs.** It is exact, it works with WSUS, and cumulative updates make "newest CU closes all" correct.
- **Windows-credential form sign-in, not single sign-on.** The usual Windows SSO library (Waffle) supports Spring Security 6 only, and Spring Boot 4 uses 7.
- **Disk-only, quiesced snapshots.** A memory snapshot would resume the agent frozen in the middle of its own govc call.
- **No revert from inside the VM.** Reverting a disk-only snapshot powers the VM off, with nothing left on it to power it back on, and erases the agent's record of the revert. Admins revert from vCenter, and the agent detects the revert afterwards. This also keeps revert permission out of the agent's vSphere role.

## Project layout

```
src/main/java/com/sandeeprathore/vmpatchagent/
  inventory/   scans the VM through the bundled scripts; stores snapshots of the inventory
  script/      runs bundled PowerShell (encoded command, env-var parameters); demo runner
  os/          process runner shared by PowerShell and govc (timeouts, kill tree, stderr)
  feed/        MSRC, NVD and CISA KEV clients, sync logic and storage; FeedWatcher schedule
  match/       versions, CPE ranges, app catalog, ExposureMatcher (the fix plan)
  security/    Windows-credential sign-in, approver group, throttling
  job/         approvals, snapshot step, cancel/delete, revert detection
  vsphere/     SnapshotService: govc, fake, disabled; DPAPI password source
  audit/       audit log (database + Windows Event Log)
  web/         dashboard, sign-in page, localhost-only filter
src/main/resources/
  scripts/     the only PowerShell the agent runs (read-only)
  db/migration Flyway schema
  demo/        canned inventory for the demo profile
  templates/, static/   dashboard UI
```

## Roadmap

1. **Test on a Windows VM.** Run the scripts, sign-in, DPAPI, Event Log and govc on a real machine, and fix what breaks. This comes before any new feature.
2. **winget spike.** Run winget as SYSTEM on your Windows Server versions; decide between winget, Chocolatey and vendor installers.
3. **M4, install and verify:**
   - Check that the VM hasn't changed since approval (compare the OS build).
   - Install exactly the approved KBs through Windows Update, and run the app upgrades.
   - Restart only if allowed, resuming after the restart.
   - Rescan and confirm each fix landed, and run health checks.
   - On failure, mark the job failed and show the revert steps.
4. **M5, rollout:**
   - An installer that runs the agent as a service (WinSW), sets folder permissions, stores the secret and registers the Event Log source.
   - Bundle govc and pin its version.
   - Roll out to 2 non-critical VMs, then the rest of the 10.
5. **Later, if needed:** a read-only fleet view across the VMs. Sign-in by group name rather than SID.
