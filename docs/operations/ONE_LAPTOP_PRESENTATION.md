# RAVEN-X one-laptop presentation — October 15, 2026

Use the HP Omen alone. The installed backend serves the built React frontend,
so no `npm` process or college LAN address is needed. The local certificate
covers `127.0.0.1`, and the public CA is trusted in this Windows user's root
store. Keep the server PowerShell window open throughout the demo.

## Before leaving

- Charge the Omen and keep its power adapter with you. Check that the local
  account can unlock Windows and that you remember the RAVEN-X administrator
  password. Do not put that password in a script or presentation.
- Rehearse the complete sequence below once. Check the Omen agent Scheduled
  Task, its approved portal identity, and the stored read-only assessment
  recorded below. A failed or unreadable check is unknown coverage, not a pass.
- The local AI model is not part of this rehearsal. Leave AI disabled and use
  the stored findings and reports for the live explanation.

## Start the backend and frontend

Open **Windows PowerShell as Administrator**, then run:

```powershell
Set-Location "$env:ProgramFiles\RAVEN-X\Server"
$env:RAVENX_LOCAL_AI_ENABLED = 'false'
& '.\venv\Scripts\python.exe' -E -s -m backend.cli serve `
  --data-dir "$env:ProgramData\RAVEN-X\server" `
  --host 127.0.0.1 --port 8443
```

Leave that window open. In another PowerShell window, check:

```powershell
(Invoke-WebRequest -Uri 'https://127.0.0.1:8443/ready' -UseBasicParsing).Content
```

It should say `ready` and show the database and control plane as
`operational`. Open **https://127.0.0.1:8443/** in the Omen browser and log in
as `admin@ravenx.local`. This serves the installed production frontend from
the same HTTPS process as the API. Do not use the older `run.py --mode all`
development launcher or `npm run dev` for this presentation.

If **Fleet → DESKTOP-ICTSOOB** shows **Offline** and **Run assessment** is
disabled, start the existing agent task in Administrator PowerShell:

```powershell
Start-ScheduledTask -TaskName 'RAVEN-X Endpoint Agent'
```

Refresh Fleet after a few seconds and wait for **Online**. The enrollment
token was consumed yesterday; its 60-minute expiry does not affect this
existing endpoint. On October 15 the task was blocked by Windows' default
battery conditions. Its installed settings were corrected to allow starting
and continuing on battery; the installer source now sets those conditions for
future laptops.

If the port is already in use, check `/ready` first: the server may already be
running. If `/ready` times out while port 8443 is occupied, stop the stalled
server with **Ctrl+C** in its PowerShell window and start it again with the
command above. Wait for `ready` before opening the portal. If the browser
shows a certificate warning, stop and verify the
public CA fingerprint and URL; do not bypass the warning. The verified public
CA file is `artifacts/RAVEN-X-Omen-Public-CA-2026-10-13.pem` in the repository,
with SHA-256 `FECF963CCA266FFF39A57E598706DDA362A9F20A6C62C6B3603055D88026D5D7`.

## Verified Omen rehearsal — October 14

- Endpoint `1a33f92e-3a3e-47ea-8357-035878ea6666` reports hostname
  `DESKTOP-ICTSOOB`, matching this Omen. The portal showed **Active** and
  **Online**. The `RAVEN-X Endpoint Agent` Scheduled Task ran as SYSTEM, and
  its local credential file granted access only to SYSTEM and Administrators.
- Assessment `eb2c2c38-2368-4d40-8d09-911f56eb9582` completed in 11 seconds.
  Windows Firewall, User Account Control, SMB Protocol, and BitLocker checks
  all executed successfully. The first three returned no findings. BitLocker
  returned **High: BitLocker Not Fully Enabled**; its evidence reported the
  C: drive as `FullyDecrypted` and 0% encrypted. Present this as the Omen's
  observed state, not a fabricated example. Do not enable encryption merely
  for the presentation.
- The **Reports** page showed 1 registered and approved machine, 1 scanned
  machine, 0 machines lacking a full scan, and 1 finding. JSON, CSV, and
  Print/PDF export controls were present; no export was required for the
  rehearsal.
- The forgotten first enrollment token was revoked. The successful token is
  consumed, and the one-time secret does not need to be shown again.

## Three-minute explanation

1. **Problem (20 seconds):** “Windows security checks are often run machine by
   machine, so an administrator lacks one place to see what was checked, when,
   and whether a check could read its source.”
2. **How it works (30 seconds):** “A Windows agent runs allowlisted, read-only
   checks. It reports through HTTPS to the RAVEN-X backend. The portal shows
   endpoint identity, assessment progress, findings, and reports. This Omen is
   both the server and a test endpoint for the one-laptop demo.”
3. **Trust boundary (30 seconds):** In **Enrollment**, explain the one-use,
   expiring token and explicit approval. Do not reveal a live token. Point out
   that registration alone does not authorize assessments.
4. **Live evidence (90 seconds):** Open **Fleet** and the Omen endpoint, then
   **Assessments**. Show the completed October 14 run and its BitLocker
   evidence. If the agent is online, dispatch a fresh read-only assessment
   for Windows firewall, UAC, BitLocker, and SMB. Open **Reports** to show
   that results persist. Treat failed or unreadable checks as incomplete
   coverage.
5. **Scope (10 seconds):** “Today this is a working single-machine prototype.
   The Dell agent package is prepared; the physical two-laptop LAN test and a
   client installer are the next validation steps.”

If asked about AI, say that local advisory analysis is optional and disabled
for this demo; the evidence and reports do not depend on it. If asked about
remediation, say that this presentation runs read-only checks and does not
apply fixes.

## Optional personal scanner view

The original personal scanner is a separate desktop workflow. If you want to
show it, open another PowerShell window in the repository root and run:

```powershell
& '.\.venv-ravenx\Scripts\python.exe' -E -s scanner.py
```

Use **Quick Scan** on your own Omen with safe mode enabled. Do not click
remediation controls. This scanner's local results are separate from the
enterprise portal unless collected through the enrolled agent assessment.

To stop the enterprise server after the presentation, press **Ctrl+C** in its
PowerShell window. The current server is a foreground process; after a reboot
you must start it again with the command above.
