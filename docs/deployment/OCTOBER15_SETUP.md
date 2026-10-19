# October 15 Windows pilot setup

For a short two-laptop demonstration without router DNS changes, use the
[IP-variable quick demo](QUICK_DEMO_IP.md). This document describes the
optional stable-hostname setup for longer-lived enrollment.

Status: prepared for the HP Omen control-plane machine. The Dell Vostro and HP
notebook have **not** been installed or verified from this workspace. Use this
runbook only with reviewed source on those physical machines. No installer is
run by reading this document.

## Topology and prerequisites

- HP Omen: one HTTPS server, SQLite database, portal build, and optional local
  OpenAI-compatible model on loopback. Choose a stable LAN DNS name for the
  portal and agents. Its A record must resolve to one private IPv4 address
  assigned to a Windows **Private** network interface; do not bind to `0.0.0.0`.
- Dell Vostro and HP notebook: outbound HTTPS Windows agents. They need no
  inbound firewall rule. All three machines need synchronized clocks and LAN
  reachability to the chosen HP Omen address and port.
- Install **system-wide** Python 3.13 with `py.exe` in `%WINDIR%` and exactly one
  base interpreter under protected `%ProgramFiles%`. A per-user 3.13 may stay
  registered; the installer ignores it and does not fall back to it. Zero or
  multiple Program Files 3.13 registrations fail closed. On the server, Node.js
  and the `npm.cmd` beside that `node.exe` must also sit under protected
  `%ProgramFiles%`. A user-global `npm.cmd` is ignored. The scripts refuse
  user-writable interpreters, reparse points, and existing install directories.
- For this pilot, use the official 64-bit Python 3.13.16 Windows installer and
  select **Install for all users** with a protected target such as
  `C:\Program Files\RavenXRuntime\Python313`. The existing per-user Python 3.11
  and Store Python 3.13 registrations may remain. Verify `py -0p` lists the
  new Program Files Python 3.13 before running either RAVEN-X installer.
- Run the scripts from an elevated PowerShell window using reviewed source.
  Installers refuse to overwrite an existing installation or database. The
  Python requirements and frontend package lock are pinned; the server script
  runs `pip install -r requirements-server.txt`, `npm ci`, and `npm run build`.
  Network package installation needs access to trusted package sources or a
  separately prepared wheel/cache mirror.

## 1. Prepare the HP Omen server

First create a LAN DNS A record on the router for a name you control, pointing
to the Omen's current private IPv4 address. The hostname, HTTPS port, and CA
will remain fixed for enrolled agents; the A record may be changed when the
Omen's IP changes. From the repository root, set these values and substitute
the intended administrator/organization names:

```powershell
$ServerName = 'ravenx.home.arpa'  # Example; use the name configured on your LAN DNS
$ServerIp = '192.168.1.121'       # Current address assigned to the Omen
$ServerUrl = "https://${ServerName}:8443"
Resolve-DnsName -Name $ServerName -Type A -DnsOnly -NoHostsFile
.\scripts\install-server.ps1 `
  -ServerHost $ServerIp `
  -ServerName $ServerName `
  -AdminEmail admin@example.test `
  -Organization 'Pilot Organization' `
  -Port 8443 `
  -OpenPrivateFirewall
```

The script prompts twice for the first administrator password; it is never a
command argument. It verifies that the DNS name resolves to the selected local
IP, creates a local CA and server certificate covering both the DNS name and
initial IP, bootstraps one organization, and prints the **public** CA
fingerprint. It leaves the server stopped unless `-Start` is supplied. The
optional firewall switch installs one inbound rule for TCP 8443 on the Private
profile, scoped to the selected interface and `LocalSubnet`. That rule follows
an IP change on the same interface. Without that switch, inspect the interface
and add the same narrow rule manually before remote enrollment. Do not add a
Public-profile or every-interface rule.

The installed code is `%ProgramFiles%\RAVEN-X\Server`. Server database and TLS
material are under `%ProgramData%\RAVEN-X\server`. The server's `ca-key.pem`
and `server-key.pem` remain there; transfer **only** `tls\ca.pem` to other
machines. These directories differ intentionally from the agent paths
`%ProgramFiles%\RavenX\Agent` and `%ProgramData%\RavenX\agent`. Do not
interchange them.

If the script reports existing Program Files or ProgramData state, stop and
inspect/backup it. There is no automatic reset or overwrite. The local
`backend.cli bootstrap` command refuses a database that already contains
users; it cannot turn an existing account into an administrator.

To start the server in the foreground from an elevated PowerShell window, use
the copy of the launch script in the protected installed directory. It resolves
the installed DNS name to the Omen's **current** IP at each start. The protected
installation config fixes the name, port, and interface, and the script refuses
an ambiguous, nonlocal, non-Private, or wrong-interface address:

```powershell
& "$env:ProgramFiles\RAVEN-X\Server\start-server.ps1"
```

The CLI forces production settings, one worker, frontend serving, and legacy
routes disabled. Its development `--local-http` option is loopback only and
must not be used for a LAN pilot. The server currently runs in this foreground
window; there is no server Windows service installer in this pilot.

## 2. Verify HTTPS and distribute the public CA

On the Omen, calculate the public certificate fingerprint independently and
verify HTTPS through the DNS name:

```powershell
$ServerName = 'ravenx.home.arpa'
$ServerUrl = "https://${ServerName}:8443"
$ca = "$env:ProgramData\RAVEN-X\server\tls\ca.pem"
(Get-FileHash -Algorithm SHA256 -LiteralPath $ca).Hash
curl.exe --cacert $ca "$ServerUrl/health"
curl.exe --cacert $ca "$ServerUrl/ready"
```

Copy only `ca.pem` to each notebook using a trusted channel. Compare its
SHA-256 fingerprint on the physical notebook with the Omen's value before
installing the agent. The agent uses this CA file for HTTPS validation and
binds its fingerprint to its protected credential state. The browser also
needs to trust the verified local CA; on the Omen's pilot browser account, an
operator may import the **public** `ca.pem` into `Cert:\CurrentUser\Root`
after confirming the fingerprint. Do not distribute either private key.

## 3. Enroll each notebook

Log in to `$ServerUrl` as the bootstrapped administrator, using the same fixed
hostname on each laptop. Confirm that the name resolves to the Omen from the
physical laptop before attempting enrollment.
Select the pilot organization, open **Enrollment**, and issue a separate
single-use token for each machine. Record the enrollment ID and transfer the
one-time token through a trusted channel directly to the operator at the
physical endpoint. Do not put it in a script, command line, ticket, screenshot,
or log. Tokens default to a short lifetime and grant registration only.

On each notebook, use the same reviewed source and verified public CA. In an
elevated PowerShell window:

```powershell
$verifiedCaSha256 = Read-Host 'SHA-256 fingerprint independently confirmed on the HP Omen'
$ServerName = 'ravenx.home.arpa'
$ServerUrl = "https://${ServerName}:8443"
Resolve-DnsName -Name $ServerName -Type A -DnsOnly -NoHostsFile
.\scripts\install-agent.ps1 `
  -ServerUrl $ServerUrl `
  -EnrollmentId 65e38624-4cfc-4f43-9897-4e1eb9eaa140 `
  -CaCertPath C:\TrustedTransfer\ca.pem `
  -CaCertSha256 $verifiedCaSha256
```

Python requests the token through a hidden prompt. The script installs the
runtime under `%ProgramFiles%\RavenX\Agent`, a protected machine credential
and CA under `%ProgramData%\RavenX\agent`, and a startup Scheduled Task that
runs as SYSTEM. It does not schedule a scan at startup. To observe one
foreground pass after enrollment, from the installed directory run elevated:

```powershell
Set-Location "$env:ProgramFiles\RavenX\Agent"
$ServerName = 'ravenx.home.arpa'
$ServerUrl = "https://${ServerName}:8443"
& '.\venv\Scripts\python.exe' -E -s -m backend.agent run `
  --server $ServerUrl `
  --ca-cert "$env:ProgramData\RavenX\agent\server-ca.pem" --once
```

The fingerprint must be the 64-character SHA-256 value obtained independently
from the Omen, not a fresh hash of an untrusted transfer file. Agent preparation
checks the exact bytes it imports against that value and refuses a mismatch.
After enrollment, changing the laptop's saved URL by editing a PowerShell
variable is not supported. To move the Omen to a new IP, update the LAN DNS A
record for the **same hostname**, restart the server with the protected launch
script, and verify `/health` from both machines. The new IP must stay on the
same Private interface used at installation; another interface requires a
reviewed firewall and installation-config update. Preserve the CA and server
private keys. Changing the hostname or port needs a separate reviewed migration.

The one-pass command can exit silently. Check the endpoint heartbeat and work
state in the portal; a zero exit code alone does not demonstrate an assessment.

The new endpoint appears in **Enrollment → Awaiting your approval**. Compare
its reported hostname and full endpoint ID with the physical machine before
selecting **Approve**. A pending agent may report presence but cannot receive
assessment work. Repeat with a different token for the second notebook.

## 4. Optional local AI

AI is disabled by default. If a compatible local model server has been
independently installed on the Omen and verified on loopback, set these only
in the foreground server session before `backend.cli serve`:

```powershell
$env:RAVENX_LOCAL_AI_ENABLED = 'true'
$env:RAVENX_LOCAL_AI_BASE_URL = 'http://127.0.0.1:1234/v1'
$env:RAVENX_LOCAL_AI_MODEL = 'llama-3.1-8b-instruct-q4_k_m'
```

The provider accepts loopback URLs only and refuses proxy use and redirects.
The model's availability, memory use, and response latency have not been
verified on the Omen. The portal shows an unavailable state when AI is off or
unreachable; stored scan facts and reports remain usable.

## Verification limits and preservation

The current workspace verified the new agent client, DPAPI round trip,
read-only scanners, protected-path rejection, host dispatch, and existing
personal scanner behavior with focused tests. A live **non-administrator**
local probe returned success for firewall, UAC, and SMB, and failed closed for
BitLocker because its CIM read was denied. SYSTEM task execution, real
ProgramData ACL installation, LAN TLS enrollment, reboot persistence, and
Dell/HP notebook scans still require physical verification. Do not describe
those as completed until recorded in the demo log.

## Personal scanner reuse and agent scope

The personal GUI and its existing working-tree source were preserved. The
agent imports a separate capability layer, not the GUI or its remediation code.

| Category | Checks and implementation |
| --- | --- |
| Reused rule intent | Firewall profile state, UAC policy, OS-volume BitLocker encryption, and SMBv1 policy from `scanner.py`. |
| Adapted for the agent | `backend/agent/windows_scanners.py` uses fixed read-only argument vectors, bounded time/output, structured findings and coverage, and explicit `READ_FAILED` outcomes. An unreadable/localized command result is not a clean scan. |
| Deferred | Other personal-edition checks, including antivirus, updates, RDP, accounts, listening ports, Wi-Fi, and deeper inventory. Linux/macOS execution and scanning 15 minutes after startup are deferred. |
| Unsafe for unattended dispatch | Personal remediation scripts, arbitrary PowerShell, Wi-Fi key extraction, and the legacy auto fixer. None is an agent capability or a production remediation API. |

Only advertised allowlisted Windows scanner IDs can be requested. Completing
these four checks does not establish that every security property was audited.

Credential lifetime is 30 days; automatic rotation and in-place re-enrollment
are not implemented. If a machine must be replaced or reprovisioned, revoke
the old endpoint in the portal, stop its task, preserve a protected backup of
its state and queued evidence, and use a reviewed clean-machine procedure with
a new token. Do not delete or replace the existing database, private keys, or
credential files as a troubleshooting shortcut. See
[the demo and recovery runbook](../operations/OCTOBER15_DEMO.md).
