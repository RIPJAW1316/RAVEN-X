# Two-laptop LAN demo with a configurable IP

Use this path for the HP Omen and Dell Vostro pilot. No router DNS change is
needed. Both laptops must be on the same trusted LAN, and the Omen's Wi-Fi
profile must be `Private`. The server IP is a setup variable; choose its actual
address when installing. Once the Dell enrolls, keep that IP for the demo.
Changing it later requires a reviewed certificate and agent URL migration.

For the current pilot, the Omen server is already installed and serving at
`192.168.1.121:8443`. Skip the installation command below while this install
exists. The Dell transfer is one file:
`artifacts/RAVEN-X-Dell-Vostro-Pilot-IPVariable-2026-10-19-v4.zip` (ZIP
SHA-256:
`3D32305CD3CD3FEA48C2487A5B44CAA58C3503844FFEA94DA63557920BEB2DEB`;
previous `v3` bundle preserved in `artifacts/`).
It contains the Omen's **public** CA at `Trust/Omen-Public-CA.pem`. The CA's
current SHA-256 is
`FECF963CCA266FFF39A57E598706DDA362A9F20A6C62C6B3603055D88026D5D7`.
Measure that CA hash on the live Omen before transfer and compare it with the
file inside the ZIP on the Dell. The hash printed inside the ZIP is not an
independent trust source. The value changes if the server CA is replaced.

## 1. Install and start the Omen server

In Administrator PowerShell from the repository root:

```powershell
$ServerIp = '192.168.1.121'  # Replace with the Omen's current Wi-Fi IPv4 address
Get-NetIPAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 |
  Select-Object IPAddress, PrefixOrigin
Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi' |
  Select-Object InterfaceAlias, NetworkCategory
.\scripts\install-server.ps1 `
  -ServerHost $ServerIp `
  -AdminEmail 'admin@ravenx.local' `
  -Organization 'RAVEN-X Demo' `
  -Port 8443 `
  -OpenPrivateFirewall
```

The installer asks twice for a new administrator password of at least 12
characters. It does not start the server unless `-Start` is supplied. Keep the
password private. The first-install script refuses existing installation state;
if it fails partway through, inspect the state before retrying.

Start the server in that elevated foreground PowerShell window:

```powershell
Set-Location "$env:ProgramFiles\RAVEN-X\Server"
$ServerIp = '192.168.1.121'  # Same address used during installation
$env:RAVENX_LOCAL_AI_ENABLED = 'false'
& '.\venv\Scripts\python.exe' -E -s -m backend.cli serve `
  --data-dir "$env:ProgramData\RAVEN-X\server" `
  --host $ServerIp --port 8443
```

From another Omen PowerShell window in the repository root, test HTTPS using
the exported public CA:

```powershell
$ServerIp = '192.168.1.121'
$ServerUrl = "https://${ServerIp}:8443"
$ca = '.\artifacts\RAVEN-X-Omen-Public-CA-2026-10-13.pem'
(Get-FileHash -Algorithm SHA256 -LiteralPath $ca).Hash
curl.exe --ssl-revoke-best-effort --cacert $ca "$ServerUrl/health"
curl.exe --ssl-revoke-best-effort --cacert $ca "$ServerUrl/ready"
```

The Omen's Windows `curl.exe` uses Schannel, which can report an unknown
revocation status for this local CA. `--ssl-revoke-best-effort` tolerates
missing revocation data while retaining CA chain and server-name checks. If
the Dell's older `curl.exe` does not support that option, use
`--ssl-no-revoke` for these individual health checks after verifying the CA
hash; it disables revocation checking for that command. Do not use `-k` or
`--insecure`. The agent itself verifies HTTPS with its pinned CA file.

For the Omen browser, verify the exported public CA's SHA-256 independently,
then trust that CA for the current Windows user if it is not already present:

```powershell
$expectedCaSha256 = 'FECF963CCA266FFF39A57E598706DDA362A9F20A6C62C6B3603055D88026D5D7'
$rootThumbprint = '8D08273358FFBE5EE3FC720BF65C7D301F8A2CF3'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $ca).Hash -ne $expectedCaSha256) {
  throw 'The public CA differs from the independently verified Omen value.'
}
if (-not (Test-Path "Cert:\CurrentUser\Root\$rootThumbprint")) {
  Import-Certificate -FilePath (Resolve-Path -LiteralPath $ca).Path `
    -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
}
(Invoke-WebRequest -Uri "$ServerUrl/ready" -UseBasicParsing).StatusCode
```

The last command returned `200` in the live Omen check. Open `$ServerUrl` in
the Omen browser and log in as `admin@ravenx.local`. This CA trust is scoped to
the Omen user's root store and can be removed after the pilot by deleting that
exact thumbprint from `Cert:\CurrentUser\Root`. Browser trust does not remove
Schannel's unknown-revocation error in plain `curl.exe`; keep using the
`--ssl-revoke-best-effort` flag for its health checks. Never transfer
`ca-key.pem`, `server-key.pem`, the database, or administrator password.

## 2. Prepare the Dell

Transfer only `artifacts/RAVEN-X-Dell-Vostro-Pilot-IPVariable-2026-10-19-v4.zip`
to the Dell by a trusted channel. On the Dell, verify the ZIP's SHA-256 against
the value above, then extract it in Administrator PowerShell:

```powershell
$zipPath = "$env:USERPROFILE\Downloads\RAVEN-X-Dell-Vostro-Pilot-IPVariable-2026-10-19-v4.zip"
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash -ne
    '3D32305CD3CD3FEA48C2487A5B44CAA58C3503844FFEA94DA63557920BEB2DEB') {
  throw 'The Dell setup ZIP does not match the verified Omen copy.'
}
if (Test-Path 'C:\RAVEN-X-AgentSetup') {
  throw 'C:\RAVEN-X-AgentSetup already exists; inspect it before extracting.'
}
Expand-Archive -LiteralPath $zipPath -DestinationPath 'C:\'
```

If you copied the ZIP somewhere other than Downloads, change `$zipPath`.
Install its official Python 3.13.16 from
`C:\RAVEN-X-AgentSetup\Prerequisites\python-3.13.16-amd64.exe` for **all users**
under a protected Program Files path. The bundled public CA is at
`C:\RAVEN-X-AgentSetup\Trust\Omen-Public-CA.pem`. Do not import it into the
Dell's Windows root store; the agent pins that file directly.

Before enrollment, from the Dell verify:

```powershell
$ServerIp = '192.168.1.121'  # Same Omen address
$ServerUrl = "https://${ServerIp}:8443"
$caPath = 'C:\RAVEN-X-AgentSetup\Trust\Omen-Public-CA.pem'
$omenCaSha256 = Read-Host 'CA SHA-256 measured independently on the live Omen'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash -ne $omenCaSha256) {
  throw 'Bundled CA does not match the live Omen CA.'
}
Test-NetConnection $ServerIp -Port 8443
curl.exe --ssl-revoke-best-effort --cacert $caPath "$ServerUrl/health"
```

If the Omen's freshly measured CA hash differs from the example above, verify
why it changed before continuing. Reading the expected hash from the ZIP's
README alone would not detect a replaced ZIP and CA.

In the portal, issue a fresh one-use enrollment token for the Dell. Record its
enrollment ID; type the secret only at the hidden prompt on the Dell. In Dell
Administrator PowerShell:

```powershell
$ServerIp = '192.168.1.121'
$ServerUrl = "https://${ServerIp}:8443"
$verifiedCaSha256 = Read-Host 'SHA-256 verified independently on the Omen'
& 'C:\RAVEN-X-AgentSetup\scripts\install-agent.ps1' `
  -ServerUrl $ServerUrl `
  -EnrollmentId '<UUID_FROM_PORTAL>' `
  -CaCertPath 'C:\RAVEN-X-AgentSetup\Trust\Omen-Public-CA.pem' `
  -CaCertSha256 $verifiedCaSha256
```

Compare the Dell hostname and full endpoint ID in the portal before approving.
Then dispatch an assessment and confirm stored results for firewall, UAC,
BitLocker, and SMB. The Dell agent uses an outbound SYSTEM Scheduled Task; it
needs no inbound firewall rule. Test one reboot, another heartbeat, and
revocation before calling the physical pilot complete.

The current server runs in a foreground window and must be restarted manually
after an Omen reboot. The secondary-laptop setup file and durable server startup
are later client-installation work, after this live pilot is validated.
