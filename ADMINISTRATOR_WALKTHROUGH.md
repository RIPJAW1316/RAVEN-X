# RAVEN-X 1.0.0 administrator walkthrough

## Install and start the portal

Use 64-bit Windows and a local administrator account. The ZIP includes Python 3.13, the dependency wheels and the built portal. Setup needs no Node.js or internet access. Download the administrator ZIP and its published checksum from the official GitHub release. The launcher is unsigned.

In **Administrator Windows PowerShell**, from the download directory, verify the ZIP digest and extract it to a new directory under Program Files:

```powershell
$zip = Get-Item -LiteralPath '.\RAVEN-X-Admin-Portal-v1.0.0.zip'
$expected = (Get-Content -LiteralPath ($zip.FullName + '.sha256') -Raw).Trim().Split(' ')[0]
if ((Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash -ine $expected) {
    throw 'The administrator ZIP digest does not match.'
}
$portal = Join-Path $env:ProgramFiles 'RAVEN-X-1.0.0'
if (Test-Path -LiteralPath $portal) { throw 'Choose a new protected release directory.' }
Expand-Archive -LiteralPath $zip.FullName -DestinationPath $portal
& "$env:WINDIR\System32\icacls.exe" $portal /setowner '*S-1-5-32-544' /T
if ($LASTEXITCODE -ne 0) { throw 'Could not set release ownership.' }
```

1. Open **RAVEN-X-Server.exe** in the extracted directory. Approve the Windows elevation prompt using the account that will run the portal.
2. Choose the **Pilot profile**. Each profile stores its database and TLS material in `%ProgramData%\RAVEN-X\<profile>-pilot`. Use a new name for a fresh setup. To reopen an existing pilot, choose its original profile and certificate address.
3. For endpoint enrollment on another computer, select the server's private LAN IPv4 address and leave **Allow LAN clients** checked. The adapter must use the Windows Private profile. For testing on the server itself, clear **Allow LAN clients** to bind only to `127.0.0.1`. Save the address and port printed by the launcher. If LAN traffic is blocked, allow inbound TCP on that port for the Private profile and the local subnet.
4. Choose optional AI providers and click **Start server**. On first start, enter an administrator email and a matching 12–128 character password in the masked dialog. Setup prepares the offline Python environment, then initializes the profile and starts HTTPS.
5. Wait for **Running** and click **Open portal**. Verify the certificate before signing in. The launcher can export the public CA so an administrator can import it into a trusted root store on authorized admin workstations. Confirm its file SHA-256 against the launcher.

## Gemini and local AI

To set or rotate your Gemini key, click **Set Gemini key…**. Enter the key twice at the local masked prompt, then close the prompt window. The key remains in Windows Credential Manager for this Windows account on this PC. Use the same account to start the launcher after logging in or rebooting.

Check **Enable Gemini demo** before starting the server. In **AI Analyst**, select **Gemini 3.5 Flash-Lite** with the bundled synthetic demo scope. Only that demo scope uses Gemini. Use the offline rules or the local LM Studio provider for real fleet data. To use LM Studio, load the model in your local server and select **Enable local AI (LM Studio)**.

To check or delete the credential from an elevated Windows PowerShell in the release directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\manage-gemini-credentials.ps1 -Action Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\manage-gemini-credentials.ps1 -Action Delete
```

## Enroll and verify a client

1. Open **Enrollment** and create an invitation. Record the **Enrollment ID** and copy the separate one-time **bootstrap token**. Send the token only to the intended endpoint operator through a secure channel.
2. From the launcher, use **Copy client settings** and **Save public CA…**. The operator needs the HTTPS origin, Enrollment ID, public CA PEM and independently verified CA fingerprint, and the bootstrap token.
3. After the operator completes the Windows Setup wizard, return to **Enrollment** and approve the pending endpoint.
4. In **Fleet**, wait for the endpoint to appear online. Start a read-only assessment, review its evidence and export a report to confirm the workflow.

The browser trust import applies only to operator workstations. Endpoint Setup verifies the supplied CA PEM itself.

## Back up and switch releases

Stop the portal before changing release directories. Preserve the protected profile directory, including its SQLite database, enrollment verifier, and TLS material. Treat backups as sensitive.

For an encrypted, same-machine snapshot, run the bundled backup script from elevated PowerShell. Supply the exact profile directory and a new destination under a protected backup parent:

```powershell
$portal = Join-Path $env:ProgramFiles 'RAVEN-X-1.0.0'
$profile = Join-Path $env:ProgramData 'RAVEN-X\home-pilot'
$backup = Join-Path $env:ProgramData 'RAVEN-X\home-backup-20261120'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$portal\scripts\backup-server-ws03.ps1" `
    -PythonExe "$portal\venv\Scripts\python.exe" -InstallRoot $portal -DataRoot $profile -Destination $backup
```

Keep the current release directory until the replacement passes verification. Rehearse restoration with the backup on the same machine in an isolated directory. Switch the live profile only after testing the replacement against the restored copy.
