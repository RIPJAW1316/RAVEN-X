# RAVEN-X 1.0.0 administrator walkthrough

## Install and start the portal

Use 64-bit Windows and a local administrator account. The ZIP includes Python 3.13, the dependency wheels and the built portal. Setup needs no Node.js or internet access. Download the administrator ZIP and its published checksum from the official GitHub release. The launcher is unsigned.

For a graphical installation, verify the published SHA-256 of **RAVEN-X-Omen-Setup.exe**, run it and approve the Windows administrator prompt. Open **RAVEN-X → Omen Server** from the Start menu. Setup places the same admin ZIP contents in a versioned Program Files directory. The server starts when you click **Start server** in the launcher.

To install the ZIP manually, run the following from the download directory in **Administrator Windows PowerShell**:

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
3. For another physical computer, select the address of Omen's trusted Windows Private LAN. For a VirtualBox guest, select the address on its host-only network. The launcher also recognizes a VirtualBox host-only adapter with no Windows network profile and no default route. Leave **Allow LAN clients** checked for either connection. Clear it for local-only testing. Use the HTTPS URL printed under **Client connection**. Any inbound firewall rule should be scoped to the intended interface, address, port and client subnet.
   The launcher first checks the profile's `tls\server.pem`. It can also use an administrator-provisioned `tls\server-vm.pem` under the same CA with the same server key. If you previously started the server from a terminal, stop that instance with Ctrl+C before using the same profile and port in the launcher.
4. Choose optional AI providers and click **Start server**. On first start, enter an administrator email and a matching 12–128 character password in the masked dialog. Setup prepares the offline Python environment, then initializes the profile and starts HTTPS.
5. Wait for **Running** and click **Open portal**. Verify the certificate before signing in. The launcher can export the public CA so an administrator can import it into a trusted root store on authorized admin workstations. Confirm its file SHA-256 against the launcher.

Use **Stop server** to release the port and profile before switching launchers. If shutdown takes over 30 seconds, the app offers **Force stop**. Confirming ends that launcher's worker processes and can interrupt active requests.

## Gemini and local AI

To set or rotate your Gemini key, click **Set Gemini key…**. Enter the key twice at the local masked prompt, then close the prompt window. The key remains in Windows Credential Manager for this Windows account on this PC. Use the same account to start the launcher after logging in or rebooting.

To use Gemini on an enrolled endpoint, select **Enable Gemini API** and **Allow Gemini on live assessments** before starting the server. Selecting just the first option enables the bundled demo. For live analysis, Omen sends temporary finding references, check categories and severities to Google. Hostnames, raw evidence and the recommendations linked to each finding stay on Omen.

To use local Gemma, load `google/gemma-3-4b` in LM Studio and start its local server on port 1234. Select **Enable local AI (LM Studio)** and choose the matching model identifier. You can enable both providers together.

In **AI Analyst**, select a completed endpoint assessment scope, choose the provider under **Model**, then click **Analyze evidence**. The result identifies the provider that actually produced the ordering. Under **Reports**, select a review model before exporting the PDF. If a provider is unavailable, the report identifies the offline rules fallback. An assessment with no findings needs no model call.

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
