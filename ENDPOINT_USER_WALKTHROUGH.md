# RAVEN-X 1.0.0 endpoint walkthrough

## Before installing

Use an x64 Windows 10 or Windows 11 computer and a local administrator account. Setup and the removal utility are unsigned. Compare the SHA-256 of the downloaded ZIP with the checksum published alongside it before extracting:

```powershell
Get-FileHash -LiteralPath '.\RAVEN-X-Endpoint-v1.0.0.zip' -Algorithm SHA256
```

Ask your administrator for:

- The HTTPS origin, including its port.
- The **Enrollment ID**, a UUID.
- The public **CA PEM** file and its independently verified **SHA-256 fingerprint**.
- The separate **bootstrap token**. Keep it private and use it in the masked Setup field.

## Install and verify

1. Extract the ZIP and open **RAVEN-X-Windows-Setup-v1.0.0.exe**. Approve the elevation prompt. The wizard requires interactive entry.
2. On the connection page, enter the HTTPS origin, Enrollment ID, and verified CA SHA-256 fingerprint.
3. On the CA page, select the supplied public `ca.pem`. Setup checks that the file matches the fingerprint before contacting the server.
4. Enter the bootstrap token in the masked field and click **Install**. Setup prepares the bundled runtime, installs pinned dependencies offline, verifies HTTPS, and enrolls the endpoint.
5. On success, ask your administrator to approve the device in **Enrollment** and verify it appears online in **Fleet**. The administrator can run a read-only assessment from the portal.

On Windows, the **RAVEN-X Endpoint Agent** scheduled task starts the agent at boot. An enrolled client uses its stored device credential on subsequent starts. Ask your administrator for a fresh or renewed invitation if an unused token expires before enrollment.

## Recover a failed installation

If Setup fails, retain the displayed error and share it with the administrator without including the token. Confirm the HTTPS origin, CA fingerprint, and Windows clock. Open **ClientRemoval.exe** and choose **Recover failed install**. You can select **Preview changes only** to see what the utility would remove. Recovery refuses to erase an existing local enrollment identity.

After recovery finishes, ask for a valid invitation and run Setup again.

## Uninstall

Ask your administrator to revoke the endpoint in the portal when decommissioning it. Open **ClientRemoval.exe**, select **Uninstall client**, and confirm. The utility stops and unregisters its Windows task, then removes its installed code, client runtime, setup state, and local enrollment credentials. Keep the error details if the utility stops before finishing.
