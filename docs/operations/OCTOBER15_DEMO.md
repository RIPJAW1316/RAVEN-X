# October 15 demo and recovery runbook

This is the operator sequence for the HP Omen server plus Dell Vostro and HP
notebook agents. Physical notebook installation and LAN execution are pending
verification; record actual results during rehearsal. The pilot is a
single-server, single-worker deployment. The server stays in its foreground
PowerShell window; each notebook's endpoint task starts at Windows boot.

## Before the audience arrives

1. Confirm the Omen's selected LAN interface is Private and has the same
   private IPv4 address used in its certificate and server command. Check the
   firewall rule is Private/LocalSubnet only. Start the server with the command
   in [the setup guide](../deployment/OCTOBER15_SETUP.md).
2. Verify `/health` and `/ready` over HTTPS with `curl.exe --cacert` and the
   public CA. Confirm the browser can open the portal without a certificate
   warning after trusting that independently verified CA.
3. On each notebook, check the `RAVEN-X Endpoint Agent` Scheduled Task state,
   the protected `server-ca.pem` fingerprint, and the reported hostname/ID.
   Do not copy agent credentials or the Omen's CA private key.
4. Sign in as the initial administrator. Check the selected organization and
   that **Enrollment**, **Fleet**, **Schedules**, **AI Analyst**, and **Reports**
   load without exposing another organization's data.
5. Keep a record of server and agent build revisions, cert fingerprint,
   endpoint IDs, timestamps, assessment IDs, and API/test results. Redact all
   bootstrap tokens, bearer credentials, password prompts, and cookies.

## Live path

1. In **Enrollment**, issue a short-lived token labelled for the Dell. Its
   secret appears once. Enter it at the Dell's hidden prompt while installing
   its agent with the verified public CA. Repeat with a different token for
   the HP notebook. Never reuse a token.
2. Show that each endpoint is initially **Awaiting your approval**. Its
   heartbeat/presence can arrive, but assessment work remains blocked.
   Compare hostname and full endpoint ID at the physical device, then approve
   each endpoint in the portal.
3. In **Fleet**, open each endpoint and start a selected, read-only assessment
   using the Windows firewall, UAC, BitLocker, and SMB checks available on
   that machine. Show work progressing to a stored assessment. A scanner whose
   source cannot be read must show failed/unknown coverage, not a clean result.
   Do not invoke remediation in this demo.
4. Show machine-specific findings and execution evidence. Open **Reports** to
   view the consolidated fleet report and an endpoint report. Export a
   compliance snapshot as JSON/CSV only after capturing one; exports reflect
   stored facts at capture time. Do not claim PDF delivery or a scheduled
   report if it is not present.
5. Open **AI Analyst** only if the Omen's local model endpoint has been tested.
   Explain that it summarizes bounded stored facts, is advisory, and is
   unavailable when the loopback model is off. The same reports remain
   accessible without AI.
6. Demonstrate the trust boundary: revoke an unused token and show that it
   cannot register; revoke an approved test endpoint only if the rehearsal
   plan permits it, then verify its next request is denied while historical
   evidence stays visible. A consumed token's revocation does not revoke an
   already enrolled endpoint; use **Revoke endpoint** for that.

The **Schedules** UI currently supports daily, weekly, and integer-hour
recurrence. An assessment 15 minutes after Windows startup is deferred and
must not be represented as implemented. The agent's startup task establishes
the outbound connection; it does not automatically start an assessment.

## Recovery without erasing evidence

| Symptom | Operator action |
| --- | --- |
| Omen not reachable | Check the Private LAN address, narrow firewall rule, foreground server process, and `/health` then `/ready` using the verified CA. Do not turn off TLS. |
| Browser certificate warning or agent TLS failure | Check the URL uses a certificate SAN, compare the copied `ca.pem` SHA-256 fingerprint, and restore the correct public CA through the trusted channel. Do not use `verify=False` or bypass the warning. |
| Token expired or rejected before enrollment | Issue a fresh token for that machine. Verify Omen and notebook clocks. Do not reuse or log the old token. |
| Endpoint remains pending | Check its hostname/full ID at the physical notebook, confirm portal organization, then approve. Presence alone is not proof of ownership. |
| Agent offline after boot | Inspect `Get-ScheduledTaskInfo -TaskName 'RAVEN-X Endpoint Agent'`, server reachability, certificate fingerprint, and local protected storage. Preserve the encrypted result outbox; it retries completed results when the network returns. |
| BitLocker check failed | Record the failed scanner coverage and inspect whether the SYSTEM task can read BitLocker CIM. The non-admin development probe failed with Access denied; do not convert it to a clean result. |
| AI unavailable | Leave AI disabled, verify the local model separately on `127.0.0.1`, and use the stored fact report. Do not point the provider at a cloud endpoint. |
| Server setup sees an existing installation, database, or TLS files | Stop. Back up and inspect the protected ProgramData state and install ACLs. `bootstrap` refuses an occupied database; `tls-init` refuses existing keys. No script automatically deletes or overwrites them. |
| Initialization reports an existing `.tls-init.lock` or `.enrollment.lock` after a crash | Confirm there is no live TLS initialization or enrollment process. Inspect the protected directory owner/ACL and all existing certificate/credential files. For enrollment, inspect the token and endpoint in the portal: redemption may already have consumed the token. An elevated operator may remove only the verified stale lock after that review. Never remove private keys, `credential.bin`, queued evidence, or the database to retry. Partial TLS output or a redeemed token without a saved identity requires a reviewed recovery procedure. |
| Endpoint revoked, credential expired, or machine replaced | Revoke the endpoint in the portal, stop its task, and preserve a protected backup of `credential.bin` and pending `*.msg` results. In-place reset/re-enrollment is not supported by the current CLI. Plan a reviewed clean-machine reprovision with a new token and verify the old endpoint remains denied. |

Agent credentials expire after 30 days and are not rotated automatically.
Operator evidence should include the actual Dell and HP notebook LAN enrollment,
reboot startup, assessment, and revocation checks before calling the pilot
complete. The code and focused tests alone do not establish those outcomes.
