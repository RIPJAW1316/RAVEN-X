/**
 * Scanner catalogue.
 *
 * BACKEND GAP: the control plane has no scanner-discovery route, so the UI
 * cannot enumerate installed scanners at runtime. The identifiers below are
 * the read-only Windows agent checks registered in
 * `backend/agent/windows_scanners.py` and `windows_extended_checks.py`.
 * Only the original four currently have compliance baseline references.
 *
 * This constant is a stop-gap, not a simulation of backend data. When
 * `GET /api/v1/organizations/{id}/scanners` lands, replace `KNOWN_SCANNERS`
 * with that call and delete this file's catalogue.
 * See docs/frontend-api-gaps.md (GAP-1).
 */

export const SCANNER_DOMAINS = [
  "Network & remote access",
  "Identity & access",
  "Endpoint protection",
  "Updates & servicing",
  "System hardening",
  "Audit & logging",
] as const;

type ScannerDomain = (typeof SCANNER_DOMAINS)[number];

export interface ScannerDescriptor {
  scanner_id: string;
  name: string;
  description: string;
  /** Platform capability the adapter declares it needs. */
  requires: string;
}

type DomainScanner = ScannerDescriptor & { domain: ScannerDomain };

const BASELINE_SCANNERS: DomainScanner[] = [
  {
    scanner_id: "windows.firewall", domain: "Network & remote access",
    name: "Windows Firewall",
    description: "Evaluates Windows Defender Firewall profile state for each network profile.",
    requires: "windows.firewall.read",
  },
  {
    scanner_id: "windows.uac", domain: "Identity & access",
    name: "User Account Control",
    description: "Observes UAC elevation policy and reports insecure configurations.",
    requires: "windows.registry.read",
  },
  {
    scanner_id: "windows.smb", domain: "Network & remote access",
    name: "SMB Protocol",
    description: "Detects whether the legacy SMBv1 protocol remains enabled.",
    requires: "windows.powershell",
  },
  {
    scanner_id: "windows.bitlocker", domain: "Endpoint protection",
    name: "BitLocker Encryption",
    description: "Reports BitLocker protection status for the operating-system volume.",
    requires: "windows.powershell",
  },
  { scanner_id: "windows.updates", domain: "Updates & servicing", name: "Windows Update Service", description: "Checks whether Windows Update is disabled; does not prove patch compliance.", requires: "windows.powershell" },
  { scanner_id: "windows.defender", domain: "Endpoint protection", name: "Microsoft Defender", description: "Checks Defender antivirus and real-time protection when Defender is active.", requires: "windows.powershell" },
  { scanner_id: "windows.defender-exclusions", domain: "Endpoint protection", name: "Defender Exclusions", description: "Flags configured exclusions for review without exposing their values.", requires: "windows.powershell" },
  { scanner_id: "windows.autologon", domain: "Identity & access", name: "Automatic Logon", description: "Checks the machine AutoAdminLogon setting without reading credentials.", requires: "windows.powershell" },
  { scanner_id: "windows.rdp", domain: "Network & remote access", name: "Remote Desktop and NLA", description: "Checks RDP enablement and Network Level Authentication.", requires: "windows.powershell" },
  { scanner_id: "windows.guest", domain: "Identity & access", name: "Built-In Guest Account", description: "Checks whether the built-in Guest account is enabled.", requires: "windows.powershell" },
  { scanner_id: "windows.password-policy", domain: "Identity & access", name: "Local Password Requirement", description: "Checks for enabled local users without a password requirement.", requires: "windows.powershell" },
  { scanner_id: "windows.open-ports", domain: "Network & remote access", name: "Sensitive TCP Listeners", description: "Checks selected local listening ports; does not scan the network.", requires: "windows.powershell" },
  { scanner_id: "windows.network-sharing", domain: "Network & remote access", name: "Non-Default SMB Shares", description: "Flags non-default SMB shares for access review.", requires: "windows.powershell" },
  { scanner_id: "windows.powershell-policy", domain: "System hardening", name: "PowerShell Execution Policy", description: "Reports permissive execution policy as an advisory.", requires: "windows.powershell" },
  { scanner_id: "windows.autorun", domain: "System hardening", name: "Machine AutoRun Policy", description: "Checks machine-wide AutoRun restrictions.", requires: "windows.powershell" },
  { scanner_id: "windows.services", domain: "Network & remote access", name: "Remote Registry Service", description: "Checks whether Remote Registry is running.", requires: "windows.powershell" },
  { scanner_id: "windows.ntp", domain: "Updates & servicing", name: "Windows Time Service", description: "Checks whether the Windows Time service is disabled.", requires: "windows.powershell" },
  { scanner_id: "windows.telnet", domain: "Network & remote access", name: "Telnet Client Feature", description: "Checks whether the optional Telnet Client feature is enabled.", requires: "windows.powershell" },
  { scanner_id: "windows.dns", domain: "Network & remote access", name: "Active DNS Configuration", description: "Checks for DNS servers on active network adapters.", requires: "windows.powershell" },
  { scanner_id: "windows.file-integrity", domain: "System hardening", name: "Core Windows Binary Signatures", description: "Checks signatures of selected Windows files; does not replace SFC.", requires: "windows.powershell" },
  { scanner_id: "windows.admin-accounts", domain: "Identity & access", name: "Built-In Administrator", description: "Checks whether the built-in Administrator account is enabled.", requires: "windows.powershell" },
  { scanner_id: "windows.startup", domain: "System hardening", name: "Machine Startup Scripts", description: "Flags script-based machine Run entries for administrator review.", requires: "windows.powershell" },
  { scanner_id: "windows.wifi", domain: "Network & remote access", name: "Connected Wi-Fi Cipher", description: "Checks the active wireless cipher and open authentication when readable.", requires: "windows.powershell" },
  { scanner_id: "windows.audit", domain: "Audit & logging", name: "Logon Audit Policy", description: "Checks whether both successful and failed logon events are audited.", requires: "windows.powershell" },
];

export const EXPANDED_SCANNERS: DomainScanner[] = [
  { scanner_id: "windows.hotfix-recency", domain: "Updates & servicing", name: "Windows Hotfix Recency", description: "Checks the newest dated entry in Windows hotfix inventory.", requires: "windows.powershell" },
  { scanner_id: "windows.smb-client-signing", domain: "Network & remote access", name: "SMB Client Signing", description: "Reads whether the Windows SMB client requires signing.", requires: "windows.powershell" },
  { scanner_id: "windows.smb-server-signing", domain: "Network & remote access", name: "SMB Server Signing", description: "Reads whether the Windows SMB server requires signing.", requires: "windows.powershell" },
  { scanner_id: "windows.smb-guest-logons", domain: "Network & remote access", name: "SMB Guest Logons", description: "Reads whether the SMB client allows insecure guest connections.", requires: "windows.powershell" },
  { scanner_id: "windows.defender-signature-age", domain: "Endpoint protection", name: "Defender Signature Age", description: "Reads the antivirus signature age for active Defender.", requires: "windows.powershell" },
  { scanner_id: "windows.defender-pua", domain: "Endpoint protection", name: "Defender PUA Protection", description: "Reads Defender potentially unwanted application policy.", requires: "windows.powershell" },
  { scanner_id: "windows.defender-exclusion-scope", domain: "Endpoint protection", name: "Defender User-Path Exclusions", description: "Recognizes Downloads and temporary path exclusions without reporting the paths.", requires: "windows.powershell" },
  { scanner_id: "windows.pending-reboot", domain: "Updates & servicing", name: "Pending Servicing Reboot", description: "Reads Windows Update and component-servicing reboot markers.", requires: "windows.powershell" },
  { scanner_id: "windows.powershell-script-block-logging", domain: "Audit & logging", name: "PowerShell Script Block Policy", description: "Reads the Windows PowerShell machine script-block logging policy.", requires: "windows.powershell" },
  { scanner_id: "windows.powershell-module-logging", domain: "Audit & logging", name: "PowerShell Module Logging Policy", description: "Reads the Windows PowerShell machine module logging policy.", requires: "windows.powershell" },
  { scanner_id: "windows.llmnr-policy", domain: "Network & remote access", name: "LLMNR Machine Policy", description: "Checks whether DNS Client machine policy disables multicast name resolution.", requires: "windows.powershell" },
  { scanner_id: "windows.wdigest-policy", domain: "Identity & access", name: "WDigest Credential Policy", description: "Detects an explicit WDigest credential-caching override.", requires: "windows.powershell" },
  { scanner_id: "windows.security-event-log", domain: "Audit & logging", name: "Windows Security Event Log", description: "Checks whether Windows reports the Security event log enabled.", requires: "windows.powershell" },
  { scanner_id: "windows.secure-boot", domain: "Endpoint protection", name: "Secure Boot", description: "Reads UEFI Secure Boot state when the firmware exposes it.", requires: "windows.powershell" },
  { scanner_id: "windows.remote-support-service", domain: "Network & remote access", name: "Remote Support Service Review", description: "Checks for a running, automatically started TeamViewer service.", requires: "windows.powershell" },
];

export const KNOWN_SCANNERS = [...BASELINE_SCANNERS, ...EXPANDED_SCANNERS];
export const DEFAULT_SCANNER_IDS = BASELINE_SCANNERS.map((scanner) => scanner.scanner_id);

const BY_ID = new Map(KNOWN_SCANNERS.map((scanner) => [scanner.scanner_id, scanner]));

/** Resolve a display name, falling back to the raw identifier. */
export function scannerName(scannerId: string | null | undefined): string {
  if (!scannerId) return "Unknown scanner";
  return BY_ID.get(scannerId)?.name ?? scannerId;
}

export function scannerDescription(scannerId: string | null | undefined): string | null {
  if (!scannerId) return null;
  return BY_ID.get(scannerId)?.description ?? null;
}

/**
 * Merge the static catalogue with scanner IDs discovered from a compliance
 * framework's evidence requirements. Those IDs come from a real API response,
 * so anything extra found there is surfaced rather than hidden.
 */
export function mergeDiscovered(discovered: string[]): ScannerDescriptor[] {
  const extra = discovered
    .filter((id) => id && !BY_ID.has(id))
    .map<ScannerDescriptor>((id) => ({
      scanner_id: id,
      name: id,
      description: "Discovered from a compliance control's evidence requirements.",
      requires: "unknown",
    }));
  const seen = new Set<string>();
  return [...KNOWN_SCANNERS, ...extra].filter((scanner) => {
    if (seen.has(scanner.scanner_id)) return false;
    seen.add(scanner.scanner_id);
    return true;
  });
}
