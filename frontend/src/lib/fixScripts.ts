import type { FixPlanItem } from "../types/api";

const fixes = new Map([
  ["smb.client_signing_not_required", {
    scanner: "windows.smb-client-signing", label: "Require outbound SMB signing",
    getter: "Get-SmbClientConfiguration", setter: "Set-SmbClientConfiguration",
    property: "RequireSecuritySignature", expected: "$true",
  }],
  ["smb.server_signing_not_required", {
    scanner: "windows.smb-server-signing", label: "Require inbound SMB signing",
    getter: "Get-SmbServerConfiguration", setter: "Set-SmbServerConfiguration",
    property: "RequireSecuritySignature", expected: "$true",
  }],
  ["smb.insecure_guest_allowed", {
    scanner: "windows.smb-guest-logons", label: "Disable insecure SMB guest logons",
    getter: "Get-SmbClientConfiguration", setter: "Set-SmbClientConfiguration",
    property: "EnableInsecureGuestLogons", expected: "$false",
  }],
]);

/** Script contents are selected solely from fixed product templates. */
export function localFixScript(item: FixPlanItem): { filename: string; text: string } | null {
  const fix = fixes.get(item.rule_id ?? "");
  if (!fix || fix.scanner !== item.scanner_id) return null;
  return {
    filename: `ravenx-${fix.scanner.slice("windows.".length)}.ps1`,
    text: [
      "#Requires -RunAsAdministrator",
      "# RAVEN-X local remediation. Review SMB compatibility and policy first.",
      "[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]",
      "param([switch]$Apply)",
      "$ErrorActionPreference = 'Stop'",
      `$current = (${fix.getter} -ErrorAction Stop).${fix.property}`,
      "if ($current -isnot [bool]) { throw 'The current setting could not be read.' }",
      `Write-Output "Current ${fix.property}: $current"`,
      `if ($current -eq ${fix.expected}) { Write-Output 'Desired state already present.'; return }`,
      "if (-not $Apply) { Write-Output 'Preview only. Use -Apply after approving the change.'; return }",
      `if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, '${fix.label}')) {`,
      `    ${fix.setter} -${fix.property} ${fix.expected} -Confirm:$false -ErrorAction Stop`,
      `    $updated = (${fix.getter} -ErrorAction Stop).${fix.property}`,
      `    if ($updated -isnot [bool] -or $updated -ne ${fix.expected}) { throw 'The requested setting could not be verified.' }`,
      "    Write-Output 'Setting verified. Run a new assessment to update the report.'",
      "}",
      "",
    ].join("\r\n"),
  };
}
