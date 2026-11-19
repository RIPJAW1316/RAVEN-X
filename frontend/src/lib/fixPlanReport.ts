import type { FixPlan } from "../types/api";

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** Static, portable report. Every endpoint-derived value is encoded as text. */
export function fixPlanHtml(plan: FixPlan): string {
  const findings = plan.items.map(item => `
    <article class="finding">
      <p class="priority">${escapeHtml(item.severity.toUpperCase())} · ${escapeHtml(item.hostname)}</p>
      <h2>${escapeHtml(item.title)}</h2>
      <p>${escapeHtml(item.details)}</p>
      <h3>Recommended action</h3>
      <p>${escapeHtml(item.action)}</p>
      <p>${escapeHtml(item.rationale)}</p>
      <p class="muted">Assessment ${escapeHtml(item.assessment_id)} · Finding ${escapeHtml(item.occurrence_id)}</p>
    </article>`).join("");
  const unverified = plan.unverified_checks.map(check => `
    <li>${escapeHtml(check.hostname)} · ${escapeHtml(check.scanner_id)}. ${escapeHtml(check.reason)}</li>`).join("");
  const complete = plan.endpoints.filter(row => row.scan_status === "scanned").length;
  const partial = plan.endpoints.filter(row => row.scan_status === "partial").length;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>RAVEN-X · Fix Plan</title>
<style>
  body{margin:0;background:#eef3f5;color:#17252e;font:15px/1.55 system-ui,sans-serif}
  main{max-width:900px;margin:auto;padding:32px 20px 56px}
  header{background:#132a32;color:white;padding:28px;border-radius:16px;margin-bottom:20px}
  h1{margin:2px 0 12px;font-size:32px} h2{font-size:20px} h3{font-size:15px}
  .finding,.followup{background:#fff;border:1px solid #d5e0e4;border-radius:12px;padding:18px 22px;margin:12px 0}
  .finding h2,.priority{margin:0 0 8px} .priority{color:#067567;font-weight:700;font-size:13px}
  .muted{color:#465b66;overflow-wrap:anywhere} li{margin-bottom:8px}
  @media print{body{background:white}.finding,.followup{break-inside:avoid}main{padding:0}header{background:white;color:black;padding:0}}
</style></head><body><main>
  <header><strong>RAVEN-X</strong><h1>Fix Plan</h1>
    <p>${plan.items.length} findings for review · ${plan.endpoints.length} endpoints in scope</p>
    <p>${complete} fully collected · ${partial} partially collected · ${plan.endpoints.length - complete - partial} without completed evidence</p>
  </header>
  ${plan.findings_omitted ? `<p>${plan.findings_omitted} findings exceeded the report limit.</p>` : ""}
  ${findings || "<p>No findings available for review in this scope.</p>"}
  ${unverified ? `<section class="followup"><h2>Checks requiring follow-up</h2><ul>${unverified}</ul></section>` : ""}
</main></body></html>`;
}
