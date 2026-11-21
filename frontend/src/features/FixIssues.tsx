import { FileDown, Wrench } from "lucide-react";
import { useState } from "react";
import { insights } from "../api/endpoints";
import { AsyncSection, Empty, Field, PageHeading, Panel, SeverityBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { localFixScript } from "../lib/fixScripts";
import { fixPlanHtml } from "../lib/fixPlanReport";
import { normalizeSeverity } from "../lib/domain";
import { scannerName } from "../lib/scanners";

const FINDINGS_PER_PAGE = 25;

function downloadText(filename: string, text: string, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function FixIssues({ organizationId, navigate }: {
  organizationId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const [endpointId, setEndpointId] = useState("");
  const [page, setPage] = useState(0);
  const fleet = useApi((signal) => insights.fixPlan(organizationId, "", signal), [organizationId]);
  const endpoint = useApi(
    (signal) => insights.fixPlan(organizationId, endpointId, signal),
    [organizationId, endpointId],
    { enabled: Boolean(endpointId) },
  );
  const plan = endpointId ? endpoint : fleet;
  const scopedData = endpointId && plan.data?.endpoints[0]?.endpoint_id !== endpointId
    ? undefined : plan.data;
  const lastPage = Math.max(0, Math.ceil((scopedData?.items.length ?? 0) / FINDINGS_PER_PAGE) - 1);
  const activePage = Math.min(page, lastPage);

  return <>
    <PageHeading eyebrow="Remediation" title="Fix Issues" description="Review assessment evidence, plan changes, and verify them with a fresh scan."
      actions={<button type="button" className="ghost" onClick={plan.reload}>Refresh</button>} />
    <Panel title="Remediation plan" icon={<Wrench size={15} aria-hidden="true" />}>
      <div className="field-compact">
        <Field label="Endpoint scope">
          <select value={endpointId} onChange={(event) => { setEndpointId(event.target.value); setPage(0); }}>
            <option value="">Fleet</option>
            {fleet.data?.endpoints.map((row) => (
              <option key={row.endpoint_id} value={row.endpoint_id}>{row.hostname}</option>
            ))}
          </select>
        </Field>
      </div>
      <AsyncSection loading={plan.loading || (!scopedData && !plan.error)}
        data={scopedData} error={plan.error} onRetry={plan.reload}>
        {(data) => <>
          <div className="fix-toolbar">
            <span className="fix-count">{data.items.length} finding{data.items.length === 1 ? "" : "s"} for review</span>
            <div className="row-actions">
              <button type="button" className="ghost small"
                onClick={() => downloadText("ravenx-fix-plan.md", data.analysis)}>
                <FileDown size={14} aria-hidden="true" /> Export Markdown
              </button>
              <button type="button" className="ghost small"
                onClick={() => downloadText("ravenx-fix-plan.html", fixPlanHtml(data), "text/html;charset=utf-8")}>
                <FileDown size={14} aria-hidden="true" /> Export HTML
              </button>
            </div>
          </div>
          {data.findings_omitted > 0 &&
            <p className="panel-note">{data.findings_omitted} findings exceeded the report limit. Open the source assessments for the remaining evidence.</p>}
          {data.items.length === 0 ? <Empty compact title="No findings available for review"
            detail="Run an assessment to collect evidence for this scope." /> :
            <ul className="fix-list">
              {data.items.slice(activePage * FINDINGS_PER_PAGE, (activePage + 1) * FINDINGS_PER_PAGE).map((finding) => {
                const script = localFixScript(finding);
                return <li key={finding.finding_key}>
                  <details className="fix-item">
                    <summary className="fix-summary">
                      <SeverityBadge severity={normalizeSeverity(finding.severity)} />{" "}
                      <strong>{finding.title}</strong> · {finding.hostname}
                    </summary>
                    <div className="fix-body">
                      <p>{finding.details}</p>
                      <h3>Recommended action</h3>
                      <p>{finding.action}</p>
                      <p className="panel-note">{finding.rationale}</p>
                      <div className="row-actions">
                        <button type="button" className="link"
                          onClick={() => navigate("assessments", finding.assessment_id)}>Source assessment</button>
                        {script && <button type="button" className="ghost small"
                          onClick={() => downloadText(script.filename, script.text)}>Download PowerShell</button>}
                      </div>
                      {script && <p className="panel-note">Run locally in preview mode first. Applying the change requires administrator access and confirmation.</p>}
                    </div>
                  </details>
                </li>;
              })}
            </ul>}
          {lastPage > 0 && <div className="row-actions fix-pagination" aria-label="Fix plan pages">
            <button type="button" className="ghost small" disabled={activePage === 0}
              onClick={() => setPage(activePage - 1)}>Previous</button>
            <span aria-live="polite">Page {activePage + 1} of {lastPage + 1}</span>
            <button type="button" className="ghost small" disabled={activePage === lastPage}
              onClick={() => setPage(activePage + 1)}>Next</button>
          </div>}
          {data.unverified_checks.length > 0 && <details className="fix-followup">
            <summary>{data.unverified_checks.length} requested checks need follow-up</summary>
            <ul className="finding-list">
              {data.unverified_checks.slice(0, FINDINGS_PER_PAGE).map((check) => <li key={`${check.assessment_id}:${check.scanner_id}`}>
                <strong>{check.hostname} · {scannerName(check.scanner_id)}</strong>
                <p>{check.reason}</p>
              </li>)}
            </ul>
            {data.unverified_checks.length > FINDINGS_PER_PAGE &&
              <p className="panel-note">The exports include all follow-up checks in this scope.</p>}
          </details>}
        </>}
      </AsyncSection>
    </Panel>
  </>;
}
