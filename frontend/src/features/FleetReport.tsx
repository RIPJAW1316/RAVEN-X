import { Download, FileText, Printer, RefreshCw } from "lucide-react";
import { insights } from "../api/endpoints";
import { AsyncSection, Badge, Empty, ErrorState, Panel, SeverityBadge, Stat } from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { normalizeSeverity } from "../lib/domain";
import { formatDateTime, titleCase } from "../lib/format";
import type { FleetEvidenceReport } from "../types/api";

export function FleetReport({ organizationId, endpointId, navigate }: {
  organizationId: string; endpointId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const report = useApi((signal) => endpointId ? insights.endpointReport(organizationId, endpointId, signal)
    : insights.fleetReport(organizationId, signal), [organizationId, endpointId]);
  const csv = useMutation(async () => {
    const result = await insights.fleetCsv(organizationId);
    downloadBlob(result.blob, "ravenx-fleet-report.csv");
    return true;
  });
  const pdf = useMutation(async () => {
    const result = await insights.fleetPdf(organizationId, endpointId);
    downloadBlob(result.blob, result.filename ?? `ravenx-${endpointId ? "machine" : "fleet"}-report.pdf`);
    return true;
  });
  return <Panel className="print-report" title={endpointId ? "Machine evidence report" : "Consolidated fleet report"} icon={<FileText size={15} />}
    actions={<button type="button" className="ghost small" onClick={report.reload}><RefreshCw size={14} /> Refresh</button>}>
    <AsyncSection loading={report.loading} error={report.error} data={report.data} onRetry={report.reload}>
      {(data) => <>
        <header className="print-heading"><span>RAVEN-X</span><h1>{endpointId ? data.endpoints[0]?.hostname ?? "Machine report" : "Fleet report"}</h1></header>
        <p className="panel-note">Generated {formatDateTime(data.generated_at)} · latest known assessment attempt per machine. {data.advisory_note}</p>
        <section className="stat-row">
          <Stat label="Registered" value={data.summary.total_enrolled} hint={`${data.summary.approved} approved · ${data.summary.pending_approval} awaiting approval`} />
          <Stat label="Scanned" value={data.summary.scanned} hint="Completed assessment evidence" tone="ok" />
          <Stat label="Not fully scanned" value={data.summary.not_scanned + data.summary.partial} hint={`${data.summary.partial} partial · ${data.summary.failed} failed · ${data.summary.pending + data.summary.running} in progress`} tone={data.summary.not_scanned + data.summary.partial ? "warn" : "neutral"} />
          <Stat label="Findings" value={data.summary.findings_from_completed_scans} hint="From completed scans in this report" />
        </section>
        <div className="page-actions report-actions">
          <button type="button" className="ghost" onClick={() => downloadReport(data)}><Download size={14} /> Export JSON</button>
          {!endpointId && <button type="button" className="ghost" disabled={csv.busy} onClick={() => csv.run()}><Download size={14} /> Export CSV</button>}
          <button type="button" className="ghost" disabled={pdf.busy} onClick={() => pdf.run()}><Download size={14} /> {pdf.busy ? "Preparing PDF…" : "Download PDF"}</button>
          <button type="button" className="ghost" onClick={() => window.print()}><Printer size={14} /> Print / PDF</button>
        </div>
        {csv.error && <ErrorState error={csv.error} />}
        {pdf.error && <ErrorState error={pdf.error} />}
        {data.endpoints.length === 0 ? <Empty title="No machines registered" detail="Enroll and approve a Windows agent to begin collecting evidence." /> :
          <div className="table-scroll"><table className="data-table"><thead><tr><th>Machine</th><th>Trust / presence</th><th>Assessment coverage</th><th>Last attempt</th><th>Findings</th></tr></thead>
            <tbody>{data.endpoints.map((row) => <tr key={row.endpoint_id}>
              <td><button type="button" className="link" onClick={() => navigate("reports", row.endpoint_id)}>{row.hostname}</button><small className="block mono">{row.endpoint_id}</small></td>
              <td>{row.lifecycle_status === "new" ? "Pending approval" : titleCase(row.lifecycle_status)}<small className="block">{titleCase(row.presence_state)} · {formatDateTime(row.last_seen_at)}</small></td>
              <td><Badge tone={row.scan_status === "scanned" ? "ok" : row.scan_status === "failed" ? "critical" : "warn"}>{titleCase(row.scan_status)}</Badge>
                {row.partial_evidence && <small className="block">Partial evidence only</small>}</td>
              <td>{row.latest_assessment ? <button type="button" className="link" onClick={() => navigate("assessments", row.latest_assessment!.assessment_id)}>{formatDateTime(row.latest_assessment.requested_at)}</button> : "No assessment"}</td>
              <td>{row.latest_assessment ? row.findings_count : "—"}</td>
            </tr>)}</tbody></table></div>}
        {endpointId && data.endpoints.map((row) => <section key={row.endpoint_id} className="report-evidence">
          <h3>{row.hostname} · evidence</h3>
          <p className="panel-note">Last successful assessment: {formatDateTime(row.last_successful_assessment_at)}. {row.malformed_findings > 0 ? `${row.malformed_findings} malformed findings excluded.` : ""} {row.findings_omitted > 0 ? `${row.findings_omitted} findings omitted from this bounded report; open the assessment for full evidence.` : ""}</p>
          {row.scanner_results.length > 0 && <table className="data-table"><thead><tr><th>Scanner</th><th>Outcome</th><th>Findings</th></tr></thead><tbody>
            {row.scanner_results.map((scanner) => <tr key={scanner.scanner_id}><td>{scanner.scanner_id}</td><td>{scanner.status}{scanner.has_error ? " · error reported" : ""}</td><td>{scanner.finding_count}</td></tr>)}
          </tbody></table>}
          {row.findings.map((finding, index) => <article className="report-finding" key={finding.finding_id ?? index}>
            <SeverityBadge severity={normalizeSeverity(finding.severity)} /><h4>{finding.title}</h4><p>{finding.description}</p>
            {finding.evidence.map((evidence, evidenceIndex) => <dl className="evidence-values" key={evidenceIndex}>
              {Object.entries(evidence).map(([name, value]) => <div key={name}>
                <dt>{name.replaceAll("_", " ")}</dt>
                <dd>{typeof value === "string" ? value : JSON.stringify(value)}</dd>
              </div>)}
            </dl>)}
          </article>)}
          {row.findings_count === 0 && <p className="panel-note">{row.scan_status === "scanned" ? "No findings reported within the completed scanner coverage. This does not establish that the entire machine is secure." : "No findings in the returned evidence. Assessment coverage is incomplete or absent; this machine is not reported as clean."}</p>}
        </section>)}
      </>}
    </AsyncSection>
  </Panel>;
}

function downloadReport(data: FleetEvidenceReport) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  downloadBlob(blob, `ravenx-${data.scope.kind}-report-${data.generated_at.slice(0, 10)}.json`);
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
