import { Download, FileText, Printer, RefreshCw, Sparkles } from "lucide-react";
import { useState } from "react";
import { insights } from "../api/endpoints";
import { AsyncSection, Badge, Empty, ErrorState, Field, Panel, SeverityBadge, Stat } from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { normalizeSeverity } from "../lib/domain";
import { hostedDemo } from "../lib/hostedDemo";
import { formatDateTime, titleCase } from "../lib/format";
import { scannerName } from "../lib/scanners";
import type { FleetEvidenceReport, ReportReviewModel, ReviewedEvidenceReport } from "../types/api";

export function FleetReport({ organizationId, endpointId, navigate }: {
  organizationId: string; endpointId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const report = useApi((signal) => endpointId ? insights.endpointReport(organizationId, endpointId, signal)
    : insights.fleetReport(organizationId, signal), [organizationId, endpointId]);
  const [model, setModel] = useState<ReportReviewModel>(hostedDemo ? "gemini" : "lm_studio");
  const [reviewed, setReviewed] = useState<ReviewedEvidenceReport | null>(null);
  const [exporting, setExporting] = useState<"pdf" | "json" | "csv" | null>(null);
  const review = useMutation(async () => {
    setReviewed(null);
    setReviewed(await insights.reviewReport(organizationId, model, endpointId));
  });
  const csv = useMutation(async () => {
    const result = await insights.fleetCsv(organizationId);
    downloadBlob(result.blob, "ravenx-fleet-report.csv");
    return true;
  });
  const exportReview = useMutation(async (format: "pdf" | "json" | "csv") => {
    setExporting(format);
    try {
      let snapshot = reviewed;
      if (hostedDemo && !snapshot) {
        snapshot = await insights.reviewReport(organizationId, model, endpointId);
        setReviewed(snapshot);
      }
      const result = await insights.reviewedExport(organizationId, model, endpointId, format, snapshot?.review_id);
      downloadBlob(result.blob, result.filename ?? `ravenx-${endpointId ? "machine" : "fleet"}-reviewed-report.${format}`);
    } finally {
      setExporting(null);
    }
  });
  const busy = review.busy || exportReview.busy;
  const clearReview = () => {
    setReviewed(null);
    review.reset();
    exportReview.reset();
  };
  return <Panel className="print-report" title={endpointId ? "Machine evidence report" : "Consolidated fleet report"} icon={<FileText size={15} />}
    actions={<button type="button" className="ghost small" disabled={busy} onClick={() => { clearReview(); report.reload(); }}><RefreshCw size={14} /> Refresh</button>}>
    <AsyncSection loading={report.loading} error={report.error} data={reviewed?.report ?? report.data} onRetry={report.reload}>
      {(data) => <>
        <header className="print-heading"><span>RAVEN-X</span><h1>{endpointId ? data.endpoints[0]?.hostname ?? "Machine report" : "Fleet report"}</h1></header>
        <p className="panel-note">Generated {formatDateTime(data.generated_at)} · latest known assessment attempt per machine. {data.advisory_note}</p>
        <section className="stat-row">
          <Stat label="Registered" value={data.summary.total_enrolled} hint={`${data.summary.approved} approved · ${data.summary.pending_approval} awaiting approval`} />
          <Stat label="Scanned" value={data.summary.scanned} hint="Completed assessment evidence" tone="ok" />
          <Stat label="Not fully scanned" value={data.summary.not_scanned + data.summary.partial} hint={`${data.summary.partial} partial · ${data.summary.failed} failed · ${data.summary.pending + data.summary.running} in progress`} tone={data.summary.not_scanned + data.summary.partial ? "warn" : "neutral"} />
          <Stat label="Findings" value={data.summary.findings_from_completed_scans} hint="From completed scans in this report" />
        </section>
        <div className="report-review-controls">
          <Field label="Review model">
            <select value={model} disabled={busy} onChange={(event) => {
              clearReview();
              setModel(event.target.value as ReportReviewModel);
            }}>
              {hostedDemo ? <option value="offline">Offline rules</option>
                : <option value="lm_studio">Local model (LM Studio)</option>}
              <option value="gemini">{hostedDemo ? "Gemini (live)" : "Gemini (Google Cloud)"}</option>
            </select>
          </Field>
          <button type="button" className="primary" disabled={busy || report.loading} onClick={() => review.run()}>
            <Sparkles size={15} /> {review.busy ? "Reviewing evidence…" : "Review evidence"}
          </button>
          <button type="button" className="ghost" disabled={busy || report.loading} onClick={() => exportReview.run("pdf")}>
            <Download size={14} /> {exporting === "pdf" ? "Preparing PDF…" : "Download PDF"}
          </button>
          <button type="button" className="ghost" disabled={!reviewed || busy} onClick={() => window.print()}>
            <Printer size={14} /> Print review
          </button>
          {model === "gemini" && <p className="panel-note" role="status">{hostedDemo
            ? busy && !reviewed ? "Gemini is reviewing the selected sample evidence…"
              : "Gemini reviews the selected sample evidence. Downloads include the summary, priorities, and source assessments."
            : "Gemini receives check categories and severities to prioritize findings."}</p>}
        </div>
        {review.error && <ErrorState error={review.error} />}
        {exportReview.error && <ErrorState error={exportReview.error} />}
        {reviewed && <ReportReview review={reviewed.review} navigate={navigate} />}
        <div className="page-actions report-actions">
          {hostedDemo ? <>
            <button type="button" className="ghost" disabled={busy} onClick={() => exportReview.run("json")}>
              <Download size={14} /> {exporting === "json" ? "Preparing JSON…" : "Download reviewed JSON"}
            </button>
            <button type="button" className="ghost" disabled={busy} onClick={() => exportReview.run("csv")}>
              <Download size={14} /> {exporting === "csv" ? "Preparing CSV…" : "Download reviewed CSV"}
            </button>
          </> : <>
            <button type="button" className="ghost" onClick={() => downloadReport(data)}><Download size={14} /> Export evidence JSON</button>
            {!endpointId && <button type="button" className="ghost" disabled={csv.busy} onClick={() => csv.run()}><Download size={14} /> Export CSV</button>}
          </>}
        </div>
        {csv.error && <ErrorState error={csv.error} />}
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

function ReportReview({ review, navigate }: {
  review: ReviewedEvidenceReport["review"];
  navigate: (section: string, ...params: string[]) => void;
}) {
  const provider = review.provider === "lm_studio" ? "LM Studio"
    : review.provider === "google_cloud" ? "Google Gemini"
    : review.provider === "offline" ? "Offline rules" : "Analysis unavailable";
  const ai = review.provider === "lm_studio" || review.provider === "google_cloud";

  return <section className="report-review" aria-labelledby="report-review-title">
    <div className="report-review-heading">
      <h3 id="report-review-title">Assessment review</h3>
      <Badge tone={ai ? "info" : "warn"}>{provider}</Badge>
    </div>
    <p className="panel-note">{ai && review.model && <>{review.model} · </>}{review.note}</p>
    {review.generated_at && <p className="panel-note">Review generated {formatDateTime(review.generated_at)}</p>}
    {review.executive_summary && <>
      <h4>Executive summary</h4>
      <p>{review.executive_summary}</p>
    </>}
    {review.priorities.length > 0 && <>
      <h4>Priority findings <small>{review.priorities.length} of {review.finding_count}</small></h4>
      <ol className="report-priorities">
        {review.priorities.map((item) => <li key={item.finding_key}>
          <div><SeverityBadge severity={normalizeSeverity(item.severity)} /> <strong>{item.title}</strong></div>
          <p>{item.action}</p>
          <small className="block">{item.rationale}</small>
          <button type="button" className="link" onClick={() => navigate("assessments", item.assessment_id)}>
            {item.hostname} · Source assessment
          </button>
        </li>)}
      </ol>
    </>}
    {review.unverified.length > 0 && <>
      <h4>Unverified checks <small>{review.unverified.length} of {review.unverified_count}</small></h4>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th scope="col">Machine</th><th scope="col">Check</th><th scope="col">Reason</th></tr></thead>
          <tbody>{review.unverified.map((item) => <tr key={item.endpoint_id + "/" + item.scanner_id}>
            <td>{item.hostname}</td><td>{scannerName(item.scanner_id)}</td><td>{item.reason}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </>}
  </section>;
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
