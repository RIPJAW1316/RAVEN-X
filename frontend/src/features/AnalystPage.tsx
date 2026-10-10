/**
 * AI Analyst workspace.
 *
 * BACKEND GAP (GAP-2): no tenant-scoped analysis endpoint exists. Rather than
 * shipping a chat box wired to nothing, this page states the capability
 * boundary, shows the deterministic signals Raven-X does hold, and documents
 * the contract an analysis service would need to satisfy.
 */
import { Radar, ShieldAlert, Sparkles } from "lucide-react";
import { useState } from "react";
import { insights, reporting } from "../api/endpoints";
import {
  AsyncSection,
  Empty,
  Badge,
  ErrorState,
  Field,
  PageHeading,
  Panel,
  SeverityBadge,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { normalizeSeverity } from "../lib/domain";
import { formatDateTime, formatRelative, shortId } from "../lib/format";
import type { LocalAnalysis } from "../types/api";
import { scannerName } from "../lib/scanners";

export function Analyst({
  organizationId,
  navigate,
}: {
  organizationId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const overview = useApi(
    (signal) => reporting.overview(organizationId, signal),
    [organizationId],
  );

  return (
    <>
      <PageHeading
        eyebrow="Assisted analysis"
        title="AI Analyst"
        description="Interpretation of findings in operator language."
      />

      <LocalAnalysisPanel key={organizationId} organizationId={organizationId} navigate={navigate} />

      <Panel
        title="SIGNALS AVAILABLE FOR ANALYSIS"
        icon={<ShieldAlert size={15} aria-hidden="true" />}
        actions={
          <button type="button" className="link" onClick={() => navigate("findings")}>
            Open findings
          </button>
        }
      >
        <AsyncSection
          loading={overview.loading}
          error={overview.error}
          data={overview.data}
          onRetry={overview.reload}
          skeletonRows={4}
        >
          {(data) =>
            data.recent_high_severity_findings.length ? (
              <>
                <p className="panel-note">
                  These findings carry structured evidence today and would be the first candidates
                  for automated interpretation.
                </p>
                <ul className="finding-list detailed">
                  {data.recent_high_severity_findings.slice(0, 8).map((finding, index) => (
                    <li key={`${finding.assessment_id}-${finding.finding_id ?? index}`}>
                      <button
                        type="button"
                        className="finding-row"
                        onClick={() => navigate("assessments", finding.assessment_id)}
                      >
                        <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                        <span className="finding-row-body">
                          <strong>{finding.title}</strong>
                          <small>
                            {scannerName(finding.scanner_id)} · {shortId(finding.endpoint_id)}
                            {finding.observed_at ? ` · ${formatRelative(finding.observed_at)}` : ""}
                          </small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <Empty
                compact
                icon={<Radar size={22} aria-hidden="true" />}
                title="No findings to analyse"
                detail="Run an assessment to collect findings that an analyst could interpret."
              />
            )
          }
        </AsyncSection>
      </Panel>
    </>
  );
}

function LocalAnalysisPanel({ organizationId, navigate }: {
  organizationId: string; navigate: (section: string, ...params: string[]) => void;
}) {
  const [endpointId, setEndpointId] = useState("");
  const [result, setResult] = useState<LocalAnalysis | null>(null);
  const report = useApi((signal) => insights.fleetReport(organizationId, signal), [organizationId]);
  const analyze = useMutation((id: string) => insights.analyze(organizationId, id || undefined));
  const reasons: Record<string, string> = {
    LOCAL_AI_DISABLED: "Local inference is disabled. An administrator can connect a loopback Llama runtime using the deployment guide.",
    LOCAL_AI_UNAVAILABLE: "The local inference service could not return a valid response. Stored evidence remains available.",
    NO_COMPLETED_EVIDENCE: "There is no completed scan evidence in this scope. Run an assessment before requesting analysis.",
  };
  return <Panel title="LOCAL EVIDENCE ANALYSIS" icon={<Sparkles size={15} />}>
    <p className="panel-note">On-demand interpretation from a local model. Assessment evidence is sent only to the configured loopback runtime. Suggestions require human review.</p>
    <AsyncSection loading={report.loading} error={report.error} data={report.data} onRetry={report.reload}>
      {(data) => <div className="analysis-controls">
        <Field label="Evidence scope"><select value={endpointId} onChange={(event) => { setEndpointId(event.target.value); setResult(null); analyze.reset(); }} disabled={analyze.busy}>
          <option value="">Consolidated fleet evidence</option>
          {data.endpoints.map((endpoint) => <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>{endpoint.hostname} · {endpoint.scan_status}</option>)}
        </select></Field>
        <button type="button" className="primary" disabled={analyze.busy} onClick={async () => { setResult(null); const value = await analyze.run(endpointId); if (value) setResult(value); }}>
          <Sparkles size={15} /> {analyze.busy ? "Analyzing local evidence…" : "Analyze evidence"}
        </button>
      </div>}
    </AsyncSection>
    {analyze.error && <ErrorState error={analyze.error} />}
    {result && <div className="analysis-result" aria-live="polite">
      <Badge tone={result.status === "available" ? "info" : "warn"}>{result.status === "available" ? "AI advisory" : "Analysis unavailable"}</Badge>
      {result.status === "available" ? <>
        <p className="panel-note">{result.model} · {formatDateTime(result.generated_at ?? null)}. {result.notice}</p>
        <div className="analysis-narrative">{result.analysis}</div>
        {result.coverage && <p className="panel-note">{result.coverage.included_endpoints} machines and {result.coverage.included_findings} findings included. {result.coverage.truncated ? "Evidence was truncated to fit the model context; consult the full report." : ""}</p>}
      </> : <p>{reasons[result.reason_code ?? ""] ?? "Analysis is unavailable for the selected evidence."}</p>}
      {result.source.assessment_ids.length > 0 && <div className="report-actions"><span className="muted">Source assessments</span>
        {result.source.assessment_ids.map((id) => <button key={id} type="button" className="link mono" onClick={() => navigate("assessments", id)}>{shortId(id)}</button>)}
      </div>}
    </div>}
  </Panel>;
}
