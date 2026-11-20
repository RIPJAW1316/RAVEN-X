/** Local and cloud demo analysis of assessment evidence for the selected organization. */
import { Radar, ShieldAlert, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
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
import { hostedDemo } from "../lib/hostedDemo";
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
        title="Signals available for analysis"
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
                  Open a finding to inspect its source assessment.
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
  const [scopeKey, setScopeKey] = useState("");
  const [model, setModel] = useState<"lm_studio" | "offline" | "gemini">(hostedDemo ? "gemini" : "lm_studio");
  const [result, setResult] = useState<LocalAnalysis | null>(null);
  const report = useApi((signal) => insights.fleetReport(organizationId, signal), [organizationId]);
  const analyze = useMutation((options: Parameters<typeof insights.analyze>[1]) =>
    insights.analyze(organizationId, options, true),
  );

  const reasons: Record<string, string> = {
    LOCAL_AI_DISABLED: "Local inference is disabled. An administrator can connect a loopback runtime using the deployment guide.",
    LOCAL_AI_UNAVAILABLE: "The local inference service could not return a valid response. Stored evidence remains available.",
    NO_COMPLETED_EVIDENCE: "There is no completed scan evidence in this scope. Run an assessment before requesting analysis.",
  };

  const handleScopeChange = (newScope: string) => {
    setScopeKey(newScope);
    setResult(null);
    analyze.reset();
  };

  const handleModelChange = (newModel: "lm_studio" | "offline" | "gemini") => {
    setModel(newModel);
    setResult(null);
    analyze.reset();
  };

  const runAnalysis = async () => {
    setResult(null);
    const selection = {
      model,
      ...(scopeKey === "__demo__"
        ? { demoId: "windows-hardening-v1" }
        : scopeKey
        ? { endpointId: scopeKey }
        : {}),
    };
    const value = await analyze.run(selection);
    if (value) setResult(value);
  };

  return (
    <Panel title="Evidence analysis" icon={<Sparkles size={15} />}>
      <p className="panel-note">
        {hostedDemo
          ? "Compare the Gemini result recorded for this sample with the deterministic offline plan."
          : model === "gemini" && scopeKey !== "__demo__"
          ? "Gemini receives Windows check categories and severities to prioritize the selected findings."
          : "Prioritize findings and review each recommendation against the source assessment."}
      </p>
      <AsyncSection loading={report.loading} error={report.error} data={report.data} onRetry={report.reload}>
        {(data) => (
          <div className="analysis-controls">
            <Field label="Evidence scope">
              <select
                value={scopeKey}
                onChange={(event) => handleScopeChange(event.target.value)}
                disabled={analyze.busy}
              >
                <option value="">Consolidated fleet evidence</option>
                {data.endpoints.map((endpoint) => (
                  <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>
                    {endpoint.hostname} · {endpoint.scan_status}
                  </option>
                ))}
                <option value="__demo__">Bundled synthetic Windows demo</option>
              </select>
            </Field>

            <Field label="Model">
              <select
                value={model}
                onChange={(event) => handleModelChange(event.target.value as "lm_studio" | "offline" | "gemini")}
                disabled={analyze.busy}
              >
                {!hostedDemo && <option value="lm_studio">Local model (LM Studio)</option>}
                <option value="offline">Offline rules (deterministic)</option>
                <option value="gemini">{hostedDemo ? "Gemini (recorded sample)" : "Gemini 3.5 Flash-Lite (Google Cloud)"}</option>
              </select>
            </Field>

            <button
              type="button"
              className="primary"
              disabled={analyze.busy}
              onClick={runAnalysis}
            >
              <Sparkles size={15} />{" "}
              {analyze.busy ? "Analyzing evidence…" : "Analyze evidence"}
            </button>
          </div>
        )}
      </AsyncSection>
      {analyze.error && <ErrorState error={analyze.error} />}
      {result && (
        <div className="analysis-result" aria-live="polite">
          <Badge
            tone={
              result.status === "available"
                ? result.provider === "offline" || (!result.provider && (result.fallback_used || result.model === "Offline rules"))
                  ? "warn"
                  : "info"
                : "warn"
            }
          >
            {result.status === "available"
              ? result.provider === "offline" || (!result.provider && result.model === "Offline rules")
                ? "Offline rules"
                : result.provider === "google_cloud"
                ? "Google Cloud"
                : "AI advisory"
              : "Analysis unavailable"}
          </Badge>
          {result.status === "available" ? (
            <>
              <p className="panel-note">
                {result.model} · {formatDateTime(result.generated_at ?? null)}. {result.notice}
                {result.fallback_used && result.fallback_reason ? ` (${result.fallback_reason})` : ""}
              </p>
              <article className="analysis-narrative" aria-label="Assessment interpretation">
                <Markdown remarkPlugins={[remarkGfm]} skipHtml disallowedElements={["a", "img", "input"]} unwrapDisallowed>
                  {unwrapAnalysis(result.analysis ?? "")}
                </Markdown>
              </article>
              {result.coverage && (
                <p className="panel-note">
                  {result.coverage.included_endpoints} machines and {result.coverage.included_findings} findings included.{" "}
                  {result.coverage.truncated ? "Some findings were omitted by report limits; consult the full report." : ""}
                </p>
              )}
            </>
          ) : (
            <p>{reasons[result.reason_code ?? ""] ?? "Analysis is unavailable for the selected evidence."}</p>
          )}
          {result.source.kind === "bundled_demo" ? (
            <div className="report-actions">
              <span className="muted">
                Source: First-party bundled synthetic Windows demo ({result.source.demo_id ?? "windows-hardening-v1"})
              </span>
            </div>
          ) : result.source.assessment_ids.length > 0 ? (
            <div className="report-actions">
              <span className="muted">Source assessments</span>
              {result.source.assessment_ids.map((id) => (
                <button key={id} type="button" className="link mono" onClick={() => navigate("assessments", id)}>
                  {shortId(id)}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

function unwrapAnalysis(value: string): string {
  const text = value.trim();
  const openingFence = /^(`{3,}|~{3,})[ \t]*(?:markdown|md)[ \t]*\r?\n/i.exec(text);
  if (!openingFence) return text;
  const body = text.slice(openingFence[0].length);
  const closingFence = new RegExp("\\r?\\n" + openingFence[1] + "[ \\t]*$");
  return body.replace(closingFence, "").trim();
}
