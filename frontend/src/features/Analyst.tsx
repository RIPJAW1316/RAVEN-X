/**
 * AI Security Analyst.
 *
 * This finding panel renders deterministic evidence and links the operator
 * to the tenant-scoped local AI Analyst. Local model output is requested
 * explicitly in that workspace at machine or consolidated fleet scope.
 */
import { Sparkles } from "lucide-react";
import { normalizeSeverity, SEVERITY_LABEL } from "../lib/domain";
import { scannerDescription, scannerName } from "../lib/scanners";
import { buildHref } from "../hooks/useRoute";
import type { FindingDetail } from "../types/api";

/** Shape a future `POST .../findings/{id}/analysis` response should return. */
export interface AnalystNarrative {
  what_happened: string;
  why_it_matters: string;
  likely_impact: string;
  recommended_action: string;
  rationale: string;
  confidence: "low" | "medium" | "high";
  evidence_references: string[];
}

export function AnalystPanel({ finding }: { finding: FindingDetail }) {
  const severity = normalizeSeverity(finding.severity);
  const detectionSource = scannerName(finding.scanner_id);
  const scannerPurpose = scannerDescription(finding.scanner_id);

  return (
    <section className="drawer-section analyst">
      <h3>
        <Sparkles size={15} aria-hidden="true" /> Security analyst
      </h3>

      <dl className="analyst-grid">
        <div>
          <dt>What was detected</dt>
          <dd>
            {detectionSource} reported <strong>{finding.title}</strong> at{" "}
            <strong>{SEVERITY_LABEL[severity]}</strong> severity.
          </dd>
        </div>
        <div>
          <dt>How it was detected</dt>
          <dd>
            {scannerPurpose ?? "The collected source and its observations are listed under Evidence."}
          </dd>
        </div>
        <div>
          <dt>Evidence collected</dt>
          <dd>
            {finding.evidence.length
              ? `${finding.evidence.length} structured evidence item(s) from ${
                  new Set(finding.evidence.map((item) => item.source)).size
                } source(s).`
              : "No structured evidence accompanied this finding."}
          </dd>
        </div>
      </dl>

      <div className="analyst-gap">
        <strong>Local advisory analysis</strong>
        <p>
          Open AI Analyst to request interpretation of completed machine or fleet evidence.
          A configured local model is required. Its output is advisory and requires human
          review; this finding panel does not claim a model interpretation.
        </p>
        <a className="link" href={buildHref("analyst")}>Open AI Analyst</a>
      </div>
    </section>
  );
}

/**
 * Renders a narrative once an analysis endpoint exists. Unused today; kept so
 * the integration point is explicit rather than a future rewrite.
 */
export function AnalystNarrativeView({ narrative }: { narrative: AnalystNarrative }) {
  return (
    <div className="analyst-narrative">
      <Section title="What happened" body={narrative.what_happened} />
      <Section title="Why this is dangerous" body={narrative.why_it_matters} />
      <Section title="Likely impact" body={narrative.likely_impact} />
      <Section title="Recommended action" body={narrative.recommended_action} />
      <Section title="Why this recommendation" body={narrative.rationale} />
      <p className="analyst-confidence">
        Confidence: <strong>{narrative.confidence}</strong>
      </p>
    </div>
  );
}

function Section({ title, body }: { title: string; body: string }) {
  return (
    <div className="analyst-section">
      <h4>{title}</h4>
      <p>{body}</p>
    </div>
  );
}
