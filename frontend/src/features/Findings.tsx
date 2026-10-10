/**
 * Findings — organization-wide severity view.
 *
 * The control plane has no cross-assessment findings query: findings are only
 * reachable through an assessment (`/assessments/{id}/details`). This screen
 * therefore aggregates the recent high-severity findings the overview route
 * returns, and says plainly that it is a recent-window view rather than a
 * complete backlog. See docs/frontend-api-gaps.md (GAP-3).
 */
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { reporting } from "../api/endpoints";
import { SeverityBars, type SeverityDatum } from "../components/charts";
import {
  AsyncSection,
  Empty,
  NotImplemented,
  PageHeading,
  Panel,
  SeverityBadge,
  Tabs,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { normalizeSeverity, SEVERITY_ORDER, SEVERITY_RANK } from "../lib/domain";
import { formatRelative, shortId } from "../lib/format";
import { scannerName } from "../lib/scanners";
import type { Severity } from "../types/api";

type Filter = Severity | "all";

export function Findings({
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
  const [filter, setFilter] = useState<Filter>("all");

  const severityData = useMemo<SeverityDatum[]>(() => {
    const counts = overview.data?.findings;
    if (!counts) return [];
    return SEVERITY_ORDER.filter((severity) => severity !== "unknown").map((severity) => ({
      severity,
      count: counts[severity] ?? 0,
    }));
  }, [overview.data]);

  const recent = useMemo(() => {
    const items = overview.data?.recent_high_severity_findings ?? [];
    const sorted = [...items].sort(
      (a, b) =>
        SEVERITY_RANK[normalizeSeverity(b.severity)] - SEVERITY_RANK[normalizeSeverity(a.severity)],
    );
    if (filter === "all") return sorted;
    return sorted.filter((item) => normalizeSeverity(item.severity) === filter);
  }, [overview.data, filter]);

  return (
    <>
      <PageHeading
        eyebrow="Security findings"
        title="Findings"
        description="Occurrences observed by completed assessments across the organization."
      />

      <AsyncSection
        loading={overview.loading}
        error={overview.error}
        data={overview.data}
        onRetry={overview.reload}
        skeletonRows={5}
      >
        {(data) => (
          <>
            <section className="grid-2">
              <Panel title="SEVERITY DISTRIBUTION" icon={<AlertTriangle size={15} aria-hidden="true" />}>
                <SeverityBars data={severityData} />
                <p className="panel-note">
                  {data.findings.total_occurrences.toLocaleString()} total occurrences across all
                  assessments. Counts reflect observation, not remediation.
                </p>
              </Panel>

              <Panel title="BACKLOG QUERY" icon={<ShieldAlert size={15} aria-hidden="true" />}>
                <NotImplemented
                  title="Recent critical and high findings"
                  detail="This list covers recent high-severity findings. Open an assessment to inspect its complete findings and evidence."
                />
              </Panel>
            </section>

            <Panel
              title="RECENT HIGH-SEVERITY FINDINGS"
              icon={<ShieldAlert size={15} aria-hidden="true" />}
              actions={<span className="panel-meta">{recent.length} shown</span>}
            >
              <Tabs
                active={filter}
                onChange={setFilter}
                tabs={[
                  { id: "all" as Filter, label: "All" },
                  { id: "critical" as Filter, label: "Critical" },
                  { id: "high" as Filter, label: "High" },
                ]}
              />
              {recent.length ? (
                <ul className="finding-list detailed">
                  {recent.map((finding, index) => (
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
                            {scannerName(finding.scanner_id)} · endpoint{" "}
                            {shortId(finding.endpoint_id)}
                            {finding.observed_at ? ` · ${formatRelative(finding.observed_at)}` : ""}
                          </small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty
                  compact
                  title="No findings in this window"
                  detail={
                    filter === "all"
                      ? "No high-severity findings were observed in recent assessments."
                      : "No findings match this severity filter."
                  }
                />
              )}
            </Panel>
          </>
        )}
      </AsyncSection>
    </>
  );
}
