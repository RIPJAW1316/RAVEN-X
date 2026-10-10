/**
 * Command Center — organization-wide operational posture.
 *
 * Every figure comes from `GET /organizations/{id}/security/overview`. Where
 * the backend does not provide a metric (risk score, threat trend history,
 * activity feed) the panel says so instead of deriving a plausible number.
 */
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  Network,
  Radar,
  ShieldCheck,
} from "lucide-react";
import { useMemo } from "react";
import { reporting } from "../api/endpoints";
import { Donut, SeverityBars, type SeverityDatum } from "../components/charts";
import {
  AsyncSection,
  Badge,
  Empty,
  NotImplemented,
  PageHeading,
  Panel,
  SeverityBadge,
  Stat,
  StatusBadge,
} from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import {
  ASSESSMENT_LABEL,
  assessmentTone,
  isActive,
  normalizeSeverity,
  SEVERITY_ORDER,
} from "../lib/domain";
import { formatRelative, shortId } from "../lib/format";
import type { AssessmentState, SecurityOverview } from "../types/api";
import { ActivityFeed } from "./ActivityFeed";
import { SecurityObservability } from "./SecurityObservability";

const PRESENCE_COLORS: Record<string, string> = {
  online: "var(--ok)",
  stale: "var(--warn)",
  offline: "var(--critical)",
  unknown: "var(--muted)",
};

export function CommandCenter({
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
  // The control plane exposes no push channel, so the dashboard polls.
  usePolling(overview.reload, 30_000, true);

  return (
    <>
      <PageHeading
        eyebrow="Operational overview"
        title="Command Center"
        description="Live security posture for the active organization."
        actions={
          <button type="button" className="primary" onClick={() => navigate("fleet")}>
            Open Fleet <Network size={15} aria-hidden="true" />
          </button>
        }
      />
      <AsyncSection
        loading={overview.loading}
        error={overview.error}
        data={overview.data}
        onRetry={overview.reload}
        skeletonRows={6}
      >
        {(data) => <Overview data={data} navigate={navigate} />}
      </AsyncSection>
    </>
  );
}

function Overview({
  data,
  navigate,
}: {
  data: SecurityOverview;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const severityData = useMemo<SeverityDatum[]>(
    () =>
      SEVERITY_ORDER.filter((severity) => severity !== "unknown").map((severity) => ({
        severity,
        count: data.findings[severity] ?? 0,
      })),
    [data.findings],
  );

  const presenceSlices = useMemo(
    () =>
      (["online", "stale", "offline", "unknown"] as const)
        .map((key) => ({
          label: key[0].toUpperCase() + key.slice(1),
          value: data.presence[key] ?? 0,
          color: PRESENCE_COLORS[key],
        }))
        .filter((slice) => slice.value > 0),
    [data.presence],
  );

  const activeAssessments = useMemo(
    () =>
      Object.entries(data.assessments)
        .filter(([state]) => isActive(state as AssessmentState))
        .reduce((sum, [, count]) => sum + count, 0),
    [data.assessments],
  );

  const attention = data.findings.critical + data.findings.high;
  const reachable = data.presence.online;
  const unreachable = data.presence.offline + data.presence.stale;

  return (
    <>
      <section className="stat-row">
        <Stat
          label="Registered endpoints"
          value={data.endpoints.total_endpoints}
          hint={`${data.endpoints.total_endpoints} enrolled · ${data.endpoints.revoked_endpoints} revoked`}
          onClick={() => navigate("fleet")}
        />
        <Stat
          label="Reachable now"
          value={reachable}
          hint={unreachable ? `${unreachable} stale or offline` : `${data.presence.unknown} with no heartbeat`}
          tone={unreachable > 0 ? "warn" : "ok"}
          onClick={() => navigate("fleet")}
        />
        <Stat
          label="Critical + high findings"
          value={attention}
          hint={`${data.findings.total_occurrences} total occurrences`}
          tone={attention > 0 ? "critical" : "ok"}
          onClick={() => navigate("findings")}
        />
        <Stat
          label="Active assessments"
          value={activeAssessments}
          hint="Queued, dispatched or running"
          tone={activeAssessments > 0 ? "info" : "neutral"}
          onClick={() => navigate("assessments")}
        />
      </section>

      <section className="grid-2">
        <Panel title="OBSERVED FINDINGS" icon={<AlertTriangle size={15} aria-hidden="true" />}>
          <SeverityBars data={severityData} />
          <p className="panel-note">
            Counts are finding occurrences observed by completed assessments. They do not
            represent remediation state — Raven-X does not perform remote remediation.
          </p>
        </Panel>

        <Panel title="FLEET PRESENCE" icon={<Activity size={15} aria-hidden="true" />}>
          {presenceSlices.length ? (
            <Donut
              slices={presenceSlices}
              centerValue={presenceSlices.reduce((sum, slice) => sum + slice.value, 0)}
              centerLabel="ENDPOINTS"
            />
          ) : (
            <Empty
              compact
              title={data.endpoints.total_endpoints > 0 ? "All endpoints revoked" : "No endpoints enrolled"}
              detail={data.endpoints.total_endpoints > 0
                ? "Revoked machines are excluded from fleet presence. Enroll and approve a new agent to restore access."
                : "Enroll a Raven-X agent to begin collecting presence telemetry."}
            />
          )}
          <p className="panel-note">
            Presence is derived from agent heartbeats and is independent of assessment
            results.
          </p>
        </Panel>
      </section>

      <section className="grid-2">
        <Panel
          title="ENDPOINTS REQUIRING ATTENTION"
          icon={<ShieldCheck size={15} aria-hidden="true" />}
          actions={
            <button type="button" className="link" onClick={() => navigate("findings")}>
              View all findings
            </button>
          }
        >
          {data.recent_high_severity_findings.length ? (
            <ul className="finding-list">
              {data.recent_high_severity_findings.slice(0, 6).map((finding, index) => (
                <li key={`${finding.assessment_id}-${finding.finding_id ?? index}`}>
                  <button
                    type="button"
                    className="finding-row"
                    onClick={() =>
                      navigate("assessments", finding.assessment_id)
                    }
                  >
                    <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                    <span className="finding-row-body">
                      <strong>{finding.title}</strong>
                      <small>
                        {shortId(finding.endpoint_id)}
                        {finding.scanner_id ? ` · ${finding.scanner_id}` : ""}
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
              title="No high-severity findings"
              detail="No critical or high findings were observed in recent assessments."
            />
          )}
        </Panel>

        <Panel
          title="RECENT ASSESSMENTS"
          icon={<Radar size={15} aria-hidden="true" />}
          actions={
            <button type="button" className="link" onClick={() => navigate("assessments")}>
              All assessments
            </button>
          }
        >
          {data.recent_assessments.length ? (
            <ul className="assessment-list">
              {data.recent_assessments.slice(0, 6).map((assessment) => {
                const state = assessment.status as AssessmentState;
                return (
                  <li key={assessment.assessment_id}>
                    <button
                      type="button"
                      className="assessment-row"
                      onClick={() => navigate("assessments", assessment.assessment_id)}
                    >
                      <StatusBadge
                        tone={assessmentTone(state)}
                        label={ASSESSMENT_LABEL[state] ?? assessment.status}
                      />
                      <span className="assessment-row-body">
                        <strong>{shortId(assessment.assessment_id)}</strong>
                        <small>
                          {shortId(assessment.endpoint_id)} ·{" "}
                          {formatRelative(assessment.completed_at ?? assessment.created_at)}
                        </small>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          ) : (
            <Empty
              compact
              title="No assessments yet"
              detail="Dispatch an assessment from the Fleet or Assessments screen."
            />
          )}
        </Panel>
      </section>

      <section className="grid-2">
        <Panel title="ASSESSMENT PIPELINE" icon={<CalendarClock size={15} aria-hidden="true" />}>
          {Object.keys(data.assessments).length ? (
            <ul className="state-tally">
              {Object.entries(data.assessments)
                .sort(([, a], [, b]) => b - a)
                .map(([state, count]) => (
                  <li key={state}>
                    <StatusBadge
                      tone={assessmentTone(state as AssessmentState)}
                      label={ASSESSMENT_LABEL[state as AssessmentState] ?? state}
                    />
                    <b>{count}</b>
                  </li>
                ))}
            </ul>
          ) : (
            <Empty compact title="No assessment history" detail="No assessments have been recorded." />
          )}
        </Panel>

        <Panel title="THREAT TRENDS" icon={<Activity size={15} aria-hidden="true" />}>
          <NotImplemented
            title="Trend chart unavailable"
            detail="Current findings are shown above. Open recorded assessments to compare evidence from individual runs."
          />
        </Panel>
      </section>

      <SecurityObservability organizationId={data.organization_id} />

      <ActivityFeed
        organizationId={data.organization_id}
        compact
        onViewAll={() => navigate("activity")}
      />

      <footer className="overview-footer">
        <span>
          Generated {formatRelative(data.generated_at)} · refreshes every 30s
        </span>
        {data.malformed_finding_count > 0 && (
          <Badge tone="warn">
            {data.malformed_finding_count} malformed finding records skipped
          </Badge>
        )}
      </footer>
    </>
  );
}
