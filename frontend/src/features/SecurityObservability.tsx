/**
 * Security observability panel.
 *
 * Renders windowed authorization/authentication telemetry and any signals the
 * backend's deterministic rules fired. Every number comes from
 * `GET /organizations/{id}/security/metrics`; nothing is derived client-side
 * beyond formatting.
 *
 * Laid out so an operator can read the security state in a few seconds:
 * signals first (they are the exception), then the counters that explain them.
 */
import { Activity, AlertTriangle, KeyRound, Lock, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { observability } from "../api/endpoints";
import { ErrorState, Panel, Skeleton } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { formatRelative } from "../lib/format";
import type { SecurityMetrics, SecuritySignal, SignalSeverity } from "../types/api";

const SEVERITY_TONE: Record<SignalSeverity, string> = {
  critical: "critical",
  warning: "warn",
  info: "info",
};

const SEVERITY_GLYPH: Record<SignalSeverity, string> = {
  critical: "!!",
  warning: "!",
  info: "·",
};

/** Human labels for the backend's deterministic rule identifiers. */
const SIGNAL_TITLE: Record<string, string> = {
  "authorization.denial_spike": "Authorization denial spike",
  "authentication.repeated_failure": "Repeated sign-in failures",
  "authorization.cross_tenant_probing": "Tenant boundary probing",
  "authorization.sensitive_action_denials": "Repeated denials on one action",
};

function percent(value: number): string {
  return `${(value * 100).toFixed(value >= 0.1 ? 0 : 1)}%`;
}

export function SecurityObservability({
  organizationId,
  windowMinutes = 15,
}: {
  organizationId: string;
  windowMinutes?: number;
}) {
  const state = useApi(
    (signal) => observability.metrics(organizationId, windowMinutes, signal),
    [organizationId, windowMinutes],
  );
  // Telemetry is a live operational view; poll while the tab is visible.
  usePolling(state.reload, 30_000, true);

  return (
    <Panel
      title="Security observability"
      icon={<Activity size={15} aria-hidden="true" />}
      actions={
        state.data && (
          <span className="panel-meta">
            last {state.data.window_minutes}m · {formatRelative(state.data.generated_at)}
          </span>
        )
      }
    >
      {state.error ? (
        <ErrorState error={state.error} onRetry={state.reload} />
      ) : state.loading && state.data === undefined ? (
        <Skeleton rows={3} />
      ) : state.data ? (
        <MetricsBody data={state.data} />
      ) : null}
    </Panel>
  );
}

function MetricsBody({ data }: { data: SecurityMetrics }) {
  const { authorization: authz, authentication: authn, signals } = data;
  const quiet = signals.length === 0;

  return (
    <>
      {quiet ? (
        <p className="observability-quiet">
          <ShieldCheck size={14} aria-hidden="true" />
          No security signals in the last {data.window_minutes} minutes.
        </p>
      ) : (
        <ul className="signal-list">
          {signals.map((signal, index) => (
            <SignalRow key={`${signal.signal_type}-${signal.scope}-${index}`} signal={signal} />
          ))}
        </ul>
      )}

      <div className="telemetry-grid">
        <TelemetryBlock
          label="Authorization"
          icon={<Lock size={13} aria-hidden="true" />}
          cells={[
            ["Attempts", authz.attempts.toLocaleString(), "neutral"],
            ["Allowed", authz.allowed.toLocaleString(), "ok"],
            ["Denied", authz.denied.toLocaleString(), authz.denied > 0 ? "critical" : "neutral"],
            [
              "Denial rate",
              percent(authz.denial_rate),
              authz.denial_rate >= 0.4 ? "critical" : authz.denial_rate > 0 ? "warn" : "neutral",
            ],
          ]}
        />
        <TelemetryBlock
          label="Authentication"
          icon={<KeyRound size={13} aria-hidden="true" />}
          hint="Sign-in happens before an organization is chosen, so these counts are process-wide."
          cells={[
            ["Successes", authn.success.toLocaleString(), "ok"],
            ["Failures", authn.failure.toLocaleString(), authn.failure > 0 ? "warn" : "neutral"],
          ]}
        />
      </div>

      {Object.keys(authz.denied_by_action).length > 0 && (
        <div className="denial-breakdown">
          <span className="field-label">Denials by action</span>
          <ul>
            {Object.entries(authz.denied_by_action)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5)
              .map(([action, count]) => (
                <li key={action}>
                  <span className="mono">{action}</span>
                  <b>{count}</b>
                </li>
              ))}
          </ul>
        </div>
      )}

      <p className="panel-note">
        Authorization telemetry is counted here, not written to the audit trail — routine
        permission checks are operational signal, not historical security records.
      </p>
    </>
  );
}

function SignalRow({ signal }: { signal: SecuritySignal }) {
  const tone = SEVERITY_TONE[signal.severity];
  return (
    <li className={`signal-row tone-rail-${signal.severity}`}>
      <span className={`signal-icon tone-${tone}`} aria-hidden="true">
        <AlertTriangle size={14} />
      </span>
      <div className="signal-body">
        <div className="signal-headline">
          <strong>{SIGNAL_TITLE[signal.signal_type] ?? signal.signal_type}</strong>
          <span className={`audit-sev tone-${tone}`}>
            <b aria-hidden="true">{SEVERITY_GLYPH[signal.severity]}</b>
            {signal.severity}
          </span>
          {signal.scope !== "organization" && (
            <span className="signal-scope mono">{signal.scope}</span>
          )}
        </div>
        <p className="signal-reason">{signal.reason}</p>
      </div>
      <time className="audit-time" title={signal.detected_at}>
        {formatRelative(signal.detected_at)}
      </time>
    </li>
  );
}

function TelemetryBlock({
  label,
  icon,
  cells,
  hint,
}: {
  label: string;
  icon: ReactNode;
  cells: Array<[string, string, string]>;
  hint?: string;
}) {
  return (
    <div className="telemetry-block">
      <span className="telemetry-label">
        {icon}
        {label}
      </span>
      <dl>
        {cells.map(([name, value, tone]) => (
          <div key={name}>
            <dt>{name}</dt>
            <dd className={`tone-${tone}`}>{value}</dd>
          </div>
        ))}
      </dl>
      {hint && <small className="field-hint">{hint}</small>}
    </div>
  );
}
