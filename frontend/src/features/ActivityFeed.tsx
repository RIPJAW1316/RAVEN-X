/**
 * Security activity feed.
 *
 * Renders genuine `SecurityAuditEvent` records from
 * `GET /organizations/{id}/audit-events`. Nothing is synthesised: an empty
 * organization shows an empty feed.
 */
import {
  Activity,
  KeyRound,
  Lock,
  Radar,
  RefreshCw,
  Server,
  ShieldCheck,
  Sparkles,
  UserCog,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { audit } from "../api/endpoints";
import { Empty, ErrorState, Panel, Skeleton } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import {
  actorLabel,
  categoryOf,
  detailChips,
  eventTitle,
  SEVERITY_GLYPH,
  SEVERITY_LABEL,
  SEVERITY_TONE,
  targetLabel,
  type AuditCategory,
} from "../lib/auditEvents";
import { formatDateTime, formatRelative } from "../lib/format";
import type { AuditEvent, AuditSeverity } from "../types/api";

const CATEGORY_ICON: Record<AuditCategory, LucideIcon> = {
  authentication: KeyRound,
  authorization: Lock,
  endpoint: Server,
  assessment: Radar,
  compliance: ShieldCheck,
  governance: UserCog,
  agent: Sparkles,
  other: Activity,
};

const SEVERITY_FILTERS: AuditSeverity[] = ["critical", "warning", "info"];

/** One event row: severity rail, headline, then actor and target. */
export function AuditEventRow({ event }: { event: AuditEvent }) {
  const Icon = CATEGORY_ICON[categoryOf(event)];
  const tone = SEVERITY_TONE[event.severity];
  const target = targetLabel(event);
  const chips = detailChips(event);

  return (
    <li className={`audit-row sev-rail-${event.severity}`}>
      <span className={`audit-icon tone-${tone}`} aria-hidden="true">
        <Icon size={15} />
      </span>
      <div className="audit-body">
        <div className="audit-headline">
          <strong>{eventTitle(event)}</strong>
          <span className={`audit-sev tone-${tone}`} title={`${SEVERITY_LABEL[event.severity]} severity`}>
            <b aria-hidden="true">{SEVERITY_GLYPH[event.severity]}</b>
            {SEVERITY_LABEL[event.severity]}
          </span>
          {event.outcome !== "success" && (
            <span className={`audit-outcome tone-${tone}`}>{event.outcome}</span>
          )}
        </div>
        <p className="audit-context">
          <span className="audit-actor">{actorLabel(event)}</span>
          {target && (
            <>
              <span className="audit-sep" aria-hidden="true">
                ·
              </span>
              <span className="audit-target">{target}</span>
            </>
          )}
        </p>
        {chips.length > 0 && (
          <dl className="audit-chips">
            {chips.map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
      <time className="audit-time" dateTime={event.occurred_at} title={formatDateTime(event.occurred_at)}>
        {formatRelative(event.occurred_at)}
      </time>
    </li>
  );
}

/**
 * Activity feed.
 *
 * `compact` renders the Command Center panel variant: a short window with no
 * filters. The full variant adds severity filters and paging.
 */
export function ActivityFeed({
  organizationId,
  compact = false,
  pageSize = compact ? 8 : 25,
  onViewAll,
}: {
  organizationId: string;
  compact?: boolean;
  pageSize?: number;
  onViewAll?: () => void;
}) {
  const [severities, setSeverities] = useState<AuditSeverity[]>([]);
  const [showPermissionChecks, setShowPermissionChecks] = useState(false);
  const [offset, setOffset] = useState(0);

  const feed = useApi(
    (signal) =>
      audit.events(
        organizationId,
        {
          severity: severities.length ? severities : undefined,
          include_permission_checks: showPermissionChecks,
          limit: pageSize,
          offset,
        },
        signal,
      ),
    [organizationId, severities.join(","), showPermissionChecks, pageSize, offset],
  );

  // No push channel exists; poll gently and only while the tab is visible.
  usePolling(feed.reload, compact ? 30_000 : 20_000, offset === 0);

  const toggleSeverity = useCallback((value: AuditSeverity) => {
    setOffset(0);
    setSeverities((current) =>
      current.includes(value) ? current.filter((item) => item !== value) : [...current, value],
    );
  }, []);

  const pagination = feed.data?.pagination;
  const items = feed.data?.items ?? [];
  const excluded = feed.data?.excluded_event_types ?? [];
  const showing = useMemo(
    () => (pagination ? `${pagination.offset + pagination.returned} of ${pagination.total}` : ""),
    [pagination],
  );

  const body = (
    <>
      {!compact && (
        <div className="toolbar">
          <div className="chip-group" role="group" aria-label="Filter by severity">
            {SEVERITY_FILTERS.map((value) => (
              <button
                key={value}
                type="button"
                aria-pressed={severities.includes(value)}
                className={severities.includes(value) ? "chip active" : "chip"}
                onClick={() => toggleSeverity(value)}
              >
                <i className={`dot tone-${SEVERITY_TONE[value]}`} aria-hidden="true" />
                {SEVERITY_LABEL[value]}
              </button>
            ))}
            <button
              type="button"
              aria-pressed={showPermissionChecks}
              className={showPermissionChecks ? "chip active" : "chip"}
              title="Successful permission checks are internal telemetry and are no longer recorded by default. Enable to show historical rows, or rows captured while diagnostic auditing was on."
              onClick={() => {
                setOffset(0);
                setShowPermissionChecks((current) => !current);
              }}
            >
              Permission checks
            </button>
          </div>
          <button type="button" className="ghost small" onClick={feed.reload}>
            <RefreshCw size={13} aria-hidden="true" /> Refresh
          </button>
        </div>
      )}

      {feed.error ? (
        <ErrorState error={feed.error} onRetry={feed.reload} />
      ) : feed.loading && feed.data === undefined ? (
        <Skeleton rows={compact ? 3 : 6} />
      ) : items.length === 0 ? (
        <Empty
          compact={compact}
          title={severities.length ? "No matching activity" : "No recorded activity"}
          detail={
            severities.length
              ? "No events match the selected severity. Clear the filter to see the full history."
              : "Security events appear here as operators and agents act on this organization."
          }
        />
      ) : (
        <>
          <ul className="audit-feed">
            {items.map((event) => (
              <AuditEventRow key={event.event_id} event={event} />
            ))}
          </ul>
          {excluded.length > 0 && (
            <p className="audit-disclosure">
              Internal permission-check telemetry ({excluded.join(", ")}) is not shown. It is no
              longer recorded for routine checks.
              {!compact && " Enable “Permission checks” to read historical rows."}
            </p>
          )}
          {!compact && pagination && (
            <div className="pagination">
              <span>{showing}</span>
              <div>
                <button
                  type="button"
                  className="ghost"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - pageSize))}
                >
                  Newer
                </button>
                <button
                  type="button"
                  className="ghost"
                  disabled={!pagination.has_next}
                  onClick={() => setOffset(offset + pageSize)}
                >
                  Older
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );

  if (!compact) return body;

  return (
    <Panel
      title="Security activity"
      icon={<Activity size={15} aria-hidden="true" />}
      actions={
        onViewAll && (
          <button type="button" className="link" onClick={onViewAll}>
            View all
          </button>
        )
      }
    >
      {body}
    </Panel>
  );
}
