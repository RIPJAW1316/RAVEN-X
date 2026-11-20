/**
 * Fleet — endpoint inventory, presence and per-endpoint security context.
 *
 * The list uses the server-side query API (`/fleet/endpoints`) so filtering,
 * sorting and pagination stay authoritative rather than being re-implemented
 * client side over a truncated page.
 */
import {
  ArrowLeft,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Radar,
  Search,
  Server,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useState } from "react";
import { assessments, compliance, fleet } from "../api/endpoints";
import {
  AsyncSection,
  Badge,
  DefinitionList,
  Empty,
  ErrorState,
  Modal,
  PageHeading,
  Panel,
  Skeleton,
  StatusBadge,
} from "../components/ui";
import { useApi, useMutation, usePolling } from "../hooks/useApi";
import {
  COMPLIANCE_LABEL,
  COMPLIANCE_REASON,
  complianceTone,
  PRESENCE_LABEL,
  presenceTone,
} from "../lib/domain";
import { DASH, formatDateTime, formatRelative, shortId, titleCase } from "../lib/format";
import { DEFAULT_SCANNER_IDS, KNOWN_SCANNERS, SCANNER_DOMAINS } from "../lib/scanners";
import type { FleetEndpoint, PresenceState } from "../types/api";
import { EndpointTrustControls } from "./Enrollment";

const PAGE_SIZE = 25;
const PRESENCE_FILTERS: PresenceState[] = ["online", "stale", "offline", "unknown"];

export function Fleet({
  organizationId,
  endpointId,
  navigate,
}: {
  organizationId: string;
  endpointId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  if (endpointId) {
    return (
      <EndpointDetailView
        organizationId={organizationId}
        endpointId={endpointId}
        navigate={navigate}
      />
    );
  }
  return <FleetList organizationId={organizationId} navigate={navigate} />;
}

/* ------------------------------------------------------------------ list */

function FleetList({
  organizationId,
  navigate,
}: {
  organizationId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const [search, setSearch] = useState("");
  const [presence, setPresence] = useState<PresenceState[]>([]);
  const [sort, setSort] = useState("created_at");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [offset, setOffset] = useState(0);

  const page = useApi(
    (signal) =>
      fleet.query(
        organizationId,
        { q: search, presence, sort, direction, limit: PAGE_SIZE, offset },
        signal,
      ),
    [organizationId, search, presence.join(","), sort, direction, offset],
  );
  usePolling(page.reload, 45_000, true);

  const togglePresence = useCallback((state: PresenceState) => {
    setOffset(0);
    setPresence((current) =>
      current.includes(state) ? current.filter((item) => item !== state) : [...current, state],
    );
  }, []);

  const toggleSort = useCallback(
    (field: string) => {
      setOffset(0);
      if (sort === field) setDirection(direction === "asc" ? "desc" : "asc");
      else {
        setSort(field);
        setDirection("asc");
      }
    },
    [sort, direction],
  );

  return (
    <>
      <PageHeading
        eyebrow="Endpoint inventory & presence"
        title="Fleet"
        description="Enrolled endpoints for the active organization, filtered server-side."
      />

      <div className="toolbar">
        <div className="filter-input">
          <Search size={15} aria-hidden="true" />
          <input
            value={search}
            placeholder="Search hostname"
            aria-label="Search endpoints by hostname"
            onChange={(event) => {
              setOffset(0);
              setSearch(event.target.value);
            }}
          />
        </div>
        <div className="chip-group" role="group" aria-label="Filter by presence">
          {PRESENCE_FILTERS.map((state) => (
            <button
              key={state}
              type="button"
              aria-pressed={presence.includes(state)}
              className={presence.includes(state) ? "chip active" : "chip"}
              onClick={() => togglePresence(state)}
            >
              <i className={`dot tone-${presenceTone(state)}`} aria-hidden="true" />
              {PRESENCE_LABEL[state]}
            </button>
          ))}
        </div>
      </div>

      <AsyncSection
        loading={page.loading}
        error={page.error}
        data={page.data}
        onRetry={page.reload}
        skeletonRows={6}
      >
        {(data) => (
          <Panel>
            {data.items.length === 0 ? (
              <Empty
                title="No endpoints match"
                detail={
                  search || presence.length
                    ? "No endpoints match the current filters. Clear them to see the full fleet."
                    : "No agents are enrolled in this organization yet."
                }
              />
            ) : (
              <>
                <table className="data-table">
                  <thead>
                    <tr>
                      <SortHeader
                        field="hostname"
                        label="Endpoint"
                        sort={sort}
                        direction={direction}
                        onSort={toggleSort}
                      />
                      <SortHeader
                        field="platform"
                        label="Platform"
                        sort={sort}
                        direction={direction}
                        onSort={toggleSort}
                      />
                      <SortHeader
                        field="agent_version"
                        label="Agent"
                        sort={sort}
                        direction={direction}
                        onSort={toggleSort}
                      />
                      <SortHeader
                        field="last_seen"
                        label="Last seen"
                        sort={sort}
                        direction={direction}
                        onSort={toggleSort}
                      />
                      <th scope="col">Presence</th>
                      <SortHeader
                        field="status"
                        label="Lifecycle"
                        sort={sort}
                        direction={direction}
                        onSort={toggleSort}
                      />
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((endpoint) => (
                      <EndpointRow
                        key={endpoint.endpoint_id}
                        endpoint={endpoint}
                        onOpen={() => navigate("fleet", endpoint.endpoint_id)}
                      />
                    ))}
                  </tbody>
                </table>
                <Pagination
                  offset={data.offset}
                  returned={data.returned}
                  total={data.total}
                  limit={data.limit}
                  onChange={setOffset}
                />
              </>
            )}
          </Panel>
        )}
      </AsyncSection>
    </>
  );
}

function SortHeader({
  field,
  label,
  sort,
  direction,
  onSort,
}: {
  field: string;
  label: string;
  sort: string;
  direction: "asc" | "desc";
  onSort: (field: string) => void;
}) {
  const active = sort === field;
  return (
    <th scope="col" aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className={active ? "sort active" : "sort"} onClick={() => onSort(field)}>
        {label}
        <span aria-hidden="true">{active ? (direction === "asc" ? "▲" : "▼") : ""}</span>
      </button>
    </th>
  );
}

function EndpointRow({ endpoint, onOpen }: { endpoint: FleetEndpoint; onOpen: () => void }) {
  return (
    <tr
      tabIndex={0}
      role="button"
      onClick={onOpen}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen();
        }
      }}
    >
      <td>
        <strong>{endpoint.hostname || "Unnamed endpoint"}</strong>
        <small className="mono">{shortId(endpoint.endpoint_id)}</small>
      </td>
      <td>
        {endpoint.platform || DASH}
        {endpoint.platform_version && <small>{endpoint.platform_version}</small>}
      </td>
      <td className="mono">{endpoint.agent_version ?? DASH}</td>
      <td title={formatDateTime(endpoint.last_seen_at)}>{formatRelative(endpoint.last_seen_at)}</td>
      <td>
        <StatusBadge
          tone={presenceTone(endpoint.presence_state)}
          label={PRESENCE_LABEL[endpoint.presence_state]}
        />
      </td>
      <td>
        <Badge tone={endpoint.lifecycle_status === "active" ? "ok" : "neutral"}>
          {titleCase(endpoint.lifecycle_status)}
        </Badge>
      </td>
    </tr>
  );
}

function Pagination({
  offset,
  returned,
  total,
  limit,
  onChange,
}: {
  offset: number;
  returned: number;
  total: number;
  limit: number;
  onChange: (offset: number) => void;
}) {
  const first = total === 0 ? 0 : offset + 1;
  const last = offset + returned;
  return (
    <div className="pagination">
      <span>
        {first}–{last} of {total.toLocaleString()}
      </span>
      <div>
        <button
          type="button"
          className="ghost"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          <ChevronLeft size={15} aria-hidden="true" /> Previous
        </button>
        <button
          type="button"
          className="ghost"
          disabled={last >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next <ChevronRight size={15} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- detail */

function EndpointDetailView({
  organizationId,
  endpointId,
  navigate,
}: {
  organizationId: string;
  endpointId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const detail = useApi(
    (signal) => fleet.endpoint(organizationId, endpointId, signal),
    [organizationId, endpointId],
  );
  const presence = useApi(
    (signal) => fleet.endpointPresence(organizationId, endpointId, signal),
    [organizationId, endpointId],
  );
  usePolling(presence.reload, 15_000, true);
  const frameworks = useApi(
    (signal) => compliance.frameworks(organizationId, signal),
    [organizationId],
  );

  const frameworkId = frameworks.data?.[0]?.framework_id;
  const evaluation = useApi(
    (signal) =>
      compliance.endpointEvaluation(organizationId, endpointId, frameworkId ?? "", signal),
    [organizationId, endpointId, frameworkId],
    { enabled: Boolean(frameworkId) },
  );

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>(
    DEFAULT_SCANNER_IDS,
  );
  const dispatch = useMutation((scannerIds: string[]) =>
    assessments.create(organizationId, endpointId, scannerIds),
  );

  const onDispatch = useCallback(async () => {
    const created = await dispatch.run(selected);
    setConfirmOpen(false);
    if (created) navigate("assessments", created.assessment_id);
  }, [dispatch, selected, navigate]);

  return (
    <>
      <button type="button" className="back" onClick={() => navigate("fleet")}>
        <ArrowLeft size={15} aria-hidden="true" /> Back to fleet
      </button>

      <AsyncSection
        loading={detail.loading}
        error={detail.error}
        data={detail.data}
        onRetry={detail.reload}
        skeletonRows={5}
      >
        {(endpoint) => (
          <>
            <PageHeading
              eyebrow="Endpoint command"
              title={endpoint.hostname || "Unnamed endpoint"}
              description={`${endpoint.platform.name || "Unknown platform"}${
                endpoint.platform.version ? ` ${endpoint.platform.version}` : ""
              } · ${endpoint.platform.architecture ?? "unknown architecture"}`}
              actions={
                <>
                <button type="button" className="ghost" onClick={() => navigate("reports", endpoint.endpoint_id)}>Machine report</button>
                <EndpointTrustControls organizationId={organizationId} endpointId={endpoint.endpoint_id}
                  hostname={endpoint.hostname} status={endpoint.status} onChanged={detail.reload} />
                <button
                  type="button"
                  className="primary"
                  onClick={() => setConfirmOpen(true)}
                  disabled={endpoint.status !== "active" || presence.data?.state !== "online"}
                  title={
                    endpoint.status !== "active"
                      ? "Only active endpoints can be assessed"
                      : presence.data?.state !== "online" ? "Wait for the approved agent to come online" : "Dispatch an assessment to this endpoint"
                  }
                >
                  <Radar size={15} aria-hidden="true" /> Run assessment
                </button>
                </>
              }
            />

            {dispatch.error && <ErrorState error={dispatch.error} />}

            <section className="grid-2">
              <Panel title="Machine identity" icon={<Server size={15} aria-hidden="true" />}>
                <DefinitionList
                  items={[
                    ["Hostname", endpoint.hostname || DASH],
                    ["Endpoint ID", <code className="mono">{endpoint.endpoint_id}</code>],
                    ["Lifecycle", <Badge tone={endpoint.status === "active" ? "ok" : "neutral"}>{endpoint.status === "new" ? "Pending approval" : titleCase(endpoint.status)}</Badge>],
                    ["Platform", endpoint.platform.name || DASH],
                    ["Version", endpoint.platform.version ?? DASH],
                    ["Architecture", endpoint.platform.architecture ?? DASH],
                    ["Enrolled", formatDateTime(endpoint.created_at)],
                    ["Last seen", formatRelative(endpoint.last_seen)],
                  ]}
                />
              </Panel>

              <Panel title="Agent & connectivity" icon={<ShieldCheck size={15} aria-hidden="true" />}>
                {presence.loading && presence.data === undefined ? (
                  <Skeleton rows={3} />
                ) : presence.error ? (
                  <ErrorState error={presence.error} onRetry={presence.reload} />
                ) : presence.data ? (
                  <DefinitionList
                    items={[
                      [
                        "Presence",
                        <StatusBadge
                          tone={presenceTone(presence.data.state)}
                          label={PRESENCE_LABEL[presence.data.state]}
                        />,
                      ],
                      ["Last heartbeat", formatRelative(presence.data.last_heartbeat_at)],
                      ["Connected since", formatDateTime(presence.data.connected_since)],
                      ["Stale since", formatDateTime(presence.data.stale_since)],
                      ["Offline since", formatDateTime(presence.data.offline_since)],
                    ]}
                  />
                ) : null}
                <div className="capability-list">
                  <span className="field-label">Declared capabilities</span>
                  {endpoint.capabilities.length ? (
                    <div className="chip-row">
                      {endpoint.capabilities.map((capability) => (
                        <span className="chip static mono" key={capability}>
                          {capability}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="panel-note">The agent has not reported any capabilities.</p>
                  )}
                </div>
              </Panel>
            </section>

            <Panel
              title="Compliance posture"
              icon={<ShieldCheck size={15} aria-hidden="true" />}
              actions={
                frameworkId && (
                  <button type="button" className="link" onClick={() => navigate("compliance")}>
                    Open compliance
                  </button>
                )
              }
            >
              {!frameworkId ? (
                <Empty
                  compact
                  title="No compliance framework available"
                  detail="No framework is visible for this organization."
                />
              ) : evaluation.loading && evaluation.data === undefined ? (
                <Skeleton rows={4} />
              ) : evaluation.error ? (
                <ErrorState error={evaluation.error} onRetry={evaluation.reload} />
              ) : evaluation.data && evaluation.data.length ? (
                <ul className="control-list">
                  {evaluation.data.map((control) => (
                    <li key={control.control_id}>
                      <StatusBadge
                        tone={complianceTone(control.status)}
                        label={COMPLIANCE_LABEL[control.status]}
                      />
                      <div>
                        <strong className="mono">{control.control_id}</strong>
                        <small>
                          {COMPLIANCE_REASON[control.reason] ?? titleCase(control.reason)}
                        </small>
                      </div>
                      <span className="control-age">
                        {control.evaluated_at ? formatRelative(control.evaluated_at) : DASH}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty
                  compact
                  title="No control evaluations"
                  detail="This endpoint has no completed assessment providing compliance evidence."
                />
              )}
            </Panel>

            <Modal
              open={confirmOpen}
              title="Dispatch assessment"
              onClose={() => setConfirmOpen(false)}
            >
              <p className="confirm-message">
                Queue an assessment on <strong>{endpoint.hostname || "this endpoint"}</strong>. The
                agent collects evidence on its next outbound poll; Raven-X never pushes commands to
                the endpoint.
              </p>
              <ScannerPicker selected={selected} onChange={setSelected} />
              <div className="modal-actions">
                <button
                  type="button"
                  className="ghost"
                  onClick={() => setConfirmOpen(false)}
                  disabled={dispatch.busy}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="primary"
                  onClick={onDispatch}
                  disabled={dispatch.busy || selected.length === 0}
                >
                  {dispatch.busy ? "Dispatching…" : `Dispatch ${selected.length} scanner(s)`}
                </button>
              </div>
            </Modal>
          </>
        )}
      </AsyncSection>
    </>
  );
}

/** Scanner selection for a dispatch. See lib/scanners.ts for the catalogue gap. */
export function ScannerPicker({
  selected,
  onChange,
}: {
  selected: string[];
  onChange: (value: string[]) => void;
}) {
  const active = new Set(selected);
  const toggle = (id: string) =>
    onChange(active.has(id) ? selected.filter((item) => item !== id) : [...selected, id]);

  return (
    <div className="scanner-picker">
      <div className="scanner-picker-heading">
        <span className="field-label">Scanner domains</span>
        <span className="muted" aria-live="polite">{selected.length} of {KNOWN_SCANNERS.length} selected</span>
      </div>
      <div className="chip-row">
        <button type="button" className="ghost small"
          onClick={() => onChange(DEFAULT_SCANNER_IDS.slice(0, 4))}>
          Quick scan
        </button>
        <button type="button" className="ghost small"
          onClick={() => onChange(KNOWN_SCANNERS.map((scanner) => scanner.scanner_id))}>
          Full Windows scan
        </button>
        <button type="button" className="ghost small" disabled={!selected.length} onClick={() => onChange([])}>
          Clear selection
        </button>
      </div>
      <div className="scanner-domains">
        {SCANNER_DOMAINS.map((domain) => {
          const scanners = KNOWN_SCANNERS.filter((scanner) => scanner.domain === domain);
          const ids = new Set(scanners.map((scanner) => scanner.scanner_id));
          const count = scanners.filter((scanner) => active.has(scanner.scanner_id)).length;
          const allSelected = count === scanners.length;
          return (
            <details className="scanner-domain" key={domain}>
              <summary>
                <ChevronDown size={15} aria-hidden="true" />
                <span>{domain}</span>
                <small>{count}/{scanners.length} selected</small>
              </summary>
              <div className="scanner-domain-checks">
                <button type="button" className="ghost small"
                  aria-label={allSelected ? 'Clear ' + domain : 'Select all in ' + domain}
                  onClick={() => onChange(allSelected
                    ? selected.filter((id) => !ids.has(id))
                    : [...new Set([...selected, ...ids])])}>
                  {allSelected ? "Clear domain" : "Select domain"}
                </button>
                <div className="chip-row" role="group" aria-label={domain}>
                  {scanners.map((scanner) => (
                    <button key={scanner.scanner_id} type="button"
                      aria-pressed={active.has(scanner.scanner_id)}
                      className={active.has(scanner.scanner_id) ? "chip active" : "chip"}
                      onClick={() => toggle(scanner.scanner_id)} title={scanner.description}>
                      {scanner.name}
                    </button>
                  ))}
                </div>
              </div>
            </details>
          );
        })}
      </div>
      <small className="field-hint">
        The expanded checks require the matching Windows agent. Older agents report them as not collected.
      </small>
    </div>
  );
}
