/**
 * Assessments — dispatch, lifecycle monitoring, results and finding detail.
 *
 * The lifecycle rendered here is the backend's own `RemoteAssessmentState`
 * machine. No state is synthesised: an assessment that the control plane
 * reports as `queued` is drawn as queued until the agent moves it on.
 */
import {
  ArrowLeft,
  Ban,
  FileSearch,
  Plus,
  Radar,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { assessments, fleet } from "../api/endpoints";
import {
  AsyncSection,
  Badge,
  Confirm,
  DefinitionList,
  Drawer,
  Empty,
  ErrorState,
  Field,
  Modal,
  PageHeading,
  Panel,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
} from "../components/ui";
import { useApi, useMutation, usePolling } from "../hooks/useApi";
import {
  ASSESSMENT_LABEL,
  ASSESSMENT_PIPELINE,
  assessmentTone,
  isActive,
  isFailure,
  normalizeSeverity,
  pipelineIndex,
  SEVERITY_RANK,
} from "../lib/domain";
import { DASH, formatDateTime, formatDuration, formatRelative, shortId } from "../lib/format";
import { DEFAULT_SCANNER_IDS, scannerName } from "../lib/scanners";
import type { Assessment, AssessmentState, FindingDetail, ScannerResultSummary } from "../types/api";
import { ScannerPicker } from "./Fleet";
import { AnalystPanel } from "./Analyst";

export function Assessments({
  organizationId,
  assessmentId,
  findingId,
  navigate,
}: {
  organizationId: string;
  assessmentId?: string;
  findingId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  if (assessmentId) {
    return (
      <AssessmentDetailView
        organizationId={organizationId}
        assessmentId={assessmentId}
        findingId={findingId}
        navigate={navigate}
      />
    );
  }
  return <AssessmentList organizationId={organizationId} navigate={navigate} />;
}

/* ------------------------------------------------------------------ list */

type Filter = "all" | "active" | "completed" | "failed";

function AssessmentList({
  organizationId,
  navigate,
}: {
  organizationId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const [composerOpen, setComposerOpen] = useState(false);

  const list = useApi(
    (signal) => assessments.list(organizationId, signal),
    [organizationId],
  );
  const hasActive = useMemo(
    () => (list.data ?? []).some((item) => isActive(item.state)),
    [list.data],
  );
  // Poll faster while work is in flight so lifecycle changes surface quickly.
  usePolling(list.reload, hasActive ? 8_000 : 45_000, true);

  const filtered = useMemo(() => {
    const items = list.data ?? [];
    const sorted = [...items].sort(
      (a, b) => new Date(b.requested_at).getTime() - new Date(a.requested_at).getTime(),
    );
    if (filter === "active") return sorted.filter((item) => isActive(item.state));
    if (filter === "completed") return sorted.filter((item) => item.state === "completed");
    if (filter === "failed") return sorted.filter((item) => isFailure(item.state));
    return sorted;
  }, [list.data, filter]);

  const counts = useMemo(() => {
    const items = list.data ?? [];
    return {
      all: items.length,
      active: items.filter((item) => isActive(item.state)).length,
      completed: items.filter((item) => item.state === "completed").length,
      failed: items.filter((item) => isFailure(item.state)).length,
    };
  }, [list.data]);

  return (
    <>
      <PageHeading
        eyebrow="Assessment operations"
        title="Assessments"
        description="Evidence-collection runs dispatched to enrolled endpoints."
        actions={
          <>
            <button type="button" className="ghost" onClick={list.reload}>
              <RefreshCw size={15} aria-hidden="true" /> Refresh
            </button>
            <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
              <Plus size={15} aria-hidden="true" /> New assessment
            </button>
          </>
        }
      />

      <Tabs
        active={filter}
        onChange={setFilter}
        tabs={[
          { id: "all", label: "All", count: counts.all },
          { id: "active", label: "In flight", count: counts.active },
          { id: "completed", label: "Completed", count: counts.completed },
          { id: "failed", label: "Failed", count: counts.failed },
        ]}
      />

      <AsyncSection
        loading={list.loading}
        error={list.error}
        data={list.data}
        onRetry={list.reload}
        skeletonRows={5}
      >
        {() =>
          filtered.length === 0 ? (
            <Empty
              title={filter === "all" ? "No assessments yet" : "Nothing in this state"}
              detail={
                filter === "all"
                  ? "Dispatch an assessment to an enrolled endpoint to begin collecting evidence."
                  : "No assessments currently match this filter."
              }
              action={
                filter === "all" ? (
                  <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
                    <Plus size={15} aria-hidden="true" /> New assessment
                  </button>
                ) : undefined
              }
            />
          ) : (
            <Panel>
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Assessment</th>
                    <th scope="col">Endpoint</th>
                    <th scope="col">Scanners</th>
                    <th scope="col">Requested</th>
                    <th scope="col">State</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item) => (
                    <AssessmentRow
                      key={item.assessment_id}
                      assessment={item}
                      onOpen={() => navigate("assessments", item.assessment_id)}
                    />
                  ))}
                </tbody>
              </table>
            </Panel>
          )
        }
      </AsyncSection>

      <Composer
        open={composerOpen}
        organizationId={organizationId}
        onClose={() => setComposerOpen(false)}
        onCreated={(created) => {
          setComposerOpen(false);
          navigate("assessments", created.assessment_id);
        }}
      />
    </>
  );
}

function AssessmentRow({
  assessment,
  onOpen,
}: {
  assessment: Assessment;
  onOpen: () => void;
}) {
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
        <strong className="mono">{shortId(assessment.assessment_id)}</strong>
        {assessment.schedule_id && <small>via schedule</small>}
      </td>
      <td className="mono">{shortId(assessment.endpoint_id)}</td>
      <td>
        <span className="chip-row tight">
          {assessment.scanner_ids.slice(0, 3).map((id) => (
            <span className="chip static" key={id}>
              {scannerName(id)}
            </span>
          ))}
          {assessment.scanner_ids.length > 3 && (
            <span className="chip static">+{assessment.scanner_ids.length - 3}</span>
          )}
        </span>
      </td>
      <td title={formatDateTime(assessment.requested_at)}>
        {formatRelative(assessment.requested_at)}
      </td>
      <td>
        <StatusBadge
          tone={assessmentTone(assessment.state)}
          label={ASSESSMENT_LABEL[assessment.state] ?? assessment.state}
        />
      </td>
    </tr>
  );
}

/* -------------------------------------------------------------- composer */

function Composer({
  open,
  organizationId,
  onClose,
  onCreated,
}: {
  open: boolean;
  organizationId: string;
  onClose: () => void;
  onCreated: (assessment: Assessment) => void;
}) {
  const [endpointId, setEndpointId] = useState("");
  const [scanners, setScanners] = useState<string[]>(
    DEFAULT_SCANNER_IDS,
  );

  const endpoints = useApi(
    (signal) => fleet.query(organizationId, { limit: 200, sort: "hostname", direction: "asc" }, signal),
    [organizationId],
    { enabled: open },
  );
  const create = useMutation(() => assessments.create(organizationId, endpointId, scanners));

  const submit = useCallback(async () => {
    const created = await create.run();
    if (created) onCreated(created);
  }, [create, onCreated]);

  const selectable = (endpoints.data?.items ?? []).filter(
    (item) => item.lifecycle_status === "active",
  );

  return (
    <Modal open={open} title="New assessment" onClose={onClose}>
      {endpoints.loading && endpoints.data === undefined ? (
        <Skeleton rows={3} />
      ) : endpoints.error ? (
        <ErrorState error={endpoints.error} onRetry={endpoints.reload} />
      ) : selectable.length === 0 ? (
        <Empty
          compact
          title="No assessable endpoints"
          detail="This organization has no active enrolled endpoints to assess."
        />
      ) : (
        <>
          <Field label="Target endpoint" hint="Only active endpoints can receive work.">
            <select
              value={endpointId}
              onChange={(event) => setEndpointId(event.target.value)}
              aria-label="Target endpoint"
            >
              <option value="">Select an endpoint…</option>
              {selectable.map((item) => (
                <option key={item.endpoint_id} value={item.endpoint_id}>
                  {item.hostname ? `${item.hostname} · ` : ""}{shortId(item.endpoint_id)}
                  {item.platform ? ` · ${item.platform}` : ""}
                  {` · ${item.presence_state}`}
                </option>
              ))}
            </select>
          </Field>

          <ScannerPicker selected={scanners} onChange={setScanners} />

          <p className="panel-note">
            The assessment is queued as durable work. The agent receives it on its next outbound
            poll — Raven-X never opens a connection to the endpoint.
          </p>

          {create.error && <ErrorState error={create.error} />}

          <div className="modal-actions">
            <button type="button" className="ghost" onClick={onClose} disabled={create.busy}>
              Cancel
            </button>
            <button
              type="button"
              className="primary"
              onClick={submit}
              disabled={create.busy || !endpointId || scanners.length === 0}
            >
              {create.busy ? "Dispatching…" : "Dispatch assessment"}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

/* ---------------------------------------------------------------- detail */

function ScannerCollectionBadge({ result }: { result: ScannerResultSummary }) {
  if (result.status === "incompatible") {
    return <Badge tone="warn">UNSUPPORTED · Collection unavailable</Badge>;
  }
  if (result.status === "skipped") {
    return <Badge tone="neutral">Not collected</Badge>;
  }
  if (result.status === "failed" && result.error === "READ_FAILED") {
    return <Badge tone="critical">READ_FAILED · Collection failed</Badge>;
  }
  if (result.status === "success" && result.error === null) {
    return result.finding_count > 0
      ? <Badge tone="warn">Security finding detected</Badge>
      : <Badge tone="ok">Successfully collected</Badge>;
  }
  return <Badge tone="critical">COLLECTION_FAILED · Collection status unavailable</Badge>;
}

function QueuedEndpoint({ organizationId, endpointId, onOpen }: {
  organizationId: string;
  endpointId: string;
  onOpen: () => void;
}) {
  const presence = useApi(
    (signal) => fleet.endpointPresence(organizationId, endpointId, signal),
    [organizationId, endpointId],
  );
  usePolling(presence.reload, 6_000, true);
  return (
    <>
      <p>Waiting for the endpoint agent to pick up this assessment.</p>
      {presence.data && !presence.error && (
        <p>Endpoint status · {presence.data.state}. Last seen · {presence.data.last_seen_at
          ? formatDateTime(presence.data.last_seen_at) : "No contact recorded"}.</p>
      )}
      {presence.error && <p>Endpoint presence is currently unavailable.</p>}
      <button type="button" className="link" onClick={onOpen}>View endpoint</button>
    </>
  );
}

function AssessmentDetailView({
  organizationId,
  assessmentId,
  findingId,
  navigate,
}: {
  organizationId: string;
  assessmentId: string;
  findingId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const summary = useApi(
    (signal) => assessments.get(organizationId, assessmentId, signal),
    [organizationId, assessmentId],
  );
  const detail = useApi(
    (signal) => assessments.detail(organizationId, assessmentId, signal),
    [organizationId, assessmentId],
  );

  const live = summary.data ? isActive(summary.data.state) : false;
  const reloadSummary = summary.reload;
  const reloadDetail = detail.reload;
  const reloadBoth = useCallback(() => {
    reloadSummary();
    reloadDetail();
  }, [reloadSummary, reloadDetail]);
  usePolling(reloadBoth, live ? 6_000 : 0, live);

  const [cancelOpen, setCancelOpen] = useState(false);
  const cancel = useMutation(() => assessments.cancel(organizationId, assessmentId));

  const onCancel = useCallback(async () => {
    await cancel.run();
    setCancelOpen(false);
    reloadBoth();
  }, [cancel, reloadBoth]);

  const selectedFinding = useMemo(
    () => detail.data?.findings.find((item) => item.occurrence_id === findingId),
    [detail.data, findingId],
  );

  return (
    <>
      <button type="button" className="back" onClick={() => navigate("assessments")}>
        <ArrowLeft size={15} aria-hidden="true" /> Back to assessments
      </button>

      <AsyncSection
        loading={summary.loading}
        error={summary.error}
        data={summary.data}
        onRetry={summary.reload}
        skeletonRows={4}
      >
        {(assessment) => (
          <>
            <PageHeading
              eyebrow="Assessment run"
              title={shortId(assessment.assessment_id)}
              description={`Endpoint ${shortId(assessment.endpoint_id)} · ${assessment.scanner_ids.length} scanner(s)`}
              actions={
                isActive(assessment.state) ? (
                  <button type="button" className="danger" onClick={() => setCancelOpen(true)}>
                    <Ban size={15} aria-hidden="true" /> Cancel run
                  </button>
                ) : (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => navigate("fleet", assessment.endpoint_id)}
                  >
                    View endpoint
                  </button>
                )
              }
            />

            <Lifecycle assessment={assessment} />

            {cancel.error && <ErrorState error={cancel.error} />}

            <section className="grid-2">
              <Panel title="Run detail" icon={<Radar size={15} aria-hidden="true" />}>
                <DefinitionList
                  items={[
                    [
                      "State",
                      <StatusBadge
                        tone={assessmentTone(assessment.state)}
                        label={ASSESSMENT_LABEL[assessment.state] ?? assessment.state}
                      />,
                    ],
                    ["Requested", formatDateTime(assessment.requested_at)],
                    [
                      "Duration",
                      detail.data
                        ? formatDuration(detail.data.started_at, detail.data.completed_at)
                        : DASH,
                    ],
                    ["Correlation ID", <code className="mono">{assessment.correlation_id}</code>],
                    [
                      "Origin",
                      assessment.schedule_id ? (
                        <button
                          type="button"
                          className="link"
                          onClick={() => navigate("schedules", assessment.schedule_id ?? "")}
                        >
                          Scheduled run
                        </button>
                      ) : (
                        "Manual dispatch"
                      ),
                    ],
                    [
                      "Scanners",
                      <span className="chip-row tight">
                        {assessment.scanner_ids.map((id) => (
                          <span className="chip static" key={id}>
                            {scannerName(id)}
                          </span>
                        ))}
                      </span>,
                    ],
                  ]}
                />
                {assessment.error && (
                  <p className="inline-error">
                    <ShieldAlert size={14} aria-hidden="true" /> {assessment.error}
                  </p>
                )}
              </Panel>

              <Panel title="Scanner execution" icon={<FileSearch size={15} aria-hidden="true" />}>
                {detail.loading && detail.data === undefined ? (
                  <Skeleton rows={3} />
                ) : detail.error ? (
                  <ErrorState error={detail.error} onRetry={detail.reload} />
                ) : detail.data && detail.data.scanner_results.length ? (
                  <>
                  {detail.data.scanner_results.some((result) => result.status !== "success" || result.error !== null) && (
                    <p className="panel-note" role="status">
                      Collection is incomplete. Confirmed findings remain visible; uncollected settings remain unknown.
                    </p>
                  )}
                  <ul className="scanner-results" aria-label="Scanner execution">
                    {detail.data.scanner_results.map((result, index) => (
                      <li key={`${result.scanner_id ?? index}`}>
                        <div>
                          <strong>{scannerName(result.scanner_id)}</strong>
                          <small className="mono">{result.scanner_id ?? DASH}</small>
                        </div>
                        <ScannerCollectionBadge result={result} />
                        <span className="scanner-count">{result.finding_count} findings</span>
                      </li>
                    ))}
                  </ul>
                  </>
                ) : assessment.state === "queued" ? (
                  <QueuedEndpoint key={`${organizationId}/${assessment.endpoint_id}`} organizationId={organizationId}
                    endpointId={assessment.endpoint_id} onOpen={() => navigate("fleet", assessment.endpoint_id)} />
                ) : (
                  <Empty
                    compact
                    title="No scanner results"
                    detail={
                      isActive(assessment.state)
                        ? "Results appear once the agent submits them."
                        : "This run recorded no per-scanner execution evidence."
                    }
                  />
                )}
              </Panel>
            </section>

            <Findings
              organizationId={organizationId}
              assessmentId={assessmentId}
              loading={detail.loading}
              error={detail.error}
              findings={detail.data?.findings}
              total={detail.data?.total_findings ?? 0}
              malformed={detail.data?.malformed_finding_count ?? 0}
              state={assessment.state}
              onRetry={detail.reload}
              onSelect={(occurrenceId) =>
                navigate("assessments", assessmentId, occurrenceId)
              }
            />

            <FindingDrawer
              organizationId={organizationId}
              assessmentId={assessmentId}
              finding={selectedFinding}
              onClose={() => navigate("assessments", assessmentId)}
            />

            <Confirm
              open={cancelOpen}
              title="Cancel assessment"
              message="Request cancellation of this run. Work already delivered to the agent may still complete; the control plane records the cancellation intent."
              confirmLabel="Request cancellation"
              destructive
              busy={cancel.busy}
              onConfirm={onCancel}
              onCancel={() => setCancelOpen(false)}
            />
          </>
        )}
      </AsyncSection>
    </>
  );
}

/** Pipeline visualisation driven by the real lifecycle state. */
function Lifecycle({ assessment }: { assessment: Assessment }) {
  const current = pipelineIndex(assessment.state);
  const failed = isFailure(assessment.state);
  const terminalBad = failed || assessment.state === "cancelled";

  // A terminal outcome does not prove that any earlier stage was reached.
  // The summary API does not include stage timestamps, so display only the
  // observed outcome rather than drawing an invented execution history.
  if (terminalBad || assessment.state === "cancel_requested") {
    return (
      <ol className="lifecycle" aria-label="Assessment lifecycle">
        <li className={`lifecycle-step ${terminalBad ? "failed" : "current"}`}>
          <span className="lifecycle-dot" aria-hidden="true" />
          <span className="lifecycle-label">{ASSESSMENT_LABEL[assessment.state] ?? assessment.state}</span>
        </li>
      </ol>
    );
  }

  return (
    <ol className="lifecycle" aria-label="Assessment lifecycle">
      {ASSESSMENT_PIPELINE.map((stage, index) => {
        const reached = index <= current;
        const isCurrent = index === current;
        const state: "done" | "current" | "pending" = isCurrent && !isTerminalStage(assessment.state, stage)
            ? "current"
            : reached
              ? "done"
              : "pending";
        return (
          <li key={stage} className={`lifecycle-step ${state}`}>
            <span className="lifecycle-dot" aria-hidden="true" />
            <span className="lifecycle-label">{ASSESSMENT_LABEL[stage]}</span>
          </li>
        );
      })}
    </ol>
  );
}

function isTerminalStage(state: AssessmentState, stage: AssessmentState): boolean {
  return state === "completed" && stage === "completed";
}

/* -------------------------------------------------------------- findings */

function Findings({
  organizationId,
  assessmentId,
  loading,
  error,
  findings,
  total,
  malformed,
  state,
  onRetry,
  onSelect,
}: {
  organizationId: string;
  assessmentId: string;
  loading: boolean;
  error: ReturnType<typeof useApi>["error"];
  findings: FindingDetail[] | undefined;
  total: number;
  malformed: number;
  state: AssessmentState;
  onRetry: () => void;
  onSelect: (occurrenceId: string) => void;
}) {
  void organizationId;
  void assessmentId;
  const active = isActive(state);
  const sorted = useMemo(
    () =>
      [...(findings ?? [])].sort(
        (a, b) =>
          SEVERITY_RANK[normalizeSeverity(b.severity)] -
          SEVERITY_RANK[normalizeSeverity(a.severity)],
      ),
    [findings],
  );

  return (
    <Panel
      title="Findings"
      icon={<ShieldAlert size={15} aria-hidden="true" />}
      actions={
        total > 0 && (
          <span className="panel-meta">
            {sorted.length} of {total} shown
            {malformed > 0 ? ` · ${malformed} malformed skipped` : ""}
          </span>
        )
      }
    >
      {loading && findings === undefined ? (
        <Skeleton rows={4} />
      ) : error ? (
        <ErrorState error={error} onRetry={onRetry} />
      ) : sorted.length === 0 ? (
        <Empty
          compact
          title={active ? "No findings yet" : "No findings recorded"}
          detail={
            active
              ? "Findings appear as the agent submits scanner results."
              : state === "completed"
                ? "This assessment completed without recorded findings. Review scanner execution for coverage and errors; zero findings does not establish that the machine is secure."
                : `This assessment ended as ${(ASSESSMENT_LABEL[state] ?? state).toLowerCase()} without recorded findings. It does not provide a completed scan.`
          }
        />
      ) : (
        <ul className="finding-list detailed">
          {sorted.map((finding) => (
            <li key={finding.occurrence_id}>
              <button
                type="button"
                className="finding-row"
                onClick={() => onSelect(finding.occurrence_id)}
              >
                <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                <span className="finding-row-body">
                  <strong>{finding.title}</strong>
                  <small>
                    {scannerName(finding.scanner_id)}
                    {finding.observed_at ? ` · ${formatRelative(finding.observed_at)}` : ""}
                    {finding.evidence.length
                      ? ` · ${finding.evidence.length} evidence item(s)`
                      : ""}
                  </small>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/** Finding detail: severity and evidence first, provenance below. */
function FindingDrawer({
  organizationId,
  assessmentId,
  finding,
  onClose,
}: {
  organizationId: string;
  assessmentId: string;
  finding: FindingDetail | undefined;
  onClose: () => void;
}) {
  const recurrence = useApi(
    (signal) =>
      assessments.findingRecurrence(
        organizationId,
        assessmentId,
        finding?.occurrence_id ?? "",
        signal,
      ),
    [organizationId, assessmentId, finding?.occurrence_id],
    { enabled: Boolean(finding) },
  );

  return (
    <Drawer open={Boolean(finding)} title={finding?.title ?? "Finding"} onClose={onClose} width={620}>
      {finding && (
        <>
          <div className="finding-headline">
            <SeverityBadge severity={normalizeSeverity(finding.severity)} />
            <span className="mono">{scannerName(finding.scanner_id)}</span>
          </div>

          <section className="drawer-section">
            <h3>What was observed</h3>
            <p className="finding-description">
              {finding.description || "The scanner did not provide a description for this finding."}
            </p>
          </section>

          <section className="drawer-section">
            <h3>Evidence</h3>
            {finding.evidence.length ? (
              <ul className="evidence-list">
                {finding.evidence.map((item, index) => (
                  <li key={`${item.source}-${index}`}>
                    <strong>{item.source}</strong>
                    {item.description && <p>{item.description}</p>}
                    {Object.keys(item.values).length > 0 && (
                      <dl className="evidence-values">
                        {Object.entries(item.values).map(([key, value]) => (
                          <div key={key}>
                            <dt>{key}</dt>
                            <dd className="mono">{typeof value === "object" && value !== null
                              ? <pre className="data-block">{JSON.stringify(value, null, 2)}</pre>
                              : String(value)}</dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="panel-note">
                No structured evidence was attached. Note that the control plane strips
                command-bearing fields from evidence before it reaches this interface.
              </p>
            )}
          </section>

          <AnalystPanel finding={finding} />

          <section className="drawer-section">
            <h3>Provenance</h3>
            <DefinitionList
              items={[
                ["Occurrence ID", <code className="mono">{finding.occurrence_id}</code>],
                ["Endpoint", <code className="mono">{shortId(finding.endpoint_id)}</code>],
                ["Scanner", finding.scanner_id ?? DASH],
                ["Observed", formatDateTime(finding.observed_at)],
              ]}
            />
          </section>

          <section className="drawer-section">
            <h3>Recurrence</h3>
            {recurrence.loading ? (
              <Skeleton rows={2} />
            ) : recurrence.error ? (
              <p className="panel-note">
                Recurrence history is unavailable ({recurrence.error.status}).
              </p>
            ) : recurrence.data ? (
              <pre className="data-block">{JSON.stringify(recurrence.data, null, 2)}</pre>
            ) : (
              <p className="panel-note">No recurrence history was returned.</p>
            )}
          </section>
        </>
      )}
    </Drawer>
  );
}
