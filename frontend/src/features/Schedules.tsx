/**
 * Schedules — recurring assessment definitions and their execution history.
 *
 * Backed by `/assessment-schedules`. Target resolution supports the three
 * backend target types (explicit endpoints, endpoint group, saved fleet scope).
 */
import { History, Pause, Play, Plus, Trash2 } from "lucide-react";
import { useCallback, useState } from "react";
import { groups, schedules, scopes } from "../api/endpoints";
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
  Skeleton,
  StatusBadge,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { DASH, formatDateTime, formatRelative, shortId, titleCase } from "../lib/format";
import { DEFAULT_SCANNER_IDS, KNOWN_SCANNERS, scannerName } from "../lib/scanners";
import type { Schedule, ScheduleStatus } from "../types/api";

const DAY_LABEL = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function statusTone(status: ScheduleStatus) {
  if (status === "active") return "ok" as const;
  if (status === "paused") return "warn" as const;
  return "neutral" as const;
}

function describeRecurrence(schedule: Schedule): string {
  const { recurrence } = schedule;
  const at =
    recurrence.hour !== null && recurrence.hour !== undefined
      ? ` at ${String(recurrence.hour).padStart(2, "0")}:${String(recurrence.minute ?? 0).padStart(2, "0")} ${recurrence.timezone}`
      : "";
  if (recurrence.frequency === "daily") {
    return recurrence.interval > 1 ? `Every ${recurrence.interval} days${at}` : `Daily${at}`;
  }
  if (recurrence.frequency === "weekly") {
    const days = recurrence.days_of_week.map((day) => DAY_LABEL[day] ?? day).join(", ");
    return `Weekly on ${days || "unspecified days"}${at}`;
  }
  return `Every ${recurrence.interval} hour(s)`;
}

function describeTarget(schedule: Schedule): string {
  const target = schedule.target;
  if (!target) return `${schedule.target_endpoint_ids.length} endpoint(s)`;
  if (target.type === "endpoint_group") return `Group ${shortId(target.reference_id ?? "")}`;
  if (target.type === "saved_fleet_scope") return `Scope ${shortId(target.reference_id ?? "")}`;
  return `${target.endpoint_ids.length} explicit endpoint(s)`;
}

export function Schedules({
  organizationId,
  scheduleId,
  navigate,
}: {
  organizationId: string;
  scheduleId?: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const list = useApi((signal) => schedules.list(organizationId, signal), [organizationId]);
  const [composerOpen, setComposerOpen] = useState(false);
  const [pendingRevoke, setPendingRevoke] = useState<Schedule | null>(null);

  const pause = useMutation((id: string) => schedules.pause(organizationId, id));
  const resume = useMutation((id: string) => schedules.resume(organizationId, id));
  const revoke = useMutation((id: string) => schedules.revoke(organizationId, id));

  const act = useCallback(
    async (action: typeof pause, id: string) => {
      await action.run(id);
      list.reload();
    },
    [list],
  );

  const selected = (list.data ?? []).find((item) => item.schedule_id === scheduleId);

  return (
    <>
      <PageHeading
        eyebrow="Recurring operations"
        title="Schedules"
        description="Assessment schedules evaluated by the control-plane scheduler worker."
        actions={
          <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
            <Plus size={15} aria-hidden="true" /> New schedule
          </button>
        }
      />

      {(pause.error || resume.error || revoke.error) && (
        <ErrorState error={(pause.error ?? resume.error ?? revoke.error)!} />
      )}

      <AsyncSection
        loading={list.loading}
        error={list.error}
        data={list.data}
        onRetry={list.reload}
        skeletonRows={4}
        empty={
          <Empty
            title="No schedules defined"
            detail="Create a schedule to assess endpoints on a recurring cadence."
            action={
              <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
                <Plus size={15} aria-hidden="true" /> New schedule
              </button>
            }
          />
        }
      >
        {(items) => (
          <Panel>
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Schedule</th>
                  <th scope="col">Cadence</th>
                  <th scope="col">Target</th>
                  <th scope="col">Next run</th>
                  <th scope="col">Last run</th>
                  <th scope="col">Status</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {items.map((schedule) => (
                  <tr key={schedule.schedule_id}>
                    <td>
                      <button
                        type="button"
                        className="link strong"
                        onClick={() => navigate("schedules", schedule.schedule_id)}
                      >
                        {schedule.name}
                      </button>
                      <small className="chip-row tight">
                        {schedule.scanner_ids.slice(0, 2).map((id) => (
                          <span className="chip static" key={id}>
                            {scannerName(id)}
                          </span>
                        ))}
                        {schedule.scanner_ids.length > 2 && (
                          <span className="chip static">+{schedule.scanner_ids.length - 2}</span>
                        )}
                      </small>
                    </td>
                    <td>{describeRecurrence(schedule)}</td>
                    <td>{describeTarget(schedule)}</td>
                    <td title={formatDateTime(schedule.next_run_at)}>
                      {schedule.status === "active" ? formatRelative(schedule.next_run_at) : DASH}
                    </td>
                    <td title={formatDateTime(schedule.last_run_at)}>
                      {formatRelative(schedule.last_run_at)}
                    </td>
                    <td>
                      <StatusBadge
                        tone={statusTone(schedule.status)}
                        label={titleCase(schedule.status)}
                      />
                    </td>
                    <td className="row-actions">
                      {schedule.status === "active" && (
                        <button
                          type="button"
                          className="icon-button"
                          aria-label={`Pause ${schedule.name}`}
                          disabled={pause.busy}
                          onClick={() => act(pause, schedule.schedule_id)}
                        >
                          <Pause size={15} />
                        </button>
                      )}
                      {schedule.status === "paused" && (
                        <button
                          type="button"
                          className="icon-button"
                          aria-label={`Resume ${schedule.name}`}
                          disabled={resume.busy}
                          onClick={() => act(resume, schedule.schedule_id)}
                        >
                          <Play size={15} />
                        </button>
                      )}
                      {schedule.status !== "revoked" && (
                        <button
                          type="button"
                          className="icon-button danger-ghost"
                          aria-label={`Revoke ${schedule.name}`}
                          onClick={() => setPendingRevoke(schedule)}
                        >
                          <Trash2 size={15} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        )}
      </AsyncSection>

      <ScheduleDrawer
        organizationId={organizationId}
        schedule={selected}
        onClose={() => navigate("schedules")}
      />

      <ScheduleComposer
        open={composerOpen}
        organizationId={organizationId}
        onClose={() => setComposerOpen(false)}
        onCreated={() => {
          setComposerOpen(false);
          list.reload();
        }}
      />

      <Confirm
        open={Boolean(pendingRevoke)}
        title="Revoke schedule"
        message={`Revoke "${pendingRevoke?.name ?? ""}"? This is permanent — a revoked schedule cannot be resumed.`}
        confirmLabel="Revoke"
        destructive
        busy={revoke.busy}
        onConfirm={async () => {
          if (pendingRevoke) await act(revoke, pendingRevoke.schedule_id);
          setPendingRevoke(null);
        }}
        onCancel={() => setPendingRevoke(null)}
      />
    </>
  );
}


function ScheduleDrawer({
  organizationId,
  schedule,
  onClose,
}: {
  organizationId: string;
  schedule: Schedule | undefined;
  onClose: () => void;
}) {
  const runs = useApi(
    (signal) => schedules.runs(organizationId, schedule?.schedule_id ?? "", signal),
    [organizationId, schedule?.schedule_id],
    { enabled: Boolean(schedule) },
  );

  return (
    <Drawer open={Boolean(schedule)} title={schedule?.name ?? "Schedule"} onClose={onClose} width={620}>
      {schedule && (
        <>
          <section className="drawer-section">
            <h3>Definition</h3>
            <DefinitionList
              items={[
                ["Status", <StatusBadge tone={statusTone(schedule.status)} label={titleCase(schedule.status)} />],
                ["Cadence", describeRecurrence(schedule)],
                ["Timezone", schedule.recurrence.timezone],
                ["Target", describeTarget(schedule)],
                ["Next run", schedule.status === "active" ? formatDateTime(schedule.next_run_at) : DASH],
                ["Last run", formatDateTime(schedule.last_run_at)],
                ["Overlap policy", titleCase(schedule.overlap_policy)],
                [
                  "Scanners",
                  <span className="chip-row tight">
                    {schedule.scanner_ids.map((id) => (
                      <span className="chip static" key={id}>
                        {scannerName(id)}
                      </span>
                    ))}
                  </span>,
                ],
              ]}
            />
          </section>

          <section className="drawer-section">
            <h3>
              <History size={14} aria-hidden="true" /> Execution history
            </h3>
            {runs.loading && runs.data === undefined ? (
              <Skeleton rows={3} />
            ) : runs.error ? (
              <ErrorState error={runs.error} onRetry={runs.reload} />
            ) : runs.data && runs.data.length ? (
              <ul className="run-list">
                {runs.data.map((run) => (
                  <li key={run.run_id}>
                    <Badge tone={run.status === "created" ? "ok" : run.status === "failed" ? "critical" : "warn"}>
                      {titleCase(run.status)}
                    </Badge>
                    <div>
                      <strong>{formatDateTime(run.scheduled_for)}</strong>
                      <small>
                        {run.assessment_ids.length} assessment(s) created
                        {run.resolved_endpoint_ids.length
                          ? ` · ${run.resolved_endpoint_ids.length} endpoint(s) resolved`
                          : ""}
                        {run.reason ? ` · ${run.reason}` : ""}
                      </small>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty compact title="No runs recorded" detail="This schedule has not executed yet." />
            )}
          </section>
        </>
      )}
    </Drawer>
  );
}

function ScheduleComposer({
  open,
  organizationId,
  onClose,
  onCreated,
}: {
  open: boolean;
  organizationId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [frequency, setFrequency] = useState<"daily" | "weekly" | "interval">("daily");
  const [hour, setHour] = useState(2);
  const [interval, setIntervalValue] = useState(1);
  const [days, setDays] = useState<number[]>([0]);
  const [targetKind, setTargetKind] = useState<"endpoint_group" | "saved_fleet_scope">(
    "endpoint_group",
  );
  const [reference, setReference] = useState("");
  const [scanners, setScanners] = useState<string[]>(
    DEFAULT_SCANNER_IDS,
  );

  const groupList = useApi((signal) => groups.list(organizationId, signal), [organizationId], {
    enabled: open,
  });
  const scopeList = useApi((signal) => scopes.list(organizationId, signal), [organizationId], {
    enabled: open,
  });

  const create = useMutation(() =>
    schedules.create(organizationId, {
      name,
      scanner_ids: scanners,
      recurrence:
        frequency === "weekly"
          ? { frequency, hour, minute: 0, days_of_week: days, timezone: "UTC" }
          : frequency === "daily"
            ? { frequency, hour, minute: 0, timezone: "UTC" }
            : { frequency, interval, timezone: "UTC" },
      target: { type: targetKind, reference_id: reference },
    }),
  );

  const options = targetKind === "endpoint_group" ? groupList.data ?? [] : scopeList.data ?? [];

  const submit = useCallback(async () => {
    const created = await create.run();
    if (created) onCreated();
  }, [create, onCreated]);

  return (
    <Modal open={open} title="New assessment schedule" onClose={onClose}>
      <Field label="Name">
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Nightly Windows baseline"
          maxLength={200}
        />
      </Field>

      <Field label="Frequency">
        <select
          value={frequency}
          onChange={(event) => setFrequency(event.target.value as typeof frequency)}
        >
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="interval">Fixed interval</option>
        </select>
      </Field>

      {frequency === "interval" ? (
        <Field label="Interval (hours)">
          <input
            type="number"
            min={1}
            value={interval}
            onChange={(event) => setIntervalValue(Number(event.target.value))}
          />
        </Field>
      ) : (
        <Field label="Hour (UTC)">
          <input
            type="number"
            min={0}
            max={23}
            value={hour}
            onChange={(event) => setHour(Number(event.target.value))}
          />
        </Field>
      )}

      {frequency === "weekly" && (
        <Field label="Days of week">
          <div className="chip-row">
            {DAY_LABEL.map((label, index) => (
              <button
                key={label}
                type="button"
                aria-pressed={days.includes(index)}
                className={days.includes(index) ? "chip active" : "chip"}
                onClick={() =>
                  setDays((current) =>
                    current.includes(index)
                      ? current.filter((day) => day !== index)
                      : [...current, index],
                  )
                }
              >
                {label}
              </button>
            ))}
          </div>
        </Field>
      )}

      <Field
        label="Target"
        hint="Targets resolve at run time, so endpoints added later are included automatically."
      >
        <select
          value={targetKind}
          onChange={(event) => {
            setTargetKind(event.target.value as typeof targetKind);
            setReference("");
          }}
        >
          <option value="endpoint_group">Endpoint group</option>
          <option value="saved_fleet_scope">Saved fleet scope</option>
        </select>
      </Field>

      <Field label={targetKind === "endpoint_group" ? "Group" : "Scope"}>
        <select value={reference} onChange={(event) => setReference(event.target.value)}>
          <option value="">Select…</option>
          {options.map((option) => {
            const id =
              "group_id" in option ? option.group_id : (option as { scope_id: string }).scope_id;
            return (
              <option key={id} value={id}>
                {option.name}
              </option>
            );
          })}
        </select>
      </Field>

      {options.length === 0 && !groupList.loading && !scopeList.loading && (
        <p className="panel-note">
          No {targetKind === "endpoint_group" ? "groups" : "scopes"} exist yet. Create one from
          Groups &amp; Scopes first.
        </p>
      )}

      <div className="scanner-picker">
        <span className="field-label">Scanners</span>
        <div className="chip-row">
          {KNOWN_SCANNERS.map((scanner) => (
            <button
              key={scanner.scanner_id}
              type="button"
              aria-pressed={scanners.includes(scanner.scanner_id)}
              className={scanners.includes(scanner.scanner_id) ? "chip active" : "chip"}
              onClick={() =>
                setScanners((current) =>
                  current.includes(scanner.scanner_id)
                    ? current.filter((id) => id !== scanner.scanner_id)
                    : [...current, scanner.scanner_id],
                )
              }
            >
              {scanner.name}
            </button>
          ))}
        </div>
      </div>

      {create.error && <ErrorState error={create.error} />}

      <div className="modal-actions">
        <button type="button" className="ghost" onClick={onClose} disabled={create.busy}>
          Cancel
        </button>
        <button
          type="button"
          className="primary"
          onClick={submit}
          disabled={create.busy || !name.trim() || !reference || scanners.length === 0}
        >
          {create.busy ? "Creating…" : "Create schedule"}
        </button>
      </div>
    </Modal>
  );
}
