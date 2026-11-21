/**
 * Compliance — framework posture, control detail and immutable snapshots.
 *
 * UNKNOWN is preserved as a first-class state throughout. The backend never
 * treats missing evidence as compliant and neither does this screen.
 */
import { Camera, ClipboardCheck, Server, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { compliance, fleet } from "../api/endpoints";
import { Donut, Meter } from "../components/charts";
import {
  AsyncSection,
  Badge,
  DefinitionList,
  Drawer,
  Empty,
  ErrorState,
  Field,
  PageHeading,
  Panel,
  Skeleton,
  StatusBadge,
  SuccessNote,
  Tabs,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { COMPLIANCE_LABEL } from "../lib/domain";
import { formatDateTime, formatRelative, percent, titleCase } from "../lib/format";
import { scannerName } from "../lib/scanners";
import type { ComplianceControl, CompliancePosture } from "../types/api";

const STATUS_COLORS: Record<string, string> = {
  compliant: "var(--ok)",
  non_compliant: "var(--critical)",
  unknown: "var(--warn)",
  not_applicable: "var(--muted)",
};

type Navigate = (section: string, ...params: string[]) => void;

export function Compliance({ organizationId, navigate }: { organizationId: string; navigate: Navigate }) {
  const frameworks = useApi(
    (signal) => compliance.frameworks(organizationId, signal),
    [organizationId],
  );
  const [frameworkId, setFrameworkId] = useState<string | null>(null);
  const active = frameworks.data?.find((item) => item.framework_id === frameworkId)?.framework_id ??
    frameworks.data?.[0]?.framework_id;

  return (
    <>
      <PageHeading
        eyebrow="Governance posture"
        title="Compliance"
        description="Control evaluation across the fleet. Unknown is never reported as compliant."
      />

      <AsyncSection
        loading={frameworks.loading}
        error={frameworks.error}
        data={frameworks.data}
        onRetry={frameworks.reload}
        empty={
          <Empty
            title="No compliance frameworks"
            detail="No framework is visible for this organization, or your role does not permit reading them."
          />
        }
      >
        {(items) => (
          <>
            {items.length > 1 && active ? (
              <Tabs
                label="Compliance frameworks"
                active={active}
                onChange={setFrameworkId}
                tabs={items.map((framework) => ({
                  id: framework.framework_id,
                  label: framework.name,
                }))}
              >
                <FrameworkView key={active} organizationId={organizationId} frameworkId={active} navigate={navigate} />
              </Tabs>
            ) : active ? (
              <FrameworkView key={active} organizationId={organizationId} frameworkId={active} navigate={navigate} />
            ) : null}
          </>
        )}
      </AsyncSection>
    </>
  );
}

function FrameworkView({
  organizationId,
  frameworkId,
  navigate,
}: {
  organizationId: string;
  frameworkId: string;
  navigate: Navigate;
}) {
  const framework = useApi(
    (signal) => compliance.framework(organizationId, frameworkId, signal),
    [organizationId, frameworkId],
  );
  const summary = useApi(
    (signal) => compliance.summary(organizationId, frameworkId, signal),
    [organizationId, frameworkId],
  );
  const snapshots = useApi(
    (signal) => compliance.snapshots(organizationId, frameworkId, 20, 0, signal),
    [organizationId, frameworkId],
  );

  const [selectedControl, setSelectedControl] = useState<ComplianceControl | null>(null);
  const capture = useMutation(() => compliance.createSnapshot(organizationId, frameworkId));
  const [captured, setCaptured] = useState(false);

  const snapshotItems = useMemo(() => {
    const data = snapshots.data;
    if (!data) return [];
    return Array.isArray(data) ? data : (data.items ?? []);
  }, [snapshots.data]);

  return (
    <>
      <section className="grid-2">
        <Panel title={framework.data?.name ?? "Framework posture"} icon={<ShieldCheck size={15} aria-hidden="true" />}>
          {summary.loading && summary.data === undefined ? (
            <Skeleton rows={4} />
          ) : summary.error ? (
            <ErrorState error={summary.error} onRetry={summary.reload} />
          ) : summary.data ? (
            <PostureView posture={summary.data} />
          ) : (
            <Empty compact title="Posture unavailable" detail="The server did not return an evaluation summary." />
          )}
        </Panel>

        <Panel title="Controls" icon={<ClipboardCheck size={15} aria-hidden="true" />}>
          {framework.loading && framework.data === undefined ? (
            <Skeleton rows={4} />
          ) : framework.error ? (
            <ErrorState error={framework.error} onRetry={framework.reload} />
          ) : framework.data ? (
            <>
              <p className="panel-note">{framework.data.description}</p>
              {framework.data.controls?.length ? (
                <ul className="control-list">
                  {framework.data.controls.map((control) => (
                    <li key={control.control_id}>
                      <Badge tone={control.capability === "full" ? "ok" : "info"}>
                        {control.capability === "full" ? "Full" : "Detection"}
                      </Badge>
                      <div>
                        <button
                          type="button"
                          className="link strong"
                          onClick={() => setSelectedControl(control)}
                        >
                          {control.title}
                        </button>
                        <small className="mono">{control.control_id}</small>
                      </div>
                      <span className="control-age">
                        {control.applicability_platform ?? "Any platform"}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="panel-note">
                  This framework declares {framework.data.control_ids?.length ?? 0} control(s); the detail
                  route did not return their definitions.
                </p>
              )}
            </>
          ) : null}
        </Panel>
      </section>

      <MachineEvaluations organizationId={organizationId} frameworkId={frameworkId}
        controls={framework.data?.controls ?? []} navigate={navigate} />

      <Panel
        title="Immutable history"
        icon={<Camera size={15} aria-hidden="true" />}
        actions={
          <button
            type="button"
            className="ghost"
            disabled={capture.busy}
            onClick={async () => {
              const result = await capture.run();
              if (result) {
                setCaptured(true);
                snapshots.reload();
              }
            }}
          >
            {capture.busy ? "Capturing…" : "Capture snapshot"}
          </button>
        }
      >
        {capture.error && <ErrorState error={capture.error} />}
        {captured && <SuccessNote>Snapshot captured and stored immutably.</SuccessNote>}
        {snapshots.loading && snapshots.data === undefined ? (
          <Skeleton rows={3} />
        ) : snapshots.error ? (
          <ErrorState error={snapshots.error} onRetry={snapshots.reload} />
        ) : snapshotItems.length ? (
          <ul className="snapshot-list">
            {snapshotItems.slice(0, 8).map((snapshot, index) => {
              const id = String(snapshot.snapshot_id ?? index);
              const at = snapshot.captured_at ?? snapshot.created_at ?? null;
              return (
                <li key={id}>
                  <div>
                    <strong>{formatDateTime(at)}</strong>
                    <small className="mono">{id.slice(0, 8)}</small>
                  </div>
                  <span className="snapshot-counts">
                    <b className="tone-ok">{snapshot.compliant ?? "—"} compliant</b>
                    <b className="tone-critical">{snapshot.non_compliant ?? "—"} non-compliant</b>
                    <b className="tone-warn">{snapshot.unknown ?? "—"} unknown</b>
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <Empty
            compact
            title="No snapshots captured"
            detail="Capture a snapshot to create an immutable record of current posture."
          />
        )}
      </Panel>

      <Drawer
        open={Boolean(selectedControl)}
        title={selectedControl?.title ?? "Control"}
        onClose={() => setSelectedControl(null)}
        width={580}
      >
        {selectedControl && (
          <>
            <section className="drawer-section">
              <h3>What this control checks</h3>
              <p className="finding-description">{selectedControl.description}</p>
            </section>
            <section className="drawer-section">
              <h3>Definition</h3>
              <DefinitionList
                items={[
                  ["Control ID", <code className="mono">{selectedControl.control_id}</code>],
                  ["Applies to", selectedControl.applicability_platform ?? "Any platform"],
                  [
                    "Evaluation capability",
                    selectedControl.capability === "full"
                      ? "Full — pass and fail can both be established"
                      : "Detection only — a violation can be observed, but a clean result is not proof of compliance",
                  ],
                ]}
              />
            </section>
            <section className="drawer-section">
              <h3>Evidence required</h3>
              <ul className="evidence-list">
                {selectedControl.evidence_requirements.map((requirement, index) => (
                  <li key={`${requirement.scanner_id}-${index}`}>
                    <strong>{scannerName(requirement.scanner_id)}</strong>
                    <p className="mono">
                      {requirement.scanner_id} · {requirement.rule_id}
                    </p>
                  </li>
                ))}
              </ul>
            </section>
          </>
        )}
      </Drawer>
    </>
  );
}

function MachineEvaluations({ organizationId, frameworkId, controls, navigate }: {
  organizationId: string; frameworkId: string; controls: ComplianceControl[]; navigate: Navigate;
}) {
  const [chosen, setChosen] = useState("");
  const machines = useApi((signal) => fleet.query(organizationId, { limit: 100 }, signal), [organizationId]);
  const items = machines.data?.items.filter((machine) => machine.lifecycle_status !== "revoked") ?? [];
  const endpointId = (items.find((machine) => machine.endpoint_id === chosen) ?? items[0])?.endpoint_id;
  return (
    <Panel title="Machine evaluations" icon={<Server size={15} aria-hidden="true" />}>
      <AsyncSection loading={machines.loading} data={machines.data} error={machines.error} onRetry={machines.reload}>
        {(data) => endpointId ? <>
          <div className="field-compact">
            <Field label="Machine">
              <select value={endpointId} onChange={(event) => setChosen(event.target.value)}>
                {items.map((machine) => (
                  <option key={machine.endpoint_id} value={machine.endpoint_id}>{machine.hostname}</option>
                ))}
              </select>
            </Field>
          </div>
          {data.total > data.items.length && <p className="panel-note">Showing the first {data.items.length} fleet records.</p>}
          <MachineControlRows key={endpointId} organizationId={organizationId} frameworkId={frameworkId}
            endpointId={endpointId} controls={controls} navigate={navigate} />
        </> : <Empty compact title="No machines available" detail="Enroll a machine to view its control evaluations." />}
      </AsyncSection>
    </Panel>
  );
}

function MachineControlRows({ organizationId, frameworkId, endpointId, controls, navigate }: {
  organizationId: string; frameworkId: string; endpointId: string;
  controls: ComplianceControl[]; navigate: Navigate;
}) {
  const evaluations = useApi(
    (signal) => compliance.endpointEvaluation(organizationId, endpointId, frameworkId, signal),
    [organizationId, endpointId, frameworkId],
  );
  return (
    <AsyncSection loading={evaluations.loading} data={evaluations.data} error={evaluations.error}
      onRetry={evaluations.reload}
      empty={<Empty compact title="No evaluations returned" detail="The server returned no control results for this machine." />}>
      {(rows) => <div className="table-scroll"><table className="data-table">
        <thead><tr><th>Control</th><th>Status</th><th>Evidence</th><th>Assessment</th></tr></thead>
        <tbody>{rows.map((row) => <tr key={row.control_id}>
          <td>{controls.find((control) => control.control_id === row.control_id)?.title ?? row.control_id}</td>
          <td><Badge tone={row.status === "compliant" ? "ok" : row.status === "non_compliant" ? "critical" : row.status === "unknown" ? "warn" : "neutral"}>
            {COMPLIANCE_LABEL[row.status]}
          </Badge></td>
          <td>{row.evidence_summary || titleCase(row.reason)}</td>
          <td>{row.source_assessment_id
            ? <button type="button" className="link" onClick={() => navigate("assessments", row.source_assessment_id!)}>View assessment</button>
            : "No source assessment"}</td>
        </tr>)}</tbody>
      </table></div>}
    </AsyncSection>
  );
}

function PostureView({ posture }: { posture: CompliancePosture }) {
  const total =
    posture.compliant + posture.non_compliant + posture.unknown + posture.not_applicable;
  const assessable = posture.compliant + posture.non_compliant;
  const slices = (["compliant", "non_compliant", "unknown", "not_applicable"] as const)
    .map((key) => ({
      label: COMPLIANCE_LABEL[key],
      value: posture[key],
      color: STATUS_COLORS[key],
    }))
    .filter((slice) => slice.value > 0);

  return (
    <>
      {slices.length ? (
        <Donut
          slices={slices}
          centerValue={assessable ? `${percent(posture.compliant, assessable)}%` : "—"}
          centerLabel="OF ASSESSABLE"
        />
      ) : (
        <Empty
          compact
          title="No control evaluations"
          detail="No endpoint has produced compliance evidence for this framework."
        />
      )}

      <Meter
        value={posture.endpoints_evaluated}
        max={posture.endpoints_examined || 1}
        label="Endpoint coverage"
        tone="var(--accent)"
      />

      <DefinitionList
        items={[
          ["Controls evaluated", posture.controls_evaluated],
          ["Endpoints evaluated", `${posture.endpoints_evaluated} of ${posture.endpoints_examined}`],
          [
            "Evaluation complete",
            <StatusBadge
              tone={posture.evaluation_complete ? "ok" : "warn"}
              label={posture.evaluation_complete ? "Complete" : "Bounded — not all endpoints examined"}
            />,
          ],
          ["Framework version", posture.framework_version],
          ["Evaluated", formatRelative(posture.evaluated_at)],
        ]}
      />

      {posture.unknown > 0 && (
        <p className="panel-note warn">
          {posture.unknown} control evaluation(s) are <strong>Unknown</strong> — evidence was
          missing, stale, or the scanner did not run. Unknown is never counted as compliant.
        </p>
      )}
      {total === 0 && (
        <p className="panel-note">No controls have been evaluated for this organization yet.</p>
      )}
    </>
  );
}
