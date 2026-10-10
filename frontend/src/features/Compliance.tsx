/**
 * Compliance — framework posture, control detail and immutable snapshots.
 *
 * UNKNOWN is preserved as a first-class state throughout. The backend never
 * treats missing evidence as compliant and neither does this screen.
 */
import { Camera, ClipboardCheck, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { compliance } from "../api/endpoints";
import { Donut, Meter } from "../components/charts";
import {
  AsyncSection,
  Badge,
  DefinitionList,
  Drawer,
  Empty,
  ErrorState,
  PageHeading,
  Panel,
  Skeleton,
  StatusBadge,
  SuccessNote,
  Tabs,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { COMPLIANCE_LABEL } from "../lib/domain";
import { formatDateTime, formatRelative, percent } from "../lib/format";
import { scannerName } from "../lib/scanners";
import type { ComplianceControl, CompliancePosture } from "../types/api";

const STATUS_COLORS: Record<string, string> = {
  compliant: "var(--ok)",
  non_compliant: "var(--critical)",
  unknown: "var(--warn)",
  not_applicable: "var(--muted)",
};

export function Compliance({ organizationId }: { organizationId: string }) {
  const frameworks = useApi(
    (signal) => compliance.frameworks(organizationId, signal),
    [organizationId],
  );
  const [frameworkId, setFrameworkId] = useState<string | null>(null);
  const active = frameworkId ?? frameworks.data?.[0]?.framework_id ?? null;

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
            {items.length > 1 && (
              <Tabs
                active={active ?? items[0].framework_id}
                onChange={setFrameworkId}
                tabs={items.map((framework) => ({
                  id: framework.framework_id,
                  label: framework.name,
                }))}
              />
            )}
            {active && <FrameworkView organizationId={organizationId} frameworkId={active} />}
          </>
        )}
      </AsyncSection>
    </>
  );
}

function FrameworkView({
  organizationId,
  frameworkId,
}: {
  organizationId: string;
  frameworkId: string;
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
        <Panel title="POSTURE" icon={<ShieldCheck size={15} aria-hidden="true" />}>
          {summary.loading && summary.data === undefined ? (
            <Skeleton rows={4} />
          ) : summary.error ? (
            <ErrorState error={summary.error} onRetry={summary.reload} />
          ) : summary.data ? (
            <PostureView posture={summary.data} />
          ) : null}
        </Panel>

        <Panel
          title="IMMUTABLE HISTORY"
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
                      <b className="tone-ok">{snapshot.compliant ?? "—"}</b>
                      <b className="tone-critical">{snapshot.non_compliant ?? "—"}</b>
                      <b className="tone-warn">{snapshot.unknown ?? "—"}</b>
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
      </section>

      <Panel title="CONTROLS" icon={<ClipboardCheck size={15} aria-hidden="true" />}>
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
                This framework declares {framework.data.control_ids.length} control(s); the detail
                route did not return their definitions.
              </p>
            )}
          </>
        ) : null}
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
          centerValue={`${assessable ? percent(posture.compliant, assessable) : 0}%`}
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
