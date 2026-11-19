/**
 * Current machine/fleet evidence reports and historical compliance snapshots.
 * JSON/CSV exports contain stored facts; Print/PDF uses the browser print flow.
 */
import { Download, FileText } from "lucide-react";
import { useMemo, useState } from "react";
import { compliance } from "../api/endpoints";
import {
  AsyncSection,
  Empty,
  ErrorState,
  PageHeading,
  Panel,
  Skeleton,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { formatDateTime } from "../lib/format";
import type { ComplianceSnapshot } from "../types/api";
import { FleetReport } from "./FleetReport";

export function Reports({ organizationId, endpointId, navigate }: { organizationId: string; endpointId?: string; navigate: (section: string, ...params: string[]) => void }) {
  const frameworks = useApi(
    (signal) => compliance.frameworks(organizationId, signal),
    [organizationId],
  );
  const frameworkId = frameworks.data?.[0]?.framework_id;

  const snapshots = useApi(
    (signal) => compliance.snapshots(organizationId, frameworkId ?? "", 50, 0, signal),
    [organizationId, frameworkId],
    { enabled: Boolean(frameworkId) },
  );

  const items = useMemo<ComplianceSnapshot[]>(() => {
    const data = snapshots.data;
    if (!data) return [];
    return Array.isArray(data) ? data : (data.items ?? []);
  }, [snapshots.data]);

  const [busyId, setBusyId] = useState<string | null>(null);
  const download = useMutation(
    async (snapshotId: string, format: "json" | "csv") => {
      const { blob, filename } = await compliance.exportSnapshot(
        organizationId,
        frameworkId ?? "",
        snapshotId,
        format,
      );
      // Object URLs are revoked immediately after the click to avoid leaking
      // the exported document into the page's memory for longer than needed.
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename ?? `ravenx-compliance-${snapshotId}.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      return true;
    },
  );

  return (
    <>
      <PageHeading
        eyebrow="Evidence & exports"
        title={endpointId ? "Machine report" : "Reports"}
        description="Exportable records produced by the control plane."
      />

      {endpointId && <button type="button" className="back" onClick={() => navigate("reports")}>Back to consolidated report</button>}
      <FleetReport key={`${organizationId}:${endpointId ?? "fleet"}`} organizationId={organizationId} endpointId={endpointId} navigate={navigate} />

      <Panel title="Compliance snapshot exports" icon={<FileText size={15} aria-hidden="true" />}>
        <AsyncSection
          loading={frameworks.loading}
          error={frameworks.error}
          data={frameworks.data}
          onRetry={frameworks.reload}
          empty={
            <Empty
              title="No frameworks available"
              detail="Exports are produced from compliance snapshots; no framework is visible for this organization."
            />
          }
        >
          {() =>
            !frameworkId ? (
              <Empty title="No framework selected" detail="No compliance framework is available." />
            ) : snapshots.loading && snapshots.data === undefined ? (
              <Skeleton rows={4} />
            ) : snapshots.error ? (
              <ErrorState error={snapshots.error} onRetry={snapshots.reload} />
            ) : items.length === 0 ? (
              <Empty
                title="No snapshots to export"
                detail="Capture the current posture in Compliance to add a snapshot to this list."
                action={<button type="button" className="ghost" onClick={() => navigate("compliance")}>Open Compliance</button>}
              />
            ) : (
              <>
                {download.error && <ErrorState error={download.error} />}
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Snapshot</th>
                      <th scope="col">Captured</th>
                      <th scope="col">Posture</th>
                      <th scope="col">Export</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((snapshot, index) => {
                      const id = String(snapshot.snapshot_id ?? index);
                      const at = snapshot.captured_at ?? snapshot.created_at ?? null;
                      return (
                        <tr key={id}>
                          <td className="mono">{id.slice(0, 12)}</td>
                          <td>{formatDateTime(at)}</td>
                          <td>
                            <span className="snapshot-counts inline">
                              <b className="tone-ok">{snapshot.compliant ?? "—"} compliant</b>
                              <b className="tone-critical">{snapshot.non_compliant ?? "—"} non-compliant</b>
                              <b className="tone-warn">{snapshot.unknown ?? "—"} unknown</b>
                            </span>
                          </td>
                          <td className="row-actions">
                            {(["json", "csv"] as const).map((format) => (
                              <button
                                key={format}
                                type="button"
                                className="ghost small"
                                disabled={download.busy && busyId === `${id}-${format}`}
                                onClick={async () => {
                                  setBusyId(`${id}-${format}`);
                                  await download.run(id, format);
                                  setBusyId(null);
                                }}
                              >
                                <Download size={13} aria-hidden="true" /> {format.toUpperCase()}
                              </button>
                            ))}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <p className="panel-note">
                  Exports are served by the control plane with <code>Cache-Control: no-store</code>.
                  Snapshots are immutable, so an export always reflects posture at capture time.
                </p>
              </>
            )
          }
        </AsyncSection>
      </Panel>

    </>
  );
}
