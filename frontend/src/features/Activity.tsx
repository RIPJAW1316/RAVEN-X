/**
 * Security activity — the full organization audit history.
 *
 * Backed by the durable `SecurityAuditEvent` log through the tenant-scoped
 * read route. Events are redacted server-side; this screen renders exactly
 * what the API returns.
 */
import { Activity as ActivityIcon } from "lucide-react";
import { PageHeading, Panel } from "../components/ui";
import { ActivityFeed } from "./ActivityFeed";

export function Activity({ organizationId }: { organizationId: string }) {
  return (
    <>
      <PageHeading
        eyebrow="Security operations"
        title="Activity"
        description="Durable record of security-relevant actions in this organization, newest first."
      />
      <Panel title="Audit trail" icon={<ActivityIcon size={15} aria-hidden="true" />}>
        <ActivityFeed organizationId={organizationId} pageSize={25} />
        <p className="panel-note">
          Events are append-only and scoped to this organization. Metadata is reduced to an
          allowlist server-side, so credentials, tokens and operator contact details are never
          included.
        </p>
      </Panel>
    </>
  );
}
