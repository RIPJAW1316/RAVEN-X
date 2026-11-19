/**
 * Settings — organization profile, membership administration and session info.
 *
 * Only capabilities with a real route are actionable. Role management, agent
 * configuration, integrations and API-key issuance have no control-plane
 * endpoints and are declared as such rather than rendered as dead controls.
 * See docs/frontend-api-gaps.md (GAP-6, GAP-7).
 */
import { Appearance } from "../components/Appearance";
import { Building2, KeyRound, ShieldCheck, UserMinus, UserPlus, Users } from "lucide-react";
import { useState } from "react";
import { auth, organizations } from "../api/endpoints";
import {
  AsyncSection,
  Badge,
  Confirm,
  DefinitionList,
  Empty,
  ErrorState,
  Field,
  Modal,
  NotImplemented,
  PageHeading,
  Panel,
  Skeleton,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { formatDateTime, titleCase } from "../lib/format";
import type { Membership } from "../types/api";

export function Settings({ organizationId }: { organizationId: string }) {
  const organization = useApi(
    (signal) => organizations.get(organizationId, signal),
    [organizationId],
  );
  const me = useApi((signal) => auth.me(signal), []);
  const memberships = useApi(
    (signal) => organizations.memberships(organizationId, signal),
    [organizationId],
  );

  const [inviteOpen, setInviteOpen] = useState(false);
  const [pending, setPending] = useState<{ membership: Membership; action: "suspend" | "revoke" } | null>(
    null,
  );

  const add = useMutation((userId: string) => organizations.addMembership(organizationId, userId));
  const suspend = useMutation((id: string) =>
    organizations.suspendMembership(organizationId, id),
  );
  const revoke = useMutation((id: string) => organizations.revokeMembership(organizationId, id));

  return (
    <>
      <PageHeading
        eyebrow="Administration"
        title="Settings"
        description="Organization profile and access administration."
      />

      <Appearance />

      <section className="grid-2">
        <Panel title="Organization" icon={<Building2 size={15} aria-hidden="true" />}>
          <AsyncSection
            loading={organization.loading}
            error={organization.error}
            data={organization.data}
            onRetry={organization.reload}
            skeletonRows={3}
          >
            {(value) => (
              <DefinitionList
                items={[
                  ["Name", value.name],
                  ["Organization ID", <code className="mono">{value.organization_id}</code>],
                  [
                    "Status",
                    <Badge tone={value.status === "active" ? "ok" : "neutral"}>
                      {titleCase(value.status)}
                    </Badge>,
                  ],
                  ["Created", formatDateTime(value.created_at)],
                  ["Updated", formatDateTime(value.updated_at)],
                ]}
              />
            )}
          </AsyncSection>
        </Panel>

        <Panel title="Your session" icon={<ShieldCheck size={15} aria-hidden="true" />}>
          {me.loading && me.data === undefined ? (
            <Skeleton rows={3} />
          ) : me.error ? (
            <ErrorState error={me.error} onRetry={me.reload} />
          ) : me.data ? (
            <>
              <DefinitionList
                items={[
                  ["Signed in as", me.data.email],
                  ["Display name", me.data.display_name || "—"],
                  ["User ID", <code className="mono">{me.data.user_id}</code>],
                  [
                    "Account status",
                    <Badge tone={me.data.status === "active" ? "ok" : "warn"}>
                      {titleCase(me.data.status)}
                    </Badge>,
                  ],
                ]}
              />
              <p className="panel-note">
                Sessions are opaque server-side tokens held in <code>sessionStorage</code> and are
                discarded when this tab closes. Signing out revokes the session on the server.
              </p>
            </>
          ) : null}
        </Panel>
      </section>

      <Panel
        title="Memberships"
        icon={<Users size={15} aria-hidden="true" />}
        actions={
          <button type="button" className="ghost" onClick={() => setInviteOpen(true)}>
            <UserPlus size={15} aria-hidden="true" /> Add member
          </button>
        }
      >
        {(suspend.error || revoke.error) && (
          <ErrorState error={(suspend.error ?? revoke.error)!} />
        )}
        <AsyncSection
          loading={memberships.loading}
          error={memberships.error}
          data={memberships.data}
          onRetry={memberships.reload}
          empty={
            <Empty
              compact
              title="No memberships"
              detail="This organization has no member records visible to you."
            />
          }
        >
          {(items) => (
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">User</th>
                  <th scope="col">Membership</th>
                  <th scope="col">Status</th>
                  <th scope="col">Added</th>
                  <th scope="col"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {items.map((membership) => (
                  <tr key={membership.membership_id}>
                    <td className="mono">{membership.user_id}</td>
                    <td className="mono">{membership.membership_id.slice(0, 8)}</td>
                    <td>
                      <Badge tone={membership.status === "active" ? "ok" : "neutral"}>
                        {titleCase(membership.status)}
                      </Badge>
                    </td>
                    <td>{formatDateTime(membership.created_at)}</td>
                    <td className="row-actions">
                      {membership.status === "active" && (
                        <button
                          type="button"
                          className="ghost small"
                          onClick={() => setPending({ membership, action: "suspend" })}
                        >
                          Suspend
                        </button>
                      )}
                      {membership.status !== "revoked" && (
                        <button
                          type="button"
                          className="icon-button danger-ghost"
                          aria-label="Revoke membership"
                          onClick={() => setPending({ membership, action: "revoke" })}
                        >
                          <UserMinus size={15} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </AsyncSection>
      </Panel>

      <section className="grid-2">
        <Panel title="Roles & permissions" icon={<KeyRound size={15} aria-hidden="true" />}>
          <NotImplemented
            title="Role editing unavailable"
            detail="Your assigned organization permissions are enforced. Contact the server administrator to change role assignments."
          />
        </Panel>

        <Panel title="Agents & integrations" icon={<ShieldCheck size={15} aria-hidden="true" />}>
          <p className="panel-note">Issue a single-use token, review the connecting machine, and approve its identity before any assessment can run.</p>
          <a className="ghost" href="#/enrollment">Open enrollment desk</a>
        </Panel>
      </section>

      <Modal open={inviteOpen} title="Add member" onClose={() => setInviteOpen(false)}>
        <AddMemberForm
          busy={add.busy}
          error={add.error}
          onCancel={() => setInviteOpen(false)}
          onSubmit={async (userId) => {
            const created = await add.run(userId);
            if (created) {
              setInviteOpen(false);
              memberships.reload();
            }
          }}
        />
      </Modal>

      <Confirm
        open={Boolean(pending)}
        title={pending?.action === "revoke" ? "Revoke membership" : "Suspend membership"}
        message={
          pending?.action === "revoke"
            ? "Revoking removes this user's access to the organization permanently."
            : "Suspending blocks this user's access until the membership is restored server-side."
        }
        confirmLabel={pending?.action === "revoke" ? "Revoke" : "Suspend"}
        destructive={pending?.action === "revoke"}
        busy={suspend.busy || revoke.busy}
        onConfirm={async () => {
          if (pending) {
            const action = pending.action === "revoke" ? revoke : suspend;
            await action.run(pending.membership.membership_id);
            memberships.reload();
          }
          setPending(null);
        }}
        onCancel={() => setPending(null)}
      />
    </>
  );
}

function AddMemberForm({
  busy,
  error,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  error: ReturnType<typeof useMutation>["error"];
  onCancel: () => void;
  onSubmit: (userId: string) => void;
}) {
  const [userId, setUserId] = useState("");
  return (
    <>
      <Field
        label="User ID"
        hint="Enter the ID of an existing account provided by the server administrator."
      >
        <input
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          placeholder="00000000-0000-0000-0000-000000000000"
        />
      </Field>
      {error && <ErrorState error={error} />}
      <div className="modal-actions">
        <button type="button" className="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className="primary"
          onClick={() => onSubmit(userId.trim())}
          disabled={busy || !userId.trim()}
        >
          {busy ? "Adding…" : "Add member"}
        </button>
      </div>
    </>
  );
}
