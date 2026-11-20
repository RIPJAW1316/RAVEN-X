/**
 * Groups & Scopes — static endpoint groups and dynamic saved fleet scopes.
 *
 * Both are tenant-owned targeting primitives consumed by schedules. A group
 * holds an explicit membership list; a scope stores a fleet query that is
 * re-resolved each time it is used.
 */
import { Layers, Plus, Radar, Trash2, UsersRound } from "lucide-react";
import { useCallback, useState } from "react";
import { fleet, groups, scopes } from "../api/endpoints";
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
  Tabs,
} from "../components/ui";
import { useApi, useMutation } from "../hooks/useApi";
import { formatDateTime, shortId, titleCase } from "../lib/format";
import type { EndpointGroup, FleetScope, PresenceState } from "../types/api";

type View = "groups" | "scopes";

export function Groups({ organizationId }: { organizationId: string }) {
  const [view, setView] = useState<View>("groups");
  const groupList = useApi((signal) => groups.list(organizationId, signal), [organizationId]);
  const scopeList = useApi((signal) => scopes.list(organizationId, signal), [organizationId]);

  return (
    <>
      <PageHeading
        eyebrow="Targeting primitives"
        title="Groups & Scopes"
        description="Reusable endpoint selections for scheduling and bulk assessment."
      />
      <Tabs
        label="Targeting views"
        active={view}
        onChange={setView}
        tabs={[
          { id: "groups", label: "Endpoint groups", count: groupList.data?.length },
          { id: "scopes", label: "Saved fleet scopes", count: scopeList.data?.length },
        ]}
      >
        {view === "groups" ? (
          <GroupsView organizationId={organizationId} state={groupList} />
        ) : (
          <ScopesView organizationId={organizationId} state={scopeList} />
        )}
      </Tabs>
    </>
  );
}

/* ---------------------------------------------------------------- groups */

function GroupsView({
  organizationId,
  state,
}: {
  organizationId: string;
  state: ReturnType<typeof useApi<EndpointGroup[]>>;
}) {
  const [composerOpen, setComposerOpen] = useState(false);
  const [selected, setSelected] = useState<EndpointGroup | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<EndpointGroup | null>(null);

  const create = useMutation((name: string, description: string) =>
    groups.create(organizationId, name, description),
  );
  const revoke = useMutation((id: string) => groups.revoke(organizationId, id));

  return (
    <>
      <div className="toolbar end">
        <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
          <Plus size={15} aria-hidden="true" /> New group
        </button>
      </div>

      <AsyncSection
        loading={state.loading}
        error={state.error}
        data={state.data}
        onRetry={state.reload}
        empty={
          <Empty
            title="No endpoint groups"
            detail="Groups hold an explicit list of endpoints and are useful for stable targeting."
            action={
              <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
                <Plus size={15} aria-hidden="true" /> New group
              </button>
            }
          />
        }
      >
        {(items) => (
          <div className="card-grid">
            {items.map((group) => (
              <article className="entity-card" key={group.group_id}>
                <header>
                  <UsersRound size={16} aria-hidden="true" />
                  <button type="button" className="link strong" onClick={() => setSelected(group)}>
                    {group.name}
                  </button>
                  <Badge tone={group.status === "active" ? "ok" : "neutral"}>
                    {titleCase(group.status)}
                  </Badge>
                </header>
                <p>{group.description || "No description provided."}</p>
                <footer>
                  <span>
                    {group.member_count === undefined
                      ? "Membership not summarised"
                      : `${group.member_count} member(s)`}
                  </span>
                  {group.status === "active" && (
                    <button
                      type="button"
                      className="icon-button danger-ghost"
                      aria-label={`Revoke ${group.name}`}
                      onClick={() => setPendingRevoke(group)}
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                </footer>
              </article>
            ))}
          </div>
        )}
      </AsyncSection>

      <GroupDrawer
        organizationId={organizationId}
        group={selected}
        onClose={() => setSelected(null)}
        onChanged={state.reload}
      />

      <Modal open={composerOpen} title="New endpoint group" onClose={() => setComposerOpen(false)}>
        <NameDescriptionForm
          busy={create.busy}
          error={create.error}
          submitLabel="Create group"
          onCancel={() => setComposerOpen(false)}
          onSubmit={async (name, description) => {
            const created = await create.run(name, description);
            if (created) {
              setComposerOpen(false);
              state.reload();
            }
          }}
        />
      </Modal>

      <Confirm
        open={Boolean(pendingRevoke)}
        title="Revoke group"
        message={`Revoke "${pendingRevoke?.name ?? ""}"? Schedules targeting it will resolve to no endpoints.`}
        confirmLabel="Revoke"
        destructive
        busy={revoke.busy}
        onConfirm={async () => {
          if (pendingRevoke) {
            await revoke.run(pendingRevoke.group_id);
            state.reload();
          }
          setPendingRevoke(null);
        }}
        onCancel={() => setPendingRevoke(null)}
      />
    </>
  );
}

function GroupDrawer({
  organizationId,
  group,
  onClose,
  onChanged,
}: {
  organizationId: string;
  group: EndpointGroup | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const members = useApi(
    (signal) => groups.members(organizationId, group?.group_id ?? "", 100, 0, signal),
    [organizationId, group?.group_id],
    { enabled: Boolean(group) },
  );
  const available = useApi(
    (signal) => fleet.query(organizationId, { limit: 200, sort: "hostname", direction: "asc" }, signal),
    [organizationId],
    { enabled: Boolean(group) },
  );
  const add = useMutation((ids: string[]) =>
    groups.addMembers(organizationId, group?.group_id ?? "", ids),
  );
  const [picked, setPicked] = useState<string[]>([]);

  const memberIds = extractEndpointIds(members.data);

  const submit = useCallback(async () => {
    if (!picked.length) return;
    await add.run(picked);
    setPicked([]);
    members.reload();
    onChanged();
  }, [add, picked, members, onChanged]);

  return (
    <Drawer open={Boolean(group)} title={group?.name ?? "Group"} onClose={onClose} width={620}>
      {group && (
        <>
          <section className="drawer-section">
            <h3>Definition</h3>
            <DefinitionList
              items={[
                ["Group ID", <code className="mono">{group.group_id}</code>],
                ["Status", titleCase(group.status)],
                ["Description", group.description || "—"],
                ["Created", formatDateTime(group.created_at)],
              ]}
            />
          </section>

          <section className="drawer-section">
            <h3>Members ({memberIds.length})</h3>
            {members.loading && members.data === undefined ? (
              <Skeleton rows={3} />
            ) : members.error ? (
              <ErrorState error={members.error} onRetry={members.reload} />
            ) : memberIds.length ? (
              <ul className="member-list">
                {memberIds.map((id) => (
                  <li key={id} className="mono">
                    {shortId(id)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="panel-note">This group has no members yet.</p>
            )}
          </section>

          {group.status === "active" && (
            <section className="drawer-section">
              <h3>Add endpoints</h3>
              {available.data ? (
                <>
                  <div className="chip-row scrollable">
                    {available.data.items
                      .filter((item) => !memberIds.includes(item.endpoint_id))
                      .map((item) => (
                        <button
                          key={item.endpoint_id}
                          type="button"
                          aria-pressed={picked.includes(item.endpoint_id)}
                          className={picked.includes(item.endpoint_id) ? "chip active" : "chip"}
                          onClick={() =>
                            setPicked((current) =>
                              current.includes(item.endpoint_id)
                                ? current.filter((value) => value !== item.endpoint_id)
                                : [...current, item.endpoint_id],
                            )
                          }
                        >
                          {item.hostname || shortId(item.endpoint_id)}
                        </button>
                      ))}
                  </div>
                  {add.error && <ErrorState error={add.error} />}
                  <button
                    type="button"
                    className="primary"
                    disabled={add.busy || picked.length === 0}
                    onClick={submit}
                  >
                    {add.busy ? "Adding…" : `Add ${picked.length} endpoint(s)`}
                  </button>
                </>
              ) : (
                <Skeleton rows={2} />
              )}
            </section>
          )}
        </>
      )}
    </Drawer>
  );
}

/** The members route shape is not strongly specified; read defensively. */
function extractEndpointIds(payload: unknown): string[] {
  if (!payload) return [];
  const source = Array.isArray(payload)
    ? payload
    : typeof payload === "object" && payload !== null && "items" in payload
      ? ((payload as { items: unknown }).items as unknown[])
      : [];
  if (!Array.isArray(source)) return [];
  return source
    .map((item) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object" && "endpoint_id" in item) {
        const value = (item as { endpoint_id: unknown }).endpoint_id;
        return typeof value === "string" ? value : null;
      }
      return null;
    })
    .filter((value): value is string => Boolean(value));
}

/* ---------------------------------------------------------------- scopes */

function ScopesView({
  organizationId,
  state,
}: {
  organizationId: string;
  state: ReturnType<typeof useApi<FleetScope[]>>;
}) {
  const [composerOpen, setComposerOpen] = useState(false);
  const [selected, setSelected] = useState<FleetScope | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<FleetScope | null>(null);
  const revoke = useMutation((id: string) => scopes.revoke(organizationId, id));

  return (
    <>
      <div className="toolbar end">
        <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
          <Plus size={15} aria-hidden="true" /> New scope
        </button>
      </div>

      <AsyncSection
        loading={state.loading}
        error={state.error}
        data={state.data}
        onRetry={state.reload}
        empty={
          <Empty
            title="No saved fleet scopes"
            detail="A scope stores a fleet query and re-resolves it whenever it is used, so new endpoints are picked up automatically."
            action={
              <button type="button" className="primary" onClick={() => setComposerOpen(true)}>
                <Plus size={15} aria-hidden="true" /> New scope
              </button>
            }
          />
        }
      >
        {(items) => (
          <div className="card-grid">
            {items.map((scope) => (
              <article className="entity-card" key={scope.scope_id}>
                <header>
                  <Layers size={16} aria-hidden="true" />
                  <button type="button" className="link strong" onClick={() => setSelected(scope)}>
                    {scope.name}
                  </button>
                  <Badge tone={scope.status === "active" ? "ok" : "neutral"}>
                    {titleCase(scope.status)}
                  </Badge>
                </header>
                <p>{scope.description || "No description provided."}</p>
                <footer>
                  <span className="chip-row tight">
                    {scope.criteria.presence_states.map((value) => (
                      <span className="chip static" key={value}>
                        {value}
                      </span>
                    ))}
                    {scope.criteria.search && (
                      <span className="chip static">“{scope.criteria.search}”</span>
                    )}
                    {!scope.criteria.presence_states.length && !scope.criteria.search && (
                      <span className="chip static">All endpoints</span>
                    )}
                  </span>
                  {scope.status === "active" && (
                    <button
                      type="button"
                      className="icon-button danger-ghost"
                      aria-label={`Revoke ${scope.name}`}
                      onClick={() => setPendingRevoke(scope)}
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                </footer>
              </article>
            ))}
          </div>
        )}
      </AsyncSection>

      <ScopeDrawer
        organizationId={organizationId}
        scope={selected}
        onClose={() => setSelected(null)}
      />

      <ScopeComposer
        open={composerOpen}
        organizationId={organizationId}
        onClose={() => setComposerOpen(false)}
        onCreated={() => {
          setComposerOpen(false);
          state.reload();
        }}
      />

      <Confirm
        open={Boolean(pendingRevoke)}
        title="Revoke scope"
        message={`Revoke "${pendingRevoke?.name ?? ""}"? Schedules targeting it will resolve to no endpoints.`}
        confirmLabel="Revoke"
        destructive
        busy={revoke.busy}
        onConfirm={async () => {
          if (pendingRevoke) {
            await revoke.run(pendingRevoke.scope_id);
            state.reload();
          }
          setPendingRevoke(null);
        }}
        onCancel={() => setPendingRevoke(null)}
      />
    </>
  );
}

function ScopeDrawer({
  organizationId,
  scope,
  onClose,
}: {
  organizationId: string;
  scope: FleetScope | null;
  onClose: () => void;
}) {
  const resolved = useApi(
    (signal) => scopes.resolve(organizationId, scope?.scope_id ?? "", 50, 0, signal),
    [organizationId, scope?.scope_id],
    { enabled: Boolean(scope) },
  );

  return (
    <Drawer open={Boolean(scope)} title={scope?.name ?? "Scope"} onClose={onClose} width={620}>
      {scope && (
        <>
          <section className="drawer-section">
            <h3>Criteria</h3>
            <DefinitionList
              items={[
                ["Search", scope.criteria.search || "—"],
                ["Presence", scope.criteria.presence_states.join(", ") || "Any"],
                ["Lifecycle", scope.criteria.statuses.join(", ") || "Any"],
                ["Platforms", scope.criteria.platforms.join(", ") || "Any"],
                ["Sort", `${scope.criteria.sort_by} ${scope.criteria.direction}`],
              ]}
            />
          </section>

          <section className="drawer-section">
            <h3>
              <Radar size={14} aria-hidden="true" /> Resolves to
            </h3>
            {resolved.loading && resolved.data === undefined ? (
              <Skeleton rows={3} />
            ) : resolved.error ? (
              <ErrorState error={resolved.error} onRetry={resolved.reload} />
            ) : resolved.data ? (
              resolved.data.items.length ? (
                <>
                  <p className="panel-note">
                    {resolved.data.total} endpoint(s) currently match this scope.
                  </p>
                  <ul className="member-list">
                    {resolved.data.items.map((item) => (
                      <li key={item.endpoint_id}>
                        {item.hostname || shortId(item.endpoint_id)}
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <Empty
                  compact
                  title="No endpoints match"
                  detail="This scope currently resolves to zero endpoints."
                />
              )
            ) : null}
          </section>
        </>
      )}
    </Drawer>
  );
}

function ScopeComposer({
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
  const [description, setDescription] = useState("");
  const [search, setSearch] = useState("");
  const [presence, setPresence] = useState<PresenceState[]>([]);
  const create = useMutation(() =>
    scopes.create(
      organizationId,
      name,
      { search, presence_states: presence, sort_by: "hostname", direction: "asc" },
      description,
    ),
  );

  return (
    <Modal open={open} title="New saved fleet scope" onClose={onClose}>
      <Field label="Name">
        <input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} />
      </Field>
      <Field label="Description">
        <input
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          maxLength={2000}
        />
      </Field>
      <Field label="Hostname contains" hint="Leave blank to match every hostname.">
        <input value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} />
      </Field>
      <Field label="Presence states" hint="Leave empty to match any presence state.">
        <div className="chip-row">
          {(["online", "stale", "offline", "unknown"] as PresenceState[]).map((state) => (
            <button
              key={state}
              type="button"
              aria-pressed={presence.includes(state)}
              className={presence.includes(state) ? "chip active" : "chip"}
              onClick={() =>
                setPresence((current) =>
                  current.includes(state)
                    ? current.filter((value) => value !== state)
                    : [...current, state],
                )
              }
            >
              {titleCase(state)}
            </button>
          ))}
        </div>
      </Field>

      {create.error && <ErrorState error={create.error} />}

      <div className="modal-actions">
        <button type="button" className="ghost" onClick={onClose} disabled={create.busy}>
          Cancel
        </button>
        <button
          type="button"
          className="primary"
          onClick={async () => {
            const created = await create.run();
            if (created) onCreated();
          }}
          disabled={create.busy || !name.trim()}
        >
          {create.busy ? "Creating…" : "Create scope"}
        </button>
      </div>
    </Modal>
  );
}

function NameDescriptionForm({
  busy,
  error,
  submitLabel,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  error: ReturnType<typeof useMutation>["error"];
  submitLabel: string;
  onCancel: () => void;
  onSubmit: (name: string, description: string) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  return (
    <>
      <Field label="Name">
        <input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} />
      </Field>
      <Field label="Description">
        <input
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          maxLength={2000}
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
          onClick={() => onSubmit(name, description)}
          disabled={busy || !name.trim()}
        >
          {busy ? "Working…" : submitLabel}
        </button>
      </div>
    </>
  );
}
