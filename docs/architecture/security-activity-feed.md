# Organization security activity feed

Tenant-scoped read API over the durable `SecurityAuditEvent` log, plus its SOC
interface. Closes GAP-7 (audit read route) from `docs/frontend-api-gaps.md`.

---

## 1. Endpoint

```
GET /api/v1/organizations/{organization_id}/audit-events
```

Requires a human session **and** the `audit.read` permission in the addressed
organization.

### Query parameters

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | `25` | 1–100. Values outside the range are rejected. |
| `offset` | int | `0` | Must be non-negative. |
| `event_type` | string, repeatable / comma-separated | — | Max 10 values, each ≤100 chars. |
| `outcome` | `success` \| `denied` \| `failed` | — | Max 10 values. |
| `severity` | `critical` \| `warning` \| `info` | — | Derived server-side (§4). |
| `actor_id` | string | — | Matches `principal_id`. Max 255 chars. |
| `endpoint_id` | string | — | Max 255 chars. |
| `from` / `to` | ISO-8601 | — | Timezone-aware. `from` must not exceed `to`. |
| `include_permission_checks` | bool | `false` | See §5. |

Any violation returns `422` with `{"detail": {"code": "INVALID_QUERY", ...}}`.
Nothing is silently clamped — an out-of-range `limit` is an error, not a
truncation, so a client can never believe it received more than it did.

`from`/`to` accept a percent-encoded offset, a `Z` suffix, or a raw `+00:00`
that an unencoded query string delivers as a space.

### Response

```json
{
  "items": [
    {
      "event_id": "…", "event_type": "assessment.created",
      "occurred_at": "2026-09-14T14:53:37+00:00",
      "outcome": "success", "severity": "info",
      "actor": { "principal_type": "human", "principal_id": "…", "user_id": "…" },
      "resource": { "resource_type": "endpoint", "resource_id": "…" },
      "action": "assessment.create", "reason_code": null,
      "endpoint_id": "…", "assessment_id": "…", "correlation_id": "…",
      "metadata": { "scanner_ids": ["windows.firewall"] }
    }
  ],
  "pagination": { "limit": 25, "offset": 0, "returned": 25, "total": 150, "has_next": true },
  "excluded_event_types": ["authorization.allowed"]
}
```

`pagination` follows the existing `FleetPage` convention with `has_next` added.
`excluded_event_types` states what the query suppressed, so the interface can
disclose it rather than silently under-report.

### Status codes

| Code | Meaning |
|---|---|
| `200` | Page returned (possibly empty). |
| `401` | No/invalid session. |
| `403` | Not a member, organization inactive, or missing `audit.read`. |
| `422` | Malformed query parameter. |
| `503` | Feed not composed in this deployment. |

---

## 2. Authorization model

New action: **`AuthorizationAction.AUDIT_READ = "audit.read"`**.

Audit history reveals who did what and when, so it is a **separate grant** from
`organization.read` — a Viewer who can see the org name does not automatically
get its security history.

**This fails closed.** Existing roles do not have `audit.read` and will receive
`403` until it is granted. To grant it to roles that already read the
organization:

```sql
-- inspect first; grant deliberately, per role
UPDATE roles
SET permissions_json = json_insert(permissions_json, '$[#]', 'audit.read')
WHERE json_extract(permissions_json, '$') LIKE '%organization.read%';
```

Order of operations in `TenantAuditQueryService.query`:
1. Reject non-human principals and missing `OrganizationContext`.
2. Authorize `AUDIT_READ` against the resolved context.
3. Only then query, using `context.organization_id`.

A denied read **raises**; it never degrades to an empty page, so "no events" and
"not allowed" are distinguishable.

---

## 3. Tenant isolation

Isolation is enforced **at the storage layer**, not in the service or UI.

`SecurityAuditEvent.organization_id` was previously stored only inside the
`event_metadata` JSON blob. Filtering a growing append-only log through JSON
extraction is unindexable and dialect-specific, so tenancy was promoted to
first-class columns:

```
security_audit_events.organization_id  VARCHAR(36)  indexed
security_audit_events.user_id          VARCHAR(36)  indexed
INDEX ix_security_audit_events_org_occurred (organization_id, occurred_at)
```

Guarantees:

- `query_for_organization` always applies `organization_id == owner` as a
  mandatory predicate. It is the first condition and is never conditional.
- **`AuditQuery` has no organization field.** The tenant comes only from the
  verified context, so no request can widen its own scope.
- **Rows with `organization_id IS NULL` are never returned to any tenant.**
  Unattributed system events (failed logins before a user is known, rate-limit
  records) belong to no organization.
- An integration test asserts the string `organization_id` appears in every
  `SELECT` the query emits, so a refactor that drops the predicate fails CI.

### Migration and backfill

Additive and idempotent, following the existing
`_upgrade_legacy_tenancy_columns` pattern, and applied on **both** the sync
(`create_tables`) and async (`create_tables_async`) startup paths — the API
uses the async one.

Pre-existing rows are backfilled from `event_metadata` via `json_extract`, so
history written before the columns existed stays visible to its owner rather
than silently disappearing. Verified on the live database: 163 rows, 143
backfilled, 20 correctly left unattributed.

No data is destroyed; `event_metadata` retains its copy, so existing readers of
the old shape are unaffected.

---

## 4. Redaction strategy

`AuditEventView` is a deliberate projection, **not** a serialization of the
stored record. `SecurityAuditEvent.metadata` legitimately contains operator
email addresses (`{"login": …}`), session identifiers, credential identifiers
and enrollment identifiers — none of which belong in a tenant feed.

**Metadata uses an allowlist, not a deny-list.** Only these keys survive:

```
framework_id, scope_type, snapshot_id, endpoint_count, row_count, format,
schedule_id, scheduled_for, target_type, target_count, resolved_count,
created_count, skipped_count, failed_count, resolution_reason, scanner_ids,
message_type, previous_state, state, observed_at, reason, reason_code,
error_category, duration_ms, deleted_count, candidate_count, failure_count,
query_version, capabilities_trust
```

An allowlist means a key added to a future audit write **cannot leak by
default** — it is dropped until explicitly allowed. A deny-list would have the
opposite failure mode.

Also applied:
- String values truncated to 200 chars; lists to 10 items.
- `AuthorizationResource.metadata` dropped entirely (an authorization input, not
  feed content).
- `SecurityPrincipal.display_metadata` never exposed.
- No email address is reachable through this API at all.
- The existing key-based `redact_metadata` still runs at write time — defence in
  depth, not the primary control.

---

## 5. Permission-check suppression

> **Superseded at the source.** `authorization.allowed` is no longer written for
> routine permission checks — see
> [`audit-event-policy.md`](audit-event-policy.md). The read-side exclusion
> below is retained for historical rows and for the opt-in diagnostic mode.
> Denials now carry verified tenant attribution and therefore appear in the
> feed, which they previously did not.

Every authorized request used to write one `authorization.allowed` record. On
the verification tenant that was **263 of 269 events (97.8%)**, burying six real
operator actions.

The API excludes `authorization.allowed` **by default**, with three properties
that keep this honest:

1. It is an explicit, documented parameter (`include_permission_checks=true`
   returns the complete history) — not a hidden filter.
2. The response declares it in `excluded_event_types`, and the UI renders that
   as visible text.
3. An explicit `event_type=authorization.allowed` filter is honoured verbatim —
   asking for them by name always returns them.

The audit record itself is never altered; only the default view is curated.

---

## 6. Frontend integration

| File | Role |
|---|---|
| `types/api.ts` | `AuditEvent`, `AuditPage`, `AuditQueryParams`, `PaginationEnvelope` |
| `api/endpoints.ts` | `audit.events(org, params, signal)` |
| `lib/auditEvents.ts` | Event-type → operator language, category icons, actor/target labels, metadata chips |
| `features/ActivityFeed.tsx` | Feed component (compact + full variants) |
| `features/Activity.tsx` | Full Activity screen |
| `features/CommandCenter.tsx` | Compact feed replaces the former placeholder panel |
| `app/App.tsx` | `activity` route and Security-group nav entry |

Presentation adds no data. `eventTitle` maps real `event_type` values to
readable headlines and falls back to a title-cased raw type for anything
unrecognised — unknown events are shown, never hidden.

Each row renders: severity rail + category icon, headline, severity badge
(glyph **and** colour), actor, target, allowlisted metadata chips, and a
relative timestamp with the absolute time on hover.

**Live refresh** uses the existing `usePolling` hook — 30 s compact, 20 s full,
paused while the tab is hidden and while paging beyond the first page. No
WebSocket was introduced; none exists in the architecture and a feed of this
cadence does not justify one.

---

## 7. Tests

**59 new tests**, suite total **275 → 334**.

`tests/unit/test_audit_feed.py` (38) — severity derivation; allowlist redaction;
PII/secret exclusion; value and list bounds; tenant isolation; unattributed-event
exclusion; absence of an org field on the query; authorization rejection paths;
denied-≠-empty; newest-first ordering; pagination without overlap; offset beyond
total; empty page; filtering by type/outcome/severity/actor/time;
permission-check suppression and override; 12 parametrized malformed queries.

`tests/unit/test_audit_feed_api.py` (14) — full HTTP boundary with the real auth
stack and real `OrganizationRbacAuthorizer`: authorized read; unauthenticated
`401`; member-without-`audit.read` `403`; cross-tenant `403` (not an empty page);
non-member org `403`; ordering; pagination; filters; three timestamp encodings;
secret/PII absence from the raw response text; 10 malformed-parameter cases;
`limit=101` rejected; empty result; `503` when unconfigured.

`tests/integration/test_sqlalchemy_audit_feed.py` (8) — real SQLite: tenant
isolation; **`organization_id` present in every emitted `SELECT`**; newest-first
pagination stability; all filters; redaction through the real persistence
round-trip; legacy backfill across a restart; empty tenant; invalid query
rejection.

No existing test was modified except two of my own assertions updated for the
new `excluded_event_types` envelope field.

---

## 8. Known limitations

0. **Audit volume is now controlled at the source.** The read-side exclusion
   is a compatibility and diagnostics affordance, not the primary control —
   see [`audit-event-policy.md`](audit-event-policy.md).
1. **Severity is derived, not stored.** A `severity` filter cannot be a SQL
   predicate, so it narrows in SQL first then filters a bounded 2000-row window
   in memory. `total` under a severity filter therefore reflects that window,
   not the entire log. Storing severity at write time would remove this.
2. ~~**`authorization.allowed` volume is a backend design issue.**~~ **Fixed** —
   routine permission checks are no longer persisted.
3. **Offset pagination.** Deep offsets scan; a cursor keyed on
   `(occurred_at, event_id)` would be better at scale.
4. **`audit.read` fails closed.** Every existing role needs an explicit grant.
   Intentional, but it is an operational step at upgrade.
5. **Unattributed events are invisible to tenants.** Correct for isolation, but
   it means failed sign-ins that never resolved a user are absent from the feed.
   Surfacing those safely needs a separate, deliberately-scoped decision.
6. **No export.** The feed is read-only in the UI; CSV/JSON export of audit
   history is not implemented.
7. **SQLite-only migration.** The additive upgrade is guarded to the SQLite
   dialect, consistent with the rest of the project. A PostgreSQL deployment
   needs its own migration.
