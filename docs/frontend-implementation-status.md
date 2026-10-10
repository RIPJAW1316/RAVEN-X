# Frontend implementation status

Status of the Raven-X enterprise operator interface after the SOC
productization pass.

**Verification date:** 2026-09-14
**Stack:** React + TypeScript + Vite, `lucide-react`, `framer-motion`
**Type check:** clean (`tsc --noEmit`, exit 0)
**Build:** clean (429 kB JS / 129 kB gzip, 27 kB CSS / 6 kB gzip)
**Backend regression:** 275 passed — unchanged by this work

---

## 1. Screens

| Screen | Status | Backing routes |
|---|---|---|
| **Login** | Implemented | `POST /auth/login` |
| **Command Center** | Implemented | `GET /security/overview` |
| **Fleet** (list) | Implemented | `GET /fleet/endpoints` |
| **Endpoint detail** | Implemented | `GET /endpoints/{id}`, `/endpoints/{id}/presence`, `/endpoints/{id}/compliance/{fw}` |
| **Assessments** (list) | Implemented | `GET /assessments` |
| **Assessment detail** | Implemented | `GET /assessments/{id}`, `/assessments/{id}/details` |
| **Finding detail** | Implemented | `GET .../findings/{occurrence}`, `.../recurrence` |
| **Schedules** | Implemented | full schedule CRUD + `/runs` |
| **Groups & Scopes** | Implemented | endpoint-group and fleet-scope CRUD |
| **Compliance** | Implemented | frameworks, summary, snapshots, export |
| **Reports** | Implemented (bounded) | compliance snapshot export only — see GAP-5 |
| **Findings** | Partial (bounded) | overview window only — see GAP-3 |
| **Activity** | Implemented | `GET /audit-events` — see [security-activity-feed.md](architecture/security-activity-feed.md) |
| **AI Analyst** | Scaffold only | none — see GAP-2 |
| **Settings** | Partial | organization, session, memberships; roles/agents blocked by GAP-6, GAP-7 |

Every screen handles loading, empty, error, `403 Forbidden` and `503
Unavailable` distinctly. `403` is rendered as a permission boundary, `503` as a
capability that is switched off — they are different operator problems.

---

## 2. Defect found and fixed

The previous `client.ts` types did not match the API, so two screens were
silently rendering placeholders:

| Screen | Expected (wrong) | Actual API | Effect |
|---|---|---|---|
| Command Center | `endpoint_count`, `online_count`, `critical_count` | `endpoints.total_endpoints`, `presence.online`, `findings.critical` | Every metric rendered `—` |
| Fleet | `platform.name`, `agent.agent_version`, `last_seen` | flat `platform`, `agent_version`, `last_seen_at` | Platform showed "Unknown", agent `—` |

Both response shapes are now typed from the backend `to_dict()` implementations
in `frontend/src/types/api.ts`. Verified live: the Command Center shows 3
endpoints / 1 online / 1 stale / 1 offline, and Fleet shows real platform
strings and agent versions.

Note the two endpoint routes genuinely return **different** shapes —
`/fleet/endpoints` is flat, `/endpoints/{id}` is nested. Both are modelled
separately (`FleetEndpoint` vs `EndpointDetail`) rather than forced into one
type.

---

## 3. Architecture

```
frontend/src/
├── types/api.ts          Wire types mirroring backend to_dict() output
├── api/
│   ├── client.ts         fetch core, ApiError, session, blob download
│   └── endpoints.ts      Typed binding per control-plane route
├── lib/
│   ├── format.ts         Dates, relative time, IDs, durations
│   ├── domain.ts         Severity / lifecycle / presence / compliance vocabulary
│   └── scanners.ts       Scanner catalogue (GAP-1 stop-gap, clearly marked)
├── hooks/
│   ├── useApi.ts         Aborting loader, polling, mutation state
│   └── useRoute.ts       Hash router
├── components/
│   ├── ui.tsx            Panels, badges, tables, drawers, modals, states
│   └── charts.tsx        SVG severity bars, donut, sparkline, meter
├── features/             One module per screen
└── app/App.tsx           Shell: auth gate, org context, navigation, routing
```

### Decisions

**Hash routing, no router dependency.** Deep links matter here — an operator
shares a link to a finding. A ~40-line hash router gives that without adding a
routing library.

**No charting library.** Four visualisations did not justify the bundle cost.
`charts.tsx` is hand-rolled SVG, and every chart is labelled in text as well as
drawn.

**Aborting fetches.** `useApi` passes an `AbortSignal` so a slow response for a
previously selected organization cannot overwrite fresh data — a correctness
requirement in a tenant-switching UI, not an optimisation.

**Polling, not push.** No server push channel exists. Intervals: 30 s Command
Center, 45 s Fleet, 8 s assessment list while work is in flight, 6 s active
assessment detail. Polling pauses while the tab is hidden.

**Server-side query.** Fleet filtering, sorting and pagination call the query
API rather than filtering a truncated page in the browser, so counts stay
truthful.

---

## 4. Visual system

Severity never relies on colour alone — each badge carries a glyph
(`!!`, `!`, `=`, `·`, `i`, `?`) and a text label.

| Severity | Token |
|---|---|
| Critical | `--sev-critical` |
| High | `--sev-high` |
| Medium | `--sev-medium` |
| Low | `--sev-low` |
| Info | `--sev-info` |
| Unknown | `--sev-unknown` |

Status tones (`ok`, `warn`, `critical`, `info`, `neutral`) are shared across
presence, lifecycle and compliance so one visual grammar covers all state.

**Motion** is used for page transitions, drawer/modal entry and bar/meter fills
only. No idle pulsing or decorative animation. `prefers-reduced-motion` is
honoured both by `useReducedMotion()` and a CSS media query.

**Accessibility:** semantic tables with `aria-sort`, `aria-pressed` filter
chips, `role="dialog"` + `aria-modal` overlays with Escape-to-close,
keyboard-activatable rows, visible focus rings, `aria-current` navigation,
`role="img"` charts with text alternatives.

---

## 5. Verified end to end

Against a live backend with a seeded tenant (3 endpoints, mixed presence):

| Flow | Result |
|---|---|
| Login → session → org context | Works |
| Command Center metrics | Real values render |
| Fleet list | Platform, agent, presence, last-seen all populated |
| Fleet presence filter | Server-side; `1–1 of 1` |
| Endpoint detail | Identity, presence, 4 real compliance evaluations |
| **Assessment dispatch** | Assessment genuinely created; lifecycle showed Created → **Queued** |
| Assessment list | Appears with tab counts and scanner chips |
| **Create endpoint group** | Persisted; card and tab count updated |
| **Capture compliance snapshot** | Persisted; appears in history |
| **CSV export** | `200 OK`, file downloaded |
| Mobile 375×812 | No horizontal overflow after fix |

The dispatched assessment stays `queued` because no agent is polling — that is
correct behaviour, shown honestly, not a stall.

### Mobile fix

Initial mobile QA found the brand wrapping, the search control overflowing the
topbar and overlapping sign-out. Fixed: brand no longer wraps, search is hidden
below 1020 px (Ctrl+K still opens the palette), the org switcher flexes, tables
scroll inside their own container, and modal actions stack.

---

## 6. Known limitations

1. **AI Analyst is a scaffold.** No tenant analysis route exists (GAP-2). The
   page publishes the required contract; `AnalystNarrativeView` is written and
   unused, waiting for the endpoint.
2. **Findings is a recent window, not a backlog** (GAP-3).
3. **Reports covers compliance exports only** (GAP-5).
4. **No role administration** (GAP-6) and **no agent/audit administration**
   (GAP-7).
5. **Scanner catalogue is a client-side constant** (GAP-1).
6. **No frontend test suite.** The project has no test runner configured; `tsc`
   and the production build are the only automated gates. Everything above was
   verified manually in a browser against a live backend.
7. **No threat-trend chart** (GAP-4).
8. **Bundle is 429 kB** (129 kB gzipped), dominated by React and
   `framer-motion`. Acceptable for an internal console; code-splitting per
   route would be the first optimisation.

---

## 7. Recommended next work

Ordered by value against effort:

1. ~~**Audit-event read route** (GAP-7).~~ **Done** — shipped as the
   organization security activity feed.
2. **Scanner discovery route** (GAP-1). Small, and removes the only hard-coded
   catalogue in the frontend.
3. **RBAC admin routes** (GAP-6). Services and repositories exist; only the
   HTTP boundary and its tests are missing.
4. **Cross-assessment findings index** (GAP-3). Unlocks a genuine backlog
   workflow — the highest-value screen still bounded.
5. **Frontend test runner.** Vitest plus a few component tests around
   `AsyncSection`, severity mapping and the lifecycle component.
6. **AI analysis route** (GAP-2). Largest product step; the UI contract is
   already specified and the components are written.
