/**
 * Application shell: authentication gate, organization context, navigation
 * and routing.
 *
 * Organization context is required by every tenant route, so the shell will
 * not render a feature screen until an organization is selected.
 */
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  Activity,
  CalendarClock,
  ChevronDown,
  Command,
  FileCheck2,
  Feather,
  LayoutDashboard,
  LogOut,
  Network,
  KeyRound,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  UsersRound,
  Wrench,
  X,
  type LucideIcon,
} from "lucide-react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { ApiError, session } from "../api/client";
import { auth } from "../api/endpoints";
import { Empty, ErrorState, SelectionHighlight, Toast } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { buildHref, useRoute } from "../hooks/useRoute";
import { Activity as ActivityPage } from "../features/Activity";
import { Assessments } from "../features/Assessments";
import { CommandCenter } from "../features/CommandCenter";
import { Compliance } from "../features/Compliance";
import { Findings } from "../features/Findings";
import { Fleet } from "../features/Fleet";
import { Enrollment } from "../features/Enrollment";
import { Groups } from "../features/Groups";
import { Reports } from "../features/Reports";
import { Schedules } from "../features/Schedules";
import { Settings } from "../features/Settings";

const Analyst = lazy(() => import("../features/AnalystPage").then(({ Analyst }) => ({ default: Analyst })));
const FixIssues = lazy(() => import("../features/FixIssues").then(({ FixIssues }) => ({ default: FixIssues })));

interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAVIGATION: NavGroup[] = [
  { label: "", items: [{ id: "command", label: "Command Center", icon: LayoutDashboard }] },
  {
    label: "Operations",
    items: [
      { id: "fleet", label: "Fleet", icon: Network },
      { id: "assessments", label: "Assessments", icon: Radar },
      { id: "schedules", label: "Schedules", icon: CalendarClock },
      { id: "groups", label: "Groups & Scopes", icon: UsersRound },
    ],
  },
  {
    label: "Security",
    items: [
      { id: "findings", label: "Findings", icon: ShieldAlert },
      { id: "fix-issues", label: "Fix Issues", icon: Wrench },
      { id: "activity", label: "Activity", icon: Activity },
      { id: "analyst", label: "AI Analyst", icon: Sparkles },
    ],
  },
  {
    label: "Governance",
    items: [
      { id: "compliance", label: "Compliance", icon: ShieldCheck },
      { id: "reports", label: "Reports", icon: FileCheck2 },
    ],
  },
  {
    label: "Administration",
    items: [{ id: "enrollment", label: "Enrollment", icon: KeyRound }, { id: "settings", label: "Settings", icon: SlidersHorizontal }],
  },
];

const ALL_ITEMS = NAVIGATION.flatMap((group) => group.items);
const ORG_KEY = "ravenx.organization";

export function App() {
  const [authenticated, setAuthenticated] = useState(Boolean(session.get()));

  useEffect(() => session.subscribe((token) => setAuthenticated(Boolean(token))), []);

  if (!authenticated) return <Login onSuccess={() => setAuthenticated(true)} />;
  return <Workspace onSignOut={() => setAuthenticated(false)} />;
}

/* ------------------------------------------------------------------ login */

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = useCallback(
    async (event: FormEvent) => {
      event.preventDefault();
      setBusy(true);
      setError(null);
      try {
        const result = await auth.login(email, password);
        session.set(result.session_token);
        onSuccess();
      } catch (reason: unknown) {
        const failure = reason instanceof ApiError ? reason : undefined;
        setError(
          failure?.status === 429
            ? `Too many attempts. Retry after ${failure.retryAfter ?? "a short interval"}.`
            : failure?.status === 401
              ? "Access denied. Verify your credentials."
              : "The control plane could not be reached.",
        );
      } finally {
        setBusy(false);
      }
    },
    [email, password, onSuccess],
  );

  return (
    <div className="login">
      <div className="login-topology" aria-hidden="true" />
      <form onSubmit={submit} className="login-card">
        <div className="wordmark">
          RAVEN<span>-X</span>
        </div>
        <p className="eyebrow">Community Edition · Local security operations</p>
        <h1>Sign in to your workspace</h1>
        <label>
          Email
          <input
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy}>
          {busy ? "Authenticating…" : "Access system"}
        </button>
        <small>Private by default · authorized operators only</small>
      </form>
    </div>
  );
}

/* -------------------------------------------------------------- workspace */

function Workspace({ onSignOut }: { onSignOut: () => void }) {
  const { route, navigate } = useRoute();
  const reduced = useReducedMotion();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toast, setToast] = useState<ApiError | null>(null);

  const organizations = useApi((signal) => auth.organizations(signal), []);
  const [organizationId, setOrganizationId] = useState<string>(() => {
    try {
      return sessionStorage.getItem(ORG_KEY) ?? "";
    } catch {
      return "";
    }
  });

  // Adopt the first available organization once the list arrives, honouring a
  // previously chosen organization when it is still accessible.
  useEffect(() => {
    const available = organizations.data;
    if (!available?.length) return;
    const stillValid = available.some((item) => item.organization_id === organizationId);
    if (!stillValid) setOrganizationId(available[0].organization_id);
  }, [organizations.data, organizationId]);

  useEffect(() => {
    if (!organizationId) return;
    try {
      sessionStorage.setItem(ORG_KEY, organizationId);
    } catch {
      /* storage unavailable — selection is still held in memory */
    }
  }, [organizationId]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await auth.logout();
    } catch {
      /* the local session is cleared regardless of the server response */
    }
    session.set(null);
    try {
      sessionStorage.removeItem(ORG_KEY);
    } catch {
      /* ignored */
    }
    onSignOut();
  }, [onSignOut]);

  const active = ALL_ITEMS.some((item) => item.id === route.section)
    ? route.section
    : "command";

  return (
    <div className="app-shell">
      <div className={reduced ? "ambient reduced" : "ambient"} aria-hidden="true" />
      <Sidebar active={active} navigate={navigate} />
      <main className="workspace">
        <Topbar
          organizations={organizations.data ?? []}
          organizationId={organizationId}
          onOrganizationChange={setOrganizationId}
          onOpenPalette={() => setPaletteOpen(true)}
          onSignOut={signOut}
        />
        <AnimatePresence mode="wait">
          <motion.section
            key={active}
            className="page"
            initial={reduced ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reduced ? undefined : { opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
          >
            {organizations.error ? (
              <ErrorState error={organizations.error} onRetry={organizations.reload} />
            ) : organizations.loading && !organizations.data ? (
              <div className="page-loading">Loading organization context…</div>
            ) : !organizationId ? (
              <Empty
                title="No organization available"
                detail="Your account has no active organization membership. An administrator must grant access before the control plane can show data."
              />
            ) : (
              <Screen
                key={organizationId}
                section={active}
                params={route.params}
                organizationId={organizationId}
                navigate={navigate}
              />
            )}
          </motion.section>
        </AnimatePresence>
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onChoose={(section) => {
          navigate(section);
          setPaletteOpen(false);
        }}
      />

      <AnimatePresence>
        {toast && <Toast error={toast} onClose={() => setToast(null)} />}
      </AnimatePresence>
    </div>
  );
}

function Screen({
  section,
  params,
  organizationId,
  navigate,
}: {
  section: string;
  params: string[];
  organizationId: string;
  navigate: (section: string, ...rest: string[]) => void;
}) {
  switch (section) {
    case "enrollment":
      return <Enrollment key={organizationId} organizationId={organizationId} navigate={navigate} />;
    case "fleet":
      return (
        <Fleet organizationId={organizationId} endpointId={params[0]} navigate={navigate} />
      );
    case "assessments":
      return (
        <Assessments
          organizationId={organizationId}
          assessmentId={params[0]}
          findingId={params[1]}
          navigate={navigate}
        />
      );
    case "schedules":
      return (
        <Schedules organizationId={organizationId} scheduleId={params[0]} navigate={navigate} />
      );
    case "groups":
      return <Groups organizationId={organizationId} />;
    case "findings":
      return <Findings organizationId={organizationId} navigate={navigate} />;
    case "fix-issues":
      return <Suspense fallback={<div className="page-loading" role="status">Loading Fix Issues…</div>}>
        <FixIssues key={organizationId} organizationId={organizationId} navigate={navigate} />
      </Suspense>;
    case "activity":
      return <ActivityPage organizationId={organizationId} />;
    case "analyst":
      return (
        <Suspense fallback={<div className="page-loading" role="status">Loading AI Analyst…</div>}>
          <Analyst key={organizationId} organizationId={organizationId} navigate={navigate} />
        </Suspense>
      );
    case "compliance":
      return <Compliance organizationId={organizationId} navigate={navigate} />;
    case "reports":
      return <Reports key={organizationId} organizationId={organizationId} endpointId={params[0]} navigate={navigate} />;
    case "settings":
      return <Settings organizationId={organizationId} />;
    case "command":
    default:
      return <CommandCenter organizationId={organizationId} navigate={navigate} />;
  }
}

/* ---------------------------------------------------------------- chrome */

function Sidebar({ active, navigate }: { active: string; navigate: (section: string) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">
          <Feather size={22} strokeWidth={1.7} />
        </span>
        <span>
          RAVEN<span>-X</span>
        </span>
      </div>
      <label className="compact-navigation">
        <span className="sr-only">Go to screen</span>
        <select value={active} onChange={(event) => navigate(event.target.value)}>
          {NAVIGATION.map((group) => (
            <optgroup key={group.label} label={group.label || "Workspace"}>
              {group.items.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </optgroup>
          ))}
        </select>
        <ChevronDown size={14} aria-hidden="true" />
      </label>
      <nav aria-label="Primary">
        {NAVIGATION.map((group, index) => (
          <div key={group.label || `group-${index}`}>
            {group.label && <div className="nav-label">{group.label}</div>}
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <a
                  key={item.id}
                  href={buildHref(item.id)}
                  aria-label={item.label}
                  title={item.label}
                  className={active === item.id ? "nav active" : "nav"}
                  aria-current={active === item.id ? "page" : undefined}
                >
                  {active === item.id && <SelectionHighlight group="primary-navigation" />}
                  <Icon size={16} aria-hidden="true" />
                  <span>{item.label}</span>
                </a>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="side-status">
        <i aria-hidden="true" />
        CONTROL PLANE
        <br />
        <small>Outbound agent transport</small>
      </div>
    </aside>
  );
}

function Topbar({
  organizations,
  organizationId,
  onOrganizationChange,
  onOpenPalette,
  onSignOut,
}: {
  organizations: Array<{ organization_id: string; name: string }>;
  organizationId: string;
  onOrganizationChange: (id: string) => void;
  onOpenPalette: () => void;
  onSignOut: () => void;
}) {
  return (
    <header className="topbar">
      <div className="org-switch">
        <span className="signal" aria-hidden="true" />
        <select
          value={organizationId}
          onChange={(event) => onOrganizationChange(event.target.value)}
          aria-label="Active organization"
          disabled={organizations.length <= 1}
        >
          {organizations.length === 0 && <option value="">No organization</option>}
          {organizations.map((item) => (
            <option key={item.organization_id} value={item.organization_id}>
              {item.name}
            </option>
          ))}
        </select>
        <ChevronDown size={14} aria-hidden="true" />
      </div>
      <button type="button" className="search" onClick={onOpenPalette}>
        <Search size={15} aria-hidden="true" />
        Jump to a screen
        <kbd>Ctrl K</kbd>
      </button>
      <div className="topbar-right">
        <button type="button" className="icon-button" onClick={onSignOut} aria-label="Sign out">
          <LogOut size={16} />
        </button>
      </div>
    </header>
  );
}

function CommandPalette({
  open,
  onClose,
  onChoose,
}: {
  open: boolean;
  onClose: () => void;
  onChoose: (section: string) => void;
}) {
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return ALL_ITEMS;
    return ALL_ITEMS.filter((item) => item.label.toLowerCase().includes(needle));
  }, [query]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="palette-wrap"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onMouseDown={onClose}
        >
          <motion.div
            className="palette"
            role="dialog"
            aria-modal="true"
            aria-label="Command palette"
            initial={{ scale: 0.98, y: -8 }}
            animate={{ scale: 1, y: 0 }}
            exit={{ scale: 0.98, opacity: 0 }}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="palette-input">
              <Command size={16} aria-hidden="true" />
              <input
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search screens"
                aria-label="Search screens"
                onKeyDown={(event) => {
                  if (event.key === "Enter" && matches[0]) onChoose(matches[0].id);
                }}
              />
            </div>
            {matches.length ? (
              matches.map((item) => {
                const Icon = item.icon;
                return (
                  <button key={item.id} type="button" onClick={() => onChoose(item.id)}>
                    <Icon size={15} aria-hidden="true" />
                    {item.label}
                  </button>
                );
              })
            ) : (
              <p className="palette-empty">No screen matches “{query}”.</p>
            )}
            <button type="button" className="palette-close" onClick={onClose}>
              <X size={15} aria-hidden="true" /> Close
            </button>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
