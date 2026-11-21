/**
 * Shared presentation primitives.
 *
 * Status is always communicated with a glyph or text label in addition to
 * colour so the interface stays readable without hue perception.
 */
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Inbox,
  Loader2,
  Lock,
  RefreshCw,
  ServerCrash,
  X,
} from "lucide-react";
import type { KeyboardEvent, ReactNode } from "react";
import { useId } from "react";
import { createPortal } from "react-dom";
import { ApiError } from "../api/client";
import { useDialogFocus } from "../hooks/useDialogFocus";
import {
  SEVERITY_GLYPH,
  SEVERITY_LABEL,
  type Tone,
} from "../lib/domain";
import {
  drawerVariants,
  modalVariants,
  SCRIM_TRANSITION,
  SPRING_PILL,
  toastVariants,
} from "../lib/motion";
import type { Severity } from "../types/api";

/* ----------------------------------------------------------------- panels */

export function Panel({
  title,
  icon,
  actions,
  children,
  className = "",
}: {
  title?: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-kicker">
          <span className="panel-title">
            {icon}
            {title}
          </span>
          {actions && <span className="panel-actions">{actions}</span>}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageHeading({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/* ----------------------------------------------------------------- badges */

export function Badge({
  tone = "neutral",
  children,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function StatusBadge({
  tone,
  label,
  title,
}: {
  tone: Tone;
  label: string;
  title?: string;
}) {
  return (
    <span className={`status-badge tone-${tone}`} title={title ?? label}>
      <i aria-hidden="true" />
      {label}
    </span>
  );
}

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`severity-badge sev-${severity}`}>
      <b aria-hidden="true">{SEVERITY_GLYPH[severity]}</b>
      {SEVERITY_LABEL[severity]}
      {count !== undefined && <em>{count}</em>}
    </span>
  );
}

/* ------------------------------------------------------------- stat tiles */

export function Stat({
  icon,
  label,
  value,
  hint,
  tone = "neutral",
  onClick,
}: {
  icon?: ReactNode;
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: Tone;
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className="stat-label">{icon && <span className={`stat-icon tone-${tone}`} aria-hidden="true">{icon}</span>}{label}</span>
      <strong className={`stat-value tone-${tone}`}>{value}</strong>
      {hint && <small className="stat-hint">{hint}</small>}
    </>
  );
  if (onClick) {
    return (
      <button type="button" className="stat stat-action" onClick={onClick}>
        {content}
      </button>
    );
  }
  return <div className="stat">{content}</div>;
}

/* ------------------------------------------------------------ empty/error */

export function Empty({
  title,
  detail,
  icon,
  compact,
  action,
}: {
  title: string;
  detail: string;
  icon?: ReactNode;
  compact?: boolean;
  action?: ReactNode;
}) {
  return (
    <div className={compact ? "empty compact" : "empty"}>
      {icon ?? <Inbox size={compact ? 22 : 34} aria-hidden="true" />}
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </div>
  );
}

/**
 * Renders an API failure in operator language. 403 and 503 are distinguished
 * because they mean very different things: one is a permission boundary, the
 * other a capability that is switched off.
 */
export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const forbidden = error.isForbidden;
  const unavailable = error.isUnavailable;
  const title = forbidden
    ? "Permission denied"
    : unavailable
      ? "Capability unavailable"
      : error.isNotFound
        ? "Not found"
        : "Control plane error";
  const detail = forbidden
    ? "Your role in this organization does not grant access to this data."
    : unavailable
      ? "This capability is not enabled on the server. No data can be shown."
      : error.message;
  return (
    <div className="empty error">
      {forbidden ? (
        <Lock size={30} aria-hidden="true" />
      ) : (
        <ServerCrash size={30} aria-hidden="true" />
      )}
      <strong>{title}</strong>
      <p>{detail}</p>
      {error.requestId && <code className="request-id">Reference {error.requestId}</code>}
      {onRetry && !forbidden && (
        <button type="button" className="ghost" onClick={onRetry}>
          <RefreshCw size={14} aria-hidden="true" /> Retry
        </button>
      )}
    </div>
  );
}

/**
 * Documents a capability the backend does not expose yet. Used instead of
 * inventing data so the interface never implies a feature exists.
 */
export function NotImplemented({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <div className="empty deferred">
      <AlertTriangle size={30} aria-hidden="true" />
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

/* --------------------------------------------------------------- loading */

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton-stack" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }, (_, index) => (
        <div className="skeleton" key={index} />
      ))}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="spinner" role="status">
      <Loader2 size={15} aria-hidden="true" />
      {label}
    </span>
  );
}

/**
 * Standard async envelope: loading → error → empty → content. Keeping this in
 * one place means every screen handles the same states the same way.
 */
export function AsyncSection<T>({
  loading,
  error,
  data,
  onRetry,
  empty,
  children,
  skeletonRows,
}: {
  loading: boolean;
  error: ApiError | undefined;
  data: T | undefined;
  onRetry?: () => void;
  empty?: ReactNode;
  children: (value: T) => ReactNode;
  skeletonRows?: number;
}) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (loading && data === undefined) return <Skeleton rows={skeletonRows ?? 4} />;
  if (data === undefined) return <>{empty ?? <Empty title="No data" detail="Nothing was returned." />}</>;
  if (Array.isArray(data) && data.length === 0 && empty) return <>{empty}</>;
  return <>{children(data)}</>;
}

/* ---------------------------------------------------------------- dialogs */

export function Drawer({
  open,
  title,
  onClose,
  children,
  width = 560,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
}) {
  const dialogRef = useDialogFocus<HTMLElement>(open, onClose);
  const reduced = useReducedMotion();

  const overlay = (
    <AnimatePresence>
      {open && (
        <motion.div
          className="drawer-scrim"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={SCRIM_TRANSITION}
          onMouseDown={onClose}
        >
          <motion.aside
            className="drawer"
            ref={dialogRef}
            tabIndex={-1}
            style={{ width }}
            role="dialog"
            aria-modal="true"
            aria-label={title}
            variants={drawerVariants(reduced)}
            initial="initial"
            animate="animate"
            exit="exit"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <header className="drawer-head">
              <h2>{title}</h2>
              <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
                <X size={16} />
              </button>
            </header>
            <div className="drawer-body">{children}</div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  );

  return typeof document === "undefined" ? overlay : createPortal(overlay, document.body);
}

export function Modal({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const dialogRef = useDialogFocus<HTMLDivElement>(open, onClose);
  const reduced = useReducedMotion();

  const overlay = (
    <AnimatePresence>
      {open && (
        <motion.div
          className="modal-scrim"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={SCRIM_TRANSITION}
          onMouseDown={onClose}
        >
          <motion.div
            className="modal"
            ref={dialogRef}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-label={title}
            variants={modalVariants(reduced)}
            initial="initial"
            animate="animate"
            exit="exit"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <header className="drawer-head">
              <h2>{title}</h2>
              <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
                <X size={16} />
              </button>
            </header>
            <div className="modal-body">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  return typeof document === "undefined" ? overlay : createPortal(overlay, document.body);
}

/* ------------------------------------------------------------------- misc */

export function Toast({
  error,
  onClose,
}: {
  error: ApiError;
  onClose: () => void;
}) {
  const reduced = useReducedMotion();

  const node = (
    <motion.div
      className="toast"
      role="alert"
      variants={toastVariants(reduced)}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      <AlertTriangle size={17} aria-hidden="true" />
      <div>
        <strong>
          {error.isForbidden
            ? "Permission denied"
            : error.status === 429
              ? "Rate limited"
              : "Request failed"}
        </strong>
        <p>{error.message}</p>
        {error.requestId && <code>Reference {error.requestId}</code>}
      </div>
      <button type="button" onClick={onClose} aria-label="Dismiss">
        <X size={15} />
      </button>
    </motion.div>
  );

  return typeof document === "undefined" ? node : createPortal(node, document.body);
}

export function SelectionHighlight({ group }: { group: string }) {
  const reduced = useReducedMotion();
  if (reduced) return <span className="selection-highlight" aria-hidden="true" />;
  return (
    <motion.span
      aria-hidden="true"
      className="selection-highlight"
      layoutId={group}
      initial={false}
      transition={SPRING_PILL}
    />
  );
}

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
  label,
  children,
}: {
  tabs: Array<{ id: T; label: string; count?: number }>;
  active: T;
  onChange: (id: T) => void;
  label: string;
  children: ReactNode;
}) {
  const group = useId();
  const tabId = (id: T) => `${group}-tab-${id}`;
  const panelId = (id: T) => `${group}-panel-${id}`;

  function moveTab(event: KeyboardEvent<HTMLDivElement>) {
    const current = tabs.findIndex((tab) => tabId(tab.id) === (event.target as HTMLElement).id);
    if (current < 0) return;
    let next: number;
    switch (event.key) {
      case "ArrowLeft": next = (current + tabs.length - 1) % tabs.length; break;
      case "ArrowRight": next = (current + 1) % tabs.length; break;
      case "Home": next = 0; break;
      case "End": next = tabs.length - 1; break;
      default: return;
    }
    event.preventDefault();
    const nextId = tabs[next].id;
    document.getElementById(tabId(nextId))?.focus();
    onChange(nextId);
  }
  return (
    <>
      <div className="tabs" role="tablist" aria-label={label} onKeyDown={moveTab}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            id={tabId(tab.id)}
            role="tab"
            type="button"
            tabIndex={tab.id === active ? 0 : -1}
            aria-controls={panelId(tab.id)}
            aria-selected={tab.id === active}
            className={tab.id === active ? "tab active" : "tab"}
            onClick={() => onChange(tab.id)}
          >
            {tab.id === active && <SelectionHighlight group={group} />}
            {tab.label}
            {tab.count !== undefined && <em>{tab.count}</em>}
          </button>
        ))}
      </div>
      {tabs.map((tab) => (
        <div key={tab.id} id={panelId(tab.id)} role="tabpanel" aria-labelledby={tabId(tab.id)}
          hidden={tab.id !== active} tabIndex={tab.id === active ? 0 : -1}>
          {tab.id === active && children}
        </div>
      ))}
    </>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}

export function DefinitionList({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="definition-list">
      {items.map(([term, value]) => (
        <div key={term}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Confirm({
  open,
  title,
  message,
  confirmLabel,
  destructive,
  busy,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal open={open} title={title} onClose={onCancel}>
      <p className="confirm-message">{message}</p>
      <div className="modal-actions">
        <button type="button" className="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className={destructive ? "danger" : "primary"}
          onClick={onConfirm}
          disabled={busy}
        >
          {busy ? "Working…" : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

export function SuccessNote({ children }: { children: ReactNode }) {
  return (
    <p className="success-note">
      <CheckCircle2 size={14} aria-hidden="true" />
      {children}
    </p>
  );
}
