/**
 * Shared vocabulary for severity, lifecycle and presence.
 *
 * Every state listed here exists in the backend domain. Nothing is invented:
 * assessment states come from `RemoteAssessmentState`, presence from
 * `PresenceState`, compliance from `ComplianceStatus`.
 */
import type { AssessmentState, ComplianceStatus, PresenceState, Severity } from "../types/api";

/* --------------------------------------------------------------- severity */

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

export function normalizeSeverity(value: string | null | undefined): Severity {
  const candidate = (value ?? "").toLowerCase();
  return (SEVERITY_ORDER as string[]).includes(candidate) ? (candidate as Severity) : "unknown";
}

/** Short glyph paired with colour so severity never relies on hue alone. */
export const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: "!!",
  high: "!",
  medium: "=",
  low: "·",
  info: "i",
  unknown: "?",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

/* ------------------------------------------------------------- assessment */

/** Ordered pipeline used by the lifecycle visualisation. */
export const ASSESSMENT_PIPELINE: AssessmentState[] = [
  "created",
  "queued",
  "dispatched",
  "running",
  "completed",
];

const TERMINAL_STATES = new Set<AssessmentState>([
  "completed",
  "failed",
  "delivery_failed",
  "expired",
  "cancelled",
  "endpoint_unavailable",
]);

const FAILED_STATES = new Set<AssessmentState>([
  "failed",
  "delivery_failed",
  "expired",
  "endpoint_unavailable",
]);

export function isTerminal(state: AssessmentState): boolean {
  return TERMINAL_STATES.has(state);
}

export function isFailure(state: AssessmentState): boolean {
  return FAILED_STATES.has(state);
}

export function isActive(state: AssessmentState): boolean {
  return !isTerminal(state);
}

export const ASSESSMENT_LABEL: Record<AssessmentState, string> = {
  created: "Created",
  queued: "Queued",
  dispatched: "Dispatched",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  delivery_failed: "Delivery failed",
  expired: "Expired",
  cancel_requested: "Cancelling",
  cancelled: "Cancelled",
  endpoint_unavailable: "Endpoint unavailable",
};

/** Maps any state onto its position in the happy-path pipeline. */
export function pipelineIndex(state: AssessmentState): number {
  const direct = ASSESSMENT_PIPELINE.indexOf(state);
  if (direct >= 0) return direct;
  if (state === "cancel_requested") return ASSESSMENT_PIPELINE.indexOf("running");
  if (isFailure(state) || state === "cancelled") return ASSESSMENT_PIPELINE.indexOf("running");
  return 0;
}

export type Tone = "critical" | "warn" | "ok" | "info" | "neutral";

export function assessmentTone(state: AssessmentState): Tone {
  if (state === "completed") return "ok";
  if (isFailure(state)) return "critical";
  if (state === "cancelled" || state === "cancel_requested") return "warn";
  if (state === "running" || state === "dispatched") return "info";
  return "neutral";
}

/* --------------------------------------------------------------- presence */

export const PRESENCE_LABEL: Record<PresenceState, string> = {
  online: "Online",
  stale: "Stale",
  offline: "Offline",
  unknown: "Unknown",
};

export function presenceTone(state: PresenceState): Tone {
  if (state === "online") return "ok";
  if (state === "stale") return "warn";
  if (state === "offline") return "critical";
  return "neutral";
}

/* ------------------------------------------------------------- compliance */

export const COMPLIANCE_LABEL: Record<ComplianceStatus, string> = {
  compliant: "Compliant",
  non_compliant: "Non-compliant",
  unknown: "Unknown",
  not_applicable: "Not applicable",
};

export function complianceTone(status: ComplianceStatus): Tone {
  if (status === "compliant") return "ok";
  if (status === "non_compliant") return "critical";
  if (status === "not_applicable") return "neutral";
  return "warn";
}

/**
 * Reason codes emitted by the compliance evaluator, rendered in plain language
 * so a non-specialist can read a posture report.
 */
export const COMPLIANCE_REASON: Record<string, string> = {
  evidence_satisfied: "Evidence satisfied the control requirement.",
  finding_observed: "A finding was observed that violates this control.",
  scanner_not_run: "The scanner providing evidence has not run on this endpoint.",
  scanner_failed: "The scanner providing evidence failed to complete.",
  coverage_unknown: "Scanner coverage for this control could not be established.",
  stale_evidence: "The available evidence is older than the freshness window.",
  assessment_incomplete: "The source assessment did not complete.",
  endpoint_not_applicable: "This control does not apply to the endpoint platform.",
  control_unsupported: "Raven-X cannot yet evaluate this control automatically.",
};
