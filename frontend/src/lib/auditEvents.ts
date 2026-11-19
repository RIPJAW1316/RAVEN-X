/**
 * Presentation vocabulary for security audit events.
 *
 * This maps the backend's real `event_type` values onto operator language. It
 * adds no data: every label describes an event the control plane actually
 * emitted, and anything unrecognised falls back to a readable form of the raw
 * type rather than being hidden or invented.
 */
import type { AuditEvent, AuditSeverity } from "../types/api";
import type { Tone } from "./domain";
import { titleCase } from "./format";

export const SEVERITY_TONE: Record<AuditSeverity, Tone> = {
  critical: "critical",
  warning: "warn",
  info: "info",
};

export const SEVERITY_LABEL: Record<AuditSeverity, string> = {
  critical: "Critical",
  warning: "Warning",
  info: "Info",
};

/** Glyph paired with colour so severity is not conveyed by hue alone. */
export const SEVERITY_GLYPH: Record<AuditSeverity, string> = {
  critical: "!!",
  warning: "!",
  info: "·",
};

/** Broad grouping used for the icon and for filter chips. */
export type AuditCategory =
  | "authentication"
  | "authorization"
  | "endpoint"
  | "assessment"
  | "compliance"
  | "governance"
  | "agent"
  | "other";

export function categoryOf(event: AuditEvent): AuditCategory {
  const type = event.event_type;
  if (type.startsWith("human.") || type.startsWith("session.")) return "authentication";
  if (type.startsWith("authorization.") || type.startsWith("organization.context")) return "authorization";
  if (type.startsWith("endpoint.") || type.startsWith("enrollment.") || type.startsWith("credential."))
    return "endpoint";
  if (type.startsWith("assessment.")) return "assessment";
  if (type.startsWith("compliance.")) return "compliance";
  if (type.startsWith("role") || type.startsWith("membership.") || type.startsWith("user.") ||
      type.startsWith("organization.")) return "governance";
  if (type.startsWith("agent.")) return "agent";
  return "other";
}

/** Short headline. Unknown types degrade to a title-cased version of the type. */
const TITLES: Record<string, string> = {
  "human.authentication_succeeded": "Sign-in succeeded",
  "human.authentication_failed": "Sign-in failed",
  "human.authentication_rate_limited": "Sign-in rate limited",
  "session.issued": "Session issued",
  "session.revoked": "Session revoked",
  "session.expired": "Session expired",
  "authorization.allowed": "Access granted",
  "authorization.denied": "Access denied",
  "organization.context_resolved": "Organization context resolved",
  "organization.context_denied": "Organization context denied",
  "organization.created": "Organization created",
  "organization.updated": "Organization updated",
  "organization.suspended": "Organization suspended",
  "organization.revoked": "Organization revoked",
  "membership.created": "Member added",
  "membership.suspended": "Member suspended",
  "membership.revoked": "Member removed",
  "user.created": "User created",
  "user.disabled": "User disabled",
  "user.revoked": "User revoked",
  "role.created": "Role created",
  "role.updated": "Role updated",
  "role.disabled": "Role disabled",
  "role.revoked": "Role revoked",
  "role_binding.created": "Role assigned",
  "role_binding.disabled": "Role assignment disabled",
  "role_binding.revoked": "Role assignment revoked",
  "endpoint.registered": "Endpoint enrolled",
  "endpoint.updated": "Endpoint updated",
  "endpoint.revoked": "Endpoint revoked",
  "endpoint.presence_online": "Endpoint came online",
  "endpoint.presence_stale": "Endpoint heartbeat stale",
  "endpoint.presence_offline": "Endpoint went offline",
  "enrollment.created": "Enrollment token issued",
  "enrollment.renewed": "Enrollment token renewed",
  "enrollment.consumed": "Enrollment completed",
  "enrollment.consumption_failed": "Enrollment rejected",
  "enrollment.revoked": "Enrollment revoked",
  "credential.issued": "Agent credential issued",
  "credential.rotated": "Agent credential rotated",
  "credential.revoked": "Agent credential revoked",
  "credential.authentication_succeeded": "Agent authenticated",
  "credential.authentication_failed": "Agent authentication failed",
  "agent.message_replay_rejected": "Replayed agent message rejected",
  "agent.message_authorization_denied": "Agent message denied",
  "assessment.created": "Assessment dispatched",
  "assessment.queued": "Assessment queued",
  "assessment.acknowledged": "Assessment acknowledged",
  "assessment.completed": "Assessment completed",
  "assessment.failed": "Assessment failed",
  "assessment.delivery_failed": "Assessment delivery failed",
  "assessment.expired": "Assessment expired",
  "assessment.cancel_requested": "Assessment cancellation requested",
  "assessment.cancelled": "Assessment cancelled",
  "assessment_schedule.created": "Schedule created",
  "assessment_schedule.updated": "Schedule updated",
  "assessment_schedule.paused": "Schedule paused",
  "assessment_schedule.resumed": "Schedule resumed",
  "assessment_schedule.revoked": "Schedule revoked",
  "assessment_schedule.run": "Schedule executed",
  "endpoint_group.create": "Endpoint group created",
  "endpoint_group.update": "Endpoint group updated",
  "endpoint_group.membership_update": "Group membership changed",
  "endpoint_group.revoke": "Endpoint group revoked",
  "fleet_scope.create": "Fleet scope created",
  "fleet_scope.update": "Fleet scope updated",
  "fleet_scope.revoke": "Fleet scope revoked",
  "compliance.snapshot.create": "Compliance snapshot captured",
  "compliance.snapshot.export": "Compliance snapshot exported",
  "compliance.snapshot.failed": "Compliance snapshot failed",
  "compliance.retention.applied": "Compliance retention applied",
};

export function eventTitle(event: AuditEvent): string {
  return TITLES[event.event_type] ?? titleCase(event.event_type);
}

/** Who acted, in display terms. Never an email — the API does not expose one. */
export function actorLabel(event: AuditEvent): string {
  const { principal_type: type, principal_id: id } = event.actor;
  if (type === "system") return "System";
  if (type === "internal") return "Control plane";
  if (type === "endpoint") return `Agent ${short(id)}`;
  if (type === "human") return id ? `Operator ${short(id)}` : "Operator";
  return titleCase(type);
}

/**
 * The most specific resource this event touched, for the secondary line.
 * Returns null when there is nothing meaningful to add.
 */
export function targetLabel(event: AuditEvent): string | null {
  const meta = event.metadata;
  const framework = typeof meta.framework_id === "string" ? meta.framework_id : null;
  const schedule = typeof meta.schedule_id === "string" ? meta.schedule_id : null;

  if (event.endpoint_id) return `Endpoint ${short(event.endpoint_id)}`;
  if (event.assessment_id) return `Assessment ${short(event.assessment_id)}`;
  if (framework) return `Framework ${framework}`;
  if (schedule) return `Schedule ${short(schedule)}`;
  if (event.resource?.resource_type && event.resource.resource_id) {
    return `${titleCase(event.resource.resource_type)} ${short(event.resource.resource_id)}`;
  }
  if (event.resource?.resource_type) return titleCase(event.resource.resource_type);
  return null;
}

/**
 * Extra operational context worth showing inline, drawn only from allowlisted
 * metadata the API already returned.
 */
export function detailChips(event: AuditEvent): Array<[string, string]> {
  const chips: Array<[string, string]> = [];
  const meta = event.metadata;
  const push = (key: string, label: string) => {
    const value = meta[key];
    if (value === undefined || value === null || value === "") return;
    if (Array.isArray(value)) {
      if (value.length) chips.push([label, value.length > 3 ? `${value.length} selected` : value.join(", ")]);
      return;
    }
    chips.push([label, String(value)]);
  };
  push("scanner_ids", "Scanners");
  push("scope_type", "Scope");
  push("endpoint_count", "Endpoints");
  push("resolved_count", "Resolved");
  push("created_count", "Created");
  push("target_type", "Target");
  push("previous_state", "From");
  push("state", "To");
  push("format", "Format");
  if (event.reason_code) chips.push(["Reason", titleCase(event.reason_code)]);
  else push("reason", "Reason");
  return chips.slice(0, 4);
}

function short(value: string | null | undefined): string {
  if (!value) return "unknown";
  return value.length <= 12 ? value : `${value.slice(0, 8)}…`;
}
