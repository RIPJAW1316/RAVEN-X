/**
 * Typed bindings for every control-plane route the UI consumes.
 *
 * Each function maps to a route that exists in
 * `backend/api/human_control_plane.py`. Capabilities without a backing route
 * are recorded in `docs/frontend-api-gaps.md` rather than stubbed here.
 */
import { request, requestBlob } from "./client";
import type {
  Assessment,
  AssessmentDetail,
  AuditPage,
  AuditQueryParams,
  ComplianceControl,
  ComplianceFramework,
  CompliancePosture,
  ComplianceSnapshot,
  ControlEvaluation,
  CurrentUser,
  EndpointDetail,
  EndpointGroup,
  EndpointPresence,
  EnrollmentToken,
  IssuedEnrollmentToken,
  FindingDetail,
  FleetEndpoint,
  FleetPage,
  FleetEvidenceReport,
  LocalAnalysis,
  ReportReviewModel,
  ReviewedEvidenceReport,
  FleetQueryParams,
  FleetScope,
  Membership,
  Organization,
  OrganizationRef,
  Recurrence,
  Schedule,
  ScheduleRun,
  SecurityMetrics,
  ScopeCriteria,
  SecurityOverview,
  SessionResponse,
} from "../types/api";

const org = (id: string) => `/api/v1/organizations/${encodeURIComponent(id)}`;

export const insights = {
  fixPlan: (id: string, endpointId: string, signal?: AbortSignal) =>
    request<import("../types/api").FixPlan>(
      `${org(id)}/reports/fix-plan${endpointId ? `?endpoint_id=${encodeURIComponent(endpointId)}` : ""}`,
      { signal },
    ),
  fleetCsv: (id: string) => requestBlob(`${org(id)}/reports/fleet.csv`),
  reviewReport: (id: string, model: ReportReviewModel, endpointId?: string) =>
    request<ReviewedEvidenceReport>(org(id) + "/reports/review", {
      method: "POST", query: { model, endpoint_id: endpointId },
    }),
  reviewedExport: (id: string, model: ReportReviewModel, endpointId?: string, format = "pdf", reviewId?: string) =>
    requestBlob(org(id) + "/reports/review", {
      method: "POST", query: { model, endpoint_id: endpointId, format, review_id: reviewId },
    }),
  fleetReport: (id: string, signal?: AbortSignal) => request<FleetEvidenceReport>(`${org(id)}/reports/fleet`, { signal }),
  endpointReport: (id: string, endpointId: string, signal?: AbortSignal) => request<FleetEvidenceReport>(`${org(id)}/endpoints/${encodeURIComponent(endpointId)}/report`, { signal }),
  analyze: (
    id: string,
    selection?: string | { endpointId?: string; demoId?: string; model?: "lm_studio" | "offline" | "gemini"; offlinePlan?: boolean },
    offlinePlan?: boolean,
  ) => {
    const body: Record<string, unknown> = {};
    if (typeof selection === "string") {
      if (selection) body.endpoint_id = selection;
      if (offlinePlan !== undefined) body.offline_plan = offlinePlan;
    } else if (selection && typeof selection === "object") {
      if (selection.endpointId) body.endpoint_id = selection.endpointId;
      if (selection.demoId) body.demo_id = selection.demoId;
      if (selection.model) {
        body.model = selection.model;
      } else if (selection.offlinePlan !== undefined) {
        body.offline_plan = selection.offlinePlan;
      }
    } else if (offlinePlan !== undefined) {
      body.offline_plan = offlinePlan;
    }
    return request<LocalAnalysis>(`${org(id)}/ai/analyze`, {
      method: "POST",
      body,
    });
  },
};

export const enrollment = {
  list: (id: string, signal?: AbortSignal) =>
    request<EnrollmentToken[]>(`${org(id)}/enrollment-tokens`, { signal }),
  issue: (id: string, label: string, ttlMinutes: number) =>
    request<IssuedEnrollmentToken>(`${org(id)}/enrollment-tokens`, {
      method: "POST", body: { label, ttl_minutes: ttlMinutes, max_uses: 1 },
    }),
  renewToken: (id: string, enrollmentId: string) =>
    request<EnrollmentToken>(`${org(id)}/enrollment-tokens/${encodeURIComponent(enrollmentId)}/renew`, { method: "POST" }),
  revokeToken: (id: string, enrollmentId: string) =>
    request<EnrollmentToken>(`${org(id)}/enrollment-tokens/${encodeURIComponent(enrollmentId)}`, { method: "DELETE" }),
  approve: (id: string, endpointId: string) =>
    request<EndpointDetail>(`${org(id)}/endpoints/${encodeURIComponent(endpointId)}/approve`, { method: "POST" }),
  revokeEndpoint: (id: string, endpointId: string) =>
    request<EndpointDetail>(`${org(id)}/endpoints/${encodeURIComponent(endpointId)}/revoke`, { method: "POST" }),
};

/* --------------------------------------------------------------- identity */

export const auth = {
  login: (email: string, password: string) =>
    request<SessionResponse>("/api/v1/auth/login", { method: "POST", body: { email, password } }),
  logout: () => request<{ status: string }>("/api/v1/auth/logout", { method: "POST" }),
  me: (signal?: AbortSignal) => request<CurrentUser>("/api/v1/auth/me", { signal }),
  organizations: (signal?: AbortSignal) =>
    request<OrganizationRef[]>("/api/v1/auth/organizations", { signal }),
};

/* ---------------------------------------------------------- organizations */

export const organizations = {
  get: (id: string, signal?: AbortSignal) => request<Organization>(org(id), { signal }),
  memberships: (id: string, signal?: AbortSignal) =>
    request<Membership[]>(`${org(id)}/memberships`, { signal }),
  addMembership: (id: string, userId: string) =>
    request<Membership>(`${org(id)}/memberships`, { method: "POST", body: { user_id: userId } }),
  suspendMembership: (id: string, membershipId: string) =>
    request<Membership>(`${org(id)}/memberships/${encodeURIComponent(membershipId)}/suspend`, {
      method: "POST",
    }),
  revokeMembership: (id: string, membershipId: string) =>
    request<Membership>(`${org(id)}/memberships/${encodeURIComponent(membershipId)}/revoke`, {
      method: "POST",
    }),
};

/* -------------------------------------------------------------- reporting */

export const reporting = {
  overview: (id: string, signal?: AbortSignal) =>
    request<SecurityOverview>(`${org(id)}/security/overview`, { signal }),
};

/* -------------------------------------------------- security observability */

export const observability = {
  /**
   * Windowed authorization/authentication telemetry and any signals it fired.
   * High-volume telemetry lives here rather than in the audit trail.
   */
  metrics: (id: string, windowMinutes = 15, signal?: AbortSignal) =>
    request<SecurityMetrics>(`${org(id)}/security/metrics`, {
      signal,
      query: { window_minutes: windowMinutes },
    }),
};

/* ------------------------------------------------------------ audit feed */

export const audit = {
  /**
   * Organization security activity, newest first.
   *
   * The organization is a path segment resolved server-side; there is no way
   * to widen the scope from the client.
   */
  events: (id: string, params: AuditQueryParams = {}, signal?: AbortSignal) =>
    request<AuditPage>(`${org(id)}/audit-events`, {
      signal,
      query: {
        event_type: params.event_type,
        outcome: params.outcome,
        severity: params.severity,
        actor_id: params.actor_id,
        endpoint_id: params.endpoint_id,
        from: params.from,
        to: params.to,
        include_permission_checks: params.include_permission_checks ? "true" : undefined,
        limit: params.limit ?? 25,
        offset: params.offset ?? 0,
      },
    }),
};

/* ------------------------------------------------------------------ fleet */

export const fleet = {
  query: (id: string, params: FleetQueryParams = {}, signal?: AbortSignal) =>
    request<FleetPage>(`${org(id)}/fleet/endpoints`, {
      signal,
      query: {
        q: params.q,
        status: params.status,
        presence: params.presence,
        platform: params.platform,
        architecture: params.architecture,
        agent_version: params.agent_version,
        sort: params.sort,
        direction: params.direction,
        limit: params.limit ?? 50,
        offset: params.offset ?? 0,
      },
    }),
  presence: (id: string, signal?: AbortSignal) =>
    request<unknown>(`${org(id)}/fleet/presence`, { signal }),
  endpoint: (id: string, endpointId: string, signal?: AbortSignal) =>
    request<EndpointDetail>(`${org(id)}/endpoints/${encodeURIComponent(endpointId)}`, { signal }),
  endpointPresence: (id: string, endpointId: string, signal?: AbortSignal) =>
    request<EndpointPresence>(`${org(id)}/endpoints/${encodeURIComponent(endpointId)}/presence`, {
      signal,
    }),
  /** Convenience: the plain (non-paged) tenant endpoint list. */
  list: (id: string, signal?: AbortSignal) =>
    request<FleetEndpoint[]>(`${org(id)}/endpoints`, { signal }),
};

/* ------------------------------------------------------------ assessments */

export const assessments = {
  list: (id: string, signal?: AbortSignal) =>
    request<Assessment[]>(`${org(id)}/assessments`, { signal }),
  get: (id: string, assessmentId: string, signal?: AbortSignal) =>
    request<Assessment>(`${org(id)}/assessments/${encodeURIComponent(assessmentId)}`, { signal }),
  detail: (id: string, assessmentId: string, signal?: AbortSignal) =>
    request<AssessmentDetail>(`${org(id)}/assessments/${encodeURIComponent(assessmentId)}/details`, {
      signal,
    }),
  create: (id: string, endpointId: string, scannerIds: string[]) =>
    request<Assessment>(`${org(id)}/assessments`, {
      method: "POST",
      body: { endpoint_id: endpointId, scanner_ids: scannerIds },
    }),
  cancel: (id: string, assessmentId: string) =>
    request<Assessment>(`${org(id)}/assessments/${encodeURIComponent(assessmentId)}/cancel`, {
      method: "POST",
    }),
  finding: (id: string, assessmentId: string, occurrenceId: string, signal?: AbortSignal) =>
    request<FindingDetail>(
      `${org(id)}/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(occurrenceId)}`,
      { signal },
    ),
  findingRecurrence: (id: string, assessmentId: string, occurrenceId: string, signal?: AbortSignal) =>
    request<unknown>(
      `${org(id)}/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(occurrenceId)}/recurrence`,
      { signal },
    ),
  findingCoverage: (id: string, assessmentId: string, occurrenceId: string, signal?: AbortSignal) =>
    request<unknown>(
      `${org(id)}/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(occurrenceId)}/coverage`,
      { signal },
    ),
};

/* -------------------------------------------------------------- schedules */

export interface ScheduleCreateInput {
  name: string;
  scanner_ids: string[];
  recurrence: Partial<Recurrence> & { frequency: string };
  target_endpoint_ids?: string[];
  target?: { type: string; endpoint_ids?: string[]; reference_id?: string | null };
}

export const schedules = {
  list: (id: string, signal?: AbortSignal) =>
    request<Schedule[]>(`${org(id)}/assessment-schedules`, { signal }),
  get: (id: string, scheduleId: string, signal?: AbortSignal) =>
    request<Schedule>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}`, { signal }),
  runs: (id: string, scheduleId: string, signal?: AbortSignal) =>
    request<ScheduleRun[]>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}/runs`, {
      signal,
    }),
  create: (id: string, input: ScheduleCreateInput) =>
    request<Schedule>(`${org(id)}/assessment-schedules`, { method: "POST", body: input }),
  update: (id: string, scheduleId: string, changes: Record<string, unknown>) =>
    request<Schedule>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}`, {
      method: "PATCH",
      body: changes,
    }),
  pause: (id: string, scheduleId: string) =>
    request<Schedule>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}/pause`, {
      method: "POST",
    }),
  resume: (id: string, scheduleId: string) =>
    request<Schedule>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}/resume`, {
      method: "POST",
    }),
  revoke: (id: string, scheduleId: string) =>
    request<Schedule>(`${org(id)}/assessment-schedules/${encodeURIComponent(scheduleId)}/revoke`, {
      method: "POST",
    }),
};

/* -------------------------------------------------------- groups & scopes */

export const groups = {
  list: (id: string, signal?: AbortSignal) =>
    request<EndpointGroup[]>(`${org(id)}/endpoint-groups`, { signal }),
  get: (id: string, groupId: string, signal?: AbortSignal) =>
    request<EndpointGroup>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}`, { signal }),
  create: (id: string, name: string, description = "") =>
    request<EndpointGroup>(`${org(id)}/endpoint-groups`, {
      method: "POST",
      body: { name, description },
    }),
  update: (id: string, groupId: string, changes: { name?: string; description?: string }) =>
    request<EndpointGroup>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}`, {
      method: "PATCH",
      body: changes,
    }),
  members: (id: string, groupId: string, limit = 50, offset = 0, signal?: AbortSignal) =>
    request<unknown>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}/members`, {
      signal,
      query: { limit, offset },
    }),
  addMembers: (id: string, groupId: string, endpointIds: string[]) =>
    request<unknown>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}/members`, {
      method: "POST",
      body: { endpoint_ids: endpointIds },
    }),
  removeMembers: (id: string, groupId: string, endpointIds: string[]) =>
    request<unknown>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}/members/remove`, {
      method: "POST",
      body: { endpoint_ids: endpointIds },
    }),
  revoke: (id: string, groupId: string) =>
    request<EndpointGroup>(`${org(id)}/endpoint-groups/${encodeURIComponent(groupId)}/revoke`, {
      method: "POST",
    }),
};

export const scopes = {
  list: (id: string, signal?: AbortSignal) =>
    request<FleetScope[]>(`${org(id)}/fleet-scopes`, { signal }),
  get: (id: string, scopeId: string, signal?: AbortSignal) =>
    request<FleetScope>(`${org(id)}/fleet-scopes/${encodeURIComponent(scopeId)}`, { signal }),
  create: (id: string, name: string, criteria: Partial<ScopeCriteria>, description = "") =>
    request<FleetScope>(`${org(id)}/fleet-scopes`, {
      method: "POST",
      body: { name, criteria, description },
    }),
  update: (id: string, scopeId: string, changes: Record<string, unknown>) =>
    request<FleetScope>(`${org(id)}/fleet-scopes/${encodeURIComponent(scopeId)}`, {
      method: "PATCH",
      body: changes,
    }),
  revoke: (id: string, scopeId: string) =>
    request<FleetScope>(`${org(id)}/fleet-scopes/${encodeURIComponent(scopeId)}/revoke`, {
      method: "POST",
    }),
  resolve: (id: string, scopeId: string, limit = 50, offset = 0, signal?: AbortSignal) =>
    request<FleetPage>(`${org(id)}/fleet-scopes/${encodeURIComponent(scopeId)}/endpoints`, {
      signal,
      query: { limit, offset },
    }),
};

/* ------------------------------------------------------------- compliance */

export const compliance = {
  frameworks: (id: string, signal?: AbortSignal) =>
    request<ComplianceFramework[]>(`${org(id)}/compliance/frameworks`, { signal }),
  framework: (id: string, frameworkId: string, signal?: AbortSignal) =>
    request<ComplianceFramework & { controls?: ComplianceControl[] }>(
      `${org(id)}/compliance/frameworks/${encodeURIComponent(frameworkId)}`,
      { signal },
    ),
  summary: (id: string, frameworkId: string, signal?: AbortSignal) =>
    request<CompliancePosture>(`${org(id)}/compliance/${encodeURIComponent(frameworkId)}/summary`, {
      signal,
    }),
  endpointEvaluation: (id: string, endpointId: string, frameworkId: string, signal?: AbortSignal) =>
    request<ControlEvaluation[]>(
      `${org(id)}/endpoints/${encodeURIComponent(endpointId)}/compliance/${encodeURIComponent(frameworkId)}`,
      { signal },
    ),
  snapshots: (id: string, frameworkId: string, limit = 50, offset = 0, signal?: AbortSignal) =>
    request<ComplianceSnapshot[] | { items?: ComplianceSnapshot[] }>(
      `${org(id)}/compliance/${encodeURIComponent(frameworkId)}/snapshots`,
      { signal, query: { limit, offset } },
    ),
  createSnapshot: (id: string, frameworkId: string, scopeType = "organization") =>
    request<ComplianceSnapshot>(`${org(id)}/compliance/${encodeURIComponent(frameworkId)}/snapshots`, {
      method: "POST",
      body: { scope_type: scopeType },
    }),
  timeline: (id: string, frameworkId: string, limit = 50, signal?: AbortSignal) =>
    request<unknown>(`${org(id)}/compliance/${encodeURIComponent(frameworkId)}/timeline`, {
      signal,
      query: { limit },
    }),
  controlTrend: (id: string, frameworkId: string, controlId: string, limit = 50, signal?: AbortSignal) =>
    request<unknown>(
      `${org(id)}/compliance/${encodeURIComponent(frameworkId)}/controls/${encodeURIComponent(controlId)}/trend`,
      { signal, query: { limit } },
    ),
  exportSnapshot: (id: string, frameworkId: string, snapshotId: string, format: "json" | "csv") =>
    requestBlob(
      `${org(id)}/compliance/${encodeURIComponent(frameworkId)}/snapshots/${encodeURIComponent(snapshotId)}/export`,
      { query: { format } },
    ),
};
