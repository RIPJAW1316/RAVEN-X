/**
 * Wire types mirroring the Raven-X control-plane responses.
 *
 * Every shape here was derived from the backend `to_dict()` implementations.
 * Fields are optional where the backend may omit them so the UI degrades
 * honestly instead of rendering fabricated values.
 */

/* ---------------------------------------------------------------- identity */

export interface SessionResponse {
  session_token: string;
  expires_at: string;
}

export interface CurrentUser {
  user_id: string;
  email: string;
  display_name: string | null;
  status: string;
}

export interface OrganizationRef {
  organization_id: string;
  name: string;
  membership_id: string;
}

export interface Organization {
  organization_id: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Membership {
  membership_id: string;
  user_id: string;
  status: string;
  created_at: string;
}

export interface EnrollmentToken {
  enrollment_id: string;
  organization_id: string;
  label: string;
  status: "pending" | "consumed" | "expired" | "revoked";
  renewable?: boolean;
  created_at: string;
  expires_at: string;
  consumed_at?: string | null;
}

export interface IssuedEnrollmentToken extends EnrollmentToken {
  enrollment_token: string;
}

/* -------------------------------------------------------------- reporting */

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export interface EndpointCountSummary {
  total_endpoints: number;
  active_endpoints: number;
  revoked_endpoints: number;
}

export interface PresenceSummary {
  unknown: number;
  online: number;
  stale: number;
  offline: number;
  revoked: number;
}

export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
  total_occurrences: number;
}

export interface AssessmentSummary {
  assessment_id: string;
  endpoint_id: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  finding_counts: Record<string, number>;
}

export interface FindingSummary {
  assessment_id: string;
  endpoint_id: string;
  finding_id: string | null;
  severity: Severity;
  title: string;
  description: string;
  scanner_id: string | null;
  observed_at: string | null;
}

export interface SecurityOverview {
  organization_id: string;
  generated_at: string;
  endpoints: EndpointCountSummary;
  presence: PresenceSummary;
  assessments: Record<string, number>;
  findings: FindingCounts;
  recent_assessments: AssessmentSummary[];
  recent_high_severity_findings: FindingSummary[];
  malformed_finding_count: number;
}

/* ------------------------------------------------------------------ fleet */

export type PresenceState = "unknown" | "online" | "stale" | "offline";
export type LifecycleStatus = string;

/** Row shape returned by `/fleet/endpoints` — note the flat platform field. */
export interface FleetEndpoint {
  endpoint_id: string;
  hostname: string;
  lifecycle_status: LifecycleStatus;
  status: LifecycleStatus;
  presence_state: PresenceState;
  last_seen_at: string | null;
  platform: string;
  platform_version: string | null;
  architecture: string | null;
  agent_version: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface FleetPage {
  items: FleetEndpoint[];
  limit: number;
  offset: number;
  returned: number;
  total: number;
}

/** Detail shape returned by `/endpoints/{id}` — nested, unlike the fleet row. */
export interface EndpointDetail {
  endpoint_id: string;
  organization_id: string | null;
  hostname: string;
  platform: { name: string; version: string | null; architecture: string | null };
  status: string;
  capabilities: string[];
  capability_observations: unknown[];
  agent: Record<string, unknown> | null;
  created_at: string;
  updated_at: string | null;
  last_seen: string | null;
  metadata: Record<string, unknown>;
}

export interface FleetEvidenceReport {
  organization_id: string;
  generated_at: string;
  scope: { kind: "fleet" | "endpoint"; endpoint_id: string | null; assessment_ids: string[]; selection_mode: string };
  summary: { total_enrolled: number; approved: number; pending_approval: number; revoked: number; scanned: number; partial: number; not_scanned: number; pending: number; running: number; failed: number; unavailable: number; findings_from_completed_scans: number; presence: Record<string, number> };
  endpoints: EndpointEvidenceReport[];
  advisory_note: string;
}
export interface EndpointEvidenceReport {
  endpoint_id: string; hostname: string; platform: string; lifecycle_status: string; approved: boolean;
  presence_state: PresenceState; last_seen_at: string | null; selected_for_report: boolean;
  scan_status: string; last_successful_assessment_at: string | null;
  latest_assessment: { assessment_id: string; status: AssessmentState; requested_at: string; started_at: string | null; completed_at: string | null; failed_at: string | null; scanner_ids: string[] } | null;
  findings_count: number; findings_omitted: number; malformed_findings: number; partial_evidence: boolean;
  findings: Array<{ finding_id: string | null; severity: string; title: string; description: string; scanner_id: string | null; evidence: Array<Record<string, string>> }>;
  scanner_results: Array<{ scanner_id: string; status: string; finding_count: number; has_error: boolean }>;
}
export interface LocalAnalysis {
  status: "available" | "unavailable"; reason_code: string | null; advisory: boolean; analysis: string | null;
  source: { organization_id: string; assessment_ids: string[]; endpoint_ids: string[]; report_generated_at: string };
  model?: string; generated_at?: string; notice?: string;
  coverage?: { scanned_endpoints: number; included_endpoints: number; included_findings: number; truncated: boolean };
}

export interface EndpointPresence {
  endpoint_id: string;
  organization_id: string | null;
  state: PresenceState;
  last_seen_at: string | null;
  last_heartbeat_at: string | null;
  connected_since: string | null;
  stale_since: string | null;
  offline_since: string | null;
  updated_at: string | null;
}

export interface FleetQueryParams {
  q?: string;
  status?: string[];
  presence?: PresenceState[];
  platform?: string[];
  architecture?: string[];
  agent_version?: string[];
  sort?: string;
  direction?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

/* ------------------------------------------------------------ assessments */

/** Real lifecycle states from `RemoteAssessmentState`. */
export type AssessmentState =
  | "created"
  | "queued"
  | "dispatched"
  | "running"
  | "completed"
  | "failed"
  | "delivery_failed"
  | "expired"
  | "cancel_requested"
  | "cancelled"
  | "endpoint_unavailable";

export interface Assessment {
  assessment_id: string;
  endpoint_id: string;
  organization_id: string | null;
  correlation_id: string;
  scanner_ids: string[];
  requested_at: string;
  state: AssessmentState;
  progress: unknown;
  result: unknown;
  error: string | null;
  schedule_id: string | null;
}

export interface EvidenceItem {
  source: string;
  description: string;
  values: Record<string, unknown>;
}

export interface FindingDetail {
  occurrence_id: string;
  assessment_id: string;
  endpoint_id: string;
  scanner_id: string | null;
  title: string;
  severity: Severity;
  description: string;
  observed_at: string | null;
  fingerprint: Record<string, unknown> | null;
  evidence: EvidenceItem[];
}

export interface ScannerResultSummary {
  scanner_id: string | null;
  status: string | null;
  finding_count: number;
  error: string | null;
}

export interface AssessmentDetail {
  assessment_id: string;
  organization_id: string;
  endpoint_id: string;
  status: string;
  created_at: string | null;
  requested_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  scanner_ids: string[];
  progress: unknown;
  scanner_results: ScannerResultSummary[];
  findings: FindingDetail[];
  total_findings: number;
  malformed_finding_count: number;
}

/* -------------------------------------------------------------- schedules */

export type ScheduleStatus = "active" | "paused" | "revoked";
export type ScheduleFrequency = "daily" | "weekly" | "interval";

export interface Recurrence {
  frequency: ScheduleFrequency;
  interval: number;
  hour: number | null;
  minute: number | null;
  days_of_week: number[];
  timezone: string;
  starts_at: string | null;
  misfire_policy: string;
}

export interface ScheduleTarget {
  type: "explicit_endpoints" | "endpoint_group" | "saved_fleet_scope";
  endpoint_ids: string[];
  reference_id: string | null;
}

export interface Schedule {
  schedule_id: string;
  organization_id: string;
  name: string;
  status: ScheduleStatus;
  target_endpoint_ids: string[];
  targets: string[];
  scanner_ids: string[];
  recurrence: Recurrence;
  next_run_at: string;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  overlap_policy: string;
  target: ScheduleTarget;
}

export interface ScheduleRun {
  run_id: string;
  schedule_id: string;
  organization_id: string;
  scheduled_for: string;
  started_at: string;
  status: "created" | "partial" | "skipped" | "failed";
  assessment_ids: string[];
  target_outcomes: Record<string, string>;
  reason: string | null;
  completed_at: string | null;
  resolved_endpoint_ids: string[];
  targets_resolved_at: string | null;
  target_type: string | null;
  target_reference_id: string | null;
  resolution_reason: string | null;
}

/* --------------------------------------------------------- groups & scopes */

export interface EndpointGroup {
  group_id: string;
  organization_id: string;
  name: string;
  description: string;
  status: "active" | "revoked";
  created_by: string | null;
  created_at: string;
  updated_at: string;
  member_count?: number;
}

export interface ScopeCriteria {
  search: string;
  statuses: string[];
  presence_states: string[];
  platforms: string[];
  architectures: string[];
  agent_versions: string[];
  sort_by: string;
  direction: string;
}

export interface FleetScope {
  scope_id: string;
  organization_id: string;
  name: string;
  description: string;
  status: "active" | "revoked";
  created_by: string | null;
  created_at: string;
  updated_at: string;
  query_version: number;
  criteria: ScopeCriteria;
}

/* ------------------------------------------------------------- compliance */

export type ComplianceStatus = "compliant" | "non_compliant" | "unknown" | "not_applicable";

export interface EvidenceRequirement {
  scanner_id: string;
  rule_id: string;
  resource_key: string | null;
  minimum_coverage: string;
}

export interface ComplianceControl {
  control_id: string;
  framework_id: string;
  title: string;
  description: string;
  applicability_platform: string | null;
  capability: "full" | "detection_only" | "unsupported";
  evidence_requirements: EvidenceRequirement[];
}

export interface ComplianceFramework {
  framework_id: string;
  name: string;
  version: string;
  description: string;
  control_ids: string[];
  controls?: ComplianceControl[];
}

export interface ControlEvaluation {
  control_id: string;
  endpoint_id: string;
  status: ComplianceStatus;
  reason: string;
  evaluated_at: string;
  source_assessment_id: string | null;
  source_finding_ids: string[];
  evidence_summary: string;
  coverage_status: string;
  evidence_age_seconds: number | null;
  capability: string;
}

export interface CompliancePosture {
  framework_id: string;
  framework_version: string;
  organization_id: string;
  evaluated_at: string;
  endpoints_evaluated: number;
  endpoints_examined: number;
  evaluation_complete: boolean;
  controls_evaluated: number;
  compliant: number;
  non_compliant: number;
  unknown: number;
  not_applicable: number;
}

/* -------------------------------------------------- security observability */

export type SignalSeverity = "critical" | "warning" | "info";

export interface SecuritySignal {
  signal_type: string;
  severity: SignalSeverity;
  detected_at: string;
  window_minutes: number;
  scope: string;
  /** Plain-language explanation naming the numbers that fired the rule. */
  reason: string;
  /** The counts that produced the signal, so an operator can verify it. */
  evidence: Record<string, unknown>;
}

export interface AuthorizationTelemetry {
  attempts: number;
  allowed: number;
  denied: number;
  denial_rate: number;
  denied_by_reason: Record<string, number>;
  denied_by_action: Record<string, number>;
}

export interface AuthenticationTelemetry {
  success: number;
  failure: number;
  failure_rate: number;
}

export interface SecurityMetrics {
  organization_id: string;
  generated_at: string;
  window_minutes: number;
  authorization: AuthorizationTelemetry;
  authentication: AuthenticationTelemetry;
  operations: Record<string, number>;
  signals: SecuritySignal[];
}

/* ------------------------------------------------------------ audit feed */

export type AuditSeverity = "critical" | "warning" | "info";
export type AuditOutcome = "success" | "denied" | "failed";

export interface AuditActor {
  principal_type: string;
  principal_id: string | null;
  user_id: string | null;
}

export interface AuditResourceRef {
  resource_type: string | null;
  resource_id: string | null;
}

export interface AuditEvent {
  event_id: string;
  event_type: string;
  occurred_at: string;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  actor: AuditActor;
  resource: AuditResourceRef | null;
  action: string | null;
  reason_code: string | null;
  endpoint_id: string | null;
  assessment_id: string | null;
  correlation_id: string | null;
  /** Allowlisted, length-bounded metadata. Never contains secrets or PII. */
  metadata: Record<string, unknown>;
}

export interface PaginationEnvelope {
  limit: number;
  offset: number;
  returned: number;
  total: number;
  has_next: boolean;
}

export interface AuditPage {
  items: AuditEvent[];
  pagination: PaginationEnvelope;
  /** Event types the server suppressed for this query, so the UI can say so. */
  excluded_event_types: string[];
}

export interface AuditQueryParams {
  event_type?: string[];
  outcome?: AuditOutcome[];
  severity?: AuditSeverity[];
  actor_id?: string;
  endpoint_id?: string;
  from?: string;
  to?: string;
  /** Include the high-volume `authorization.allowed` trace. Default false. */
  include_permission_checks?: boolean;
  limit?: number;
  offset?: number;
}

export interface ComplianceSnapshot {
  snapshot_id: string;
  framework_id: string;
  framework_version?: string;
  organization_id?: string;
  status?: string;
  captured_at?: string;
  created_at?: string;
  compliant?: number;
  non_compliant?: number;
  unknown?: number;
  not_applicable?: number;
  [key: string]: unknown;
}
