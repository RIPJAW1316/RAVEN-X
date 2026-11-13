import { test as base, expect, type Page } from "@playwright/test";
import type { Assessment, AssessmentDetail, AssessmentState, AuditPage, FleetEvidenceReport,
  OrganizationRef, SecurityMetrics, SecurityOverview, SessionResponse } from "../src/types/api";

const fixtureResponses = process.env.RAVENX_BROWSER_LAYER === "ui-fixtures";
const organizationId = "synthetic-organization";
const timestamp = "2026-10-10T10:00:00Z";

// BROWSER UI WITH FIXTURE RESPONSES: no real authentication or backend custody claim.
// This auto fixture is test-only and intercepts every API request before it can
// reach a server. More-specific assessment routes below override this handler.
const test = base.extend<{ fixtureApiResponses: void }>({
  fixtureApiResponses: [async ({ page }, use) => {
    const unexpected: string[] = [];
    if (fixtureResponses) {
      const session: SessionResponse = {
        session_token: "synthetic-ui-session-not-a-server-credential", expires_at: "2099-01-01T00:00:00Z",
      };
      const organizations: OrganizationRef[] = [{
        organization_id: organizationId, name: "Synthetic browser fixture", membership_id: "synthetic-membership",
      }];
      const overview: SecurityOverview = {
        organization_id: organizationId, generated_at: timestamp,
        endpoints: { total_endpoints: 0, active_endpoints: 0, revoked_endpoints: 0 },
        presence: { unknown: 0, online: 0, stale: 0, offline: 0, revoked: 0 },
        assessments: {}, findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total_occurrences: 0 },
        recent_assessments: [], recent_high_severity_findings: [], malformed_finding_count: 0,
      };
      const report: FleetEvidenceReport = {
        organization_id: organizationId, generated_at: timestamp,
        scope: { kind: "fleet", endpoint_id: null, assessment_ids: [], selection_mode: "synthetic" },
        summary: { total_enrolled: 0, approved: 0, pending_approval: 0, revoked: 0, scanned: 0,
          partial: 0, not_scanned: 0, pending: 0, running: 0, failed: 0, unavailable: 0,
          findings_from_completed_scans: 0, presence: {} },
        endpoints: [], advisory_note: "Synthetic browser fixture only.",
      };
      const metrics: SecurityMetrics = {
        organization_id: organizationId, generated_at: timestamp, window_minutes: 60,
        authorization: { attempts: 0, allowed: 0, denied: 0, denial_rate: 0,
          denied_by_reason: {}, denied_by_action: {} },
        authentication: { success: 0, failure: 0, failure_rate: 0 }, operations: {}, signals: [],
      };
      const audit: AuditPage = {
        items: [], pagination: { limit: 20, offset: 0, returned: 0, total: 0, has_next: false },
        excluded_event_types: [],
      };
      const responses: Record<string, unknown> = {
        "POST /api/v1/auth/login": session,
        "GET /api/v1/auth/organizations": organizations,
        [`GET /api/v1/organizations/${organizationId}/security/overview`]: overview,
        [`GET /api/v1/organizations/${organizationId}/reports/fleet`]: report,
        [`GET /api/v1/organizations/${organizationId}/security/metrics`]: metrics,
        [`GET /api/v1/organizations/${organizationId}/audit-events`]: audit,
      };
      await page.route("**/api/v1/**", async (route) => {
        const key = `${route.request().method()} ${new URL(route.request().url()).pathname}`;
        if (Object.hasOwn(responses, key)) {
          await route.fulfill({ json: responses[key] });
        } else {
          unexpected.push(key);
          await route.abort("blockedbyclient");
        }
      });
    }
    await use();
    expect(unexpected, "Every UI fixture API request must have an explicit response").toEqual([]);
  }, { auto: true }],
});

/** Synthetic API responses test presentation; they are not scanner results. */
class AssessmentOutcomePortal {
  private sequence = 0;
  constructor(readonly page: Page) {}

  async signIn() {
    await this.page.goto("/");
    await this.page.getByLabel("Email", { exact: true }).fill("browser-test@example.invalid");
    await this.page.getByLabel("Password", { exact: true }).fill("Synthetic-browser-test-only-2026");
    await this.page.getByRole("button", { name: "Access system", exact: true }).click();
    await expect(this.page.getByRole("heading", { name: "Command Center", exact: true })).toBeVisible();
  }

  async showSyntheticOutcome(state: AssessmentState, withFinding = false,
    scannerResults: AssessmentDetail["scanner_results"] = []) {
    const id = `synthetic-${state}-${this.sequence++}`;
    const partialUac = scannerResults.some((result) => result.scanner_id === "windows.uac"
      && result.status === "failed" && result.finding_count > 0);
    const timestamp = "2026-10-10T10:00:00Z";
    const summary: Assessment = {
      assessment_id: id, endpoint_id: "synthetic-endpoint", organization_id: null,
      correlation_id: `synthetic-correlation-${state}`, scanner_ids: ["windows.uac"],
      requested_at: timestamp, state, progress: null, result: null,
      error: null, schedule_id: null,
    };
    const detail: AssessmentDetail = {
      assessment_id: id, organization_id: "synthetic-organization", endpoint_id: "synthetic-endpoint",
      status: state, created_at: timestamp, requested_at: timestamp, started_at: null,
      completed_at: state === "completed" ? timestamp : null, scanner_ids: ["windows.uac"],
      progress: null, scanner_results: scannerResults, findings: withFinding ? [{
        occurrence_id: "synthetic-occurrence", assessment_id: id, endpoint_id: "synthetic-endpoint",
        scanner_id: "windows.uac", title: partialUac ? "UAC Disabled" : "Synthetic evidence finding",
        severity: partialUac ? "high" : "medium",
        description: "Synthetic presentation fixture, not a machine observation.", observed_at: timestamp,
        fingerprint: null, evidence: [],
      }] : [], total_findings: withFinding ? 1 : 0, malformed_finding_count: 0,
    };
    await this.page.route(`**/assessments/${id}`, (route) => route.fulfill({ json: summary }));
    await this.page.route(`**/assessments/${id}/details`, (route) => route.fulfill({ json: detail }));
    if (fixtureResponses) {
      await this.page.route(`**/assessments/${id}/findings/synthetic-occurrence/recurrence`,
        (route) => route.fulfill({ json: {} }));
    }
    await this.page.goto(`/#/assessments/${id}`);
  }
}

test("zero findings preserve incomplete and terminal failure states", async ({ page }) => {
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  const failureStates: AssessmentState[] = ["failed", "delivery_failed", "expired", "cancelled", "endpoint_unavailable"];
  for (const state of failureStates) {
    await portal.showSyntheticOutcome(state);
    await expect(page.getByText(/This assessment ended as .* without recorded findings\. It does not provide a completed scan\./)).toBeVisible();
    await expect(page.getByText(/This assessment completed without/)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel run", exact: true })).toHaveCount(0);
    const lifecycle = page.getByRole("list", { name: "Assessment lifecycle" });
    await expect(lifecycle.getByRole("listitem")).toHaveCount(1);
    await expect(lifecycle.getByText("Dispatched", { exact: true })).toHaveCount(0);
    await expect(lifecycle.getByText("Running", { exact: true })).toHaveCount(0);
  }
  for (const state of ["queued", "running"] as const) {
    await portal.showSyntheticOutcome(state);
    await expect(page.getByText("Findings appear as the agent submits scanner results.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancel run", exact: true })).toBeVisible();
  }
  await portal.showSyntheticOutcome("completed");
  await expect(page.getByText(/This assessment completed without recorded findings\. Review scanner execution/)).toBeVisible();
  await expect(page.getByText(/This assessment ended as/)).toHaveCount(0);
});

test("finding evidence links the implemented local AI advisory workspace", async ({ page }) => {
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  await portal.showSyntheticOutcome("completed", true);
  await page.getByRole("button", { name: /Synthetic evidence finding/ }).click();
  const finding = page.getByRole("dialog", { name: "Synthetic evidence finding" });
  await expect(finding.getByText("Local advisory analysis", { exact: true })).toBeVisible();
  await expect(finding.getByText(/endpoint that does not exist/)).toHaveCount(0);
  await finding.getByRole("link", { name: "Open AI Analyst", exact: true }).click();
  await expect(page.getByRole("heading", { name: "AI Analyst", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Analyze evidence", exact: true })).toBeVisible();
});

test("partial collection shows READ_FAILED and UNSUPPORTED beside the confirmed High finding", async ({ page }) => {
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  await portal.showSyntheticOutcome("completed", true, [
    { scanner_id: "windows.uac", status: "failed", finding_count: 1, error: "READ_FAILED" },
    { scanner_id: "windows.bitlocker", status: "incompatible", finding_count: 0, error: "UNSUPPORTED" },
  ]);
  const execution = page.getByRole("list", { name: "Scanner execution" });
  const uac = execution.getByRole("listitem").filter({ hasText: "windows.uac" });
  const bitlocker = execution.getByRole("listitem").filter({ hasText: "windows.bitlocker" });
  await expect(uac.getByText("READ_FAILED · Collection failed", { exact: true })).toBeVisible();
  await expect(uac.locator(".badge.tone-critical")).toHaveCount(1);
  await expect(uac.getByText("1 findings", { exact: true })).toBeVisible();
  await expect(bitlocker.getByText("UNSUPPORTED · Collection unavailable", { exact: true })).toBeVisible();
  await expect(bitlocker.locator(".badge.tone-warn")).toHaveCount(1);
  await expect(execution.getByText("Successfully collected", { exact: true })).toHaveCount(0);
  await expect(execution.getByText("Security finding detected", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/Collection is incomplete\. Confirmed findings remain visible/)).toBeVisible();
  const finding = page.getByRole("button", { name: /UAC Disabled/ });
  await expect(finding).toHaveCount(1);
  await expect(finding).toBeVisible();
  await expect(finding).toContainText(/high/i);
  await expect(page.getByText("str", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/This assessment completed without recorded findings/)).toHaveCount(0);
});

test("successful, finding, uncollected and malformed states use fixed labels without raw errors", async ({ page }) => {
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  const collected: AssessmentDetail["scanner_results"] = [
    { scanner_id: "windows.uac", status: "success", finding_count: 1, error: null },
    { scanner_id: "windows.bitlocker", status: "success", finding_count: 0, error: null },
  ];
  await portal.showSyntheticOutcome("completed", true, collected);
  await expect(page.getByText("Security finding detected", { exact: true })).toBeVisible();
  await expect(page.getByText("Successfully collected", { exact: true })).toBeVisible();
  await expect(page.getByText(/Collection is incomplete/)).toHaveCount(0);
  await portal.showSyntheticOutcome("completed", true, [
    ...collected,
    { scanner_id: "windows.firewall", status: "skipped", finding_count: 0, error: "NOT_COLLECTED" },
  ]);
  await expect(page.getByText("Not collected", { exact: true })).toBeVisible();
  await expect(page.getByText(/Collection is incomplete/)).toBeVisible();
  for (const malformed of [
    { status: "failed", error: "SECRET_CANARY_ERROR" },
    { status: "SECRET_CANARY_STATUS", error: "SECRET_CANARY_ERROR" },
    { status: "failed", error: { message: "SECRET_CANARY_ERROR" } },
  ]) {
    // Intentionally violate the error wire type to exercise defensive rendering.
    const results = [
      { scanner_id: "windows.smb", finding_count: 0, ...malformed },
    ] as unknown as AssessmentDetail["scanner_results"];
    await portal.showSyntheticOutcome("completed", false, results);
    await expect(page.getByText("COLLECTION_FAILED · Collection status unavailable", { exact: true })).toBeVisible();
    await expect(page.locator("body")).not.toContainText("SECRET_CANARY");
    await expect(page.getByText("Successfully collected", { exact: true })).toHaveCount(0);
  }
});
