import { test as base, expect, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
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

test("appearance persists and formatted advisories keep model output inert", async ({ page }, testInfo) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  await page.route("**/security/overview", route => route.fulfill({ json: {
    organization_id: organizationId, generated_at: timestamp,
    endpoints: { total_endpoints: 3, active_endpoints: 3, revoked_endpoints: 0 },
    presence: { unknown: 0, online: 2, stale: 0, offline: 1, revoked: 0 },
    assessments: { completed: 2, queued: 1 }, findings: { critical: 0, high: 2, medium: 1, low: 0, info: 0, total_occurrences: 3 },
    recent_assessments: [], recent_high_severity_findings: [], malformed_finding_count: 0,
  } }));
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  await expect(page.getByRole("img", { name: "Online: 2, Offline: 1" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("dashboard-dark.png") });
  await page.route("**/auth/me", route => route.fulfill({ json: { email: "operator@example.invalid", status: "active" } }));
  await page.route("**/organizations/synthetic-organization", route => route.fulfill({ json: { name: "Test organization", status: "active" } }));
  await page.route("**/memberships", route => route.fulfill({ json: [] }));
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("radio", { name: "Dark" })).toBeChecked();
  await page.getByText("Light", { exact: true }).click();
  await page.reload();
  await expect(page.getByRole("radio", { name: "Light" })).toBeChecked();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.screenshot({ path: testInfo.outputPath("settings-light.png") });
  await page.getByText("Dark", { exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("combobox", { name: "Go to screen" }).selectOption("analyst");
  await page.route("**/ai/analyze", route => route.fulfill({ json: {
    status: "available", model: "Fixture model", source: { assessment_ids: ["fixture-run"] },
    analysis: "```markdown\n## Assessment summary\n\n- **Review** the encryption setting.\n\n![image](/tracking-image)\n<script>alert(1)</script>\n```",
  } }));
  await page.getByRole("button", { name: "Analyze evidence" }).click();
  const advisory = page.getByRole("article", { name: "Assessment interpretation" });
  await expect(advisory.getByRole("heading", { name: "Assessment summary" })).toBeVisible();
  await expect(advisory.getByRole("listitem")).toContainText("Review the encryption setting.");
  await expect(advisory.locator("strong")).toHaveText("Review");
  await expect(advisory.locator("img, script")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("AI Analyst requests the fix plan and labels offline results", async ({ page }) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  await page.getByRole("link", { name: "AI Analyst", exact: true }).click();
  await page.route("**/ai/analyze", route => route.fulfill({ json: {
    status: "available", model: "Offline rules", provider: "offline", fallback_used: true,
    source: { assessment_ids: ["fixture-run"] },
    analysis: "### Prioritized Fix Plan\n\nReview the observed BitLocker protection state.",
  } }));
  const request = page.waitForRequest(req => req.method() === "POST" && req.url().endsWith("/ai/analyze"));
  await page.getByRole("button", { name: "Analyze evidence" }).click();

  expect((await request).postDataJSON()).toEqual({ model: "lm_studio" });
  const resultContainer = page.locator(".analysis-result");
  await expect(resultContainer).toBeVisible();
  await expect(resultContainer.getByText("Offline rules", { exact: true })).toBeVisible();
  await expect(resultContainer.getByRole("heading", { name: "Prioritized Fix Plan" })).toBeVisible();
});

test("AI Analyst uses Gemini in live and demo scopes and clears stale output", async ({ page }) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  const portal = new AssessmentOutcomePortal(page);
  await portal.signIn();
  await page.getByRole("link", { name: "AI Analyst", exact: true }).click();

  let capturedRequests: any[] = [];
  let geminiShouldFallback = false;
  await page.route("**/ai/analyze", async route => {
    const postData = route.request().postDataJSON();
    capturedRequests.push(postData);
    if (postData.model === "offline") {
      await route.fulfill({ json: {
        status: "available", model: "Offline rules", provider: "offline", fallback_used: false,
        source: { assessment_ids: ["fixture-run"] },
        analysis: "### Prioritized Fix Plan\n\nExplicit offline rules plan.",
      } });
    } else if (postData.model === "gemini") {
      if (geminiShouldFallback) {
        await route.fulfill({ json: {
          status: "available", model: "Offline rules", provider: "offline", fallback_used: true,
          fallback_reason: "Gemini response validation failed; evaluated offline rules instead.",
          notice: "Analysis was evaluated deterministically from verified local rules because Gemini inference was unavailable or invalid.",
          source: { kind: "bundled_demo", demo_id: "windows-hardening-v1", assessment_ids: [] },
          analysis: "### Prioritized Fix Plan\n\nFallback offline rules plan.",
        } });
      } else {
        await route.fulfill({ json: {
          status: "available", model: "gemini-3.5-flash-lite", provider: "google_cloud", fallback_used: false,
          source: postData.demo_id
            ? { kind: "bundled_demo", demo_id: postData.demo_id, assessment_ids: [] }
            : { assessment_ids: ["fixture-run"] },
          analysis: "### Prioritized Fix Plan\n\nGemini prioritization.",
        } });
      }
    }
  });

  const geminiOption = page.getByLabel("Model").locator('option[value="gemini"]');
  const resultContainer = page.locator(".analysis-result");

  await expect(geminiOption).toHaveJSProperty("disabled", false);

  // Select Offline rules and run analysis
  await page.getByLabel("Model").selectOption("offline");
  await page.getByRole("button", { name: "Analyze evidence" }).click();
  await expect(resultContainer).toBeVisible();
  await expect(resultContainer.getByText("Explicit offline rules plan.")).toBeVisible();
  await expect(resultContainer.getByText("Offline rules", { exact: true })).toBeVisible();
  // Selector sends only model plus source (no legacy offline_plan boolean)
  expect(capturedRequests[0]).toEqual({ model: "offline" });

  // Review the synthetic demo with the same model selector
  await page.getByLabel("Evidence scope").selectOption("__demo__");
  // Stale result is immediately cleared on scope change
  await expect(resultContainer).not.toBeVisible();

  // Selecting Gemini does NOT change the evidence scope
  await page.getByLabel("Model").selectOption("gemini");
  await expect(page.getByLabel("Evidence scope")).toHaveValue("__demo__");

  await page.getByRole("button", { name: "Analyze evidence" }).click();
  await expect(resultContainer).toBeVisible();
  await expect(resultContainer.getByText("Gemini prioritization.")).toBeVisible();
  // Cloud badge derived from provider: "google_cloud" scoped to analysis-result container
  await expect(resultContainer.getByText("Google Cloud", { exact: true })).toBeVisible();
  await expect(resultContainer.getByText("Source: First-party bundled synthetic Windows demo")).toBeVisible();
  expect(capturedRequests[1]).toEqual({ model: "gemini", demo_id: "windows-hardening-v1" });

  // Switching model clears stale result
  await page.getByLabel("Model").selectOption("offline");
  await expect(resultContainer).not.toBeVisible();

  // Test cloud fallback display: switch back to Gemini, but inference fails back to offline rules
  await page.getByLabel("Model").selectOption("gemini");
  geminiShouldFallback = true;
  await page.getByRole("button", { name: "Analyze evidence" }).click();
  await expect(resultContainer).toBeVisible();
  await expect(resultContainer.getByText("Fallback offline rules plan.")).toBeVisible();
  // Badge in analysis-result reflects offline rules provider despite selecting gemini
  await expect(resultContainer.getByText("Offline rules", { exact: true })).toBeVisible();
  // Fallback notice is disclosed
  await expect(resultContainer.getByText("Gemini response validation failed; evaluated offline rules instead.")).toBeVisible();

  await page.getByLabel("Evidence scope").selectOption("");
  await expect(resultContainer).not.toBeVisible();
  await expect(page.getByLabel("Model")).toHaveValue("gemini");
  await expect(page.getByText("Gemini receives Windows check categories and severities", { exact: false })).toBeVisible();
  geminiShouldFallback = false;
  await page.getByRole("button", { name: "Analyze evidence" }).click();
  await expect(resultContainer.getByText("Google Cloud", { exact: true })).toBeVisible();
  expect(capturedRequests[3]).toEqual({ model: "gemini" });
});

test("Enrollment renews eligible expired tokens and keeps their ID", async ({ page }) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  const enrollmentId = "11111111-2222-4333-8444-555555555555";
  const issued = {
    enrollment_id: enrollmentId, label: "Test workstation", organization_id: organizationId,
    created_at: timestamp, expires_at: timestamp, status: "expired", renewable: true,
  };
  const pending = { ...issued, expires_at: "2026-10-10T10:30:00Z", status: "pending", renewable: false };
  let list = [issued];
  await page.route("**/fleet/endpoints?**", route => route.fulfill({ json: { items: [] } }));
  await page.route("**/enrollment-tokens", route => route.fulfill({ json: list }));
  await page.route(`**/enrollment-tokens/${enrollmentId}/renew`, async route => {
    list = [pending];
    await route.fulfill({ json: pending });
  });

  await new AssessmentOutcomePortal(page).signIn();
  await page.getByRole("link", { name: "Enrollment", exact: true }).click();
  await page.getByRole("button", { name: "Renew token", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Renew expired enrollment token" });
  const request = page.waitForRequest(req =>
    req.method() === "POST" && req.url().endsWith(`/enrollment-tokens/${enrollmentId}/renew`));
  await dialog.getByRole("button", { name: "Renew for 30 minutes" }).click();
  expect((await request).postData()).toBeNull();
  await expect(page.getByRole("row", { name: /Test workstation/ })).toContainText("pending");
  await expect(page.getByRole("status").filter({ hasText: "Use the same enrollment ID and saved token." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Renew token", exact: true })).toHaveCount(0);
});

test("Fix Issues exports a safe local script and portable HTML", async ({ page }) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  await page.route("**/reports/fix-plan", route => route.fulfill({ json: {
    endpoints: [{ endpoint_id: "fixture-pc", hostname: "Review PC", scan_status: "partial" }],
    items: [{
      finding_key: "fixture-record", endpoint_id: "fixture-pc", hostname: "Review PC",
      occurrence_id: "fixture-finding", assessment_id: "fixture-assessment",
      scanner_id: "windows.smb-client-signing", rule_id: "smb.client_signing_not_required",
      severity: "medium", title: "SMB Client Signing Not Required",
      details: "<script>untrusted evidence</script>", action: "Require outbound SMB signing.",
      rationale: "Signing protects SMB traffic integrity.",
    }],
    findings_omitted: 0, unverified_checks: [], analysis: "### Prioritized Fix Plan",
  } }));
  await new AssessmentOutcomePortal(page).signIn();
  await page.getByRole("link", { name: "Fix Issues", exact: true }).click();
  await page.getByText("SMB Client Signing Not Required", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Recommended action" })).toBeVisible();
  const pendingScript = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PowerShell" }).click();
  const script = await pendingScript;
  expect(script.suggestedFilename()).toBe("ravenx-smb-client-signing.ps1");
  const source = await readFile(await script.path(), "utf8");
  expect(source).toContain("SupportsShouldProcess");
  expect(source).toContain("if (-not $Apply)");
  expect(source).toContain("Set-SmbClientConfiguration -RequireSecuritySignature $true");
  expect(source).not.toContain("untrusted evidence");

  const pendingReport = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export HTML" }).click();
  const report = await pendingReport;
  expect(report.suggestedFilename()).toBe("ravenx-fix-plan.html");
  const document = await readFile(await report.path(), "utf8");
  expect(document).toContain("fixture-assessment");
  expect(document).toContain("&lt;script&gt;untrusted evidence&lt;/script&gt;");
  expect(document).not.toContain("<script>");
});

test("assessment picker dispatches only the checks selected inside scanner domains", async ({ page }) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  await new AssessmentOutcomePortal(page).signIn();
  await page.route("**/fleet/endpoints?**", route => route.fulfill({ json: {
    items: [{ endpoint_id: "fixture-machine", hostname: "Lab VM", platform: "Windows", lifecycle_status: "active" }],
    total: 1,
  } }));
  const payloads: unknown[] = [];
  await page.route("**/assessments", route => {
    if (route.request().method() === "POST") {
      payloads.push(route.request().postDataJSON());
      return route.fulfill({ status: 409, json: { detail: { message: "Fixture dispatch captured" } } });
    }
    return route.fulfill({ json: [{
      assessment_id: "fixture-existing", endpoint_id: "fixture-machine", scanner_ids: ["windows.uac"],
      requested_at: timestamp, state: "completed",
    }] });
  });
  await page.getByRole("link", { name: "Assessments", exact: true }).click();
  await page.getByRole("button", { name: "New assessment", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "New assessment" });
  await dialog.getByLabel("Target endpoint").selectOption("fixture-machine");
  await expect(dialog.getByText("24 of 39 selected")).toBeVisible();
  await dialog.getByRole("button", { name: "Full Windows scan" }).click();
  await expect(dialog.getByText("39 of 39 selected")).toBeVisible();
  await dialog.getByRole("button", { name: "Clear selection" }).click();
  await expect(dialog.getByRole("button", { name: "Dispatch assessment" })).toBeDisabled();

  await dialog.getByText("Network & remote access", { exact: true }).click();
  const network = dialog.getByRole("group", { name: "Network & remote access" });
  await network.getByRole("button", { name: "SMB Client Signing" }).click();
  await dialog.getByText("Audit & logging", { exact: true }).click();
  const audit = dialog.getByRole("group", { name: "Audit & logging" });
  await audit.getByRole("button", { name: "Windows Security Event Log" }).click();
  await expect(dialog.getByText("2 of 39 selected")).toBeVisible();
  await dialog.getByRole("button", { name: "Dispatch assessment" }).click();
  await expect(dialog.getByText("Fixture dispatch captured")).toBeVisible();
  expect(payloads).toEqual([{ endpoint_id: "fixture-machine",
    scanner_ids: ["windows.smb-client-signing", "windows.security-event-log"] }]);
});

test("posture with unknown evidence and a paginated printable machine report", async ({ page }, testInfo) => {
  test.skip(!fixtureResponses, "Presentation fixture");
  await new AssessmentOutcomePortal(page).signIn();
  const framework = { framework_id: "baseline", name: "Windows baseline", control_ids: [], controls: [] };
  await page.route("**/compliance/frameworks", route => route.fulfill({ json: [framework] }));
  await page.route("**/compliance/frameworks/baseline", route => route.fulfill({ json: framework }));
  await page.route("**/compliance/baseline/summary", route => route.fulfill({ json: {
    compliant: 0, non_compliant: 0, unknown: 4, not_applicable: 0, controls_evaluated: 4,
    endpoints_evaluated: 1, endpoints_examined: 1, evaluation_complete: true, framework_version: "1",
  } }));
  await page.route("**/snapshots?**", route => route.fulfill({ json: [] }));
  await page.route("**/fleet/endpoints?**", route => route.fulfill({ json: {
    items: [{ endpoint_id: "fixture-machine", hostname: "Print fixture", lifecycle_status: "active" }], total: 1,
  } }));
  await page.route("**/endpoints/fixture-machine/compliance/baseline", route => route.fulfill({ json: [{
    control_id: "RX-WIN-FW-001", status: "unknown", reason: "scanner_failed", source_assessment_id: "fixture-run",
  }] }));
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  await expect(page.getByRole("img", { name: "Unknown: 4" })).toBeVisible();
  await expect(page.getByText("No snapshots captured")).toBeVisible();
  await expect(page.getByRole("cell", {name: "Scanner Failed", exact: true})).toBeVisible();
  const report = {
    generated_at: timestamp, summary: { total_enrolled: 1, approved: 1, pending_approval: 0, scanned: 1,
      not_scanned: 0, partial: 0, failed: 0, pending: 0, running: 0, findings_from_completed_scans: 1 },
    endpoints: [{ endpoint_id: "fixture-machine", hostname: "Print fixture", lifecycle_status: "approved",
      presence_state: "online", scan_status: "scanned", findings_count: 1, latest_assessment: { requested_at: timestamp },
      scanner_results: Array.from({ length: 60 }, (_, i) => ({ scanner_id: "fixture-check-" + (i + 1), status: "success", finding_count: 0 })),
      findings: [{ title: "Evidence at end of report", severity: "high", description: "Fixture observation.", evidence: [{ source: "local fixture" }] }],
    }],
  };
  await page.route("**/endpoints/fixture-machine/report", route => route.fulfill({ json: report }));
  await page.route("**/reports/review?**", route => {
    expect(route.request().method()).toBe("POST");
    const selection = new URL(route.request().url()).searchParams;
    expect(selection.get("endpoint_id")).toBe("fixture-machine");
    expect(selection.get("model")).toBe("gemini");
    if (selection.get("format") === "pdf") {
      return route.fulfill({
        body: "%PDF-1.7\n", contentType: "application/pdf", headers: {
          "Content-Disposition": 'attachment; filename="ravenx-machine-reviewed-report.pdf"',
        },
      });
    }
    return route.fulfill({ json: { report, review: {
      status: "available", model: "gemini-flash", provider: "google_cloud", note: "Verify each recommendation.",
      finding_count: 1, priorities: [{ finding_key: "fixture-priority", title: "Review firewall",
        hostname: "Print fixture", severity: "high", action: "Review the firewall profile.",
        rationale: "Protect the network boundary.", assessment_id: "fixture-run" }],
      unverified_count: 1, unverified: [{ endpoint_id: "fixture-machine", hostname: "Print fixture",
        scanner_id: "windows.wifi", assessment_id: "fixture-run", reason: "No wireless adapter detected." }],
    } } });
  });
  await page.goto("/#/reports/fixture-machine");
  await expect(page.getByText("Evidence at end of report")).toBeVisible();
  await page.getByLabel("Review model").selectOption("gemini");
  await page.getByRole("button", { name: "Review evidence" }).click();
  await expect(page.getByRole("heading", { name: "Assessment review" })).toBeVisible();
  await expect(page.getByText("Google Gemini", { exact: true })).toBeVisible();
  await expect(page.getByText("No wireless adapter detected.")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PDF" }).click();
  expect((await download).suggestedFilename()).toBe("ravenx-machine-reviewed-report.pdf");
  await page.emulateMedia({ media: "print" });
  await expect(page.getByRole("heading", { name: "Print fixture", exact: true })).toBeVisible();
  await expect(page.getByText("Compliance snapshot exports")).toBeHidden();
  await page.pdf({ path: testInfo.outputPath("machine-report.pdf"), format: "A4" });
});
