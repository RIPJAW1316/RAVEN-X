import { test, expect, type Page } from "@playwright/test";
import type { Assessment, AssessmentDetail, AssessmentState } from "../src/types/api";

/** Synthetic API responses test presentation; they are not scanner results. */
class AssessmentOutcomePortal {
  constructor(readonly page: Page) {}

  async signIn() {
    await this.page.goto("/");
    await this.page.getByLabel("Email", { exact: true }).fill("browser-test@example.invalid");
    await this.page.getByLabel("Password", { exact: true }).fill("Synthetic-browser-test-only-2026");
    await this.page.getByRole("button", { name: "Access system", exact: true }).click();
    await expect(this.page.getByRole("heading", { name: "Command Center", exact: true })).toBeVisible();
  }

  async showSyntheticOutcome(state: AssessmentState, withFinding = false) {
    const id = `synthetic-${state}`;
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
      progress: null, scanner_results: [], findings: withFinding ? [{
        occurrence_id: "synthetic-occurrence", assessment_id: id, endpoint_id: "synthetic-endpoint",
        scanner_id: "windows.uac", title: "Synthetic evidence finding", severity: "medium",
        description: "Synthetic presentation fixture, not a machine observation.", observed_at: timestamp,
        fingerprint: null, evidence: [],
      }] : [], total_findings: withFinding ? 1 : 0, malformed_finding_count: 0,
    };
    await this.page.route(`**/assessments/${id}`, (route) => route.fulfill({ json: summary }));
    await this.page.route(`**/assessments/${id}/details`, (route) => route.fulfill({ json: detail }));
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
