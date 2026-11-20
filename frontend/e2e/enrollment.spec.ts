import { test, expect, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";

class OperatorPortal {
  constructor(readonly page: Page) {}
  async signIn() {
    await this.page.goto("/");
    await this.page.getByLabel("Email", { exact: true }).fill("browser-test@example.invalid");
    await this.page.getByLabel("Password", { exact: true }).fill("Synthetic-browser-test-only-2026");
    await this.page.getByRole("button", { name: "Access system", exact: true }).click();
    await expect(this.page.getByRole("heading", { name: "Command Center", exact: true })).toBeVisible();
  }
  async enrollment() {
    await this.page.getByRole("link", { name: "Enrollment", exact: true }).click();
    await expect(this.page.getByRole("heading", { name: "Enrollment & approval" })).toBeVisible();
  }
}

test("real API: one-time secret, pending approval, revocation and no fabricated online state", async ({ page, request }, testInfo) => {
  test.setTimeout(60_000);
  const portal = new OperatorPortal(page);
  await portal.signIn();
  await expect(page.getByText("Registered endpoints", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("command-center.png"), fullPage: true });
  await portal.enrollment();
  await page.getByRole("button", { name: "Issue token", exact: true }).click();
  const issue = page.getByRole("dialog", { name: "Issue an enrollment token" });
  await issue.getByRole("button", { name: "Issue single-use token" }).focus();
  await page.keyboard.press("Tab");
  await expect(issue.getByRole("button", { name: "Close", exact: true })).toBeFocused();
  await issue.getByLabel("Machine label").fill("Synthetic protocol fixture");
  await issue.getByRole("button", { name: "Issue single-use token" }).click();
  const secretDialog = page.getByRole("dialog", { name: "Save this token now" });
  const secret = await secretDialog.getByLabel("One-time token").inputValue();
  const enrollmentId = await secretDialog.getByLabel("Enrollment ID").inputValue();
  expect(secret.length).toBeGreaterThan(30);
  const storage = await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }));
  expect(storage).not.toContain(secret);
  await secretDialog.getByRole("button", { name: "I have saved the token" }).click();
  await expect(secretDialog).not.toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Enrollment & approval" })).toBeVisible();
  expect(await page.evaluate((value) => Array.from(document.querySelectorAll("input, textarea"))
    .some((element) => (element as HTMLInputElement).value.includes(value)), secret)).toBe(false);
  const headers = { Authorization: `Bearer ${secret}`, "X-Raven-Enrollment-Id": enrollmentId };
  const body = { hostname: "SYNTHETIC-PROTOCOL-FIXTURE", platform: { name: "Windows", version: "test", architecture: "AMD64" },
    agent_version: "test", protocol_version: "1.0", request_id: randomUUID(), nonce: randomUUID() };
  const response = await request.post("/api/v1/agent/enroll", { headers, data: body });
  expect(response.status()).toBe(201);
  const grant = await response.json();
  expect(grant.status).toBe("new");
  expect((await request.post("/api/v1/agent/enroll", { headers, data: body })).status()).toBe(401);
  const agentHeaders = { Authorization: `Bearer ${grant.credential_secret}`, "X-Raven-Endpoint-Id": grant.endpoint_id };
  expect((await request.post("/api/v1/agent/work", { headers: agentHeaders })).status()).toBe(403);
  await page.reload();
  const row = page.getByRole("row").filter({ hasText: "SYNTHETIC-PROTOCOL-FIXTURE" });
  await row.getByRole("button", { name: "Approve", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Approve machine", exact: true }).click();
  await expect(row).toHaveCount(0);
  await page.goto(`/#/fleet/${grant.endpoint_id}`);
  await expect(page.getByRole("button", { name: "Run assessment" })).toBeDisabled();
  await page.getByRole("button", { name: "Machine report", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Machine report", exact: true })).toBeVisible();
  await expect(page.getByText("No assessment", { exact: true })).toBeVisible();
  const [evidence] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export evidence JSON", exact: true }).click(),
  ]);
  expect(evidence.suggestedFilename()).toMatch(/\.json$/);
  await page.setViewportSize({ width: 1024, height: 768 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("machine-report.png"), fullPage: true });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.emulateMedia({ media: "print" });
  await expect(page.getByRole("button", { name: "SYNTHETIC-PROTOCOL-FIXTURE", exact: true })).toBeVisible();
  await page.emulateMedia({ media: "screen" });
  await page.getByRole("link", { name: "AI Analyst", exact: true }).click();
  await page.getByRole("button", { name: "Analyze evidence", exact: true }).click();
  await expect(page.getByText("Analysis unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText(/There is no completed scan evidence/)).toBeVisible();
  await page.goto(`/#/fleet/${grant.endpoint_id}`);
  await expect(page.getByRole("button", { name: "Revoke", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith(`/endpoints/${grant.endpoint_id}/revoke`) && response.status() === 200),
    page.getByRole("dialog").getByRole("button", { name: "Revoke access", exact: true }).click(),
  ]);
  expect((await request.post("/api/v1/agent/work", { headers: agentHeaders })).status()).toBe(401);
  await expect(page.getByRole("button", { name: "Run assessment" })).toBeDisabled();
});
