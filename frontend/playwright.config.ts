import { defineConfig, devices } from "@playwright/test";
import { fileURLToPath } from "node:url";

const python = process.env.RAVENX_TEST_PYTHON ?? fileURLToPath(new URL("../.venv-ravenx/Scripts/python.exe", import.meta.url));
const server = fileURLToPath(new URL("../scripts/e2e-server.py", import.meta.url));
const vite = fileURLToPath(new URL("./node_modules/vite/bin/vite.js", import.meta.url));
const layer = process.env.RAVENX_BROWSER_LAYER ?? "real-backend";
if (layer !== "real-backend" && layer !== "ui-fixtures") throw new Error("Unsupported browser test layer");
const fixtureResponses = layer === "ui-fixtures";
if (/["\r\n%]/.test(python + server + process.execPath + vite)) throw new Error("Unsupported test runtime path");

export default defineConfig({
  testDir: "./e2e",
  // Fixture rendering is a separate layer; enrollment still requires the real server.
  testMatch: fixtureResponses ? "**/assessment-outcomes.spec.ts" : undefined,
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: "http://127.0.0.1:8849", trace: "retain-on-failure", screenshot: "only-on-failure",
    launchOptions: process.env.RAVENX_TEST_BROWSER ? { executablePath: process.env.RAVENX_TEST_BROWSER } : {} },
  projects: [{ name: fixtureResponses ? "chromium-ui-fixtures" : "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: fixtureResponses
      ? `"${process.execPath}" "${vite}" preview --host 127.0.0.1 --port 8849 --strictPort`
      : `"${python}" "${server}" --port 8849`,
    url: fixtureResponses ? "http://127.0.0.1:8849/" : "http://127.0.0.1:8849/ready",
    reuseExistingServer: false,
    timeout: 45_000,
  },
});
