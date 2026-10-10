import { defineConfig, devices } from "@playwright/test";
import { fileURLToPath } from "node:url";

const python = process.env.RAVENX_TEST_PYTHON ?? fileURLToPath(new URL("../.venv-ravenx/Scripts/python.exe", import.meta.url));
const server = fileURLToPath(new URL("../scripts/e2e-server.py", import.meta.url));
if (/["\r\n%]/.test(python + server)) throw new Error("Unsupported test runtime path");

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: "http://127.0.0.1:8849", trace: "retain-on-failure", screenshot: "only-on-failure",
    launchOptions: process.env.RAVENX_TEST_BROWSER ? { executablePath: process.env.RAVENX_TEST_BROWSER } : {} },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `"${python}" "${server}" --port 8849`,
    url: "http://127.0.0.1:8849/ready",
    reuseExistingServer: false,
    timeout: 45_000,
  },
});
