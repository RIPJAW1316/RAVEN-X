import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { analyzeWithGemini } from "./gemini.mjs";

const reviews = new Map();
const reviewLifetime = 10 * 60_000;
const renderScript = fileURLToPath(new URL("./render_pdf.py", import.meta.url));
let activeRenders = 0;

export async function getReview(scope, model, report, offline, reviewId) {
  const now = Date.now();
  for (const [id, entry] of reviews) {
    if (now >= entry.expires) reviews.delete(id);
  }
  const saved = reviews.get(reviewId);
  if (saved?.scope === scope && saved.model === model) return saved.snapshot;

  const analysis = model === "gemini" ? await analyzeWithGemini(scope, offline, true) : offline;
  if (model === "gemini" && analysis.provider !== "google_cloud") return null;

  const id = randomUUID();
  const snapshot = {
    report,
    review: {
      status: analysis.status,
      model: analysis.model,
      provider: analysis.provider,
      generated_at: model === "gemini" ? analysis.generated_at : new Date().toISOString(),
      executive_summary: analysis.executive_summary,
      note: model === "gemini"
        ? "Gemini summarized the sample evidence and ranked the findings. Each action links to its source assessment."
        : "Offline rules ranked the findings from the sample assessment evidence.",
      finding_count: analysis.plan.length,
      priorities: analysis.plan,
      unverified: analysis.blind_spots,
      unverified_count: analysis.blind_spots.length,
    },
    review_id: id,
  };
  if (reviews.size >= 64) reviews.delete(reviews.keys().next().value);
  reviews.set(id, { scope, model, expires: Date.now() + reviewLifetime, snapshot });
  return snapshot;
}

export function reportCsv({ report, review }) {
  const rows = [
    ["Section", "Machine", "Assessment", "Priority", "Severity", "Item", "Detail", "Rationale"],
    ["Review", "", "", "", "", "Model", review.model],
    ["Review", "", "", "", "", "Provider", review.provider],
    ["Review", "", "", "", "", "Generated at", review.generated_at],
    ["Review", "", "", "", "", "Evidence scope", report.advisory_note],
  ];
  if (review.executive_summary) rows.push(["Review", "", "", "", "", "Executive summary", review.executive_summary]);
  for (const machine of report.endpoints) {
    rows.push(["Coverage", machine.hostname, machine.latest_assessment.assessment_id, "", "",
      machine.scan_status, machine.findings_count + " finding(s)"]);
  }
  for (const [index, item] of review.priorities.entries()) {
    rows.push(["Finding", item.hostname, item.assessment_id, index + 1, item.severity,
      item.title, item.action, item.rationale]);
  }
  for (const item of review.unverified) {
    const machine = report.endpoints.find((row) => row.endpoint_id === item.endpoint_id);
    rows.push(["Unverified", item.hostname, machine?.latest_assessment?.assessment_id, "", "",
      item.scanner_id, item.reason]);
  }
  return rows.map((row) => Array.from({ length: 8 }, (_, index) => {
    const value = String(row[index] ?? "");
    const cell = /^[\t\r\n]|^\s*[=+@-]/.test(value) ? "'" + value : value;
    return '"' + cell.replaceAll('"', '""') + '"';
  }).join(",")).join("\r\n") + "\r\n";
}

export async function reportPdf(snapshot) {
  if (activeRenders >= 2) return null;
  activeRenders += 1;
  try {
    return await new Promise((resolve, reject) => {
      const child = execFile(process.env.RAVENX_PDF_PYTHON || "python3", [renderScript], {
        encoding: "buffer", maxBuffer: 2 * 1024 * 1024, timeout: 8_000, windowsHide: true,
      }, (error, stdout) => error ? reject(error) : resolve(stdout));
      child.stdin.on("error", () => child.kill());
      child.stdin.end(JSON.stringify(snapshot));
    });
  } finally {
    activeRenders -= 1;
  }
}
