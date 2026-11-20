import { readFile } from "node:fs/promises";

const MODEL = "gemini-3.5-flash-lite";
const BACKUP_MODEL = "gemini-3.1-flash-lite";
const SECRET_FILE = "/var/run/ravenx-secrets/gemini";
const RATE_WINDOW_MS = 60_000;
const MAX_CALLS_PER_WINDOW = 12;
const MAX_CONCURRENT_CALLS = 3;
const attempts = [];
const pending = new Map();

function fallback(offline, reason) {
  return { ...offline, requested_model: MODEL, fallback_used: true, fallback_reason: reason };
}

function literal(value) {
  return String(value).replace(/\s+/g, " ").replace(/[\\[\]{}()*_~<>|#&!\x60]/g, "\\$&");
}

async function rank(offline, reportReview = false) {
  const findings = offline.plan.map((item, index) => ({
    ref: "f" + (index + 1),
    check: item.scanner_id,
    severity: item.severity,
  }));
  const key = (await readFile(SECRET_FILE, "utf8")).trim();
  if (!key) throw new Error("Secret unavailable");
  const rankingSchema = { type: "array", items: { type: "string" } };
  const prompt = reportReview
    ? "Rank these synthetic Windows security findings by remediation priority, highest first. " +
      "Return each string reference exactly once in order. Write an executiveSummary of two or three plain-language sentences " +
      "explaining the main risks for a small IT team and the first defensive priority. " +
      "Use only the supplied evidence, distinguish unverified checks, and avoid commands or assertions about actual attacks. " +
      "Keep the summary under 500 characters. Context: " + JSON.stringify({
        systems: offline.source.endpoint_ids.length,
        unverified: offline.blind_spots.map((item) => ({ check: item.scanner_id, reason: item.reason })),
        findings: findings.map((item, index) => ({ ...item, observation: offline.plan[index].title })),
      })
    : "Rank these synthetic Windows security findings by remediation priority, highest first. " +
      "Return each string reference exactly once as a JSON array. Findings: " + JSON.stringify(findings);
  const request = {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    redirect: "error",
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: reportReview ? 1024 : 512,
        thinkingConfig: { thinkingLevel: "MINIMAL" },
        responseMimeType: "application/json",
        responseJsonSchema: reportReview ? {
          type: "object",
          properties: { order: rankingSchema, executiveSummary: { type: "string" } },
          required: ["order", "executiveSummary"],
        } : rankingSchema,
      },
    }),
  };
  const { result, model } = await generateRanking(request);
  const candidate = result.candidates?.[0];
  if (candidate?.finishReason !== "STOP") throw new Error("Incomplete Gemini response");
  const text = candidate.content?.parts?.find((part) => !part.thought && typeof part.text === "string")?.text;
  const output = JSON.parse(text);
  const order = reportReview ? output?.order : output;
  const executiveSummary = reportReview && typeof output?.executiveSummary === "string"
    ? output.executiveSummary.replace(/\s+/g, " ").trim() : undefined;
  if (reportReview && (!executiveSummary || executiveSummary.length > 650)) {
    throw new Error("Gemini returned an invalid executive summary");
  }
  const byRef = new Map(findings.map((item, index) => [item.ref, offline.plan[index]]));
  if (!Array.isArray(order) || order.length !== findings.length || new Set(order).size !== findings.length ||
      order.some((ref) => !byRef.has(ref))) {
    throw new Error("Gemini returned an invalid ranking");
  }
  const plan = order.map((ref, index) => ({ ...byRef.get(ref), priority: index + 1 }));
  const priorities = plan.map((item) =>
    "**Priority " + item.priority + " · " + literal(item.title) + "** (" +
    literal(item.severity.toUpperCase()) + ") · " + literal(item.hostname) +
    "\n- **Recommended action** " + literal(item.action) +
    "\n- **Rationale** " + literal(item.rationale) +
    "\n- **Source assessment** " + literal(item.assessment_id));
  const unverified = offline.blind_spots.map((item) => "- **" + literal(item.hostname) +
    " · " + literal(item.scanner_id) + "** " + literal(item.reason));
  const analysis = [
    "### Prioritized Fix Plan",
    ...priorities,
    "### Unverified Checks",
    unverified.length ? unverified.join("\n") : "All requested checks returned evidence for this sample.",
  ].join("\n\n");
  return {
    ...offline, status: "available", model, provider: "google_cloud", requested_model: MODEL,
    generated_at: new Date().toISOString(), analysis, plan, executive_summary: executiveSummary,
    fallback_used: false, fallback_reason: null,
    notice: "Gemini ranked the selected findings live. Recommendations are linked to the sample evidence.",
  };
}

async function generateRanking(request) {
  for (const model of [MODEL, BACKUP_MODEL, MODEL]) {
    const url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent";
    let response;
    try {
      response = await fetch(url, { ...request, signal: AbortSignal.timeout(8_500) });
    } catch {
      continue;
    }
    if (response.ok) return { result: await response.json(), model };
    console.warn("Gemini upstream status", response.status, model);
    await response.body?.cancel();
    if (![500, 502, 503, 504].includes(response.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error("Gemini request failed");
}

export function analyzeWithGemini(scope, offline, reportReview = false) {
  const key = reportReview ? "report:" + scope : scope;
  if (pending.has(key)) return pending.get(key);
  if (!offline.plan.length) return offline;
  const now = Date.now();
  while (attempts.length && now - attempts[0] >= RATE_WINDOW_MS) attempts.shift();
  if (attempts.length >= MAX_CALLS_PER_WINDOW || pending.size >= MAX_CONCURRENT_CALLS) {
    return fallback(offline, "The public demo is busy. Retry Gemini shortly.");
  }
  attempts.push(now);
  const result = rank(offline, reportReview)
    .catch(() => fallback(offline, "Gemini is temporarily unavailable. The offline plan is shown below."))
    .finally(() => pending.delete(key));
  pending.set(key, result);
  return result;
}
