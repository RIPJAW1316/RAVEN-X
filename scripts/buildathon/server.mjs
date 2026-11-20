import { readFile, readdir } from "node:fs/promises";
import { createServer } from "node:http";
import { analyzeWithGemini } from "./gemini.mjs";
import { getReview, reportCsv, reportPdf } from "./reviews.mjs";

// The deployment context contains only synthetic data and the production UI.
const data = JSON.parse(await readFile(new URL("./demo.json", import.meta.url), "utf8"));
const namespace = "/api/v1/organizations/" + data.org;
const machineIds = new Set(data.machines.map((item) => item.endpoint_id));
const portal = new URL("./portal/", import.meta.url);
const files = new Map([["/", await readFile(new URL("index.html", portal))]]);
for (const filename of await readdir(new URL("assets/", portal))) {
  if (/^[A-Za-z0-9_.-]+\.(css|js)$/.test(filename)) {
    const path = "assets/" + filename;
    files.set("/" + path, await readFile(new URL(path, portal)));
  }
}
const csv = await readFile(new URL("fleet.csv", import.meta.url));

function respond(req, res, status, type, body, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": type, ...extraHeaders });
  res.end(req.method === "HEAD" ? undefined : body);
}

function json(req, res, body, status = 200) {
  return respond(req, res, status, "application/json; charset=utf-8", JSON.stringify(body));
}

async function readAnalysisRequest(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2048) return null;
    chunks.push(chunk);
  }
  try {
    const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!input || !["gemini", "offline"].includes(input.model) ||
        Object.keys(input).some((key) => !["model", "endpoint_id", "demo_id"].includes(key)) ||
        ("endpoint_id" in input && !machineIds.has(input.endpoint_id)) ||
        ("demo_id" in input && (input.demo_id !== "windows-hardening-v1" || "endpoint_id" in input))) return null;
    return { model: input.model, scope: input.endpoint_id ?? "fleet" };
  } catch {
    return null;
  }
}

async function handle(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  const url = new URL(req.url, "http://localhost");
  const get = req.method === "GET" || req.method === "HEAD";
  if (get && url.pathname === "/health") return json(req, res, { status: "ready", mode: "synthetic-demo" });
  if (get && url.pathname === "/api/v1/auth/organizations") {
    return json(req, res, [{ organization_id: data.org, name: "RAVEN-X · Buildathon demo", membership_id: "demo" }]);
  }
  if (get && files.has(url.pathname)) {
    const contentType = url.pathname.endsWith(".js") ? "application/javascript" :
      url.pathname.endsWith(".css") ? "text/css" : "text/html";
    if (url.pathname.startsWith("/assets/")) res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    return respond(req, res, 200, contentType + "; charset=utf-8", files.get(url.pathname));
  }
  const path = url.pathname.startsWith(namespace + "/") ? url.pathname.slice(namespace.length) : undefined;
  if (get && path === "/fleet/endpoints") {
    const q = (url.searchParams.get("q") || "").toLowerCase();
    const presence = url.searchParams.getAll("presence");
    const items = data.machines.filter((item) => item.hostname.toLowerCase().includes(q) &&
      (presence.length === 0 || presence.includes(item.presence_state)));
    const sort = url.searchParams.get("sort") || "hostname";
    const direction = url.searchParams.get("direction") === "desc" ? -1 : 1;
    if (["hostname", "platform", "presence_state", "last_seen_at"].includes(sort)) {
      items.sort((a, b) => direction * a[sort].localeCompare(b[sort]));
    }
    const limit = Math.max(1, Math.min(200, Number.parseInt(url.searchParams.get("limit"), 10) || 40));
    const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset"), 10) || 0);
    const page = items.slice(offset, offset + limit);
    return json(req, res, { items: page, limit, offset, returned: page.length, total: items.length });
  }
  if (get && path === "/reports/fleet.csv") {
    return respond(req, res, 200, "text/csv; charset=utf-8", csv,
      { "Content-Disposition": 'attachment; filename="ravenx-synthetic-fleet.csv"' });
  }
  if (get && path && Object.hasOwn(data.routes, path)) return json(req, res, data.routes[path]);
  if (req.method === "POST" && path === "/ai/analyze") {
    const request = await readAnalysisRequest(req);
    if (!request) return json(req, res, { detail: "Unknown sample or model" }, 400);
    const offline = data.analyses[request.scope];
    const analysis = request.model === "gemini" ? await analyzeWithGemini(request.scope, offline) : offline;
    return json(req, res, analysis);
  }
  if (req.method === "POST" && path === "/reports/review") {
    const endpoint = url.searchParams.get("endpoint_id");
    const model = url.searchParams.get("model");
    const format = url.searchParams.get("format");
    if ((endpoint !== null && !machineIds.has(endpoint)) || !["offline", "gemini"].includes(model) ||
        ![null, "pdf", "json", "csv"].includes(format)) {
      return json(req, res, { detail: "Unknown sample, model, or export format" }, 400);
    }
    const scope = endpoint ?? "fleet";
    const report = data.routes[endpoint ? `/endpoints/${endpoint}/report` : "/reports/fleet"];
    const snapshot = await getReview(scope, model, report, data.analyses[scope], url.searchParams.get("review_id"));
    if (!snapshot) return json(req, res, { detail: "Gemini is temporarily unavailable. Retry Gemini or select Offline rules." }, 503);
    if (!format) return json(req, res, snapshot);
    const headers = { "Content-Disposition": `attachment; filename="ravenx-synthetic-${scope}-${model}.${format}"` };
    if (format === "json") {
      return respond(req, res, 200, "application/json; charset=utf-8", JSON.stringify(snapshot, null, 2), headers);
    }
    if (format === "csv") return respond(req, res, 200, "text/csv; charset=utf-8", reportCsv(snapshot), headers);
    const pdf = await reportPdf(snapshot);
    if (!pdf) return json(req, res, { detail: "The PDF renderer is busy. Try downloading again shortly." }, 503);
    return respond(req, res, 200, "application/pdf", pdf, headers);
  }
  return json(req, res, { detail: "This operation is unavailable in the public prototype." }, 404);
}

createServer((req, res) => {
  handle(req, res).catch(() => {
    if (!res.headersSent) json(req, res, { detail: "The prototype could not handle this request." }, 500);
    else res.end();
  });
}).listen(Number(process.env.PORT || 8080), process.env.HOST || "0.0.0.0");
