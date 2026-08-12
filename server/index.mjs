import http from "node:http";
import { authorizeRpc, auditEvent, RPC_POLICY, safeAuditEvent } from "./authz.mjs";

const PORT = Number(process.env.PORT || 8787);
const SUPABASE_URL = String(process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const MAX_BODY_BYTES = 256 * 1024;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("Security gateway requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY server-side. No privileged key is bundled in the frontend.");
}

const auditSink = (event) => console.info(`[audit] ${safeAuditEvent(event)}`);

async function readJson(req) {
  let size = 0;
  let body = "";
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error("request_too_large"), { status: 413 });
    body += chunk;
  }
  if (!body) return {};
  return JSON.parse(body);
}

async function supabaseRpc(name, params) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw Object.assign(new Error("backend_not_configured"), { status: 503 });
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: "POST",
    headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  const text = await response.text();
  let payload; try { payload = text ? JSON.parse(text) : null; } catch { payload = { message: "upstream_error" }; }
  if (!response.ok) throw Object.assign(new Error(payload?.message || "upstream_error"), { status: response.status });
  return payload;
}

function bearer(req) {
  const value = String(req.headers.authorization || "");
  return /^Bearer\s+([^\s]+)$/i.exec(value)?.[1] || null;
}

async function sessionContext(req) {
  const token = bearer(req);
  if (!token) return null;
  return await supabaseRpc("rpc_get_session_context", { p_token: token });
}

function json(res, status, value) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(JSON.stringify(value));
}

async function handle(req, res) {
  if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
  if (req.method !== "POST" || req.url !== "/api/rpc") return json(res, 404, { error: "not_found" });
  let body;
  try { body = await readJson(req); } catch (error) { return json(res, error.status || 400, { error: error.message === "request_too_large" ? error.message : "invalid_json" }); }

  const fnName = String(body.fnName || "");
  const policy = RPC_POLICY[fnName];
  if (!policy) return json(res, 403, { error: "rpc_not_allowed" });

  let context = null;
  if (!policy.public) {
    try { context = await sessionContext(req); } catch { context = null; }
    const decision = authorizeRpc(context, fnName, body.params || {});
    auditSink(auditEvent({ request: req, context, action: fnName, target: body.params?.p_table || null, decision }));
    if (!decision.allowed) return json(res, decision.status, { error: decision.reason });
  }

  const token = bearer(req);
  const params = { ...(body.params || {}) };
  delete params.p_token;
  if (!policy.public) params.p_token = token;
  try {
    const data = await supabaseRpc(fnName, params);
    return json(res, 200, { data });
  } catch (error) {
    const decision = { allowed: false, reason: "upstream_rejected" };
    auditSink(auditEvent({ request: req, context, action: fnName, target: params.p_table || null, decision, metadata: { status: error.status || 502 } }));
    return json(res, error.status || 502, { error: "request_rejected" });
  }
}

http.createServer((req, res) => handle(req, res).catch((error) => json(res, error.status || 500, { error: "internal_error" }))).listen(PORT, "0.0.0.0", () => {
  console.log(`SAMICIOUS security gateway listening on ${PORT}`);
});
