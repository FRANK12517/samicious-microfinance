import http from "node:http";
import { pbkdf2Sync, randomBytes } from "node:crypto";
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

const STAFF_PASSWORD_ITERATIONS = 150000;
const STAFF_PASSWORD_SYMBOLS = "@#$%^&*()";

function staffPasswordPrefix(fullName) {
  const letters = String(fullName || "").match(/[A-Za-z]/g) || [];
  if (letters.length < 3) return "";
  return letters.slice(0, 3).join("").replace(/^([A-Za-z])([A-Za-z])([A-Za-z])$/, (_, first, second, third) => first.toUpperCase() + second.toLowerCase() + third.toLowerCase());
}

function validateStaffPassword(password, fullName) {
  const value = String(password || "");
  const prefix = staffPasswordPrefix(fullName);
  if (!prefix) return { ok: false, message: "Full Name must contain at least three alphabetic characters" };
  if (value.length !== 7) return { ok: false, message: "Staff passwords must contain exactly 7 characters" };
  if (!STAFF_PASSWORD_SYMBOLS.includes(value[0]) || value.slice(1, 4) !== prefix || !/^[0-9]{3}$/.test(value.slice(4))) return { ok: false, message: "Staff password must be symbol + name prefix + 3 digits" };
  return { ok: true, message: "" };
}

function hashStaffPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(String(password), Buffer.from(salt, "hex"), STAFF_PASSWORD_ITERATIONS, 32, "sha256").toString("hex");
  return { passwordHash: hash, passwordSalt: salt, passwordIterations: STAFF_PASSWORD_ITERATIONS, passwordAlgo: "PBKDF2-SHA256", passwordSetAt: new Date().toISOString() };
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function usernameCandidates(fullName) {
  const words = String(fullName || "").trim().toLowerCase().normalize("NFKD").replace(/[\\u0300-\\u036f]/g, "").split(/[^a-z0-9]+/).filter(Boolean);
  if (!words.length) return [];
  const first = words[0];
  const surname = words.length > 1 ? words[words.length - 1] : "";
  return [...new Set([first, surname, first + surname].filter(Boolean))];
}

async function validateUserUpsert(params, token) {
  const data = params?.p_data;
  if (!data || typeof data !== "object") throw Object.assign(new Error("invalid_user_record"), { status: 400 });
  const username = normalizeUsername(data.username);
  if (!username || !/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/.test(username)) throw Object.assign(new Error("invalid_username"), { status: 400 });
  if (data.username !== username) throw Object.assign(new Error("username_must_be_lowercase"), { status: 400 });
  if (typeof data.password === "string" && data.password.length > 0) throw Object.assign(new Error("plaintext_password_not_allowed"), { status: 400 });
  const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  const existing = (Array.isArray(rows) ? rows : []).find((row) => String(row.id || "") === String(data.id || "") || normalizeUsername(row.username) === username);
  if (!String(data.fullName || "").trim() && !existing) throw Object.assign(new Error("full_name_required"), { status: 400 });
  const duplicate = (Array.isArray(rows) ? rows : []).find((row) => {
    if (normalizeUsername(row.username) !== username) return false;
    const sameRecord = String(row.id || "") && String(data.id || "")
      ? String(row.id) === String(data.id)
      : String(row.username) === String(data.username);
    return !sameRecord;
  });
  if (duplicate) throw Object.assign(new Error("username_already_taken"), { status: 409 });
  return Object.assign({}, data, { username });
}

async function hashStaffPasswordRequest(params) {
  const password = String(params?.p_password || "");
  const fullName = String(params?.p_full_name || "");
  const validation = validateStaffPassword(password, fullName);
  if (!validation.ok) throw Object.assign(new Error(validation.message), { status: 400 });
  return hashStaffPassword(password);
}

async function generateUsername(params, token) {
  const fullName = String(params?.p_full_name || "").trim();
  if (!fullName) throw Object.assign(new Error("full_name_required"), { status: 400 });
  const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  const used = new Set((Array.isArray(rows) ? rows : []).map((row) => normalizeUsername(row.username)).filter(Boolean));
  const candidates = usernameCandidates(fullName);
  for (const candidate of candidates) if (!used.has(candidate)) return { username: candidate };
  const base = candidates[0] || "staff";
  for (let n = 2; n < 10000; n++) {
    const candidate = base + n;
    if (!used.has(candidate)) return { username: candidate };
  }
  throw Object.assign(new Error("unable_to_generate_username"), { status: 409 });
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
    if (fnName === "rpc_generate_username") return json(res, 200, { data: await generateUsername(params, token) });
    if (fnName === "rpc_hash_staff_password") return json(res, 200, { data: await hashStaffPasswordRequest(params) });
    if (fnName === "rpc_table_upsert" && params.p_table === "users") params.p_data = await validateUserUpsert(params, token);
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
