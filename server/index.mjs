import http from "node:http";
import { pbkdf2Sync, randomBytes, randomInt } from "node:crypto";
import { authorizeRpc, auditEvent, RPC_POLICY, safeAuditEvent } from "./authz.mjs";

const PORT = Number(process.env.PORT || 8787);
const SUPABASE_URL = String(process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;
const MAX_BODY_BYTES = 256 * 1024;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("Security gateway requires a server-side Supabase URL and SUPABASE_SERVICE_ROLE_KEY/SUPABASE_SERVICE_KEY. No privileged key is bundled in the frontend.");
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
const PRIVILEGED_DEFAULTS_VERSION = "2026-08-privileged-defaults-v2";
const STAFF_ACCOUNT_ROLES = new Set(["Teller", "Susu Collector"]);
const STAFF_ACCOUNT_PREFIXES = Object.freeze({Teller: "T", "Susu Collector": "SC"});

const PRIVILEGED_DEFAULTS = Object.freeze({
  administrator: Object.freeze({ username: "adugyamfi", displayName: "ADUGYAMFI", fullName: "Adugyamfi", role: "Administrator", passwordHash: "ef554534c1e3da33ac5d79f62346d43d661bcc846ae733aebb7f6326f3ed0261", passwordSalt: "e2b3ae184c3792b4ad07449b4435f820", passwordIterations: 150000, passwordAlgo: "PBKDF2-SHA256" }),
  developer: Object.freeze({ username: "frank", displayName: "FRANK", fullName: "Frank", role: "Developer", passwordHash: "d36ce14e591a9b98541cbe22b090206a7cdbf4df91c3fc5af01512ff6a7eccb3", passwordSalt: "47988073b26e91eb07d2d7a0ca7d46b3", passwordIterations: 150000, passwordAlgo: "PBKDF2-SHA256" })
});

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

async function allocateStaffAccountNumber(role, token, existingRows) {
  if (!STAFF_ACCOUNT_ROLES.has(role)) throw Object.assign(new Error("staff_account_number_not_applicable"), { status: 400 });
  const rows = Array.isArray(existingRows) ? existingRows : await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  const used = new Set(rows.map((row) => String(row.staffAccountNumber || "").trim()).filter(Boolean));
  const prefix = STAFF_ACCOUNT_PREFIXES[role];
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const candidate = `SAM-${prefix}-${randomInt(100000, 1000000)}`;
    if (!used.has(candidate)) return candidate;
  }
  throw Object.assign(new Error("staff_account_number_generation_failed"), { status: 503 });
}

async function generateStaffAccountNumber(params, token) {
  const role = String(params?.p_role || "").trim();
  const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  return { staffAccountNumber: await allocateStaffAccountNumber(role, token, rows) };
}

async function backfillStaffAccountNumbers(params, token) {
  const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  const working = Array.isArray(rows) ? rows.map((row) => ({ ...row })) : [];
  const changed = [];
  for (const row of working) {
    if (!STAFF_ACCOUNT_ROLES.has(String(row.role || "").trim()) || String(row.staffAccountNumber || "").trim()) continue;
    row.staffAccountNumber = await allocateStaffAccountNumber(String(row.role).trim(), token, working);
    await supabaseRpc("rpc_table_upsert", { p_token: token, p_table: "users", p_data: row });
    changed.push({ username: row.username, staffAccountNumber: row.staffAccountNumber });
  }
  return { updated: changed.length, records: changed };
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
  const role = String(data.role || existing?.role || "").trim();
  const normalized = Object.assign({}, existing || {}, data, { username });
  /* The browser may display this field but can never choose or replace it.
     Existing numbers remain attached to the staff record for its full lifecycle. */
  if (existing?.staffAccountNumber) normalized.staffAccountNumber = existing.staffAccountNumber;
  else if (STAFF_ACCOUNT_ROLES.has(role)) normalized.staffAccountNumber = await allocateStaffAccountNumber(role, token, rows);
  else delete normalized.staffAccountNumber;
  return normalized;
}

async function verifyLoginRequest(params) {
  const username = normalizeUsername(params?.p_username);
  const password = String(params?.p_password || "");
  if (!username || !password) return { ok: false, reason: "invalid_credentials" };
  const rows = await supabaseRpc("rpc_get_login_material", { p_username: username });
  const material = Array.isArray(rows) ? rows[0] : rows;
  if (!material) return { ok: false, reason: "invalid_credentials" };
  if (material.active === false || material.usernameRevoked || material.passwordRevoked) return { ok: false, reason: "account_revoked" };
  let valid = false;
  if (material.passwordHash && material.passwordSalt) {
    const computed = pbkdf2Sync(password, Buffer.from(material.passwordSalt, "hex"), Number(material.passwordIterations) || 150000, 32, "sha256").toString("hex");
    valid = computed === material.passwordHash;
  } else if (typeof material.password === "string") {
    valid = material.password === password;
  }
  if (!valid) return { ok: false, reason: "invalid_credentials" };
  return { ok: true, username: material.username, role: material.role, active: material.active !== false, usernameRevoked: false, passwordRevoked: false, sessionEpoch: Number(material.sessionEpoch) || 0 };
}

const TELLER_LOCKED_TRANSACTION_TABLES = new Set(["transactions", "loanRepayments", "loans", "cashHandovers", "vaultTransfers"]);
const COLLECTOR_LOCKED_TRANSACTION_TABLES = new Set(["transactions", "loanRepayments", "loans"]);

async function assertTellerEodMutationAllowed(params, token, context) {
  const table = String(params?.p_table || "");
  const data = params?.p_data && typeof params.p_data === "object" ? params.p_data : {};
  if (!TELLER_LOCKED_TRANSACTION_TABLES.has(table) && !COLLECTOR_LOCKED_TRANSACTION_TABLES.has(table) && !["tellerTillClosings","eodReconciliations"].includes(table)) return;
  const isAdministrator = String(context?.role || "") === "Administrator";
  const collectorRoles = new Set(["Susu Collector", "Field Officer", "Loan Officer"]);
  if (table === "eodReconciliations") {
    const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "eodReconciliations" });
    const existing = (Array.isArray(rows) ? rows : []).find((row) => String(row.id || "") === String(data.id || "") || (String(row.username || "") === String(data.username || context?.username || "") && String(row.date || "") === String(data.date || "")));
    if (existing && (existing.submissionStatus === "CLOSED" || existing.status === "closed")) throw Object.assign(new Error("collector_eod_closed_immutable"), { status: 403 });
    if (!isAdministrator && existing && collectorRoles.has(String(existing.role || "")) && String(existing.username || "") === String(context?.username || "") && existing.status !== "draft") throw Object.assign(new Error("collector_eod_submitted_locked"), { status: 403 });
    return;
  }
  const tillRows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "tellerTillClosings" });
  const rows = Array.isArray(tillRows) ? tillRows : [];
  if (table === "tellerTillClosings") {
    const existing = rows.find((row) => String(row.id || "") === String(data.id || ""));
    if (existing && (existing.workflowStage === "manager_approved" || existing.workflowStage === "ceo_approved")) throw Object.assign(new Error("teller_eod_closed_immutable"), { status: 403 });
    if (!isAdministrator && existing && existing.workflowStage !== "draft" && String(existing.username || "") === String(data.username || context?.username || "")) throw Object.assign(new Error("teller_eod_submitted_locked"), { status: 403 });
    return;
  }
  const actor = data.actorUserId || data.disbursedByUserId || data.receivingOfficerUserId || data.username;
  const date = data.date || data.transactionDate;
  if (!actor || !date) return;
  if (TELLER_LOCKED_TRANSACTION_TABLES.has(table)) {
    const locked = rows.find((row) => String(row.username || "") === String(actor) && String(row.date || "") === String(date) && row.workflowStage !== "draft");
    if (locked && (!isAdministrator || locked.workflowStage === "manager_approved" || locked.workflowStage === "ceo_approved")) throw Object.assign(new Error("teller_eod_submitted_transaction_locked"), { status: 403 });
  }
  if (COLLECTOR_LOCKED_TRANSACTION_TABLES.has(table)) {
    const eodRows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "eodReconciliations" });
    const locked = (Array.isArray(eodRows) ? eodRows : []).find((row) => collectorRoles.has(String(row.role || "")) && String(row.username || "") === String(actor) && String(row.date || "") === String(date) && row.status !== "draft");
    if (locked) throw Object.assign(new Error("collector_eod_submitted_transaction_locked"), { status: 403 });
  }
}

function isStaffAccountNumberCollision(error) {
  const message = String(error?.message || error || "").toLowerCase();
  return message.includes("staffaccountnumber") || message.includes("staff_account_number") || message.includes("duplicate key") || message.includes("unique constraint");
}

function redactCredentialMaterial(value) {
  if (Array.isArray(value)) return value.map(redactCredentialMaterial);
  if (!value || typeof value !== "object") return value;
  const safe = { ...value };
  for (const key of ["password", "passwordHash", "passwordSalt", "passwordIterations", "passwordAlgo", "passwordHistory"]) delete safe[key];
  return safe;
}

const SETTINGS_KEY_PREFIX="user-settings::";
function settingsDefaults(role){
  const admin=role==="Administrator";
  return {account:true,security:true,passwordManagement:admin,loginSession:true,notifications:true,appearance:true,language:true,accessibility:true,offlineSync:true,privacy:true,applicationPreferences:true,helpSupport:true,helpManagement:admin,developerInformation:role==="Developer"||admin,about:true};
}
async function settingsCapabilities(params, context){
  const role=String(context?.role||"");
  return {role,categories:settingsDefaults(role)};
}
async function settingsRead(params,token){
  const username=String(params?.p_username||"");
  const row=await supabaseRpc("rpc_table_select_one",{p_token:token,p_table:"policySettings",p_key:SETTINGS_KEY_PREFIX+username});
  return row&&typeof row==="object"?redactCredentialMaterial(row):{key:SETTINGS_KEY_PREFIX+username,username,preferences:{}};
}
async function settingsSave(params,token){
  const username=String(params?.p_username||"");
  const preferences=params?.p_preferences&&typeof params.p_preferences==="object"?params.p_preferences:{};
  const allowedKeys=new Set(["theme","language","fontScale","highContrast","reducedMotion","notificationsEnabled","soundEnabled","autoSync","offlineMode","telemetryEnabled"]);
  const safePreferences=Object.fromEntries(Object.entries(preferences).filter(([key])=>allowedKeys.has(key)).map(([key,value])=>[key,typeof value==="boolean"||typeof value==="number"||typeof value==="string"?value:null]));
  const record={key:SETTINGS_KEY_PREFIX+username,username,preferences:safePreferences,updatedAt:new Date().toISOString(),updatedByUserId:username};
  await supabaseRpc("rpc_table_upsert",{p_token:token,p_table:"policySettings",p_data:record});
  return {saved:true,username,updatedAt:record.updatedAt,preferences:safePreferences};
}
function cleanSupportText(value,max=800){
  return String(value??"").replace(/(password|passcode|secret|token|api[_-]?key|jwt|database|service[_-]?role)[^\n,;]*/gi,"[redacted]").replace(/[<>]/g,"").slice(0,max).trim();
}
function safeSupportReport(input={},context){
  const report={
    id:cleanSupportText(input.id,80)||crypto.randomUUID(),
    role:cleanSupportText(context?.role,80),
    userId:cleanSupportText(context?.userId||context?.username,120),
    module:cleanSupportText(input.module,120),
    problemCategory:cleanSupportText(input.problemCategory,120),
    timestamp:cleanSupportText(input.timestamp,80)||new Date().toISOString(),
    transactionReference:cleanSupportText(input.transactionReference,100),
    applicationVersion:cleanSupportText(input.applicationVersion,40),
    deviceInformation:cleanSupportText(input.deviceInformation,240),
    connectivity:cleanSupportText(input.connectivity,40),
    userDescription:cleanSupportText(input.userDescription,1200),
    attemptedSteps:Array.isArray(input.attemptedSteps)?input.attemptedSteps.map(step=>cleanSupportText(step,240)).filter(Boolean).slice(0,20):[],
    status:["OPEN","IN_PROGRESS","RESOLVED","CLOSED"].includes(String(input.status||""))?String(input.status):"OPEN",
    createdAt:cleanSupportText(input.createdAt,80)||new Date().toISOString(),
    createdByUserId:cleanSupportText(context?.userId||context?.username,120)
  };
  return report;
}
async function createSupportReport(params,token,context){
  const report=safeSupportReport(params?.p_report||{},context);
  await supabaseRpc("rpc_table_upsert",{p_token:token,p_table:"supportReports",p_data:report});
  return {created:true,report};
}
async function listSupportReports(params,token){
  const rows=await supabaseRpc("rpc_table_select_all",{p_token:token,p_table:"supportReports"});
  return (Array.isArray(rows)?rows:[]).map(row=>safeSupportReport(row,{role:row.role,userId:row.userId})).sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,200);
}
function safeHelpContent(row){
  if(!row||typeof row!=="object")return null;
  return {id:cleanSupportText(row.id,100),title:cleanSupportText(row.title,180),category:cleanSupportText(row.category,100),module:cleanSupportText(row.module,100),roles:Array.isArray(row.roles)?row.roles.map(r=>cleanSupportText(r,80)).slice(0,20):[],purpose:cleanSupportText(row.purpose,600),instructions:Array.isArray(row.instructions)?row.instructions.map(s=>cleanSupportText(s,500)).slice(0,30):[],expectedResult:cleanSupportText(row.expectedResult,500),troubleshooting:cleanSupportText(row.troubleshooting,700),escalation:cleanSupportText(row.escalation,700),active:row.active!==false,updatedAt:cleanSupportText(row.updatedAt,80),updatedByUserId:cleanSupportText(row.updatedByUserId,120)};
}
async function listHelpContent(params,token){
  const rows=await supabaseRpc("rpc_table_select_all",{p_token:token,p_table:"helpContent"});
  return (Array.isArray(rows)?rows:[]).map(safeHelpContent).filter(Boolean).filter(row=>row.active!==false);
}
async function saveHelpContent(params,token,context){
  const source=params?.p_content&&typeof params.p_content==="object"?params.p_content:{};
  const content=safeHelpContent(Object.assign({},source,{id:source.id||crypto.randomUUID(),updatedAt:new Date().toISOString(),updatedByUserId:context?.userId||context?.username,active:source.active!==false}));
  if(!content.title||!content.category)throw Object.assign(new Error("help_content_title_and_category_required"),{status:400});
  await supabaseRpc("rpc_table_upsert",{p_token:token,p_table:"helpContent",p_data:content});
  return {saved:true,content};
}
async function deleteHelpContent(params,token){
  const id=cleanSupportText(params?.p_id,100);
  if(!id)throw Object.assign(new Error("help_content_id_required"),{status:400});
  await supabaseRpc("rpc_table_delete",{p_token:token,p_table:"helpContent",p_key:id});
  return {deleted:true,id};
}
async function migratePrivilegedDefaults(params, token) {
  const rows = await supabaseRpc("rpc_table_select_all", { p_token: token, p_table: "users" });
  const existingRows = Array.isArray(rows) ? rows : [];
  const specs = [
    { key: "administrator", aliases: ["edugyamfi"] },
    { key: "developer", aliases: ["frank abban", "developer"] },
  ];
  const results = [];
  for (const spec of specs) {
    const account = PRIVILEGED_DEFAULTS[spec.key];
    const target = existingRows.find((row) => row.username === account.username);
    const alias = target ? null : existingRows.find((row) => spec.aliases.includes(row.username));
    const record = Object.assign({}, target || alias || {}, account, {
      active: true,
      credentialStatus: "ACTIVE",
      defaultPasswordChanged: false,
      passwordSetupRequired: false,
      privilegedDefaultsVersion: PRIVILEGED_DEFAULTS_VERSION,
      technicalOnly: account.role === "Developer",
      createdAt: (target || alias)?.createdAt || new Date().toISOString(),
      createdByUserId: (target || alias)?.createdByUserId || "system",
    });
    await supabaseRpc("rpc_table_upsert", { p_token: token, p_table: "users", p_data: record });
    for (const old of existingRows.filter((row) => spec.aliases.includes(row.username) && row.username !== account.username)) {
      await supabaseRpc("rpc_table_upsert", { p_token: token, p_table: "users", p_data: { ...old, active: false, credentialStatus: "REVOKED", usernameRevoked: true, revocationReason: "Replaced by the current privileged default account" } });
    }
    results.push({ username: account.username, role: account.role, status: "ACTIVE" });
  }
  return { version: PRIVILEGED_DEFAULTS_VERSION, accounts: results };
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
  const rows = await supabaseRpc("rpc_get_session_context", { p_token: token });
  const row = Array.isArray(rows) ? rows[0] : rows;
  return row || null;
}

function json(res, status, value) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(JSON.stringify(value));
}

const BRANCH_SCOPED_READ_TABLES = new Set(["users","branches","transactions","loanRepayments","loans","accounts","customers","eodReconciliations","cashHandovers","tellerTillClosings","notifications","activityLog","adminTxnNotifications"]);
function applyBranchManagerReadScope(data, table, context) {
  if (String(context?.role || "") !== "Branch Manager" || !BRANCH_SCOPED_READ_TABLES.has(table)) return data;
  const raw = context?.authorizedBranchIds || context?.branchIds || context?.authorizedBranches;
  const ids = new Set((Array.isArray(raw) ? raw.map(x => typeof x === "object" ? x.id : x) : []).filter(Boolean).map(String));
  if (context?.branchId) ids.add(String(context.branchId));
  const scoped = (row) => row && (table === "branches" ? ids.has(String(row.id)) : row.branchId != null && ids.has(String(row.branchId)));
  if (Array.isArray(data)) return data.filter(scoped);
  return scoped(data) ? data : null;
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
    if (fnName === "rpc_verify_login") return json(res, 200, { data: await verifyLoginRequest(params) });
    if (fnName === "rpc_settings_capabilities") return json(res, 200, { data: await settingsCapabilities(params, context) });
    if (fnName === "rpc_settings_read") return json(res, 200, { data: await settingsRead(params, token) });
    if (fnName === "rpc_settings_save") return json(res, 200, { data: await settingsSave(params, token) });
    if (fnName === "rpc_support_report_create") return json(res, 200, { data: await createSupportReport(params, token, context) });
    if (fnName === "rpc_support_report_list") return json(res, 200, { data: await listSupportReports(params, token) });
    if (fnName === "rpc_help_content_list") return json(res, 200, { data: await listHelpContent(params, token) });
    if (fnName === "rpc_help_content_save") return json(res, 200, { data: await saveHelpContent(params, token, context) });
    if (fnName === "rpc_help_content_delete") return json(res, 200, { data: await deleteHelpContent(params, token) });
    if (fnName === "rpc_generate_username") return json(res, 200, { data: await generateUsername(params, token) });
    if (fnName === "rpc_hash_staff_password") return json(res, 200, { data: await hashStaffPasswordRequest(params) });
    if (fnName === "rpc_generate_staff_account_number") return json(res, 200, { data: await generateStaffAccountNumber(params, token) });
    if (fnName === "rpc_backfill_staff_account_numbers") return json(res, 200, { data: await backfillStaffAccountNumbers(params, token) });
    if (fnName === "rpc_migrate_privileged_defaults") return json(res, 200, { data: await migratePrivilegedDefaults(params, token) });
    let data;
    if (fnName === "rpc_table_upsert") await assertTellerEodMutationAllowed(params, token, context);
    if (fnName === "rpc_table_upsert" && params.p_table === "users") {
      let lastError;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          params.p_data = await validateUserUpsert(params, token);
          data = await supabaseRpc(fnName, params);
          lastError = null;
          break;
        } catch (error) {
          lastError = error;
          if (!isStaffAccountNumberCollision(error) || attempt === 2) throw error;
        }
      }
      if (lastError) throw lastError;
    } else {
      data = await supabaseRpc(fnName, params);
    }
    const scopedData = ["rpc_table_select_all","rpc_table_select_one","rpc_table_select_by"].includes(fnName) ? applyBranchManagerReadScope(data, params.p_table, context) : data;
    const safeData = params.p_table === "users" ? redactCredentialMaterial(scopedData) : scopedData;
    return json(res, 200, { data: safeData });
  } catch (error) {
    const status = error.status || 502;
    const reason = status === 503 ? "backend_not_configured" : "upstream_rejected";
    const decision = { allowed: false, reason };
    auditSink(auditEvent({ request: req, context, action: fnName, target: params.p_table || null, decision, metadata: { status } }));
    return json(res, status, { error: reason });
  }
}

export { handle };

if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_VERSION) {
  http.createServer((req, res) => handle(req, res).catch((error) => json(res, error.status || 500, { error: "internal_error" }))).listen(PORT, "0.0.0.0", () => {
    console.log(`SAMICIOUS security gateway listening on ${PORT}`);
  });
}
