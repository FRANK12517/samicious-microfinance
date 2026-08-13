import crypto from "node:crypto";

export const ROLE_PERMISSIONS = Object.freeze({
  Administrator: new Set(["developer:read", "developer:write", "admin:read", "admin:write", "data:read", "data:write", "audit:read"]),
  Developer: new Set(["developer:read", "developer:write", "admin:read", "admin:write", "data:read", "data:write", "audit:read"]),
  "Branch Manager": new Set(["data:read", "data:write"]),
  "Loan Manager": new Set(["data:read", "data:write"]),
  Teller: new Set(["data:read", "data:write"]),
  Cashier: new Set(["data:read", "data:write"]),
  "Susu Collector": new Set(["data:read", "data:write"]),
  "Loan Officer": new Set(["data:read", "data:write"]),
  Auditor: new Set(["data:read", "audit:read"]),
  Accountant: new Set(["data:read", "data:write", "audit:read"]),
  "HR/Staff Manager": new Set(["data:read", "data:write"]),
  "Customer Service": new Set(["data:read"]),
});

export const DEVELOPER_TABLES = new Set(["devSmsConfig", "security_audit_log"]);
export const AUTHORIZATION_TABLES = new Set(["users", "userRoles", "roles", "permissions", "tenantScopes"]);
export const ADMINISTRATOR_ONLY_RPCS = new Set(["rpc_generate_username", "rpc_hash_staff_password", "rpc_migrate_privileged_defaults", "rpc_help_content_save", "rpc_help_content_delete", "rpc_support_report_list"]);
export const SUPPORT_MANAGEMENT_TABLES = new Set(["helpContent", "supportReports"]);

export const RPC_POLICY = Object.freeze({
  rpc_verify_login: { public: true },
  rpc_record_login_attempt: { public: true },
  rpc_create_session: { public: true },
  rpc_generate_username: { permission: "admin:write" },
  rpc_hash_staff_password: { permission: "admin:write" },
  rpc_migrate_privileged_defaults: { permission: "admin:write" },
  rpc_settings_capabilities: { permission: "data:read" },
  rpc_settings_read: { permission: "data:read" },
  rpc_settings_save: { permission: "data:write" },
  rpc_support_report_create: { permission: "data:read" },
  rpc_support_report_list: { permission: "admin:read" },
  rpc_help_content_list: { permission: "data:read" },
  rpc_help_content_save: { permission: "admin:write" },
  rpc_help_content_delete: { permission: "admin:write" },
  rpc_logout: { permission: "data:read" },
  rpc_table_select_all: { permission: "data:read" },
  rpc_table_select_one: { permission: "data:read" },
  rpc_table_select_by: { permission: "data:read" },
  rpc_table_upsert: { permission: "data:write" },
  rpc_table_delete: { permission: "data:write" },
  rpc_table_clear: { permission: "admin:write" },
});

export function normalizeRole(role) {
  return typeof role === "string" ? role.trim() : "";
}

export function hasPermission(context, permission) {
  if (!context || context.active === false || context.usernameRevoked || context.passwordRevoked) return false;
  const role = normalizeRole(context.role);
  return Boolean(ROLE_PERMISSIONS[role]?.has(permission));
}

export function isWithinScope(context, requestedScope) {
  if (!requestedScope || !context) return false;
  if (normalizeRole(context.role) === "Administrator" || normalizeRole(context.role) === "Developer") return true;
  const allowed = ["branchId", "tenantId", "organizationId", "schoolId", "districtId", "regionId"];
  return allowed.every((key) => requestedScope[key] == null || context[key] == null || String(requestedScope[key]) === String(context[key]));
}

export function authorize(context, { permission, scope } = {}) {
  if (!context) return { allowed: false, status: 401, reason: "authentication_required" };
  if (context.active === false || context.usernameRevoked || context.passwordRevoked) return { allowed: false, status: 403, reason: "account_inactive" };
  if (permission && !hasPermission(context, permission)) return { allowed: false, status: 403, reason: "insufficient_privilege" };
  if (scope && !isWithinScope(context, scope)) return { allowed: false, status: 403, reason: "scope_violation" };
  return { allowed: true, status: 200, reason: "authorized" };
}

export function authorizeRpc(context, fnName, params = {}) {
  const table = String(params.p_table || "");
  if (["rpc_settings_capabilities", "rpc_settings_read", "rpc_settings_save"].includes(fnName)) {
    const base = authorize(context, { permission: RPC_POLICY[fnName].permission });
    if (!base.allowed) return base;
    const requested = String(params.p_username || "");
    if (requested && requested !== String(context.username || context.userId || "") && normalizeRole(context.role) !== "Administrator") return { allowed: false, status: 403, reason: "settings_scope_violation" };
    return base;
  }
  if (ADMINISTRATOR_ONLY_RPCS.has(fnName)) {
    const base = authorize(context, { permission: "admin:write" });
    if (!base.allowed) return base;
    return normalizeRole(context.role) === "Administrator" ? base : { allowed: false, status: 403, reason: "administrator_required" };
  }
  if (SUPPORT_MANAGEMENT_TABLES.has(table)) return { allowed: false, status: 403, reason: "use_protected_support_endpoint" };
  if (DEVELOPER_TABLES.has(table)) return authorize(context, { permission: "developer:write" });
  if (AUTHORIZATION_TABLES.has(table)) {
    const base = authorize(context, { permission: "admin:write" });
    if (table === "users" && base.allowed && normalizeRole(context.role) !== "Administrator") return { allowed: false, status: 403, reason: "administrator_required" };
    return base;
  }
  if (fnName === "rpc_table_clear") return authorize(context, { permission: "admin:write" });
  if (params.p_data && typeof params.p_data === "object" && ("role" in params.p_data || "permissions" in params.p_data || "tenantId" in params.p_data || "branchId" in params.p_data || (table === "users" && ("username" in params.p_data || "fullName" in params.p_data)))) {
    return authorize(context, { permission: "admin:write" });
  }
  if (!RPC_POLICY[fnName]) return { allowed: false, status: 403, reason: "rpc_not_allowed" };
  return authorize(context, { permission: RPC_POLICY[fnName].permission });
}

export function auditEvent({ request, context, action, target, decision, metadata = {} }) {
  return {
    id: crypto.randomUUID(),
    userId: context?.userId ?? context?.username ?? null,
    role: context?.role ?? null,
    timestamp: new Date().toISOString(),
    action,
    target: target ?? null,
    success: decision?.allowed === true,
    authorizationDecision: decision?.reason ?? "unknown",
    request: { method: request?.method, path: request?.url, ip: request?.socket?.remoteAddress ?? null },
    metadata,
  };
}

export function safeAuditEvent(event) {
  const serialized = JSON.stringify(event);
  return serialized.replace(/(password|secret|token|api[_-]?key|service[_-]?role)[^,}]*([,}])/gi, "$1:[redacted]$2");
}
