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
export const ADMINISTRATOR_ONLY_RPCS = new Set(["rpc_generate_username", "rpc_hash_staff_password", "rpc_generate_staff_account_number", "rpc_backfill_staff_account_numbers", "rpc_migrate_privileged_defaults", "rpc_help_content_save", "rpc_help_content_delete", "rpc_support_report_list"]);
export const SUPPORT_MANAGEMENT_TABLES = new Set(["helpContent", "supportReports"]);
export const EOD_SCOPED_TABLES = new Set(["eodReconciliations", "cashHandovers", "channelReconciliations", "journalVouchers", "eodDayClosures", "systemEodRuns", "tellerTillClosings", "loanInterestAccruals", "savingsInterestAccruals", "savingsInterestPostings", "dailyReports"]);
export const EOD_FINAL_APPROVAL_TABLES = new Set(["eodDayClosures", "systemEodRuns"]);

export const RPC_POLICY = Object.freeze({
  rpc_verify_login: { public: true },
  rpc_record_login_attempt: { public: true },
  rpc_create_session: { public: true },
  rpc_generate_username: { permission: "admin:write" },
  rpc_hash_staff_password: { permission: "admin:write" },
  rpc_generate_staff_account_number: { permission: "admin:write" },
  rpc_backfill_staff_account_numbers: { permission: "admin:write" },
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
  return allowed.every((key) => {
    if (key === "branchId") {
      if (requestedScope[key] == null) return true;
      const raw = context.authorizedBranchIds || context.branchIds || context.authorizedBranches;
      const ids = Array.isArray(raw) ? raw.map((value) => typeof value === "object" ? value.id : value).filter(Boolean).map(String) : [];
      if (context.branchId != null) ids.push(String(context.branchId));
      return ids.length ? ids.includes(String(requestedScope[key])) : false;
    }
    if (requestedScope[key] == null || context[key] == null) return true;
    return String(requestedScope[key]) === String(context[key]);
  });
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
  const role = normalizeRole(context?.role);
  const data = params?.p_data && typeof params.p_data === "object" ? params.p_data : {};
  const auditTables = new Set(["activityLog", "credentialAuditLog", "security_audit_log"]);
  if (fnName === "rpc_table_delete" && auditTables.has(table)) return { allowed: false, status: 403, reason: "immutable_audit_record" };
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
  if (EOD_SCOPED_TABLES.has(table)) {
    if (fnName === "rpc_table_delete" && role !== "Administrator") return { allowed: false, status: 403, reason: "eod_delete_forbidden" };
    if (["Teller", "Cashier", "Susu Collector", "Field Officer", "Loan Officer"].includes(role)) {
      const identity = String(data.username || data.tellerId || data.collectorId || "");
      if (identity && identity !== String(context?.username || "")) return { allowed: false, status: 403, reason: "eod_identity_forbidden" };
      const protectedFields = ["approvedAt","approvedBy","approvedByUserId","ceoApprovedAt","ceoApprovedBy","ceoDecisionAt","ceoDecisionBy","closedAt","cashReceivedBy","cashHandoverAt"];
      if (protectedFields.some((field) => data[field] != null && data[field] !== "")) return { allowed: false, status: 403, reason: "eod_approval_fields_forbidden" };
      if (String(data.submissionStatus || "").toUpperCase() === "CLOSED" || String(data.workflowStage || "") === "ceo_approved") return { allowed: false, status: 403, reason: "eod_close_forbidden" };
    }
    const finalTillStage = String(params?.p_data?.workflowStage || "");
    if (EOD_FINAL_APPROVAL_TABLES.has(table) || (table === "tellerTillClosings" && ["ceo_approved", "ceo_rejected"].includes(finalTillStage)) || (table === "eodReconciliations" && ["CLOSED", "REJECTED BY ADMINISTRATOR/CEO", "RETURNED FOR CORRECTION"].includes(String(params?.p_data?.submissionStatus || "")))) {
      if (normalizeRole(context?.role) !== "Administrator") return { allowed: false, status: 403, reason: "administrator_required" };
      const record = params?.p_data && typeof params.p_data === "object" ? params.p_data : {};
      const approvingStaff = String(record.username || record.staffId || "");
      const finalApproval = (table === "tellerTillClosings" && finalTillStage === "ceo_approved") || (table === "eodReconciliations" && String(record.submissionStatus || "") === "CLOSED");
      const explicitHigherLevelPolicy = context?.selfApprovalAllowed === true && context?.selfApprovalPolicy === "higher_level";
      if (finalApproval && approvingStaff && String(context?.username || context?.userId || "") === approvingStaff && !explicitHigherLevelPolicy) return { allowed: false, status: 403, reason: "self_approval_forbidden" };
    }
    const branchId = params?.p_data?.branchId;
    return authorize(context, { permission: "data:write", scope: branchId ? { branchId } : undefined });
  }
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
