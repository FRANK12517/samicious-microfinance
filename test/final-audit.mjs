import assert from "node:assert/strict";
import fs from "node:fs";
import { authorizeRpc, ROLE_PERMISSIONS } from "../server/authz.mjs";

const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const roles = Object.keys(ROLE_PERMISSIONS);
const user = role => ({ userId: role.toLowerCase().replace(/[^a-z0-9]+/g, "-"), username: role.toLowerCase().replace(/[^a-z0-9]+/g, "-"), role, active: true, usernameRevoked: false, passwordRevoked: false });

assert.ok(roles.length >= 10);
for (const role of roles) {
  const context = user(role);
  const settings = authorizeRpc(context, "rpc_settings_capabilities", { p_username: context.username, p_role: "Administrator" });
  assert.equal(settings.allowed, true, `${role} should access own Settings capabilities`);
  const ownRead = authorizeRpc(context, "rpc_settings_read", { p_username: context.username });
  assert.equal(ownRead.allowed, true, `${role} should read own Settings`);
  const foreignRead = authorizeRpc(context, "rpc_settings_read", { p_username: "another-user" });
  assert.equal(foreignRead.allowed, role === "Administrator", `${role} foreign Settings scope must be protected`);
  const helpSave = authorizeRpc(context, "rpc_help_content_save", { p_content: { title: "test" } });
  assert.equal(helpSave.allowed, role === "Administrator", `${role} Help content mutation must be Administrator-only`);
  const reportList = authorizeRpc(context, "rpc_support_report_list", {});
  assert.equal(reportList.allowed, role === "Administrator", `${role} support-report review must be Administrator-only`);
  const genericHelpWrite = authorizeRpc(context, "rpc_table_upsert", { p_table: "helpContent", p_data: { title: "bypass" } });
  assert.equal(genericHelpWrite.allowed, false, `${role} generic Help-content write must be blocked`);
  const genericSupportWrite = authorizeRpc(context, "rpc_table_upsert", { p_table: "supportReports", p_data: { userDescription: "bypass" } });
  assert.equal(genericSupportWrite.allowed, false, `${role} generic support-report write must be blocked`);
}

for (const forbidden of ["p_report.password", "p_content.password", "p_report.passwordHash", "p_content.passwordHash", "supportReport.apiSecret", "supportReport.accessToken", "supportReport.JWT_SECRET", "supportReport.DATABASE_PASSWORD"]) {
  assert.equal(source.includes(forbidden), false, `support/Help payload must not expose ${forbidden}`);
}
assert.equal(source.includes('id="sidebarSettingsBtn"'), true);
assert.equal(source.includes('id="logoutBtn"'), true);
assert.equal(source.indexOf('id="sidebarSettingsBtn"') < source.indexOf('id="logoutBtn"'), true);
assert.equal(source.includes('function renderSettings'), true);
assert.equal(source.includes('function renderHelpCenter'), true);
assert.equal(source.includes('function renderTroubleshootingEngine'), true);
assert.equal(source.includes('function renderSupportEscalation'), true);
console.log(`Final audit passed for ${roles.length} roles.`);
// Keep this file executable as a Node ESM test helper.
