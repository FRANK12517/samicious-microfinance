import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { authorize, authorizeRpc, hasPermission, isWithinScope, safeAuditEvent } from "../server/authz.mjs";

test("denies unauthenticated privileged access", () => {
  assert.deepEqual(authorize(null, { permission: "developer:read" }), { allowed: false, status: 401, reason: "authentication_required" });
});

test("denies ordinary users developer access", () => {
  const user = { username: "staff", role: "Teller", active: true, branchId: "b1" };
  assert.equal(hasPermission(user, "developer:read"), false);
  assert.equal(authorize(user, { permission: "developer:read" }).status, 403);
});

test("denies ordinary users developer-only table access", () => {
  const user = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(user, "rpc_table_select_all", { p_table: "devSmsConfig" }).allowed, false);
  assert.equal(authorizeRpc(user, "rpc_table_upsert", { p_table: "users", p_data: { role: "Administrator" } }).allowed, false);
});

test("only administrators may migrate privileged defaults", () => {
  const admin = { username: "adugyamfi", role: "Administrator", active: true };
  const developer = { username: "frank", role: "Developer", active: true };
  const staff = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(admin, "rpc_migrate_privileged_defaults", {}).allowed, true);
  assert.equal(authorizeRpc(developer, "rpc_migrate_privileged_defaults", {}).allowed, false);
  assert.equal(authorizeRpc(staff, "rpc_migrate_privileged_defaults", {}).allowed, false);
  assert.equal(authorizeRpc(admin, "rpc_get_privileged_defaults", {}).allowed, false);
});

test("settings RPCs are authenticated and scoped to the current user", () => {
  const admin = { username: "adugyamfi", role: "Administrator", active: true };
  const staff = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(staff, "rpc_settings_capabilities", { p_username: "staff" }).allowed, true);
  assert.equal(authorizeRpc(staff, "rpc_settings_read", { p_username: "staff" }).allowed, true);
  assert.equal(authorizeRpc(staff, "rpc_settings_save", { p_username: "other" }).allowed, false);
  assert.equal(authorizeRpc(admin, "rpc_settings_save", { p_username: "staff" }).allowed, true);
  assert.equal(authorizeRpc(staff, "rpc_settings_delete", { p_username: "staff" }).allowed, false);
});

test("centralized Settings route and categories are present", () => {
  const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.equal(source.includes('id:"settings",label:"Settings"'), true);
  assert.equal(source.includes("async function renderSettings(el)"), true);
  for (const category of ["Account & Profile","Security","Password Management","Login & Session","Notifications","Appearance","Language","Accessibility","Offline & Synchronization","Privacy","Application Preferences","Help & Support","Developer Information","About Samicious Microfinance"]) assert.equal(source.includes(category), true);
  assert.equal(source.includes("rpc_settings_capabilities"), true);
  assert.equal(source.includes("rpc_settings_read"), true);
  assert.equal(source.includes("rpc_settings_save"), true);
});

test("only administrators may generate usernames", () => {
  const admin = { username: "admin", role: "Administrator", active: true };
  const staff = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(admin, "rpc_generate_username", {}).allowed, true);
  assert.equal(authorizeRpc(staff, "rpc_generate_username", {}).allowed, false);
});

test("staff identity fields require administrator authorization", () => {
  const staff = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(staff, "rpc_table_upsert", { p_table: "users", p_data: { username: "newuser", fullName: "New User" } }).allowed, false);
});

test("allows administrator developer access", () => {
  const admin = { username: "admin", role: "Administrator", active: true };
  assert.equal(authorize(admin, { permission: "developer:write" }).allowed, true);
});

test("rejects cross-branch access", () => {
  const user = { username: "staff", role: "Teller", active: true, branchId: "b1" };
  assert.equal(isWithinScope(user, { branchId: "b2" }), false);
  assert.equal(authorize(user, { permission: "data:read", scope: { branchId: "b2" } }).reason, "scope_violation");
});

test("revoked staff sessions are denied by backend authorization", () => {
  const revoked = { username: "enest", role: "Teller", active: true, usernameRevoked: true };
  const passwordRevoked = { username: "ama", role: "Teller", active: true, passwordRevoked: true };
  assert.equal(authorize(revoked, { permission: "data:read" }).allowed, false);
  assert.equal(authorize(passwordRevoked, { permission: "data:read" }).allowed, false);
});

test("only Administrator may mutate the users table", () => {
  const developer = { username: "frank", role: "Developer", active: true };
  const staff = { username: "staff", role: "Teller", active: true };
  assert.equal(authorizeRpc(developer, "rpc_table_upsert", { p_table: "users", p_data: { username: "staff" } }).allowed, false);
  assert.equal(authorizeRpc(staff, "rpc_table_upsert", { p_table: "users", p_data: { username: "staff" } }).allowed, false);
});

test("staff lifecycle controls preserve revocation and session invalidation markers", () => {
  const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.equal(source.includes("Revoke Access"), true);
  assert.equal(source.includes("Reset Password"), true);
  assert.equal(source.includes("Reactivate"), true);
  assert.equal(source.includes("sessionEpoch=(Number(target.sessionEpoch)||0)+1"), true);
  assert.equal(source.includes("usernameRevoked=true"), true);
  assert.equal(source.includes("passwordRevoked=true"), true);
});

test("credential hardening keeps hashes server-side and redacts normal user responses", () => {
  const frontend = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const server = fs.readFileSync(new URL("../server/index.mjs", import.meta.url), "utf8");
  assert.equal(frontend.includes("rpc_get_login_material"), false);
  assert.equal(frontend.includes("credentialMaterial"), true);
  assert.equal(server.includes("redactCredentialMaterial"), true);
  assert.equal(server.includes("rpc_verify_login"), true);
  assert.equal(server.includes("passwordHash"), true);
  assert.equal(server.includes("return { ok: true, username: material.username"), true);
});

test("frontend source contains no required plaintext privileged passwords", () => {
  const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.equal(source.includes("@Adu200"), false);
  assert.equal(source.includes("#Fran200"), false);
});

test("credential audit fields do not include plaintext password fields", () => {
  const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.equal(source.includes("passwordChanged"), true);
  assert.equal(source.includes("p_password"), true);
  assert.equal(/(?:^|[,{\s])password\s*:\s*(?:[A-Za-z0-9_$]|["'])/.test(source), false);
  assert.equal(source.includes("localStorage.setItem(\"passwordHash\""), false);
  assert.equal(source.includes("sessionStorage.setItem(\"passwordHash\""), false);
});

test("redacts sensitive audit metadata", () => {
  const value = safeAuditEvent({ metadata: { token: "secret-value", apiKey: "private-value" }, action: "test" });
  assert.equal(value.includes("secret-value"), false);
  assert.equal(value.includes("private-value"), false);
});
