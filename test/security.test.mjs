import test from "node:test";
import assert from "node:assert/strict";
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

test("redacts sensitive audit metadata", () => {
  const value = safeAuditEvent({ metadata: { token: "secret-value", apiKey: "private-value" }, action: "test" });
  assert.equal(value.includes("secret-value"), false);
  assert.equal(value.includes("private-value"), false);
});
