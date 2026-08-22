import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { authorizeRpc } from "../server/authz.mjs";

const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const server = fs.readFileSync(new URL("../server/index.mjs", import.meta.url), "utf8");
const authz = fs.readFileSync(new URL("../server/authz.mjs", import.meta.url), "utf8");
const migration = fs.readFileSync(new URL("../supabase/migrations/202608220001_staff_operational_account_numbers.sql", import.meta.url), "utf8");

test("staff account numbers are server-generated and read-only in the UI", () => {
  assert.match(server, /randomInt\(/);
  assert.match(server, /staffAccountNumber/);
  assert.match(server, /validateUserUpsert/);
  assert.match(source, /id="u_staff_account"[^>]+readonly/);
  assert.match(source, /Staff Account Number/);
});

test("eligible roles are covered by generation and migration", () => {
  assert.match(server, /new Set\(\["Teller", "Susu Collector"\]\)/);
  assert.match(source, /u\.staffAccountNumber/);
  assert.match(migration, /"staffAccountNumber"/);
  assert.match(migration, /create unique index/i);
});

test("only Administrator may invoke account-number generation and backfill", () => {
  const admin = { username: "adugyamfi", role: "Administrator", active: true };
  const teller = { username: "teller", role: "Teller", active: true, branchId: "BR-001" };
  assert.equal(authorizeRpc(admin, "rpc_generate_staff_account_number", {}).allowed, true);
  assert.equal(authorizeRpc(teller, "rpc_generate_staff_account_number", {}).reason, "insufficient_privilege");
  assert.equal(authorizeRpc(teller, "rpc_backfill_staff_account_numbers", {}).reason, "insufficient_privilege");
  assert.match(authz, /rpc_backfill_staff_account_numbers/);
});

test("login credentials remain represented by username and password material, not staff account number", () => {
  assert.match(server, /verifyLoginRequest/);
  assert.match(server, /p_username/);
  assert.match(source, /loginUser|loginPass/);
  assert.doesNotMatch(server, /staffAccountNumber[^\n]*(?:password|login)/i);
});
