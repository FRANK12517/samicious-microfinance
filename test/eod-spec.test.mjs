import assert from "node:assert/strict";
import test from "node:test";
import { authorizeRpc } from "../server/authz.mjs";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const server = fs.readFileSync(new URL("../server/index.mjs", import.meta.url), "utf8");

const administrator = { username: "adugyamfi", role: "Administrator", branchId: "HO-001", active: true };
const manager = { username: "manager", role: "Branch Manager", branchId: "BR-001", active: true };
const teller = { username: "teller", role: "Teller", branchId: "BR-001", active: true };
const collector = { username: "collector", role: "Susu Collector", branchId: "BR-001", active: true };

function decision(context, table, data) {
  return authorizeRpc(context, "rpc_table_upsert", { p_table: table, p_data: data });
}

test("Teller and Susu Collector can submit branch-scoped EOD records", () => {
  assert.equal(decision(teller, "eodReconciliations", { id: "r1", branchId: "BR-001" }).allowed, true);
  assert.equal(decision(collector, "eodReconciliations", { id: "r2", branchId: "BR-001" }).allowed, true);
});

test("operational EOD writes cannot cross branch scope", () => {
  assert.equal(decision(manager, "cashHandovers", { id: "h1", branchId: "BR-002" }).allowed, false);
});

test("only Administrator can finalize a business day or System EOD run", () => {
  assert.equal(decision(manager, "eodDayClosures", { id: "c1", branchId: "BR-001" }).reason, "administrator_required");
  assert.equal(decision(manager, "systemEodRuns", { id: "r1", branchId: "BR-001", status: "completed" }).reason, "administrator_required");
  assert.equal(decision(administrator, "eodDayClosures", { id: "c2", branchId: "BR-001" }).allowed, true);
  assert.equal(decision(administrator, "systemEodRuns", { id: "r2", branchId: "BR-001", status: "completed" }).allowed, true);
});

test("Teller EOD final decisions are Administrator-only while submission remains branch-scoped", () => {
  assert.equal(decision(teller, "tellerTillClosings", { id: "t1", branchId: "BR-001", workflowStage: "teller_confirmed" }).allowed, true);
  assert.equal(decision(manager, "tellerTillClosings", { id: "t1", branchId: "BR-001", workflowStage: "branch_manager_reviewed" }).allowed, true);
  assert.equal(decision(manager, "tellerTillClosings", { id: "t1", branchId: "BR-001", workflowStage: "ceo_approved" }).reason, "administrator_required");
  assert.equal(decision(administrator, "tellerTillClosings", { id: "t1", branchId: "BR-001", workflowStage: "ceo_approved" }).allowed, true);
});

test("Teller EOD source includes complete Ghana denominations and backend lock checks", () => {
  for (const value of ["d200","d100","d50","d20","d10","d5","d2","d1","c50","c20","c10","c5","c1"]) assert.match(source, new RegExp(value));
  assert.match(source, /SUBMITTED — PENDING CEO APPROVAL/);
  assert.match(source, /varianceCategory/);
  assert.match(source, /approveTellerTillClosingAsCeo/);
  assert.match(source, /rejectTellerTillEod/);
  assert.match(server, /teller_eod_submitted_transaction_locked/);
  assert.match(server, /teller_eod_closed_immutable/);
});
