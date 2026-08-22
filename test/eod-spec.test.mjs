import assert from "node:assert/strict";
import test from "node:test";
import { authorizeRpc } from "../server/authz.mjs";

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
