import assert from "node:assert/strict";
import test from "node:test";

process.env.VERCEL = "1";
const { default: rpc, handle } = await import("../api/rpc.js");

function responseCapture() {
  return {
    statusCode: null,
    headers: null,
    body: "",
    writeHead(status, headers) {
      this.statusCode = status;
      this.headers = headers;
    },
    end(value = "") {
      this.body += String(value);
    },
  };
}

test("Vercel /api/rpc adapter exposes the gateway health endpoint", async () => {
  const req = { method: "GET", url: "/healthz", headers: {} };
  const res = responseCapture();
  await rpc(req, res);
  assert.equal(typeof rpc, "function");
  assert.equal(typeof handle, "function");
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true });
  assert.equal(res.headers["cache-control"], "no-store");
});
