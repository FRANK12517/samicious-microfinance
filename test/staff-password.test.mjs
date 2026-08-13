import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const start = source.indexOf("function staffPasswordPrefix");
const end = source.indexOf("async function passwordWasRecentlyUsed", start);
assert.ok(start >= 0 && end > start, "staff password helpers must exist in the application");
const context = { crypto: { getRandomValues(bytes) { for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 37 + 11) & 255; return bytes; } } };
vm.runInNewContext(source.slice(start, end), context);

for (const name of ["Enest Abban", "Ama Mensah", "Justine Doe"]) {
  test(`generated staff password meets the seven-character policy for ${name}`, () => {
    const password = context.generateStaffPassword(name);
    const prefix = context.staffPasswordPrefix(name);
    assert.equal(password.length, 7);
    assert.match(password[0], /[@#$%^&*()]/);
    assert.equal(password.slice(1, 4), prefix);
    assert.match(password.slice(4), /^\d{3}$/);
    const validation = context.staffPasswordMeetsPolicy(password, name);
    assert.equal(validation.ok, true);
    assert.equal(validation.message, "");
  });
}

test("invalid eight-character staff passwords are rejected", () => {
  assert.equal(context.staffPasswordMeetsPolicy("#Just186", "Justine Doe").ok, false);
});

test("names with fewer than three alphabetic characters are rejected", () => {
  assert.equal(context.staffPasswordMeetsPolicy("#Ab1234", "A1").ok, false);
});
