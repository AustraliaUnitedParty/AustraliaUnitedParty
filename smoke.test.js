const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const base = path.join(__dirname, "..");

test("party name is configured consistently", () => {
  const server = fs.readFileSync(path.join(base,"server.js"),"utf8");
  const html = fs.readFileSync(path.join(base,"public","index.html"),"utf8");
  assert.match(server,/Australia United Party/);
  assert.match(html,/Australia United Party/);
});
test("member statuses and AEC export cap are present", () => {
  const server = fs.readFileSync(path.join(base,"server.js"),"utf8");
  assert.match(server,/reserve/);
  assert.match(server,/selected/);
  assert.match(server,/LIMIT 1650/);
  assert.match(server,/supports_registration=1/);
  assert.match(server,/not_counted_for_other_party=1/);
});
test("no real member data or secrets are shipped", () => {
  assert.equal(fs.existsSync(path.join(base,".env")),false);
  assert.equal(fs.existsSync(path.join(base,"data")),false);
});
