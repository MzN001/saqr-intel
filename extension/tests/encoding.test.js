// Chrome refuses to load an extension file that contains Unicode "noncharacters"
// (U+FFFE, U+FFFF, U+FDD0-U+FDEF): it reports "It isn't UTF-8 encoded".
// Write them as escapes (\\uffff) instead of literal characters.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const BAD = /[\uFDD0-\uFDEF\uFFFE\uFFFF]|[\u{1FFFE}\u{1FFFF}]/u;

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(js|cjs|css|html|json)$/.test(e.name)) out.push(p);
  }
  return out;
}

test("every extension file is valid UTF-8 without noncharacters", () => {
  for (const f of walk(ROOT)) {
    const buf = fs.readFileSync(f);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
    assert.ok(!BAD.test(text), path.relative(ROOT, f) + " contains a Unicode noncharacter");
  }
});
