// End-to-end test of the ISO 9660 walker against the real FIFA 07 US image.
// Wraps the file in a minimal File-like (slice -> arrayBuffer) so the browser
// Iso class runs unchanged under node.
import { openSync, readSync, fstatSync, closeSync } from "node:fs";
import assert from "node:assert";
import { Iso } from "../.tmp/iso9660.js";
import { parseSerial, analyzeGame } from "../.tmp/analyze.js";
import { buildCht } from "../.tmp/cheats.js";

const ISO = process.env.TEST_PS2_ISO;
if (!ISO) {
  console.log("SKIP: set TEST_PS2_ISO to a FIFA 07 US .iso path (see .env.example).");
  process.exit(0);
}
const fd = openSync(ISO, "r");
const size = fstatSync(fd).size;

class FakeBlob {
  constructor(start, end) { this.start = start; this.end = Math.min(end, size); }
  async arrayBuffer() {
    const len = this.end - this.start;
    const buf = Buffer.allocUnsafe(len);
    readSync(fd, buf, 0, len, this.start);
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + len);
  }
}
const fakeFile = { slice: (s, e) => new FakeBlob(s, e) };

const iso = new Iso(fakeFile);
const files = await iso.listFiles();
console.log(`Found ${files.length} files. Sample:`);
for (const f of files.filter((x) => /\.ELF$|^SLUS|^SLES|^SLPS/i.test(x.name)).slice(0, 10))
  console.log(`  ${f.path}  lba=${f.lba} size=${f.size}`);

const cnf = files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF");
assert.ok(cnf, "SYSTEM.CNF present");
const cnfText = new TextDecoder().decode(await iso.readFileData(cnf));
const serial = parseSerial(cnfText);
console.log("serial:", serial);
assert.equal(serial, "SLUS_214.33");

const wanted = files.filter(
  (f) => f.name.toUpperCase() === serial.toUpperCase() || f.name.toUpperCase() === "EA_DASH.ELF",
);
const blobs = [];
for (const f of wanted) blobs.push({ name: f.name, path: f.path, data: new Uint8Array(await iso.readFileData(f)) });

const game = analyzeGame(serial, blobs);
const cht = buildCht(serial, "FIFA07", game.targets);
console.log("\n" + cht);
assert.ok(cht.includes("90370428 0C0DC0B2"), "main hook from ISO");
assert.ok(cht.includes("9023D698 0C08F54E"), "dash hook from ISO");
assert.ok(cht.includes("205C8028 00000000"), "main BNE from ISO");
assert.ok(cht.includes("201E16CC 00000000"), "dash BNE from ISO");
assert.ok(cht.includes("205D10C0 24E70000"), "main SSL port from ISO");
assert.ok(cht.includes("201E4088 24E70000"), "dash SSL port from ISO");
assert.equal(game.port, 10400, "game port from ISO");

closeSync(fd);
console.log("ISO END-TO-END PASSED ✓");
