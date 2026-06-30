// Phase 2 in-place patcher: verify the ISO byte offsets the writes resolve to.
// Validated against the real FIFA 07 US image: each computed offset must point
// at the exact original instruction (so the seek+write lands on the right word),
// and the bytes read straight from the ISO must equal the bytes in the ELF blob
// at the same file offset (proving the lba mapping). Needs TEST_PS2_ISO.
import { openSync, readSync, fstatSync, closeSync } from "node:fs";
import assert from "node:assert";
import { Iso } from "../.tmp/iso9660.js";
import { Elf } from "../.tmp/elf.js";
import { parseSerial, analyzeGame } from "../.tmp/analyze.js";
import { targetWrites } from "../.tmp/cheats.js";
import { buildIsoWrites, encodeLE } from "../.tmp/isopatch.js";

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

/** Read `len` bytes straight from the ISO at an absolute offset. */
function readIso(offset, len) {
  const buf = Buffer.allocUnsafe(len);
  readSync(fd, buf, 0, len, offset);
  return new Uint8Array(buf);
}
const u32le = (b, i = 0) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;

const iso = new Iso(fakeFile);
const files = await iso.listFiles();
const cnf = files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF");
const serial = parseSerial(new TextDecoder().decode(await iso.readFileData(cnf)));
assert.equal(serial, "SLUS_214.33");

// Pair each wanted ELF's IsoFile (carries the lba) with its extracted blob.
const wanted = files.filter(
  (f) => f.name.toUpperCase() === serial.toUpperCase() || f.name.toUpperCase() === "EA_DASH.ELF",
);
const blobs = [];
const isoFiles = {};
for (const f of wanted) {
  blobs.push({ name: f.name, path: f.path, data: new Uint8Array(await iso.readFileData(f)) });
  isoFiles[f.name.toUpperCase()] = f;
}

const game = analyzeGame(serial, blobs);

// Build the in-place patch targets: Elf + lba + the default-enabled writes
// (DNAS + SSL on, port/domain off — matching analyzeGame's defaults).
const byName = (name) => blobs.find((b) => b.name.toUpperCase() === name);
const patchTargets = game.targets.map((t, i) => {
  const blob = i === 0 ? byName(serial.toUpperCase()) : byName("EA_DASH.ELF");
  const file = isoFiles[blob.name.toUpperCase()];
  return { elf: new Elf(blob.data), lba: file.lba, writes: targetWrites(t), blob, file };
});

const { writes, warnings } = buildIsoWrites(patchTargets.map(({ elf, lba, writes }) => ({ elf, lba, writes })));
assert.equal(warnings.length, 0, `no unmapped writes: ${warnings.join("; ")}`);
console.log(`Resolved ${writes.length} in-place writes from ${patchTargets.length} ELFs.`);

// Every computed offset must (a) land on the same bytes the extracted ELF holds
// at that file offset, and (b) for the DNAS write, point at the original BNE.
for (const pt of patchTargets) {
  for (const w of targetWrites(game.targets[patchTargets.indexOf(pt)])) {
    const fo = pt.elf.vaddrToFile(w.addr);
    const width = w.width ?? 4;
    const offset = pt.file.lba * 2048 + fo;
    const fromIso = readIso(offset, width);
    const fromElf = pt.blob.data.subarray(fo, fo + width);
    assert.deepEqual([...fromIso], [...fromElf], `ISO bytes match ELF blob at ${w.addr.toString(16)}`);
  }
}

// Spot-check the main DNAS write: offset points at the original BNE word, and
// the patch bytes are the NOP (00 00 00 00).
const mainBne = game.targets[0].dnas.bne;
const mainElf = patchTargets[0].elf;
const bneFo = mainElf.vaddrToFile(mainBne.vaddr);
const bneOffset = patchTargets[0].file.lba * 2048 + bneFo;
assert.equal(u32le(readIso(bneOffset, 4)), mainBne.original >>> 0, "ISO holds the original BNE at the DNAS offset");
const dnasWrite = writes.find((w) => w.vaddr === (mainBne.vaddr >>> 0));
assert.ok(dnasWrite, "DNAS write present");
assert.equal(dnasWrite.offset, bneOffset, "DNAS write offset = lba*2048 + vaddrToFile");
assert.deepEqual([...dnasWrite.bytes], [0, 0, 0, 0], "DNAS patch is a NOP");

// Spot-check the main SSL port write: value 0x24E70000 -> little-endian bytes.
const sslPort = game.targets[0].ssl.port;
const sslWrite = writes.find((w) => w.vaddr === (sslPort.vaddr >>> 0));
assert.deepEqual([...sslWrite.bytes], [...encodeLE(sslPort.value, 4)], "SSL port bytes are little-endian");
assert.deepEqual([...sslWrite.bytes], [0x00, 0x00, 0xe7, 0x24], "SSL port LE = 00 00 E7 24");

// encodeLE unit checks.
assert.deepEqual([...encodeLE(0, 4)], [0, 0, 0, 0]);
assert.deepEqual([...encodeLE(0x12345678, 4)], [0x78, 0x56, 0x34, 0x12]);
assert.deepEqual([...encodeLE(0x3039, 2)], [0x39, 0x30]);
assert.deepEqual([...encodeLE(0x65, 1)], [0x65]);

closeSync(fd);
console.log("ISO IN-PLACE PATCH OFFSETS PASSED ✓");
