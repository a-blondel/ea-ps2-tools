// DNAS 2.x IOP-module bypass (Sony engine, e.g. Burnout 3). Two parts:
//   1. a synthetic unit test of findDnasModulePatch (always runs);
//   2. a byte-for-byte cross-check against the real DNAS_PATCHER21 output, using
//      the original + patched Burnout 3 ISOs (env-gated, skipped if unset).
import { openSync, readSync, fstatSync, closeSync } from "node:fs";
import assert from "node:assert";
import { findDnasModulePatch, scanForDnasModule, scanIsoFilesForDnasModule } from "../.tmp/dnasimg.js";
import { Iso } from "../.tmp/iso9660.js";

function u32le(v) {
  return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
}
function writeU32(buf, off, v) {
  buf.set(u32le(v), off);
}

// The six word rewrites, mirrored from src/dnasimg.ts, keyed by anchor-relative
// offset. This is what we expect the detector to emit.
const EXPECT = [
  { rel: 0x00, orig: 0x8c43147c, value: 0xac80147c },
  { rel: 0x08, orig: 0x1060000e, value: 0x10600000 },
  { rel: 0x1c, orig: 0x00000000, value: 0xace00004 },
  { rel: 0x44, orig: 0x03e00008, value: 0x34030005 },
  { rel: 0x48, orig: 0x00000000, value: 0x03e00008 },
  { rel: 0x4c, orig: 0x00000000, value: 0xacc30000 },
];

// --- 1. synthetic unit test ---------------------------------------------------
{
  const AT = 0x120; // arbitrary anchor placement inside a padded buffer
  const buf = new Uint8Array(0x200);
  // anchor words: lw v1,0x147C(v0) ; li v0,-8 ; beqz v1,+0xE
  writeU32(buf, AT + 0x00, 0x8c43147c);
  writeU32(buf, AT + 0x04, 0x2402fff8);
  writeU32(buf, AT + 0x08, 0x1060000e);
  // the guarded orig words the rest of PATCH checks (0x00/0x08 already set)
  for (const p of EXPECT) writeU32(buf, AT + p.rel, p.orig);
  // re-assert the anchor middle word (li v0,-8) which EXPECT doesn't cover
  writeU32(buf, AT + 0x04, 0x2402fff8);

  const hit = findDnasModulePatch(buf);
  assert.ok(hit, "detector finds the planted signature");
  assert.equal(hit.anchorOff, AT, "anchor offset");
  assert.equal(hit.writes.length, EXPECT.length, "six writes");
  for (let i = 0; i < EXPECT.length; i++) {
    assert.equal(hit.writes[i].off, AT + EXPECT[i].rel, `write ${i} offset`);
    assert.equal(hit.writes[i].orig >>> 0, EXPECT[i].orig >>> 0, `write ${i} orig`);
    assert.equal(hit.writes[i].value >>> 0, EXPECT[i].value >>> 0, `write ${i} value`);
  }

  // anti-brick: a build whose tail word differs must be refused, not patched.
  const bad = buf.slice();
  writeU32(bad, AT + 0x44, 0x00000000); // not the expected jr ra
  assert.equal(findDnasModulePatch(bad), null, "mismatched window is refused");

  // absence -> null
  assert.equal(findDnasModulePatch(new Uint8Array(0x100)), null, "no signature -> null");

  // chunked scan with an anchor whose window straddles chunk boundaries: the
  // anchor at 0x0c with a tiny 8-byte chunk means the match spans several chunks.
  const spanBuf = new Uint8Array(0x40 + 0x60);
  for (const p of EXPECT) writeU32(spanBuf, 0x0c + p.rel, p.orig);
  writeU32(spanBuf, 0x0c + 0x04, 0x2402fff8);
  const readSpan = async (off, len) => spanBuf.subarray(off, off + len);
  const scan = await scanForDnasModule(readSpan, spanBuf.length, undefined, 8);
  assert.ok(scan, "chunked scan finds boundary-straddling match");
  assert.equal(scan.anchorOff, 0x0c, "chunked scan absolute anchor offset");
  assert.equal(scan.writes[0].off, 0x0c, "chunked scan absolute write offset");
  assert.equal(scan.writes[5].value >>> 0, 0xacc30000, "chunked scan last write value");

  // file-aware scan: a big "movie" file (no ELF, no signature) must be skipped;
  // a small file carrying an embedded ELF + the signature must be found, with an
  // absolute offset = its lba*2048 + local offset.
  const SECTOR = 2048;
  const movie = { name: "INTRO.PSS", lba: 10, size: 0x8000 }; // no ELF magic, ignored
  const mod = { name: "NET.BIN", lba: 100, size: 0x100 }; // ELF magic + signature
  const modBuf = new Uint8Array(mod.size);
  modBuf.set([0x7f, 0x45, 0x4c, 0x46], 0x10); // ELF magic within triage window
  for (const p of EXPECT) writeU32(modBuf, 0x40 + p.rel, p.orig);
  writeU32(modBuf, 0x40 + 0x04, 0x2402fff8);
  const fileRead = async (off, len) => {
    if (off >= mod.lba * SECTOR && off < mod.lba * SECTOR + mod.size)
      return modBuf.subarray(off - mod.lba * SECTOR, off - mod.lba * SECTOR + len);
    return new Uint8Array(len); // movie / anything else: zeros (no ELF, no anchor)
  };
  const fscan = await scanIsoFilesForDnasModule(fileRead, [movie, mod]);
  assert.ok(fscan, "file-aware scan finds the module file");
  assert.equal(fscan.anchorOff, mod.lba * SECTOR + 0x40, "file-aware absolute anchor offset");
  assert.equal(fscan.writes[3].value >>> 0, 0x34030005, "file-aware forced li v1,5 write");

  // fallback: a container with no *.IMG name and no ELF magic near start (like
  // Revenge's TERF ONLINE.DAT) is invisible to triage — the full-scan fallback
  // (given a size) must still find it.
  const HIDDEN_AT = 30 * SECTOR; // absolute offset with no owning "candidate"
  const image = new Uint8Array(40 * SECTOR);
  for (const p of EXPECT) writeU32(image, HIDDEN_AT + p.rel, p.orig);
  writeU32(image, HIDDEN_AT + 0x04, 0x2402fff8);
  const imgRead = async (off, len) => image.subarray(off, off + len);
  const noCand = [{ name: "MOVIE.PSS", lba: 0, size: 20 * SECTOR }]; // no ELF, not *.IMG
  assert.equal(await scanIsoFilesForDnasModule(imgRead, noCand), null, "triage alone misses it");
  const fb = await scanIsoFilesForDnasModule(imgRead, noCand, undefined, image.length);
  assert.ok(fb, "full-scan fallback finds the hidden container");
  assert.equal(fb.anchorOff, HIDDEN_AT, "fallback absolute anchor offset");

  console.log("dnasimg unit: PASSED ✓");
}

// --- 2. real-ISO byte-for-byte cross-check (env-gated) ------------------------
const ORIG = process.env.TEST_BURNOUT_ISO;
const PATCHED = process.env.TEST_BURNOUT_ISO_PATCHED;
if (!ORIG) {
  console.log("SKIP real-ISO check: set TEST_BURNOUT_ISO (see .env.example).");
  process.exit(0);
}

function readWordAt(fd, off) {
  const b = Buffer.allocUnsafe(4);
  readSync(fd, b, 0, 4, off);
  return b.readUInt32LE(0);
}

const ofd = openSync(ORIG, "r");
const osize = fstatSync(ofd).size;
const read = async (offset, len) => {
  const b = Buffer.allocUnsafe(Math.min(len, osize - offset));
  readSync(ofd, b, 0, b.length, offset);
  return new Uint8Array(b.buffer, b.byteOffset, b.length);
};

// Walk the disc, then use the fast file-aware scan (the browser's path): it must
// find the same module without reading the whole 2.87 GB image.
class FakeBlob {
  constructor(s, e) { this.start = s; this.end = Math.min(e, osize); }
  async arrayBuffer() {
    const len = this.end - this.start;
    const b = Buffer.allocUnsafe(len);
    readSync(ofd, b, 0, len, this.start);
    return b.buffer.slice(b.byteOffset, b.byteOffset + len);
  }
}
const files = await new Iso({ slice: (s, e) => new FakeBlob(s, e) }).listFiles();
const mod = await scanIsoFilesForDnasModule(read, files);
assert.ok(mod, "DNAS module found in the original Burnout 3 ISO (file-aware scan)");
console.log(`anchor @ 0x${mod.anchorOff.toString(16)}, ${mod.writes.length} writes`);
assert.equal(mod.anchorOff, 0x11b1cf8, "anchor at the known Burnout 3 offset");
assert.equal(mod.writes.length, 6, "six writes");

// The whole-image chunked scan must agree with the file-aware one.
const whole = await scanForDnasModule(read, osize);
assert.ok(whole && whole.anchorOff === mod.anchorOff, "whole-image scan agrees with file-aware");

// Every target word in the ORIGINAL must equal the detector's `orig`.
for (const w of mod.writes) {
  assert.equal(readWordAt(ofd, w.off) >>> 0, w.orig >>> 0,
    `orig word @ 0x${w.off.toString(16)}`);
}
closeSync(ofd);

// Generalisation: Burnout Revenge (SLUS-21242, DNAS300 + DNAS280, EA_DASH). Same
// 2.x accessor, but hidden in a "TERF"-format /STREET/DATA/ONLINE.DAT with no
// *.IMG name and no ELF magic near its start — only the full-scan fallback sees
// it. Proves the detector isn't Burnout-3-specific.
const REVENGE = process.env.TEST_REVENGE_ISO;
if (REVENGE) {
  const rfd = openSync(REVENGE, "r");
  const rsize = fstatSync(rfd).size;
  const rread = async (offset, len) => {
    const b = Buffer.allocUnsafe(Math.min(len, rsize - offset));
    readSync(rfd, b, 0, b.length, offset);
    return new Uint8Array(b.buffer, b.byteOffset, b.length);
  };
  class RB {
    constructor(s, e) { this.start = s; this.end = Math.min(e, rsize); }
    async arrayBuffer() {
      const len = this.end - this.start;
      const b = Buffer.allocUnsafe(len);
      readSync(rfd, b, 0, len, this.start);
      return b.buffer.slice(b.byteOffset, b.byteOffset + len);
    }
  }
  const rfiles = await new Iso({ slice: (s, e) => new RB(s, e) }).listFiles();
  const rmod = await scanIsoFilesForDnasModule(rread, rfiles, undefined, rsize);
  assert.ok(rmod, "DNAS accessor found in Burnout Revenge (via full-scan fallback)");
  assert.equal(rmod.anchorOff, 0x49388cf8, "Revenge anchor at the known offset");
  assert.equal(rmod.writes.length, 6, "Revenge: six writes");
  for (const w of rmod.writes) {
    assert.equal(readWordAt(rfd, w.off) >>> 0, w.orig >>> 0, `Revenge orig word @ 0x${w.off.toString(16)}`);
  }
  closeSync(rfd);
  console.log("Burnout Revenge (DNAS300) generalisation ✓");
}

if (PATCHED) {
  const pfd = openSync(PATCHED, "r");
  // Every target word in the PATCHED ISO must equal the detector's `value`:
  // proves our output is byte-identical to the real DNAS_PATCHER21 patch.
  for (const w of mod.writes) {
    assert.equal(readWordAt(pfd, w.off) >>> 0, w.value >>> 0,
      `patched word @ 0x${w.off.toString(16)}`);
  }
  closeSync(pfd);
  console.log("byte-for-byte match vs real DNAS_PATCHER21 patched ISO ✓");
} else {
  console.log("(set TEST_BURNOUT_ISO_PATCHED to also verify against the patched ISO)");
}
console.log("dnasimg real-ISO: PASSED ✓");
