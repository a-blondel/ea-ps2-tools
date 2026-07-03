// Sony DNAS main-ELF poll gate — the version-independent detector, checked
// against BOTH validated samples (live-traced in PCSX2, online-confirmed):
//   Burnout 3 (DNAS 2.8): bltz gate + sltu->move busy-skip
//   Burnout Revenge (DNAS 3.0): bgez gate (-> unconditional b) + bnez->nop busy-skip
// Env-gated per ISO (TEST_BURNOUT_ISO / TEST_REVENGE_ISO).
import { openSync, readSync, fstatSync, closeSync } from "node:fs";
import assert from "node:assert";
import { Iso } from "../.tmp/iso9660.js";
import { Elf } from "../.tmp/elf.js";
import { parseSerial } from "../.tmp/analyze.js";
import { analyzeDnas } from "../.tmp/dnas.js";
import { targetWrites } from "../.tmp/cheats.js";

async function mainElf(ISO) {
  const fd = openSync(ISO, "r");
  const size = fstatSync(fd).size;
  class FakeBlob {
    constructor(s, e) { this.start = s; this.end = Math.min(e, size); }
    async arrayBuffer() {
      const b = Buffer.allocUnsafe(this.end - this.start);
      readSync(fd, b, 0, b.length, this.start);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
    }
  }
  const iso = new Iso({ slice: (s, e) => new FakeBlob(s, e) });
  const files = await iso.listFiles();
  const serial = parseSerial(new TextDecoder().decode(await iso.readFileData(files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF"))));
  const ef = files.find((f) => f.name.toUpperCase() === serial.toUpperCase());
  const elf = new Elf(new Uint8Array(await iso.readFileData(ef)));
  closeSync(fd);
  return { serial, elf };
}

// Each case: the values verified live in PCSX2.
const CASES = [
  {
    env: "TEST_BURNOUT_ISO", serial: "SLUS_210.50",
    gate: 0x0026bf20, gateOrig: 0x04400007, gateValue: 0x00000000, // bltz -> NOP
    busy: { addr: 0x0026bef8, value: 0x0000102d }, // sltu v0,zero,v0 -> move v0,zero
  },
  {
    env: "TEST_REVENGE_ISO", serial: "SLUS_212.42",
    gate: 0x001c5030, gateOrig: 0x0441003e, gateValue: 0x1000003e, // bgez -> b succ
    busy: { addr: 0x001c5014, value: 0x00000000 }, // bnez v0 -> NOP
  },
];

let ran = 0;
for (const c of CASES) {
  const ISO = process.env[c.env];
  if (!ISO) { console.log(`SKIP ${c.serial}: set ${c.env}.`); continue; }
  const { serial, elf } = await mainElf(ISO);
  assert.equal(serial, c.serial, `${c.env} serial`);
  const dnas = analyzeDnas(elf);
  assert.equal(dnas.method, "sonygate", `${serial}: detected via the Sony gate`);
  assert.equal(dnas.bne.vaddr >>> 0, c.gate, `${serial}: gate vaddr`);
  assert.equal(dnas.bne.original >>> 0, c.gateOrig, `${serial}: gate original word`);
  assert.equal((dnas.gateValue ?? 0) >>> 0, c.gateValue, `${serial}: gate replacement`);
  assert.deepEqual(dnas.extraWrites, [c.busy], `${serial}: busy-skip write`);

  const t = {
    label: "Main Game", dnas, ssl: { port: null, secure: null }, port: null, domain: null,
    enable: { dnas: true, ssl: false, port: false, domain: false },
  };
  const ws = targetWrites(t);
  assert.ok(ws.some((w) => (w.addr >>> 0) === c.gate && (w.value >>> 0) === c.gateValue), `${serial}: gate write in list`);
  assert.ok(ws.some((w) => (w.addr >>> 0) === c.busy.addr && (w.value >>> 0) === c.busy.value), `${serial}: busy write in list`);
  console.log(`gate ${serial}: PASSED ✓  ${dnas.bne.original.toString(16)}@0x${c.gate.toString(16)} -> ${c.gateValue.toString(16).padStart(8, "0")}  busy@0x${c.busy.addr.toString(16)}`);
  ran++;
}
if (ran === 0) console.log("SKIP gate test: no TEST_BURNOUT_ISO / TEST_REVENGE_ISO set.");
