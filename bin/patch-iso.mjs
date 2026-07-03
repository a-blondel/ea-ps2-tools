#!/usr/bin/env node
// CLI patcher — the bulletproof path the browser can't match for multi-GB ISOs.
// Copies the disc (or patches it in place) and seek-writes the few patch bytes
// straight at their offsets: no .crswap, no antivirus commit race, no 2 GB blob
// cap, no save dialog. Reuses the exact same analysis + offset engine the web UI
// uses (compiled into .tmp via `npm run build:test`).
//
//   npm run patch -- <iso> [options]
//     --out <path>     write the patched copy here (default: <iso>-patched.iso)
//     --in-place       patch the ISO itself, no copy (instant; back it up first)
//     --port <n>       also override the game port
//     --domain <host>  also override the EA hostname
//     --no-dnas        skip the DNAS bypass (on by default)
//     --ssl            also apply the SSL bypass (off by default)
//     --cht            also write the OPL .cht next to the output
//     --pnach          also write the PCSX2 .pnach file(s) next to the output
//     --no-iso         don't build a patched ISO (use with --cht/--pnach)
//     -h, --help

import { openSync, readSync, fstatSync, closeSync, copyFileSync, writeSync, writeFileSync } from "node:fs";
import { basename, dirname, join, extname } from "node:path";
import { Iso } from "../.tmp/iso9660.js";
import { Elf } from "../.tmp/elf.js";
import { parseSerial, analyzeGame } from "../.tmp/analyze.js";
import { targetWrites, buildCht, buildPnach, chtFilename } from "../.tmp/cheats.js";
import { buildIsoWrites, encodeLE } from "../.tmp/isopatch.js";
import { scanIsoFilesForDnasModule } from "../.tmp/dnasimg.js";

function parseArgs(argv) {
  const o = { iso: null, out: null, inPlace: false, port: null, domain: null, dnas: true, ssl: false, cht: false, pnach: false, iso_out: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "--in-place") o.inPlace = true;
    else if (a === "--no-dnas") o.dnas = false;
    else if (a === "--ssl") o.ssl = true;
    else if (a === "--no-ssl") o.ssl = false;
    else if (a === "--cht") o.cht = true;
    else if (a === "--pnach") o.pnach = true;
    else if (a === "--no-iso") o.iso_out = false;
    else if (a === "--out") o.out = argv[++i];
    else if (a === "--port") o.port = parseInt(argv[++i], 10);
    else if (a === "--domain") o.domain = argv[++i];
    else if (!a.startsWith("-") && !o.iso) o.iso = a;
    else throw new Error(`Unknown or misplaced argument: ${a}`);
  }
  return o;
}

const HELP = `Usage: npm run patch -- <iso> [--out <path>] [--in-place]
                           [--port <n>] [--domain <host>] [--no-dnas] [--ssl]
                           [--cht] [--pnach] [--no-iso]`;

const opts = parseArgs(process.argv.slice(2));
if (opts.help || !opts.iso) {
  console.log(HELP);
  process.exit(opts.iso ? 0 : 1);
}

const fd = openSync(opts.iso, "r");
const size = fstatSync(fd).size;

// Minimal File-like so the browser Iso walker runs unchanged under node.
class FakeBlob {
  constructor(start, end) {
    this.start = start;
    this.end = Math.min(end, size);
  }
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

const cnf = files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF");
if (!cnf) throw new Error("SYSTEM.CNF not found — is this a PS2 ISO?");
const serial = parseSerial(new TextDecoder().decode(await iso.readFileData(cnf)));
if (!serial) throw new Error("Could not read BOOT2 serial from SYSTEM.CNF.");

const wanted = files.filter(
  (f) => f.name.toUpperCase() === serial.toUpperCase() || f.name.toUpperCase() === "EA_DASH.ELF",
);
const blobs = [];
const lbaByName = {};
for (const f of wanted) {
  blobs.push({ name: f.name, path: f.path, data: await iso.readFileData(f) });
  lbaByName[f.name.toUpperCase()] = f.lba;
}

const game = analyzeGame(serial, blobs);
console.log(`${serial} — ${game.title}`);

// Apply the CLI's feature selection to the analysed targets.
const port = Number.isFinite(opts.port) ? opts.port : null;
const domain = opts.domain ?? null;
const patchTargets = [];
for (const t of game.targets) {
  t.enable.dnas = opts.dnas && !!t.dnas.bne;
  t.enable.ssl = opts.ssl && !!t.ssl.port;
  t.enable.port = port != null && !!t.port;
  t.enable.domain = domain != null && !!t.domain;
  const elfName = t.label === "EA Dashboard" ? "EA_DASH.ELF" : serial.toUpperCase();
  const blob = blobs.find((b) => b.name.toUpperCase() === elfName);
  const lba = lbaByName[elfName];
  if (!blob || lba === undefined) continue;
  patchTargets.push({ elf: new Elf(blob.data), lba, writes: targetWrites(t, port, domain) });
}

// Optional cheat outputs — the same OPL .cht / PCSX2 .pnach the browser produces,
// written next to the output. (These carry only in-ELF writes; a Sony DNAS module
// patch is ISO-only and can't be a cheat.)
const outDir = dirname(opts.out ?? opts.iso);
if (opts.cht) {
  const name = chtFilename(serial);
  writeFileSync(join(outDir, name), buildCht(serial, game.title, game.targets, port, domain));
  console.log(`Wrote ${name}`);
}
if (opts.pnach) {
  for (const f of buildPnach(serial, game.targets, port, domain)) {
    writeFileSync(join(outDir, f.filename), f.content);
    console.log(`Wrote ${f.filename}`);
  }
}
if (!opts.iso_out) {
  closeSync(fd);
  process.exit(0);
}

const { writes, warnings } = buildIsoWrites(patchTargets);
for (const w of warnings) console.warn(`  warning: ${w}`);

// Fallback for stock Sony DNAS titles where NO in-ELF check was found (not
// DNASSKIP / DirtyDnas / the main-ELF sony-gate): the auth runs in a relocated
// module whose plaintext code is embedded on the disc. Scan for it and add the
// raw byte patch. Skipped when an in-ELF method already covers DNAS (preferred,
// since those are also expressible as .cht/.pnach).
if (opts.dnas && !game.targets.some((t) => t.dnas.bne)) {
  const readChunk = async (offset, len) => {
    const b = Buffer.allocUnsafe(len);
    readSync(fd, b, 0, len, offset);
    return new Uint8Array(b.buffer, b.byteOffset, len);
  };
  const mod = await scanIsoFilesForDnasModule(readChunk, files, undefined, size);
  if (mod) {
    console.log(`DNAS module: found auth accessor @ 0x${mod.anchorOff.toString(16)} in the disc image.`);
    for (const w of mod.writes) writes.push({ offset: w.off, bytes: encodeLE(w.value, 4), vaddr: 0 });
  } else if (!game.targets.some((t) => t.enable.dnas)) {
    console.warn("  warning: no in-ELF DNAS check and no embedded DNAS module signature found.");
  }
}

if (writes.length === 0) {
  console.error("No patches to apply (nothing enabled or found).");
  closeSync(fd);
  process.exit(1);
}
console.log(`Patches: ${writes.length} write(s) [DNAS:${opts.dnas} SSL:${opts.ssl}` +
  `${port != null ? ` port:${port}` : ""}${domain ? ` domain:${domain}` : ""}]`);
closeSync(fd);

// Decide the target file: the ISO itself, or a fresh copy.
let target;
if (opts.inPlace) {
  target = opts.iso;
  console.log(`Patching in place: ${target}`);
} else {
  target = opts.out ?? join(dirname(opts.iso), `${basename(opts.iso, extname(opts.iso))}-patched.iso`);
  console.log(`Copying → ${target} …`);
  copyFileSync(opts.iso, target);
}

// Seek + write each patch word at its absolute offset. Instant — only a few bytes.
const out = openSync(target, "r+");
try {
  for (const w of writes) {
    writeSync(out, Buffer.from(w.bytes), 0, w.bytes.length, w.offset);
  }
} finally {
  closeSync(out);
}

console.log(`Done — wrote ${writes.length} patch location(s) into ${target}.`);
