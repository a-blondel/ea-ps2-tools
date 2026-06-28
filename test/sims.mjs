// Validation against the real Sims Bustin' Out US ELF — the older EA "DirtyDnas"
// reloc engine (no DNASSKIP string, no SSL, no dashboard). Exercises the
// fallback DNAS detector. Point TEST_SIMS_DIR at the extracted game folder
// (contains SLUS_208.42); skipped when unset.
import { readFileSync } from "node:fs";
import assert from "node:assert";
import { analyzeGame } from "../.tmp/analyze.js";
import { buildCht, buildPnach } from "../.tmp/cheats.js";

const DIR = process.env.TEST_SIMS_DIR;
if (!DIR) {
  console.log("SKIP: set TEST_SIMS_DIR to the extracted Sims Bustin' Out US folder (see .env.example).");
  process.exit(0);
}
const serial = "SLUS_208.42";
const blobs = [{ name: serial, path: `/${serial}`, data: new Uint8Array(readFileSync(`${DIR}/${serial}`)) }];

const game = analyzeGame(serial, blobs);
const t = game.targets[0];

// One ELF only — no EA_DASH on this title.
assert.equal(game.targets.length, 1, "main ELF only (no dashboard)");

// DNAS found via the DirtyDnas reloc fallback, not the DNASSKIP path.
assert.equal(t.dnas.method, "dirtydnas", "older engine -> DirtyDnas detector");
assert.equal(t.dnas.bne.vaddr >>> 0, 0x002626c0, "DNAS result gate addr");
assert.equal(t.dnas.bne.original >>> 0, 0x14600006, "gate is bne v1,zero,+0x18");
assert.equal(t.dnas.bne.anchorDist, null, "DirtyDnas gate has no DNASSKIP anchor");

// OPL still needs (and finds) the sceSifSendCmd 9x hook.
assert.equal(t.dnas.hook.vaddr >>> 0, 0x003976b0, "hook addr");
assert.equal(t.dnas.hook.value >>> 0, 0x0c0e5d54, "hook value (orig JAL)");

// This engine has neither SSL nor a patchable port.
assert.equal(t.ssl.port, null, "no ProtoAriesSecure site");
assert.equal(t.port, null, "no game port site");

// Domain override is available (older engine still phones home).
assert.equal(game.domain, "ps2sims04.ea.com", "located EA hostname");
assert.equal(t.domain.host, "ps2sims04.ea.com", "domain host");
assert.equal(t.domain.sites.length, 1, "one domain occurrence");
assert.equal(t.domain.sites[0].vaddr >>> 0, 0x003c4c88, "domain addr");
assert.equal(t.domain.capacity, 24, "domain capacity (16 host + 8 NUL)");

// .cht default: hook + the single DNAS NOP, nothing else (domain off).
const cht = buildCht(serial, "The Sims Bustin Out", game.targets);
const expectedCht = `"The Sims Bustin Out /ID SLUS_208.42"
//Online patches — Main Game
903976B0 0C0E5D54
//DNAS bypass: Skip the DNAS authentication check.
202626C0 00000000
`;
assert.equal(cht, expectedCht, "full .cht (DNAS-only, DirtyDnas gate)");

// .pnach default: one file, the reliable 1-line bypass.
const pnach = buildPnach(serial, game.targets);
assert.equal(pnach.length, 1, "one pnach file");
assert.ok(pnach[0].content.startsWith("[DNAS bypass]"), "pnach starts with the DNAS section");
assert.ok(
  pnach[0].content.includes("patch=1,EE,202626C0,extended,00000000"),
  "pnach has the gate NOP",
);
assert.ok(!pnach[0].content.includes("24E70000"), "no SSL lines");
assert.ok(!pnach[0].content.includes("Domain override"), "domain off by default");

// Domain on -> coalesced word writes (host start is 4-aligned here).
const withDomain = structuredClone(game.targets);
withDomain[0].enable.domain = true;
const pnachDom = buildPnach(serial, withDomain, null, "eahub.eu");
assert.ok(pnachDom[0].content.includes("[Domain override]"), "domain section present");
// "eahub.eu" packs into 4 words: "eahu","b.eu",NUL,NUL (erasing the old host).
assert.ok(pnachDom[0].content.includes("patch=1,EE,203C4C88,extended,75686165"), "domain word 'eahu'");
assert.ok(pnachDom[0].content.includes("patch=1,EE,203C4C8C,extended,75652E62"), "domain word 'b.eu'");
assert.ok(pnachDom[0].content.includes("patch=1,EE,203C4C90,extended,00000000"), "domain word NUL (old host erased)");

console.log("SIMS ASSERTIONS PASSED ✓");
