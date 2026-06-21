// Validation against the real extracted FIFA 07 US ELFs.
// Needs the extracted game folder (SLUS_214.33 + EACN/BIN/EA_DASH.ELF).
// Point TEST_PS2_DIR at it, e.g. via an untracked .env:
//   npm test            (uses node --env-file=.env, see package.json)
// or: TEST_PS2_DIR="/path/to/FIFA Soccer 07 (USA) (En,Es)" node test/run.mjs
import { readFileSync } from "node:fs";
import assert from "node:assert";
import { analyzeGame } from "../.tmp/analyze.js";
import { buildCht, buildPnach } from "../.tmp/cheats.js";

const DIR = process.env.TEST_PS2_DIR;
if (!DIR) {
  console.log("SKIP: set TEST_PS2_DIR to the extracted FIFA 07 US folder (see .env.example).");
  process.exit(0);
}
const serial = "SLUS_214.33";

const blobs = [
  { name: "SLUS_214.33", path: "/SLUS_214.33", data: new Uint8Array(readFileSync(`${DIR}/SLUS_214.33`)) },
  { name: "EA_DASH.ELF", path: "/EACN/BIN/EA_DASH.ELF", data: new Uint8Array(readFileSync(`${DIR}/EACN/BIN/EA_DASH.ELF`)) },
];

const game = analyzeGame(serial, blobs);
const cht = buildCht(serial, "FIFA07", game.targets);
console.log(cht);
console.log("warnings:", game.warnings);

assert.equal(game.title, "FIFA07", "title guessed from ps2fifa07.ea.com");

const main = game.targets[0].analysis;
const dash = game.targets[1].analysis;
assert.equal(main.bne.vaddr >>> 0, 0x005c8028, "main BNE addr");
assert.equal(dash.bne.vaddr >>> 0, 0x001e16cc, "dash BNE addr");
assert.equal(main.hook.vaddr >>> 0, 0x00370428, "main hook addr");
assert.equal(main.hook.value >>> 0, 0x0c0dc0b2, "main hook value");
assert.equal(dash.hook.vaddr >>> 0, 0x0023d698, "dash hook addr");
assert.equal(dash.hook.value >>> 0, 0x0c08f54e, "dash hook value");
assert.equal(main.bne.anchorDist, 0x20, "main DNASSKIP anchor distance");
assert.equal(dash.bne.anchorDist, 0x20, "dash DNASSKIP anchor distance");

const expected = `"FIFA07 /ID SLUS_214.33"
//DNAS bypass Main Game
90370428 0C0DC0B2
205C8028 00000000
201E16CC 00000000

//DNAS bypass EA Dashboard
9023D698 0C08F54E
205C8028 00000000
201E16CC 00000000
`;
assert.equal(cht, expected, "full .cht matches OPL /ID format");

// pnach: filenames carry the auto-computed PCSX2 CRC; one file per ELF.
const pnach = buildPnach(serial, game.targets);
console.log(pnach.map((f) => `${f.filename}:\n${f.content}`).join("\n"));
const pnachMain = `[Network\\DNAS Patch]
author=EA Nation Hub
description=DNAS check bypass
patch=1,EE,205C8028,extended,00000000
`;
assert.equal(pnach[0].filename, "SLUS-21433_083C57E2.pnach", "main pnach filename");
assert.equal(pnach[0].content, pnachMain, "main pnach content/format");
assert.equal(pnach[1].filename, "SLUS-21433_C4923636.pnach", "dash pnach filename");
assert.ok(pnach[1].content.includes("patch=1,EE,201E16CC,extended,00000000"), "dash pnach line");
assert.ok(pnach[1].content.startsWith("[Network\\DNAS Patch]"), "dash pnach header");

console.log("ALL ASSERTIONS PASSED ✓");
