// Validation against the real extracted FIFA 07 US ELFs.
// Needs the extracted game folder (SLUS_214.33 + EACN/BIN/EA_DASH.ELF).
// Point TEST_PS2_DIR at it, e.g. via an untracked .env:
//   npm test            (uses node --env-file=.env, see package.json)
// or: TEST_PS2_DIR="/path/to/FIFA Soccer 07 (USA) (En,Es)" node test/run.mjs
import { readFileSync } from "node:fs";
import assert from "node:assert";
import { analyzeGame } from "../.tmp/analyze.js";
import { buildCht, buildPnach } from "../.tmp/cheats.js";
import { Elf } from "../.tmp/elf.js";
import { analyzeRoster } from "../.tmp/roster.js";

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
// SSL bypass now defaults OFF (product default); enable it here to test its output.
for (const t of game.targets) t.enable.ssl = true;
const cht = buildCht(serial, "FIFA07", game.targets);
console.log(cht);
console.log("warnings:", game.warnings);

assert.equal(game.title, "FIFA07", "title guessed from ps2fifa07.ea.com");

const main = game.targets[0].dnas;
const dash = game.targets[1].dnas;
assert.equal(main.bne.vaddr >>> 0, 0x005c8028, "main BNE addr");
assert.equal(dash.bne.vaddr >>> 0, 0x001e16cc, "dash BNE addr");
assert.equal(main.hook.vaddr >>> 0, 0x00370428, "main hook addr");
assert.equal(main.hook.value >>> 0, 0x0c0dc0b2, "main hook value");
assert.equal(dash.hook.vaddr >>> 0, 0x0023d698, "dash hook addr");
assert.equal(dash.hook.value >>> 0, 0x0c08f54e, "dash hook value");
assert.equal(main.bne.anchorDist, 0x20, "main DNASSKIP anchor distance");
assert.equal(dash.bne.anchorDist, 0x20, "dash DNASSKIP anchor distance");
assert.equal(main.method, "dnasskip", "FIFA uses the DNASSKIP detector");

// SSL: ProtoAriesSecure NOP + port +1 -> +0, one site per ELF.
const mainSsl = game.targets[0].ssl;
const dashSsl = game.targets[1].ssl;
assert.equal(mainSsl.port.vaddr >>> 0, 0x005d10c0, "main SSL port addr");
assert.equal(mainSsl.port.value >>> 0, 0x24e70000, "main SSL port value (+0)");
assert.equal(mainSsl.secure.vaddr >>> 0, 0x005d10c8, "main SSL secure (NOP) addr");
assert.equal(dashSsl.port.vaddr >>> 0, 0x001e4088, "dash SSL port addr");
assert.equal(dashSsl.secure.vaddr >>> 0, 0x001e4090, "dash SSL secure (NOP) addr");

// Roster download bypass: main-only. Force HasLatestRoster's pushed bool to true
// (dmove a0,v0 -> li a0,1) so the game never prompts for or fetches a roster.
assert.equal(game.targets[0].roster.skip.vaddr >>> 0, 0x00602950, "main roster skip addr");
assert.equal(game.targets[0].roster.skip.value >>> 0, 0x24040001, "main roster skip value (li a0,1)");
assert.equal(game.targets[1].roster.skip, null, "dash has no roster adaptor");
// Opt-in: off by default, so the default .cht carries no roster block.
assert.ok(!cht.includes("Roster download bypass"), "roster off by default -> no block");
const withRoster = structuredClone(game.targets);
for (const t of withRoster) if (t.roster?.skip) t.enable.roster = true;
const chtRoster = buildCht(serial, "FIFA07", withRoster);
assert.ok(
  chtRoster.includes("//Roster download bypass: Skip the online roster update (no download prompt)."),
  "roster block header",
);
assert.ok(chtRoster.includes("20602950 24040001"), "roster code (li a0,1)");
const pnachRoster = buildPnach(serial, withRoster);
assert.ok(pnachRoster[0].content.includes("[Roster download bypass]"), "main pnach roster section");
assert.ok(pnachRoster[0].content.includes("patch=1,EE,20602950,extended,24040001"), "roster pnach word");

// Default .cht: per-ELF hook group, one comment-headed block per feature, every
// ELF's writes repeated under each hook (OPL applies the whole list per hook).
const expected = `"FIFA07 /ID SLUS_214.33"
//Online patches — Main Game
90370428 0C0DC0B2
//DNAS bypass: Skip the DNAS authentication check.
205C8028 00000000
201E16CC 00000000
//SSL bypass: Disable ProtoAries SSL on the lobby link.
205D10C0 24E70000
205D10C8 00000000
201E4088 24E70000
201E4090 00000000

//Online patches — EA Dashboard
9023D698 0C08F54E
//DNAS bypass: Skip the DNAS authentication check.
205C8028 00000000
201E16CC 00000000
//SSL bypass: Disable ProtoAries SSL on the lobby link.
205D10C0 24E70000
205D10C8 00000000
201E4088 24E70000
201E4090 00000000
`;
assert.equal(cht, expected, "full .cht matches the block format");

// Toggling features off must drop their block.
const onlyDnas = structuredClone(game.targets);
for (const t of onlyDnas) t.enable.ssl = false;
const chtDnas = buildCht(serial, "FIFA07", onlyDnas);
assert.ok(!chtDnas.includes("24E70000"), "SSL off -> no SSL block");
assert.ok(!chtDnas.includes("SSL bypass"), "SSL off -> no SSL header");
assert.ok(chtDnas.includes("//DNAS bypass: Skip the DNAS authentication check."), "DNAS block kept");
assert.ok(chtDnas.includes("205C8028 00000000"), "DNAS code kept");

// Game port: main = readable .data word; dash = connect-site rewrite.
assert.equal(game.port, 10400, "detected game port (from main data word)");
assert.equal(game.targets[0].port.kind, "data", "main port kind");
assert.equal(game.targets[0].port.value, 10400, "main port value");
assert.equal(game.targets[0].port.sites[0] >>> 0, 0x00725c5c, "main port addr");
assert.equal(game.targets[1].port.kind, "connect", "dash port kind = connect rewrite");

// Port is opt-in per ELF: with the checkboxes off, no port write even if a value is passed.
assert.ok(!buildCht(serial, "FIFA07", game.targets, 12345).includes("20725C5C"), "port off -> no main patch");
assert.ok(!buildCht(serial, "FIFA07", game.targets, 12345).includes("Game port"), "port off -> no port block");

// Tick "Edit game port" on both ELFs -> main data word; dash connect ori a3,zero,port.
const withPort = structuredClone(game.targets);
for (const t of withPort) t.enable.port = true;
const chtPort = buildCht(serial, "FIFA07", withPort, 12345); // 0x3039
assert.ok(chtPort.includes("//Game port: Set the game port to 12345."), "port on -> port block header");
assert.ok(chtPort.includes("20725C5C 00003039"), "port on -> main data word write");
assert.ok(chtPort.includes("34073039"), "port on -> dash ori a3,zero,12345");
const pnachPort = buildPnach(serial, withPort, 12345);
assert.ok(pnachPort[0].content.includes("[Game port]"), "main pnach has Game port section");
assert.ok(pnachPort[0].content.includes("patch=1,EE,20725C5C,extended,00003039"), "main pnach data word");
assert.ok(pnachPort[1].content.includes(",extended,34073039"), "dash pnach connect ori");

// Domain override: located in the main ELF (ps2fifa07.ea.com, 2 sites); the
// dashboard has no copy of the game host, so it gets no domain block.
assert.equal(game.domain, "ps2fifa07.ea.com", "detected EA hostname");
assert.equal(game.targets[0].domain.host, "ps2fifa07.ea.com", "main domain host");
assert.equal(game.targets[0].domain.sites.length, 2, "main domain occurrences");
assert.equal(game.targets[0].domain.sites[0].vaddr >>> 0, 0x0033e551, "main domain addr");
assert.equal(game.targets[0].domain.capacity, 23, "main domain capacity (16 host + 7 NUL)");
assert.equal(game.targets[1].domain, null, "dash has no game-host domain");

// Domain is opt-in: off -> no writes even when a replacement is passed.
assert.ok(!buildCht(serial, "FIFA07", game.targets, null, "eahub.eu").includes("Domain override"), "domain off -> no block");

// Tick it on -> byte writes for "eahub.eu" at each occurrence.
const withDomain = structuredClone(game.targets);
for (const t of withDomain) if (t.domain) t.enable.domain = true;
const chtDom = buildCht(serial, "FIFA07", withDomain, null, "eahub.eu");
assert.ok(chtDom.includes('//Domain override: Redirect the EA hostname to "eahub.eu".'), "domain block header");
// Writes are coalesced + alignment-aware: the unaligned host start (…551) leads
// with a byte (0) then a halfword (1), the aligned middle is words (2).
assert.ok(chtDom.includes("0033E551 00000065"), "site 1: leading byte 'e' (unaligned)");
assert.ok(chtDom.includes("1033E552 00006861"), "site 1: halfword 'ah'");
assert.ok(chtDom.includes("2033E554 652E6275"), "site 1: word 'ub.e'");
assert.ok(chtDom.includes("003532E9 00000065"), "site 2: leading byte 'e'");
const pnachDom = buildPnach(serial, withDomain, null, "eahub.eu");
assert.ok(pnachDom[0].content.includes("[Domain override]"), "main pnach has Domain override section");
assert.ok(pnachDom[0].content.includes("patch=1,EE,2033E554,extended,652E6275"), "domain word write 'ub.e'");
// Alignment safety: every word (cmd 2) address is 4-aligned, every halfword
// (cmd 1) is 2-aligned — no unaligned multi-byte store can fault the EE.
assert.ok(!/patch=1,EE,2[0-9A-F]{6}[^048C],/.test(pnachDom[0].content), "no word write at a non-4-aligned address");
assert.ok(!/patch=1,EE,1[0-9A-F]{6}[13579BDF],/.test(pnachDom[0].content), "no halfword write at an odd address");
// A replacement too long for the capacity must be rejected (no writes).
assert.ok(
  !buildCht(serial, "FIFA07", withDomain, null, "this-domain-is-way-too-long.example.com").includes("Domain override"),
  "over-capacity domain -> no block",
);

// pnach: filenames carry the auto-computed PCSX2 CRC; one file per ELF.
const pnach = buildPnach(serial, game.targets);
console.log(pnach.map((f) => `${f.filename}:\n${f.content}`).join("\n"));
const pnachMain = `[DNAS bypass]
author=EA Nation Hub
description=Skip the DNAS authentication check.
patch=1,EE,205C8028,extended,00000000

[SSL bypass]
author=EA Nation Hub
description=Disable ProtoAries SSL on the lobby link.
patch=1,EE,205D10C0,extended,24E70000
patch=1,EE,205D10C8,extended,00000000
`;
assert.equal(pnach[0].filename, "SLUS-21433_083C57E2.pnach", "main pnach filename");
assert.equal(pnach[0].content, pnachMain, "main pnach content/format");
assert.equal(pnach[1].filename, "SLUS-21433_C4923636.pnach", "dash pnach filename");
assert.ok(pnach[1].content.includes("patch=1,EE,201E16CC,extended,00000000"), "dash pnach DNAS line");
assert.ok(pnach[1].content.startsWith("[DNAS bypass]"), "dash pnach starts with a section");

// Roster detection on an older build (NHL 06) where "HasLatestRoster" appears
// twice — a debug copy plus the dispatch-table copy. Detection must skip the
// copy no pointer references and still land the handler. Guarded on TEST_NHL_DIR.
const NHL = process.env.TEST_NHL_DIR;
if (NHL) {
  const nhl = new Elf(new Uint8Array(readFileSync(`${NHL}/SLUS_212.41`)));
  const r = analyzeRoster(nhl);
  assert.ok(r.skip, "NHL06: roster site found despite duplicate method string");
  assert.equal(r.skip.vaddr >>> 0, 0x003db568, "NHL06 roster skip addr");
  assert.equal(r.skip.value >>> 0, 0x24040001, "NHL06 roster skip value (li a0,1)");
  console.log("NHL06 roster detection PASSED ✓");
} else {
  console.log("SKIP NHL06 roster check: set TEST_NHL_DIR.");
}

console.log("ALL ASSERTIONS PASSED ✓");
