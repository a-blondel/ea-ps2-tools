// Roster-download skip for EA PS2 (OSDK) ELFs.
//
// Online titles poll `EASO_RostersAdaptor::HasLatestRoster` before showing the
// "new roster available — download?" prompt. The native adaptor entry computes
// the bool, moves it into a0, then tail-calls the script return-value setter:
//
//     jal   <check impl>
//     lw    a0, 0x4(v0)          ; delay slot (feeds the impl)
//     jal   <push-bool-to-script>
//     dmove a0, v0               ; delay slot: a0 = result  -> patch to li a0,1
//
// Verified live (PCSX2, FIFA 07 PAL): the impl naturally returns 0 = "not
// latest", which triggers the download. Forcing the pushed value to 1 = "have
// latest" makes the game believe it is up to date, so the prompt and the HTTP
// fetch are skipped entirely.
//
// The adaptor is reached through a `{name-ptr, handler-fn-ptr}` dispatch table,
// so we anchor on the "HasLatestRoster" method-name string: find a data word
// equal to its address (the table entry), take the following word as the
// handler, then locate the `jal` whose delay slot is `dmove a0,v0`. That
// delay-slot test is unique in the entry — the impl `jal`'s slot is `lw a0,...`.
// This idiom is shared across OSDK builds, so the same anchor generalises.

import { Elf } from "./elf.js";
import { ascii, findAll } from "./bytes.js";

const METHOD = "HasLatestRoster";
// The bool is moved into the arg register right before the return-setter call.
// Newer builds emit `dmove a0,v0` (daddu), older ones `move a0,v0` (or) — both
// are the same operation and both are the anchor's delay slot.
const MOVE_A0_V0 = [0x0040202d, 0x00402025];
const LI_A0_1 = 0x24040001; // addiu a0,zero,1  (force "have latest" = true)
const MAX_ENTRY_INSTR = 48; // adaptor entry is tiny; cap the handler scan

export interface RosterPatch {
  vaddr: number;
  original: number; // current opcode word (dmove a0,v0)
  value: number; // word to write (li a0,1)
}

export interface RosterAnalysis {
  skip: RosterPatch | null; // the `dmove a0,v0` -> `li a0,1` edit
}

/** Virtual addresses of every NUL-terminated occurrence of `s`. */
function findStringVaddrs(elf: Elf, s: string): number[] {
  const needle = ascii(s);
  const out: number[] = [];
  for (const off of findAll(elf.data, needle)) {
    const after = off + needle.length;
    if (after >= elf.data.length || elf.data[after] !== 0) continue; // must be whole string
    const va = elf.fileToVaddr(off);
    if (va !== null) out.push(va);
  }
  return out;
}

/**
 * Given the adaptor handler, find the `jal` (the script return-setter) whose
 * delay slot moves the result into a0, and return the delay-slot patch.
 */
function findMovePatch(elf: Elf, hf: number): RosterPatch | null {
  for (let i = 0; i < MAX_ENTRY_INSTR; i++) {
    const insOff = hf + i * 4;
    if (insOff + 8 > elf.data.length) break;
    if (elf.readU32(insOff) >>> 26 !== 3 /* JAL */) continue;
    const slot = elf.readU32(insOff + 4);
    if (!MOVE_A0_V0.includes(slot)) continue;
    const vaddr = elf.fileToVaddr(insOff + 4);
    if (vaddr === null) break;
    return { vaddr, original: slot, value: LI_A0_1 };
  }
  return null;
}

export function analyzeRoster(elf: Elf): RosterAnalysis {
  // The method-name string can appear more than once (e.g. a debug copy plus the
  // dispatch-table copy); only the copy the table points at yields the handler,
  // so try them all.
  for (const strVa of findStringVaddrs(elf, METHOD)) {
    // Find the dispatch-table entry: a word == the method-name address, whose
    // following word points at the adaptor handler.
    for (let fo = 0; fo + 8 <= elf.data.length; fo += 4) {
      if (elf.readU32(fo) !== strVa) continue;
      const hf = elf.vaddrToFile(elf.readU32(fo + 4));
      if (hf === null) continue;
      const patch = findMovePatch(elf, hf);
      if (patch) return { skip: patch };
    }
  }
  return { skip: null };
}
