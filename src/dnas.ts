// DNAS bypass detection for EA PS2 ELFs.
//
// The DNAS check compiles to:
//     JAL  <dnas_fn>          ; result in $v0
//     DADDU a1, zero, zero    ; delay slot   -> bytes 2D 28 00 00
//     BNE  $v0, $s0, <error>  ; the check    -> bytes ?? 00 50 14
//     ...
// NOP-ing that BNE (write 0x00000000) forces fall-through, skipping DNAS.
//
// The branch displacement differs slightly between builds, so the BNE shows up
// as either `2D 28 00 00 06 00 50 14` or `2D 28 00 00 07 00 50 14`. Larger games
// contain several copies of that byte sequence, so we disambiguate by anchoring
// on a code reference to the "DNASSKIP" string, which sits a few instructions
// before the real check (empirically ~0x20 bytes earlier).
//
// For OPL (.cht) we also need a runtime hook (9x code): the original JAL found
// just after the fixed `_sceSifSendCmd` wrapper prologue. Its opcode word is the
// value the 9x code stores; its address is the hook address.
//
// Older EA titles (the "DirtySock" reloc engine, ~2003-2005, e.g. The Sims
// Bustin' Out) have NO DNASSKIP string and no inline JAL/BNE: DNAS auth lives in
// a relocated `dirtydnas.elf` polled through a wrapper, and the engine branches
// on its result. `analyzeDirtyDnas` handles that case as a fallback — see below.

import { hex, ascii } from "./bytes.js";
import { Elf } from "./elf.js";

const DNAS_BNE_PATTERNS = [hex("2D28000006005014"), hex("2D28000007005014")];

// Fixed prologue of the _sceSifSendCmd wrapper (10 instructions = 40 bytes),
// identical across EA titles. The JAL immediately after it is the hook target.
const SCEIF_WRAPPER = hex(
  "2D10C000" + "2D18E000" + "2D580001" + "F0FFBD27" + "2D502001" +
    "2D30A000" + "0000BFFF" + "2D384000" + "2D406000" + "2D486001",
);

const DNASSKIP = ascii("DNASSKIP");

// How far before the BNE a DNASSKIP reference may sit to count as its anchor.
const ANCHOR_WINDOW = 0x200;

export interface BneCandidate {
  vaddr: number;
  fileOff: number;
  original: number; // current opcode word at the BNE
  anchorDist: number | null; // bytes from the nearest preceding DNASSKIP ref
}

export interface Hook {
  vaddr: number;
  value: number; // original JAL opcode (the 9x payload)
}

export interface DnasAnalysis {
  bne: BneCandidate | null; // chosen BNE (best-anchored, else only/first)
  candidates: BneCandidate[]; // all matches, for transparency
  ambiguous: boolean; // multiple matches and none clearly anchored
  hook: Hook | null;
  method: "dnasskip" | "dirtydnas" | null; // which detector found `bne`
}

const DIRTYDNAS_SYM = ascii("DirtyDnasRelUpdt");

/** Sign-extend a 16-bit immediate. */
function signExt16(v: number): number {
  return v & 0x8000 ? v - 0x10000 : v;
}

/** Virtual addresses of every "DNASSKIP" string in the file. */
function dnasskipStringVaddrs(elf: Elf): number[] {
  const out: number[] = [];
  for (const fo of elf.find(DNASSKIP)) {
    const va = elf.fileToVaddr(fo);
    if (va !== null) out.push(va);
  }
  return out;
}

/**
 * Scan the code segment for `lui rX, hi` / `addiu rX, rX, lo` pairs that
 * materialise the address of one of the DNASSKIP strings. Returns the vaddr of
 * each such reference (the address of the lui).
 */
function dnasskipRefVaddrs(elf: Elf, strVaddrs: number[]): number[] {
  if (strVaddrs.length === 0) return [];
  const targets = new Set(strVaddrs);
  const refs: number[] = [];
  const seg = elf.codeSegment;
  const luiImm = new Int32Array(32).fill(-1); // -1 = no pending lui
  const luiVa = new Int32Array(32);
  for (let fo = seg.off; fo + 4 <= seg.off + seg.filesz; fo += 4) {
    const w = elf.readU32(fo);
    const op = w >>> 26;
    if (op === 0x0f) {
      // LUI rt, imm
      const rt = (w >>> 16) & 0x1f;
      luiImm[rt] = w & 0xffff;
      luiVa[rt] = elf.fileToVaddr(fo) ?? 0;
    } else if (op === 0x09) {
      // ADDIU rt, rs, imm
      const rs = (w >>> 21) & 0x1f;
      const rt = (w >>> 16) & 0x1f;
      let imm = w & 0xffff;
      if (imm & 0x8000) imm -= 0x10000;
      const hi = luiImm[rs] ?? -1;
      if (rt === rs && hi !== -1) {
        const tgt = (((hi & 0xffff) << 16) + imm) >>> 0;
        if (targets.has(tgt)) refs.push(luiVa[rs] ?? 0);
      }
    }
  }
  return refs;
}

function findBneCandidates(elf: Elf, refVaddrs: number[]): BneCandidate[] {
  const cands: BneCandidate[] = [];
  for (const pat of DNAS_BNE_PATTERNS) {
    for (const matchFo of elf.find(pat)) {
      const bneFo = matchFo + 4; // skip the DADDU delay-slot bytes
      const va = elf.fileToVaddr(bneFo);
      if (va === null) continue;
      // nearest DNASSKIP ref sitting *before* this BNE within the window
      let anchorDist: number | null = null;
      for (const ref of refVaddrs) {
        const d = va - ref;
        if (d > 0 && d <= ANCHOR_WINDOW && (anchorDist === null || d < anchorDist)) {
          anchorDist = d;
        }
      }
      cands.push({ vaddr: va, fileOff: bneFo, original: elf.readU32(bneFo), anchorDist });
    }
  }
  cands.sort((a, b) => a.vaddr - b.vaddr);
  return cands;
}

function findHook(elf: Elf): Hook | null {
  const occ = elf.find(SCEIF_WRAPPER);
  if (occ.length === 0) return null;
  // First occurrence matches the established community cheats; all occurrences
  // call the same function so any works, but we stay consistent.
  const jalFo = occ[0]! + SCEIF_WRAPPER.length;
  if (jalFo + 4 > elf.data.length) return null;
  const value = elf.readU32(jalFo);
  if (value >>> 26 !== 3 /* JAL */) return null;
  const vaddr = elf.fileToVaddr(jalFo);
  if (vaddr === null) return null;
  return { vaddr, value };
}

/**
 * Fallback DNAS detector for the older EA "DirtySock" reloc engine (no DNASSKIP
 * string; e.g. The Sims Bustin' Out). DNAS auth is the relocated `dirtydnas.elf`
 * polled through a thin wrapper, and the state machine branches on its result.
 * We trace, all by structure (ABI-fixed regs, no hard-coded addresses):
 *   1. the "DirtyDnasRelUpdt" string -> the symbol-resolve store that stashes the
 *      resolved function pointer (`lui rB,hi; sw v0,lo(rB)` => the ptr global);
 *   2. the wrapper that calls it (`lui rX,hi; lw rY,lo(rX); ...; jalr rY`);
 *   3. that wrapper's `jal` call site in the state machine; then
 *   4. the first `lw v?,off(sp); bne v?,zero,<fail>` after the call — the result
 *      gate. NOP-ing that BNE makes DNAS always report success.
 * Validated against The Sims Bustin' Out US (gate @ 0x002626c0).
 */
function analyzeDirtyDnas(elf: Elf): BneCandidate | null {
  const seg = elf.codeSegment;
  const end = seg.off + seg.filesz;

  const strVa = new Set<number>();
  for (const fo of elf.find(DIRTYDNAS_SYM)) {
    const va = elf.fileToVaddr(fo);
    if (va !== null) strVa.add(va);
  }
  if (strVa.size === 0) return null; // not this engine

  // (1) lui/addiu ref to the string -> nearby `sw v0,lo(rB)` (+`lui rB,hi`).
  let dat: number | null = null;
  {
    const luiImm = new Int32Array(32).fill(-1);
    for (let fo = seg.off; fo + 4 <= end && dat === null; fo += 4) {
      const w = elf.readU32(fo), op = w >>> 26;
      if (op === 0x0f) luiImm[(w >>> 16) & 0x1f] = w & 0xffff;
      else if (op === 0x09) {
        const rs = (w >>> 21) & 0x1f, rt = (w >>> 16) & 0x1f, hi = luiImm[rs] ?? -1;
        if (rt !== rs || hi === -1) continue;
        const tgt = (((hi & 0xffff) << 16) + signExt16(w & 0xffff)) >>> 0;
        if (!strVa.has(tgt)) continue;
        const luiH = new Int32Array(32).fill(-1);
        for (let g = fo; g < fo + 8 * 4 && g + 4 <= end; g += 4) {
          const wg = elf.readU32(g), opg = wg >>> 26;
          if (opg === 0x0f) luiH[(wg >>> 16) & 0x1f] = wg & 0xffff;
          else if (opg === 0x2b /* sw */) {
            const base = (wg >>> 21) & 0x1f, srt = (wg >>> 16) & 0x1f, h = luiH[base] ?? -1;
            if (srt === 2 /* v0 */ && h !== -1) {
              dat = ((h << 16) + signExt16(wg & 0xffff)) >>> 0;
              break;
            }
          }
        }
      }
    }
  }
  if (dat === null) return null;
  const hiD = (dat >>> 16) & 0xffff, loD = dat & 0xffff;

  // (2) the wrapper: `lui rX,hi(dat)` ; `lw rY,lo(dat)(rX)` ; ... `jalr rY`.
  let wrapperVa: number | null = null;
  {
    const luiH = new Int32Array(32).fill(-1);
    const luiAt = new Int32Array(32);
    for (let fo = seg.off; fo + 4 <= end && wrapperVa === null; fo += 4) {
      const w = elf.readU32(fo), op = w >>> 26;
      if (op === 0x0f) { const rt = (w >>> 16) & 0x1f; luiH[rt] = w & 0xffff; luiAt[rt] = fo; }
      else if (op === 0x23 /* lw */) {
        const base = (w >>> 21) & 0x1f, rt = (w >>> 16) & 0x1f;
        if ((luiH[base] ?? -1) !== hiD || (signExt16(w & 0xffff) & 0xffff) !== loD) continue;
        for (let g = fo + 4; g < fo + 5 * 4 && g + 4 <= end; g += 4) {
          const wg = elf.readU32(g);
          if (wg >>> 26 === 0 && (wg & 0x3f) === 0x09 /* jalr */ && ((wg >>> 21) & 0x1f) === rt) {
            wrapperVa = elf.fileToVaddr(luiAt[base] ?? 0);
            break;
          }
        }
      }
    }
  }
  if (wrapperVa === null) return null;

  // (3) `jal wrapperVa` call sites -> (4) the result gate after each.
  for (let fo = seg.off; fo + 4 <= end; fo += 4) {
    const w = elf.readU32(fo);
    if (w >>> 26 !== 0x03 /* jal */) continue;
    if ((((w & 0x03ffffff) << 2) >>> 0) !== (wrapperVa >>> 0)) continue;
    const gate = dirtyDnasGate(elf, fo, end);
    if (gate) return gate;
  }
  return null;
}

/** First `lw v?,off(sp)` immediately followed by `bne v?,zero,<fwd>` after `callFo`. */
function dirtyDnasGate(elf: Elf, callFo: number, end: number): BneCandidate | null {
  for (let g = callFo + 4; g < callFo + 24 * 4 && g + 8 <= end; g += 4) {
    const w = elf.readU32(g);
    if (w >>> 26 !== 0x23 /* lw */) continue;
    if (((w >>> 21) & 0x1f) !== 29 /* sp */) continue;
    const rt = (w >>> 16) & 0x1f;
    if (rt !== 2 && rt !== 3) continue; // v0/v1 hold the result code
    const nw = elf.readU32(g + 4);
    if (nw >>> 26 !== 0x05 /* bne */) continue;
    if (((nw >>> 21) & 0x1f) !== rt || ((nw >>> 16) & 0x1f) !== 0) continue; // bne rt,zero
    if (signExt16(nw & 0xffff) <= 0) continue; // forward branch -> the fail block
    const va = elf.fileToVaddr(g + 4);
    if (va === null) continue;
    return { vaddr: va, fileOff: g + 4, original: nw, anchorDist: null };
  }
  return null;
}

export function analyzeDnas(elf: Elf): DnasAnalysis {
  const strVaddrs = dnasskipStringVaddrs(elf);
  const refVaddrs = dnasskipRefVaddrs(elf, strVaddrs);
  const candidates = findBneCandidates(elf, refVaddrs);

  const anchored = candidates.filter((c) => c.anchorDist !== null);
  let bne: BneCandidate | null = null;
  let ambiguous = false;
  if (anchored.length > 0) {
    // best-anchored = smallest distance to a DNASSKIP reference
    bne = anchored.reduce((a, b) => (a.anchorDist! <= b.anchorDist! ? a : b));
    ambiguous = anchored.length > 1 &&
      anchored.filter((c) => c.anchorDist === bne!.anchorDist).length > 1;
  } else if (candidates.length === 1) {
    bne = candidates[0]!;
  } else if (candidates.length > 1) {
    bne = candidates[0]!;
    ambiguous = true; // multiple matches, no DNASSKIP anchor to choose
  }

  let method: DnasAnalysis["method"] = bne ? "dnasskip" : null;
  if (!bne) {
    // No inline DNASSKIP check — try the older DirtyDnas reloc engine.
    const gate = analyzeDirtyDnas(elf);
    if (gate) {
      bne = gate;
      method = "dirtydnas";
    }
  }

  return {
    bne,
    candidates: method === "dirtydnas" && bne ? [bne] : candidates,
    ambiguous,
    hook: findHook(elf),
    method,
  };
}
