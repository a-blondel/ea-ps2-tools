// DNAS bypass for the stock Sony DNAS 2.x "module" engine (e.g. Burnout 3:
// Takedown, SLUS-21050). Unlike the EA in-ELF checks (DNASSKIP / DirtyDnas, see
// dnas.ts), here the authentication runs in a separate IOP module that the game
// loads and relocates at runtime, so there is no BNE to NOP in the main ELF.
//
// The plaintext code of that module is embedded on the disc — on Burnout 3 it
// sits inside a decoy-named data file (/DATA/INTRO2.M2V, an ELF with `dnas` /
// `aries` strings), NOT in the encrypted /IOP/DNAS280.IMG loader. The community
// tool DNAS_PATCHER21 finds it by scanning the whole image for a fixed code
// signature and rewrites the auth-status accessor to always report status 5
// (= authenticated). We replicate that exact byte patch.
//
// The accessor's tail (MIPS-LE) is transformed like so:
//     lw   v1,0x147C(v0)     -> sw   zero,0x147C(v0)   ; drop the real status
//     beqz v1,<skip>         -> beq  v1,zero,+0        ; neutralise the branch
//     nop                    -> sw   zero,4(a3)
//     ...
//     jr   ra                -> li   v1,5              ; forced verdict = 5
//     nop                    -> jr   ra
//     nop                    -> sw   v1,0(a2)          ; store 5 into the result
//
// Verified byte-for-byte against the real DNAS_PATCHER21 output on Burnout 3 US.

import { findAll } from "./bytes.js";

// Unique 12-byte anchor: lw v1,0x147C(v0) ; li v0,-8 ; beqz v1,+0xE (LE bytes).
// Occurs exactly once in the Burnout 3 image; absent from EA-DNASSKIP titles.
const ANCHOR = new Uint8Array([
  0x7c, 0x14, 0x43, 0x8c, 0xf8, 0xff, 0x02, 0x24, 0x0e, 0x00, 0x60, 0x10,
]);

// The six word rewrites, at offsets relative to the anchor. `orig` is verified
// before patching — a build whose surrounding words differ (different DNAS
// version / layout) is refused rather than blindly overwritten (anti-brick).
interface Rel {
  rel: number;
  orig: number;
  value: number;
}
const PATCH: Rel[] = [
  { rel: 0x00, orig: 0x8c43147c, value: 0xac80147c }, // lw v1,..  -> sw zero,..
  { rel: 0x08, orig: 0x1060000e, value: 0x10600000 }, // beqz v1   -> beq v1,zero,+0
  { rel: 0x1c, orig: 0x00000000, value: 0xace00004 }, // nop       -> sw zero,4(a3)
  { rel: 0x44, orig: 0x03e00008, value: 0x34030005 }, // jr ra     -> li v1,5
  { rel: 0x48, orig: 0x00000000, value: 0x03e00008 }, // nop       -> jr ra
  { rel: 0x4c, orig: 0x00000000, value: 0xacc30000 }, // nop       -> sw v1,0(a2)
];

// Furthest byte a match touches past the anchor — the overlap a chunked scan
// must carry so a match straddling a chunk boundary is never missed.
export const DNASIMG_WINDOW = 0x50;

export interface DnasImgWrite {
  off: number; // offset within the scanned buffer
  orig: number; // expected current word (little-endian)
  value: number; // little-endian word to write
}

export interface DnasImgPatch {
  anchorOff: number;
  writes: DnasImgWrite[];
}

function readU32LE(b: Uint8Array, o: number): number {
  return (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
}

/**
 * Locate the Sony DNAS 2.x auth-status accessor in `buf` and return the bypass
 * writes, with offsets relative to `buf`. `buf` can be the whole image, one
 * chunk of it, or the extracted module. Returns null if the signature is not
 * present, or if a candidate's surrounding words don't match the known function
 * (skipped, so a truncated match at a buffer edge is simply ignored).
 */
export function findDnasModulePatch(buf: Uint8Array): DnasImgPatch | null {
  for (const at of findAll(buf, ANCHOR)) {
    const writes: DnasImgWrite[] = [];
    let ok = true;
    for (const p of PATCH) {
      const off = at + p.rel;
      if (off + 4 > buf.length || readU32LE(buf, off) !== p.orig) {
        ok = false;
        break;
      }
      writes.push({ off, orig: p.orig, value: p.value });
    }
    if (ok) return { anchorOff: at, writes };
  }
  return null;
}

/**
 * Scan a large image for the DNAS module patch via a chunked async reader, so
 * the browser / CLI never holds the whole multi-GB ISO in memory. Each chunk is
 * read with `DNASIMG_WINDOW` bytes of overlap so a match on a chunk boundary is
 * still seen whole. Returns absolute offsets into the image, or null.
 */
export async function scanForDnasModule(
  read: (offset: number, len: number) => Promise<Uint8Array>,
  size: number,
  onProgress?: (frac: number) => void,
  chunkSize = 8 * 1024 * 1024,
): Promise<DnasImgPatch | null> {
  for (let pos = 0; pos < size; pos += chunkSize) {
    const len = Math.min(chunkSize + DNASIMG_WINDOW, size - pos);
    const hit = findDnasModulePatch(await read(pos, len));
    if (hit) {
      onProgress?.(1);
      return {
        anchorOff: pos + hit.anchorOff,
        writes: hit.writes.map((w) => ({ ...w, off: pos + w.off })),
      };
    }
    onProgress?.(Math.min(1, (pos + chunkSize) / size));
  }
  return null;
}

const SECTOR = 2048;
const ELF_MAGIC = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]);
// The DNAS module hides in a file that is either an IOP module (*.IMG) or an EA
// container wrapping a relocatable ELF. On Burnout 3 that ELF sits at +0x800; a
// 16 KB triage window catches it and any modest TOC in front of it.
const TRIAGE = 0x4000;

/** Just what the file-aware scan needs from an ISO 9660 directory entry. */
export interface IsoFileLike {
  name: string;
  lba: number;
  size: number;
}

/**
 * Locate the DNAS module without reading the whole multi-GB image. Files are
 * triaged cheaply — an `*.IMG` name, or an ELF magic in the first 16 KB — then
 * only the candidates (smallest first) are read in full. Returns absolute ISO
 * offsets. Falls back to a full chunked scan only if triage finds no candidate
 * that carries the signature, so an unforeseen container is still caught.
 */
export async function scanIsoFilesForDnasModule(
  read: (offset: number, len: number) => Promise<Uint8Array>,
  files: IsoFileLike[],
  onProgress?: (frac: number) => void,
  fullScanSize?: number,
): Promise<DnasImgPatch | null> {
  const candidates: IsoFileLike[] = [];
  for (const f of files) {
    if (f.size < ANCHOR.length) continue;
    if (/\.IMG$/i.test(f.name)) {
      candidates.push(f);
      continue;
    }
    const head = await read(f.lba * SECTOR, Math.min(TRIAGE, f.size));
    if (findAll(head, ELF_MAGIC).length > 0) candidates.push(f);
  }
  candidates.sort((a, b) => a.size - b.size);

  for (let i = 0; i < candidates.length; i++) {
    const f = candidates[i]!;
    const base = f.lba * SECTOR;
    const hit = findDnasModulePatch(await read(base, f.size));
    if (hit) {
      onProgress?.(1);
      return {
        anchorOff: base + hit.anchorOff,
        writes: hit.writes.map((w) => ({ ...w, off: base + w.off })),
      };
    }
    onProgress?.((i + 1) / candidates.length);
  }

  // The module can hide in a container with no *.IMG name and no ELF magic near
  // its start (e.g. Burnout Revenge's "TERF"-format /STREET/DATA/ONLINE.DAT), so
  // triage can't see it. Fall back to a full chunked scan when we know the size.
  if (fullScanSize !== undefined) return scanForDnasModule(read, fullScanSize, onProgress);
  return null;
}
