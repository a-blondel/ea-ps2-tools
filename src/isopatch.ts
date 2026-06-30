// Phase 2: map the cheat writes onto absolute byte offsets in the ISO image so
// they can be applied in place — a seek + write of a few bytes into the user's
// disc, with no multi-GB rebuild or copy. DOM-free so it runs under node tests;
// the browser glue (File System Access API) lives in main.ts.

import type { Elf } from "./elf.js";
import type { Write } from "./cheats.js";
import { hex8 } from "./bytes.js";

const SECTOR = 2048; // ISO 9660 logical sector size

/** One in-place edit: write `bytes` at absolute `offset` in the ISO file. */
export interface IsoWrite {
  offset: number; // absolute byte offset within the ISO image
  bytes: Uint8Array; // little-endian encoded value, `width` bytes long
  vaddr: number; // source EE virtual address, for display/logging
}

/** One ELF located in the ISO: its parsed image plus the LBA its data starts
 *  at, and the cheat writes targeting it (from cheats.targetWrites). */
export interface IsoPatchTarget {
  elf: Elf;
  lba: number; // sector where this ELF's file data begins in the ISO
  writes: Write[];
}

/** Little-endian encode a value into `width` bytes (matches the EE store). */
export function encodeLE(value: number, width: 1 | 2 | 4): Uint8Array {
  const out = new Uint8Array(width);
  let v = value >>> 0;
  for (let i = 0; i < width; i++) {
    out[i] = v & 0xff;
    v >>>= 8;
  }
  return out;
}

/**
 * Translate every cheat write (EE virtual address + value) into an absolute
 * ISO byte offset: lba*2048 + (vaddr -> ELF file offset). A write whose address
 * falls outside the ELF's loaded segments, or whose word would run past the ELF
 * image, is skipped with a warning rather than silently dropped or clamped —
 * writing the wrong offset would brick the disc.
 */
export function buildIsoWrites(targets: IsoPatchTarget[]): { writes: IsoWrite[]; warnings: string[] } {
  const writes: IsoWrite[] = [];
  const warnings: string[] = [];

  for (const { elf, lba, writes: ws } of targets) {
    for (const w of ws) {
      const fo = elf.vaddrToFile(w.addr);
      if (fo === null) {
        warnings.push(`${hex8(w.addr)} is outside the ELF's loaded segments — skipped.`);
        continue;
      }
      const width = w.width ?? 4;
      if (fo + width > elf.data.length) {
        warnings.push(`${hex8(w.addr)} maps past the end of the ELF image — skipped.`);
        continue;
      }
      writes.push({ offset: lba * SECTOR + fo, bytes: encodeLE(w.value, width), vaddr: w.addr >>> 0 });
    }
  }

  return { writes, warnings };
}
