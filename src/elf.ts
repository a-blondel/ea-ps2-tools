// Minimal ELF32 little-endian (MIPS / PS2 EE) reader.
// We only need: PT_LOAD segments, file-offset <-> virtual-address mapping,
// raw u32 reads, and pattern search.

import { findAll } from "./bytes.js";

export interface Segment {
  off: number; // p_offset
  vaddr: number; // p_vaddr
  filesz: number; // p_filesz
}

export class Elf {
  readonly data: Uint8Array;
  private readonly dv: DataView;
  readonly segments: Segment[];

  constructor(data: Uint8Array) {
    this.data = data;
    this.dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.segments = this.parseProgramHeaders();
  }

  /** ELF magic 7F 45 4C 46. */
  static isElf(data: Uint8Array): boolean {
    return (
      data.length >= 4 &&
      data[0] === 0x7f &&
      data[1] === 0x45 &&
      data[2] === 0x4c &&
      data[3] === 0x46
    );
  }

  private parseProgramHeaders(): Segment[] {
    if (!Elf.isElf(this.data)) throw new Error("Not an ELF file");
    const phoff = this.dv.getUint32(0x1c, true);
    const phentsize = this.dv.getUint16(0x2a, true);
    const phnum = this.dv.getUint16(0x2c, true);
    const segs: Segment[] = [];
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phentsize;
      if (o + 32 > this.data.length) break;
      const p_type = this.dv.getUint32(o, true);
      if (p_type !== 1 /* PT_LOAD */) continue;
      segs.push({
        off: this.dv.getUint32(o + 4, true),
        vaddr: this.dv.getUint32(o + 8, true),
        filesz: this.dv.getUint32(o + 16, true),
      });
    }
    if (segs.length === 0) throw new Error("ELF has no PT_LOAD segments");
    return segs;
  }

  /** File offset -> virtual address, or null if not in any loaded segment. */
  fileToVaddr(fo: number): number | null {
    for (const s of this.segments) {
      if (fo >= s.off && fo < s.off + s.filesz) return (fo - s.off + s.vaddr) >>> 0;
    }
    return null;
  }

  /** Virtual address -> file offset, or null. */
  vaddrToFile(va: number): number | null {
    for (const s of this.segments) {
      if (va >= s.vaddr && va < s.vaddr + s.filesz) return va - s.vaddr + s.off;
    }
    return null;
  }

  readU32(fo: number): number {
    return this.dv.getUint32(fo, true) >>> 0;
  }

  /**
   * PCSX2's ELF CRC: XOR of every little-endian 32-bit word of the whole file
   * (trailing bytes that don't fill a word are ignored). This is the value
   * PCSX2 puts in pnach filenames: SERIAL_CRC.pnach.
   */
  crc(): number {
    let c = 0;
    const n = Math.floor(this.data.length / 4);
    for (let i = 0; i < n; i++) c = (c ^ this.dv.getUint32(i * 4, true)) >>> 0;
    return c >>> 0;
  }

  find(pattern: Uint8Array): number[] {
    return findAll(this.data, pattern);
  }

  /** The (first) executable PT_LOAD segment — code lives here. */
  get codeSegment(): Segment {
    return this.segments[0]!;
  }
}
