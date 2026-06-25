// Game port detection + patching for EA PS2 ELFs.
//
// Two eras store the port differently, so we use two strategies:
//
// (1) DATA-WORD (FIFA 07 era): the port is a 32-bit word in .data, read by a
//     trivial getter `lui rX,hi; lw v0,lo(rX); jr ra` whose result feeds
//     `_TagFieldSetNumber(buf,len,"PORT",value)`. We anchor on the "PORT" tag
//     key, walk to the getter, recover the .data address and read the value.
//     Patch = overwrite that word (source of truth → both connect and the tag
//     announced to the lobby use the new port). Lets us also DISPLAY the value.
//
// (2) CONNECT-SITE (NASCAR 06 / older): the port is loaded into a3 from a struct
//     field right before `jal ProtoAriesConnect`; the literal lives in an
//     immediate leaf-getter reached through a .data pointer table, with no clean
//     static anchor. Instead we patch the connect itself: both `lw a3,OFF(s1)`
//     loads before the SSL/connect anchor become `ori a3,zero,<port>`. Forces
//     the lobby to dial the chosen port (the secure path's `+1` still applies).
//     We can't read the current value statically, so the field is left blank.
//
// Validated: FIFA 07 main → data word 0x725C5C = 10400; FIFA 07 dash + NASCAR 06
// main/dash → connect-site (2 loads each, OFF 0x1820 / 0x1840).

import { Elf } from "./elf.js";
import type { SslAnalysis } from "./ssl.js";

// "PORT\0" — the NUL terminator keeps us off substrings like "SUPPORT".
const PORT_KEY = new Uint8Array([0x50, 0x4f, 0x52, 0x54, 0x00]);

export interface PortAnalysis {
  kind: "data" | "connect";
  value: number | null; // current port (null = couldn't read statically)
  sites: number[]; // vaddrs to patch (data: 1 word; connect: the lw a3 loads)
}

/** `ori a3, zero, port` — the connect-site replacement for `lw a3, OFF(s1)`. */
export function oriA3(port: number): number {
  return (0x34070000 | (port & 0xffff)) >>> 0;
}

// ---- strategy (1): data-word getter via the "PORT" tag --------------------

function resolveGetter(elf: Elf, refFo: number): { addr: number; value: number } | null {
  const seg = elf.codeSegment;
  let getter = -1;
  for (let fo = refFo - 4; fo >= refFo - 12 * 4 && fo >= seg.off; fo -= 4) {
    const w = elf.readU32(fo);
    if (w >>> 26 === 3 /* JAL */) {
      getter = ((w & 0x03ffffff) << 2) >>> 0;
      break;
    }
  }
  if (getter < 0) return null;
  const gfo = elf.vaddrToFile(getter);
  if (gfo === null) return null;

  let hi = -1;
  let hiReg = -1;
  let dataVa = -1;
  for (let fo = gfo; fo < gfo + 8 * 4 && fo + 4 <= elf.data.length; fo += 4) {
    const w = elf.readU32(fo);
    const op = w >>> 26;
    if (op === 0x0f /* LUI */) {
      hiReg = (w >>> 16) & 0x1f;
      hi = w & 0xffff;
    } else if (op === 0x23 /* LW */) {
      const base = (w >>> 21) & 0x1f;
      let off = w & 0xffff;
      if (off & 0x8000) off -= 0x10000;
      if (base === hiReg && hi >= 0) {
        dataVa = (((hi & 0xffff) << 16) + off) >>> 0;
        break;
      }
    }
  }
  if (dataVa < 0) return null;
  const dfo = elf.vaddrToFile(dataVa);
  if (dfo === null || dfo + 4 > elf.data.length) return null;
  const value = elf.readU32(dfo);
  if (value < 1 || value > 0xffff) return null; // implausible port
  return { addr: dataVa, value };
}

function detectDataWord(elf: Elf): { addr: number; value: number } | null {
  const strVas = new Set<number>();
  for (const fo of elf.find(PORT_KEY)) {
    const v = elf.fileToVaddr(fo);
    if (v !== null) strVas.add(v);
  }
  if (strVas.size === 0) return null;

  const seg = elf.codeSegment;
  const luiImm = new Int32Array(32).fill(-1);
  const found = new Map<number, number>(); // addr -> value
  for (let fo = seg.off; fo + 4 <= seg.off + seg.filesz; fo += 4) {
    const w = elf.readU32(fo);
    const op = w >>> 26;
    if (op === 0x0f) {
      luiImm[(w >>> 16) & 0x1f] = w & 0xffff;
    } else if (op === 0x09 /* ADDIU */) {
      const rs = (w >>> 21) & 0x1f;
      const rt = (w >>> 16) & 0x1f;
      let imm = w & 0xffff;
      if (imm & 0x8000) imm -= 0x10000;
      const hi = luiImm[rs] ?? -1;
      if (rt === rs && hi !== -1) {
        const tgt = (((hi & 0xffff) << 16) + imm) >>> 0;
        if (strVas.has(tgt)) {
          const info = resolveGetter(elf, fo);
          if (info) found.set(info.addr, info.value);
        }
      }
    }
  }
  const addrs = [...found.keys()].sort((a, b) => a - b);
  const addr = addrs[0];
  return addr === undefined ? null : { addr, value: found.get(addr)! };
}

// ---- strategy (2): connect-site `lw a3, OFF(s1)` loads --------------------

function detectConnect(elf: Elf, ssl: SslAnalysis): number[] | null {
  if (!ssl.port) return null; // no SSL/connect anchor
  const siteFo = elf.vaddrToFile(ssl.port.vaddr);
  if (siteFo === null) return null;
  const seg = elf.codeSegment;

  const loads: { va: number; off: number }[] = [];
  for (let fo = siteFo - 4; fo >= siteFo - 40 * 4 && fo >= seg.off; fo -= 4) {
    const w = elf.readU32(fo);
    const op = w >>> 26;
    // stop at the function prologue: `addiu sp, sp, -N`
    if (op === 0x09 && ((w >>> 16) & 0x1f) === 29 && ((w >>> 21) & 0x1f) === 29) {
      let im = w & 0xffff;
      if (im & 0x8000) im -= 0x10000;
      if (im < 0) break;
    }
    if (op === 0x23 /* LW */ && ((w >>> 16) & 0x1f) === 7 /* a3 */) {
      const va = elf.fileToVaddr(fo);
      if (va !== null) loads.push({ va, off: w & 0xffff });
    }
  }
  if (loads.length === 0) return null;
  // keep the loads sharing the most common offset (the port struct field)
  const counts = new Map<number, number>();
  for (const l of loads) counts.set(l.off, (counts.get(l.off) ?? 0) + 1);
  let bestOff = loads[0]!.off;
  let best = 0;
  for (const [o, c] of counts) if (c > best) (best = c), (bestOff = o);
  return loads.filter((l) => l.off === bestOff).map((l) => l.va);
}

export function analyzePort(elf: Elf, ssl: SslAnalysis): PortAnalysis | null {
  const dw = detectDataWord(elf);
  if (dw) return { kind: "data", value: dw.value, sites: [dw.addr] };
  const conn = detectConnect(elf, ssl);
  if (conn) return { kind: "connect", value: null, sites: conn };
  return null;
}
