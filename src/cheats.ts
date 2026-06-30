// Build OPL (.cht) and PCSX2 (.pnach) output from the analysis.
// Each feature is an independent, separately-described block: DNAS bypass, SSL
// bypass, game-port override and domain override. Every block is toggleable per
// ELF; the .pnach emits one `[section]` per block, the .cht one comment-headed
// group of codes per block.

import { hex8, ascii } from "./bytes.js";
import type { DnasAnalysis } from "./dnas.js";
import type { SslAnalysis } from "./ssl.js";
import { oriA3, type PortAnalysis } from "./port.js";
import { domainFits, type DomainAnalysis } from "./domain.js";

export interface ElfTarget {
  label: string; // "Main Game" | "EA Dashboard"
  dnas: DnasAnalysis;
  ssl: SslAnalysis;
  port: PortAnalysis | null; // game port: data-word or connect-site (null if none)
  domain: DomainAnalysis | null; // EA hostname override target (null if none)
  crc?: number; // PCSX2 ELF CRC, for the pnach filename
  enable: { dnas: boolean; ssl: boolean; port: boolean; domain: boolean }; // UI toggles
}

export interface Write {
  addr: number;
  value: number;
  width?: 1 | 2 | 4; // bytes written (default 4 = word); 2 = halfword; 1 = byte
}

interface Block {
  title: string; // section name, e.g. "DNAS bypass"
  description: string; // one-line human description
  writes: Write[];
}

// PS2 cheat codes are one command nibble + a 28-bit (7-hex) EE address.
// Command 2 = 32-bit write, 0 = 8-bit write, e.g. 2+0x05C8028 -> "205C8028".
function code(cmdNibble: string, addr: number): string {
  return cmdNibble + (addr & 0x0fffffff).toString(16).toUpperCase().padStart(7, "0");
}

/** Command nibble for a write width: byte -> "0", halfword -> "1", word -> "2". */
function cmd(width?: 1 | 2 | 4): string {
  return width === 1 ? "0" : width === 2 ? "1" : "2";
}

/**
 * Pack a contiguous run of bytes into the fewest aligned writes: a 32-bit word
 * only on a 4-aligned address, a 16-bit halfword on a 2-aligned address, else a
 * single byte. Keeping every write naturally aligned avoids the address-error
 * fault an unaligned word store would raise on the EE. Little-endian: byte i
 * lands in the low 8 bits of its chunk.
 */
function packAligned(base: number, bytes: number[]): Write[] {
  const out: Write[] = [];
  const n = bytes.length;
  let i = 0;
  while (i < n) {
    const addr = base + i;
    const rem = n - i;
    if (addr % 4 === 0 && rem >= 4) {
      out.push({
        addr,
        value: (bytes[i]! | (bytes[i + 1]! << 8) | (bytes[i + 2]! << 16) | (bytes[i + 3]! << 24)) >>> 0,
        width: 4,
      });
      i += 4;
    } else if (addr % 2 === 0 && rem >= 2) {
      out.push({ addr, value: (bytes[i]! | (bytes[i + 1]! << 8)) >>> 0, width: 2 });
      i += 2;
    } else {
      out.push({ addr, value: bytes[i]!, width: 1 });
      i += 1;
    }
  }
  return out;
}

/** Port writes for one ELF: overwrite the data word, or rewrite the lw a3 loads. */
function portWrites(t: ElfTarget, port: number | null): Write[] {
  if (!t.enable.port || !t.port || port == null) return [];
  if (t.port.kind === "data") return t.port.sites.map((a) => ({ addr: a, value: port >>> 0 }));
  return t.port.sites.map((a) => ({ addr: a, value: oriA3(port) }));
}

/**
 * Domain writes for one ELF: byte-rewrite each occurrence of the located EA
 * hostname with `domain`, padding with NUL. Only bytes that actually change are
 * emitted, and only inside the original host + its trailing NUL run (validated
 * by domainFits), so neighbouring data is never touched.
 */
function domainWrites(t: ElfTarget, domain: string | null): Write[] {
  if (!t.enable.domain || !t.domain || !domain) return [];
  const d = t.domain;
  if (!domainFits(d, domain)) return [];
  const repl = ascii(domain);
  const out: Write[] = [];
  for (const s of d.sites) {
    // Shorter/equal host: write the whole old host (replacement + NUL erase its
    // tail), but stop there — the trailing padding NULs stay untouched. Longer:
    // just the replacement; the padding NUL already after it terminates the
    // string, so no extra terminator write is needed.
    const writeLen = Math.max(repl.length, s.hostLen);
    const bytes: number[] = [];
    for (let i = 0; i < writeLen; i++) bytes.push(i < repl.length ? repl[i]! : 0);
    out.push(...packAligned(s.vaddr, bytes));
  }
  return out;
}

/** The enabled feature blocks for one ELF, in display order. */
function targetBlocks(t: ElfTarget, port: number | null, domain: string | null): Block[] {
  const blocks: Block[] = [];
  if (t.enable.dnas && t.dnas.bne) {
    blocks.push({
      title: "DNAS bypass",
      description: "Skip the DNAS authentication check.",
      writes: [{ addr: t.dnas.bne.vaddr, value: 0 }],
    });
  }
  if (t.enable.ssl && (t.ssl.port || t.ssl.secure)) {
    const writes: Write[] = [];
    if (t.ssl.port) writes.push({ addr: t.ssl.port.vaddr, value: t.ssl.port.value });
    if (t.ssl.secure) writes.push({ addr: t.ssl.secure.vaddr, value: t.ssl.secure.value });
    blocks.push({
      title: "SSL bypass",
      description: "Disable ProtoAries SSL on the lobby link.",
      writes,
    });
  }
  const pw = portWrites(t, port);
  if (pw.length) {
    blocks.push({ title: "Game port", description: `Set the game port to ${port}.`, writes: pw });
  }
  const dw = domainWrites(t, domain);
  if (dw.length) {
    blocks.push({
      title: "Domain override",
      description: `Redirect the EA hostname to "${domain}".`,
      writes: dw,
    });
  }
  return blocks;
}

/**
 * Every enabled write for one ELF, flattened across its feature blocks in
 * display order. This is the same write list the .cht/.pnach emit as cheat
 * codes; the in-place ISO patcher consumes it to seek + write the bytes
 * directly (see isopatch.ts).
 */
export function targetWrites(t: ElfTarget, port: number | null = null, domain: string | null = null): Write[] {
  return targetBlocks(t, port, domain).flatMap((b) => b.writes);
}

// Display order the merged .cht blocks keep, regardless of contributing ELF.
const BLOCK_ORDER = ["DNAS bypass", "SSL bypass", "Game port", "Domain override"];

/**
 * Union of every ELF's blocks, merged by title (writes de-duplicated by address
 * + value). OPL applies the whole code list whenever any hook fires, so the .cht
 * carries every ELF's writes under each hook; merging keeps one labelled section
 * per feature instead of repeating the ELF split.
 */
function mergeBlocks(targets: ElfTarget[], port: number | null, domain: string | null): Block[] {
  const map = new Map<string, Block>();
  for (const t of targets) {
    for (const b of targetBlocks(t, port, domain)) {
      const ex = map.get(b.title);
      if (!ex) {
        map.set(b.title, { title: b.title, description: b.description, writes: [...b.writes] });
      } else {
        for (const w of b.writes) {
          if (!ex.writes.some((x) => x.addr === w.addr && x.value === w.value)) ex.writes.push(w);
        }
      }
    }
  }
  return BLOCK_ORDER.filter((t) => map.has(t)).map((t) => map.get(t)!);
}

const writeLine = (w: Write): string => `${code(cmd(w.width), w.addr)} ${hex8(w.value)}`;

/**
 * OPL .cht — Open-PS2-Loader / PS2RD cheat format. The first line is the cheat
 * entry name, a quoted `"<title> /ID <serial>"`. Lines starting with "//" are
 * comments the parser strips, so we use them as block headers. Each ELF with a
 * runtime hook (9x) gets a section; under it every feature block is printed with
 * its description comment followed by its codes.
 */
export function buildCht(
  serial: string,
  title: string,
  targets: ElfTarget[],
  port?: number | null,
  domain?: string | null,
): string {
  const pn = port ?? null;
  const dn = domain ?? null;
  const blocks = mergeBlocks(targets, pn, dn);

  const renderBlocks = (): string =>
    blocks
      .map((b) => `//${b.title}: ${b.description}\n` + b.writes.map(writeLine).join("\n") + "\n")
      .join("");

  let out = `"${title} /ID ${serial}"\n`;
  if (blocks.length === 0) return out;

  const groups: string[] = [];
  for (const t of targets) {
    if (!t.dnas.hook) continue;
    groups.push(
      `//Online patches — ${t.label}\n` +
        `${code("9", t.dnas.hook.vaddr)} ${hex8(t.dnas.hook.value)}\n` +
        renderBlocks(),
    );
  }
  out += groups.length > 0 ? groups.join("\n") : renderBlocks();
  return out;
}

export interface PnachFile {
  filename: string; // SERIAL_CRC.pnach
  content: string;
}

/** PCSX2 serial form: hyphen, no dot. "SLUS_214.33" -> "SLUS-21433". */
export function pcsx2Serial(serial: string): string {
  return serial.toUpperCase().replace("_", "-").replace(/\./g, "");
}

/**
 * PCSX2 .pnach — one file per ELF. PCSX2 picks the file whose CRC (in the
 * filename) matches the ELF it is running, so each file patches only its own
 * addresses and needs no runtime hook. Every enabled feature becomes its own
 * `[section]` with an author + description, so each can be toggled individually.
 */
export function buildPnach(
  serial: string,
  targets: ElfTarget[],
  port?: number | null,
  domain?: string | null,
): PnachFile[] {
  const ser = pcsx2Serial(serial);
  const pn = port ?? null;
  const dn = domain ?? null;
  const files: PnachFile[] = [];
  for (const t of targets) {
    if (t.crc === undefined) continue;
    const blocks = targetBlocks(t, pn, dn);
    if (blocks.length === 0) continue;
    const content = blocks
      .map(
        (b) =>
          `[${b.title}]\n` +
          `author=EA Nation Hub\n` +
          `description=${b.description}\n` +
          b.writes
            .map((w) => `patch=1,EE,${code(cmd(w.width), w.addr)},extended,${hex8(w.value)}`)
            .join("\n") +
          "\n",
      )
      .join("\n");
    files.push({ filename: `${ser}_${hex8(t.crc)}.pnach`, content });
  }
  return files;
}

/** Derive the .cht filename OPL expects: serial with "_" and "." kept. */
export function chtFilename(serial: string): string {
  return `${serial}.cht`;
}
