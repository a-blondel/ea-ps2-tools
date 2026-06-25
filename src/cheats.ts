// Build OPL (.cht) and PCSX2 (.pnach) bypass output from the analysis.
// Two independent features per ELF: DNAS bypass and SSL bypass, each toggleable.

import { hex8 } from "./bytes.js";
import type { DnasAnalysis } from "./dnas.js";
import type { SslAnalysis } from "./ssl.js";
import { oriA3, type PortAnalysis } from "./port.js";

export interface ElfTarget {
  label: string; // "Main Game" | "EA Dashboard"
  dnas: DnasAnalysis;
  ssl: SslAnalysis;
  port: PortAnalysis | null; // game port: data-word or connect-site (null if none)
  crc?: number; // PCSX2 ELF CRC, for the pnach filename
  enable: { dnas: boolean; ssl: boolean; port: boolean }; // UI toggles (port off by default)
}

interface Write {
  addr: number;
  value: number;
}

// PS2 cheat codes are one command nibble + a 28-bit (7-hex) EE address,
// e.g. command 2 + address 0x05C8028 -> "205C8028".
function code(cmd: string, addr: number): string {
  return cmd + (addr & 0x0fffffff).toString(16).toUpperCase().padStart(7, "0");
}

/** Port writes for one ELF: overwrite the data word, or rewrite the lw a3 loads. */
function portWrites(t: ElfTarget, port: number | null): Write[] {
  if (!t.enable.port || !t.port || port == null) return [];
  if (t.port.kind === "data") return t.port.sites.map((a) => ({ addr: a, value: port >>> 0 }));
  return t.port.sites.map((a) => ({ addr: a, value: oriA3(port) }));
}

/**
 * Memory writes a target contributes, honouring its enable toggles and the
 * optional `port` value (decimal port the user typed, applied when its checkbox
 * is ticked).
 */
function patchWrites(t: ElfTarget, port: number | null): Write[] {
  const out: Write[] = [];
  if (t.enable.dnas && t.dnas.bne) out.push({ addr: t.dnas.bne.vaddr, value: 0 });
  if (t.enable.ssl && t.ssl.port) out.push({ addr: t.ssl.port.vaddr, value: t.ssl.port.value });
  if (t.enable.ssl && t.ssl.secure) out.push({ addr: t.ssl.secure.vaddr, value: t.ssl.secure.value });
  out.push(...portWrites(t, port));
  return out;
}

/** "DNAS + SSL + PORT", etc — whichever features are enabled and present. */
function featureLabel(t: ElfTarget, port: number | null): string {
  const f: string[] = [];
  if (t.enable.dnas && t.dnas.bne) f.push("DNAS");
  if (t.enable.ssl && (t.ssl.port || t.ssl.secure)) f.push("SSL");
  if (portWrites(t, port).length > 0) f.push("PORT");
  return f.join(" + ");
}

/**
 * OPL .cht — Open-PS2-Loader / PS2RD cheat format. The first line is the cheat
 * entry name: a quoted `"<title> /ID <serial>"`. Lines starting with "//" are
 * comments the parser strips, so we use them as section headers. Each ELF with a
 * runtime hook (9x) gets a section; OPL applies the whole code list whenever any
 * hook fires, so every enabled patch is repeated under each hook (the duplicate
 * writes are harmless and mirror the proven community cheat).
 */
export function buildCht(
  serial: string,
  title: string,
  targets: ElfTarget[],
  port?: number | null,
): string {
  const pn = port ?? null;
  const allWrites = targets.flatMap((t) => patchWrites(t, pn));
  const patchLines = allWrites.map((w) => `${code("2", w.addr)} ${hex8(w.value)}`);

  const groups: string[] = [];
  for (const t of targets) {
    if (!t.dnas.hook) continue;
    if (patchWrites(t, pn).length === 0) continue; // nothing enabled for this ELF
    groups.push(
      `//Online patches for ${t.label}: ${featureLabel(t, pn)}\n` +
        `${code("9", t.dnas.hook.vaddr)} ${hex8(t.dnas.hook.value)}\n` +
        patchLines.join("\n") + "\n",
    );
  }

  let out = `"${title} /ID ${serial}"\n`;
  if (groups.length > 0) {
    out += groups.join("\n"); // blank line between sections
  } else if (patchLines.length > 0) {
    out += `//Online patches\n` + patchLines.join("\n") + "\n";
  }
  return out;
}

/** PCSX2 serial form: hyphen, no dot. "SLUS_214.33" -> "SLUS-21433". */
export function pcsx2Serial(serial: string): string {
  return serial.toUpperCase().replace("_", "-").replace(/\./g, "");
}

export interface PnachFile {
  filename: string; // SERIAL_CRC.pnach
  content: string;
}

/**
 * PCSX2 .pnach — one file per ELF. PCSX2 picks the file whose CRC (in the
 * filename) matches the ELF it is currently running, so each file patches only
 * its own addresses and needs no runtime hook. Every enabled write for that ELF
 * becomes a `patch=` line.
 */
export function buildPnach(
  serial: string,
  targets: ElfTarget[],
  port?: number | null,
): PnachFile[] {
  const ser = pcsx2Serial(serial);
  const pn = port ?? null;
  const files: PnachFile[] = [];
  for (const t of targets) {
    if (t.crc === undefined) continue;
    const writes = patchWrites(t, pn);
    if (writes.length === 0) continue;
    const lines = writes.map(
      (w) => `patch=1,EE,${code("2", w.addr)},extended,${hex8(w.value)}`,
    );
    files.push({
      filename: `${ser}_${hex8(t.crc)}.pnach`,
      content:
        `[Network\\Online Patches]\n` +
        `author=EA Nation Hub\n` +
        `description=Online patches: ${featureLabel(t, pn)}\n` +
        lines.join("\n") + "\n",
    });
  }
  return files;
}

/** Derive the .cht filename OPL expects: serial with "_" and "." kept. */
export function chtFilename(serial: string): string {
  return `${serial}.cht`;
}
