// Build OPL (.cht) and PCSX2 (.pnach) DNAS-bypass output from the analysis.

import { hex8 } from "./bytes.js";
import type { DnasAnalysis } from "./dnas.js";

export interface ElfTarget {
  label: string; // "Main Game" | "EA Dashboard"
  analysis: DnasAnalysis;
  crc?: number; // PCSX2 ELF CRC, for the pnach filename
}

// PS2 cheat codes are one command nibble + a 28-bit (7-hex) EE address,
// e.g. command 2 + address 0x05C8028 -> "205C8028".
function code(cmd: string, addr: number): string {
  return cmd + (addr & 0x0fffffff).toString(16).toUpperCase().padStart(7, "0");
}

/**
 * OPL .cht — Open-PS2-Loader / PS2RD cheat format. The first line is the cheat
 * entry name: a quoted `"<title> /ID <serial>"` (no leading "//", so the OPL
 * parser keeps it). Lines starting with "//" are comments the parser strips, so
 * we use them as section headers. All hooks (9x) and BNE patches (2x) live under
 * that single entry; OPL applies the whole code list at each hook firing.
 *
 * Each section repeats both BNE patches after its hook, mirroring the proven
 * community cheat; the duplicate writes are harmless.
 */
export function buildCht(serial: string, title: string, targets: ElfTarget[]): string {
  const patchLines: string[] = [];
  for (const t of targets) {
    if (t.analysis.bne) patchLines.push(`${code("2", t.analysis.bne.vaddr)} 00000000`);
  }

  const groups: string[] = [];
  for (const t of targets) {
    if (!t.analysis.hook) continue;
    groups.push(
      `//DNAS bypass ${t.label}\n` +
        `${code("9", t.analysis.hook.vaddr)} ${hex8(t.analysis.hook.value)}\n` +
        patchLines.join("\n") + "\n",
    );
  }

  let out = `"${title} /ID ${serial}"\n`;
  if (groups.length > 0) {
    out += groups.join("\n"); // blank line between sections
  } else if (patchLines.length > 0) {
    out += `//DNAS bypass\n` + patchLines.join("\n") + "\n";
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
 * its own BNE and needs no runtime hook. The filename keeps the disc serial as
 * prefix for both files; only the CRC differs (main ELF vs EA_DASH).
 */
export function buildPnach(serial: string, targets: ElfTarget[]): PnachFile[] {
  const ser = pcsx2Serial(serial);
  const files: PnachFile[] = [];
  for (const t of targets) {
    if (!t.analysis.bne || t.crc === undefined) continue;
    files.push({
      filename: `${ser}_${hex8(t.crc)}.pnach`,
      content:
        `[Network\\DNAS Patch]\n` +
        `author=EA Nation Hub\n` +
        `description=DNAS check bypass\n` +
        `patch=1,EE,${code("2", t.analysis.bne.vaddr)},extended,00000000\n`,
    });
  }
  return files;
}

/** Derive the .cht filename OPL expects: serial with "_" and "." kept. */
export function chtFilename(serial: string): string {
  return `${serial}.cht`;
}
