// High-level glue with no DOM/File dependency, so it runs under node tests too.
// Input is the set of ELF blobs already pulled out of the ISO.

import { Elf } from "./elf.js";
import { analyzeDnas } from "./dnas.js";
import { analyzeSsl } from "./ssl.js";
import { analyzePort } from "./port.js";
import { analyzeDomain } from "./domain.js";
import { analyzeRoster } from "./roster.js";
import { guessTitle } from "./title.js";
import type { ElfTarget } from "./cheats.js";

export interface NamedBlob {
  name: string; // bare filename, e.g. "SLUS_214.33" or "EA_DASH.ELF"
  path: string; // full ISO path for display
  data: Uint8Array;
}

export interface GameAnalysis {
  serial: string;
  title: string; // best-effort guess from the main ELF, editable in the UI
  port: number | null; // detected game port (shared across ELFs), editable
  domain: string | null; // located EA hostname (shared across ELFs), editable
  targets: ElfTarget[]; // main first, then dashboard(s)
  warnings: string[];
}

/** Read BOOT2 = cdrom0:\SLUS_214.33;1 out of SYSTEM.CNF text. */
export function parseSerial(systemCnf: string): string | null {
  const m = systemCnf.match(/BOOT2\s*=\s*cdrom0:\\?([^\s;]+)/i);
  return m ? m[1]!.replace(/^\\/, "") : null;
}

const isElf = (b: NamedBlob) => Elf.isElf(b.data);

export function analyzeGame(serial: string, blobs: NamedBlob[]): GameAnalysis {
  const warnings: string[] = [];
  const elfs = blobs.filter(isElf);

  const mainBlob = elfs.find((b) => b.name.toUpperCase() === serial.toUpperCase());
  const dashBlob = elfs.find((b) => b.name.toUpperCase() === "EA_DASH.ELF");

  const targets: ElfTarget[] = [];
  let gameHost: string | null = null; // the main ELF's EA hostname, reused for the dash

  if (mainBlob) {
    const e = new Elf(mainBlob.data);
    const dnas = analyzeDnas(e);
    const ssl = analyzeSsl(e);
    const port = analyzePort(e, ssl);
    const domain = analyzeDomain(e);
    const roster = analyzeRoster(e);
    gameHost = domain?.host ?? null;
    if (!dnas.bne) warnings.push("No DNAS check found in the main ELF.");
    if (dnas.ambiguous) warnings.push("Main ELF: multiple DNAS candidates — verify the selected address.");
    if (!ssl.port) warnings.push("No SSL (ProtoAriesSecure) site found in the main ELF.");
    if (!port) warnings.push("No game port found in the main ELF.");
    targets.push({ label: "Main Game", dnas, ssl, port, domain, roster, crc: e.crc(), enable: { dnas: true, ssl: false, roster: false, port: false, domain: false } });
  } else {
    warnings.push(`Main ELF "${serial}" not found in the ISO.`);
  }

  if (dashBlob) {
    const e = new Elf(dashBlob.data);
    const dnas = analyzeDnas(e);
    const ssl = analyzeSsl(e);
    const port = analyzePort(e, ssl);
    // Reuse the main ELF's host so we patch the real game domain, not the
    // dashboard's most-frequent (often a leftover test lobby) host.
    const domain = gameHost ? analyzeDomain(e, gameHost) : analyzeDomain(e);
    const roster = analyzeRoster(e);
    if (!dnas.bne) warnings.push("No DNAS check found in EA_DASH.ELF.");
    if (dnas.ambiguous) warnings.push("EA_DASH: multiple DNAS candidates — verify the selected address.");
    if (!ssl.port) warnings.push("No SSL (ProtoAriesSecure) site found in EA_DASH.ELF.");
    targets.push({ label: "EA Dashboard", dnas, ssl, port, domain, roster, crc: e.crc(), enable: { dnas: true, ssl: false, roster: false, port: false, domain: false } });
  } else {
    warnings.push("EA_DASH.ELF not found — dashboard cheat will be omitted.");
  }

  const title = mainBlob ? guessTitle(mainBlob.data, serial) : serial;
  // Display value: the port we could read statically from any ELF (null if only
  // connect-site patching is available, e.g. NASCAR — user enters it manually).
  const port = targets.find((t) => t.port?.value != null)?.port?.value ?? null;
  // Display value: the EA hostname located in any ELF (same across ELFs).
  const domain = targets.find((t) => t.domain)?.domain?.host ?? null;
  return { serial, title, port, domain, targets, warnings };
}
