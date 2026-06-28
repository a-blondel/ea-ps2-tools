// Game-domain override for EA PS2 ELFs.
//
// EA online titles phone home to "<codename>.ea.com" (the same hostname the
// title guess is derived from). To point a game at a revival server you can
// rewrite that hostname string in place. We replace it with a shorter (or equal)
// host and pad the rest with NUL — but ONLY into the bytes that are already
// empty: the original host plus the run of NUL padding that follows it. We never
// write past the first non-zero byte, so neighbouring strings stay intact.
//
// The patch is emitted as byte writes (raw PS2 code command nibble 0), so the
// host need not be word-aligned.

import { Elf } from "./elf.js";
import { ascii, findAll } from "./bytes.js";

// Hosts that appear across many EA builds and aren't the game codename
// (kept in sync with title.ts).
const NOISE = /demangler|dirtysock/i;

const HOST_CHAR = (b: number) =>
  (b >= 0x61 && b <= 0x7a) || // a-z
  (b >= 0x41 && b <= 0x5a) || // A-Z
  (b >= 0x30 && b <= 0x39) || // 0-9
  b === 0x2e || b === 0x2d; // . -

export interface DomainSite {
  vaddr: number; // start of the host string
  hostLen: number; // length of the original host
  capacity: number; // hostLen + trailing NUL run = max bytes we may write here
}

export interface DomainAnalysis {
  host: string; // located EA hostname, e.g. "ps2sims04.ea.com"
  sites: DomainSite[]; // every standalone occurrence in this ELF
  capacity: number; // smallest site capacity (the binding limit)
}

/** Most-frequent non-noise `<host>.ea.com` hostname in the ELF, or null. */
function findEaHost(elf: Elf): string | null {
  const text = new TextDecoder("latin1").decode(elf.data);
  const re = /[a-z0-9][a-z0-9.-]*\.ea\.com/gi;
  const counts = new Map<string, number>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const host = m[0].toLowerCase();
    if (NOISE.test(host)) continue;
    counts.set(host, (counts.get(host) ?? 0) + 1);
  }
  let best: string | null = null;
  let bestCount = 0;
  for (const [host, c] of counts) {
    if (c > bestCount) {
      best = host;
      bestCount = c;
    }
  }
  return best;
}

/** Bytes of NUL padding directly after `end` (exclusive upper bound = data end). */
function trailingNulRun(elf: Elf, end: number): number {
  let z = 0;
  while (end + z < elf.data.length && elf.data[end + z] === 0) z++;
  return z;
}

/**
 * Locate the override target. Pass `forceHost` to search a specific hostname
 * (used for the dashboard, so it patches the SAME game domain the main ELF uses
 * rather than its own most-frequent host, which is often a leftover test lobby).
 */
export function analyzeDomain(elf: Elf, forceHost?: string): DomainAnalysis | null {
  const host = forceHost ?? findEaHost(elf);
  if (!host) return null;
  const needle = ascii(host);
  const sites: DomainSite[] = [];
  for (const off of findAll(elf.data, needle)) {
    const after = off + needle.length;
    // Skip a match that is only a prefix of a longer host (next char is a host
    // char), so we measure the real string's padding.
    if (after < elf.data.length && HOST_CHAR(elf.data[after]!)) continue;
    const vaddr = elf.fileToVaddr(off);
    if (vaddr === null) continue;
    const capacity = needle.length + trailingNulRun(elf, after);
    sites.push({ vaddr, hostLen: needle.length, capacity });
  }
  if (sites.length === 0) return null;
  const capacity = sites.reduce((min, s) => Math.min(min, s.capacity), Infinity);
  return { host, sites, capacity };
}

/** True when `replacement` is a syntactically valid host that fits every site. */
export function domainFits(d: DomainAnalysis, replacement: string): boolean {
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(replacement)) return false;
  return replacement.length + 1 <= d.capacity; // +1 for the NUL terminator
}
