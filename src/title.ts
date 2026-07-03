// Best-effort game title guess. PS2 discs carry no reliable human title field,
// but EA online titles all phone home to "<codename>.ea.com". The hostname's
// leading label is a robust stand-in for the game name.
//
// We scan the main ELF, drop generic dev/test hosts, strip a leading platform
// token (ps2fifa07 -> fifa07), and uppercase. Falls back to the serial.

// Hosts that appear across many EA builds and aren't the game codename.
const NOISE = /demangler|msgconn|beta|dirtysock3/i;

// Leading platform tokens to drop from the codename.
const PLATFORM = /^(ps2)(?=[a-z])/i;

export function guessTitle(mainElf: Uint8Array, serial: string): string {
  const text = new TextDecoder("latin1").decode(mainElf);
  const re = /\b([a-z0-9][a-z0-9-]*)\.ea\.com\b/gi;

  const counts = new Map<string, number>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const label = m[1]!.toLowerCase();
    if (NOISE.test(label)) continue;
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  if (counts.size === 0) return serial;

  // most frequent label wins; ties resolved by first seen (Map order)
  let best = "";
  let bestCount = -1;
  for (const [label, c] of counts) {
    if (c > bestCount) {
      best = label;
      bestCount = c;
    }
  }

  const codename = best.replace(PLATFORM, "");
  return (codename || best).toUpperCase();
}
