// Small byte helpers used across the parsers. Browser-safe (no Buffer).

/** Parse a hex string like "2D28000006005014" into a Uint8Array. */
export function hex(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

/** ASCII string into bytes. */
export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Find every offset where `needle` occurs in `hay`. */
export function findAll(hay: Uint8Array, needle: Uint8Array): number[] {
  const res: number[] = [];
  if (needle.length === 0) return res;
  const last = hay.length - needle.length;
  outer: for (let i = 0; i <= last; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    res.push(i);
  }
  return res;
}

/** 8-digit uppercase hex, the form PS2 cheat codes use. */
export function hex8(n: number): string {
  return (n >>> 0).toString(16).toUpperCase().padStart(8, "0");
}
