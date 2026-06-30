// Unit test for the inline streaming patcher: every patch byte must land at its
// absolute offset in the streamed output, including a write that straddles a
// chunk boundary, and untouched bytes must pass through verbatim. No ISO needed.
import assert from "node:assert";
import { makePatchedStream } from "../.tmp/isostream.js";

/** Drain a ReadableStream into a flat byte array. */
async function drain(stream) {
  const reader = stream.getReader();
  const out = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out.push(...value);
  }
  return out;
}

// Source = bytes 0..19. Small chunkSize (8) forces multiple blocks + a straddle.
const SIZE = 20;
const base = new Uint8Array(SIZE);
for (let i = 0; i < SIZE; i++) base[i] = i;

const fakeFile = {
  size: SIZE,
  slice(s, e) {
    return { async arrayBuffer() { return base.slice(s, e).buffer; } };
  },
};

const writes = [
  { offset: 2, bytes: new Uint8Array([0xaa, 0xbb]), vaddr: 0 }, // inside block 0
  { offset: 7, bytes: new Uint8Array([0xc1, 0xc2, 0xc3]), vaddr: 0 }, // straddles 0/1 (7|8,9)
  { offset: 16, bytes: new Uint8Array([0xff]), vaddr: 0 }, // start of block 2
];

const progress = [];
const out = await drain(makePatchedStream(fakeFile, writes, (f) => progress.push(f), 8));

assert.equal(out.length, SIZE, "output length = source length");

const expected = [...base];
expected[2] = 0xaa;
expected[3] = 0xbb;
expected[7] = 0xc1;
expected[8] = 0xc2; // landed in the next chunk
expected[9] = 0xc3;
expected[16] = 0xff;
assert.deepEqual(out, expected, "patch bytes overlaid at the right offsets, rest verbatim");

// Progress monotonic and ends at 1.
assert.equal(progress[progress.length - 1], 1, "progress ends at 100%");
for (let i = 1; i < progress.length; i++) assert.ok(progress[i] > progress[i - 1], "progress increases");

// A write past EOF simply never appears (no throw, no overlap).
const out2 = await drain(
  makePatchedStream(fakeFile, [{ offset: 100, bytes: new Uint8Array([1]), vaddr: 0 }], undefined, 8),
);
assert.deepEqual(out2, [...base], "out-of-range write is a no-op");

console.log("ISO STREAM INLINE PATCH PASSED ✓");
