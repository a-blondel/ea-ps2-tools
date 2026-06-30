// Produce the patched ISO as a native ReadableStream, so it can be piped
// straight into a StreamSaver download. Using a real ReadableStream + pipeTo
// (not a manual getWriter()/close()) lets StreamSaver TRANSFER the stream to its
// service worker: that's what makes the download finalise reliably (the close
// handshake travels with the transferred stream) and what makes Firefox work
// without the fragile keep-alive ping. A download stream can't seek, so we
// overlay the patch bytes inline as each chunk is produced. DOM-free enough for
// node tests (ReadableStream is a global in Node 18+).

import type { IsoWrite } from "./isopatch.js";

/** The slice of `file` we need: just size + a Blob-like slice() reader. */
export interface SliceSource {
  size: number;
  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

/**
 * Overlay every patch byte that falls inside the block `[chunkStart, chunkStart
 * + chunk.length)` onto `chunk`, in place. Writes are tiny (≤4 bytes) so one can
 * straddle a block boundary; we apply only the intersecting bytes and let the
 * rest land in the neighbouring block. `writes` must be sorted by offset.
 */
export function applyPatchesToChunk(chunk: Uint8Array, chunkStart: number, writes: IsoWrite[]): void {
  const end = chunkStart + chunk.length;
  for (const w of writes) {
    const ws = w.offset;
    const we = w.offset + w.bytes.length;
    if (we <= chunkStart || ws >= end) continue; // no overlap with this block
    const from = Math.max(ws, chunkStart);
    const to = Math.min(we, end);
    for (let i = from; i < to; i++) chunk[i - chunkStart] = w.bytes[i - ws]!;
  }
}

/**
 * A ReadableStream of the source ISO with the patch bytes baked in. `pull` reads
 * one `chunkSize` block per demand (so back-pressure is the stream's job, not
 * ours) and reports progress (0..1). Enqueues nothing past EOF and closes.
 */
export function makePatchedStream(
  file: SliceSource,
  writes: IsoWrite[],
  onProgress?: (frac: number) => void,
  chunkSize = 8 * 1024 * 1024,
): ReadableStream<Uint8Array> {
  const sorted = [...writes].sort((a, b) => a.offset - b.offset);
  let pos = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (pos >= file.size) {
        controller.close();
        return;
      }
      const end = Math.min(pos + chunkSize, file.size);
      const chunk = new Uint8Array(await file.slice(pos, end).arrayBuffer());
      applyPatchesToChunk(chunk, pos, sorted);
      controller.enqueue(chunk);
      pos = end;
      onProgress?.(pos / file.size);
    },
  });
}
