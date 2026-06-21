// Minimal ISO 9660 reader for PS2 discs, backed by a browser File so we only
// read the few sectors we need (directory tree + the target ELFs), never the
// whole multi-GB image into memory.

const SECTOR = 2048;

export interface IsoFile {
  name: string; // identifier without the ";1" version suffix
  path: string; // full path for display, e.g. /EACN/BIN/EA_DASH.ELF
  lba: number;
  size: number;
}

export class Iso {
  constructor(private readonly file: File) {}

  private async read(offset: number, len: number): Promise<Uint8Array> {
    const blob = this.file.slice(offset, offset + len);
    return new Uint8Array(await blob.arrayBuffer());
  }

  async readFileData(f: IsoFile): Promise<Uint8Array> {
    return this.read(f.lba * SECTOR, f.size);
  }

  /** Walk the directory tree from the PVD root. */
  async listFiles(): Promise<IsoFile[]> {
    // Primary Volume Descriptor is at sector 16. Root directory record sits at
    // byte 156 within it.
    const pvd = await this.read(16 * SECTOR, SECTOR);
    const dv = new DataView(pvd.buffer, pvd.byteOffset, pvd.byteLength);
    const rootLba = dv.getUint32(156 + 2, true);
    const rootSize = dv.getUint32(156 + 10, true);

    const files: IsoFile[] = [];
    const visited = new Set<number>();
    await this.walk(rootLba, rootSize, "", files, visited);
    return files;
  }

  private async walk(
    lba: number,
    size: number,
    prefix: string,
    out: IsoFile[],
    visited: Set<number>,
  ): Promise<void> {
    if (visited.has(lba)) return; // guard against malformed/looping discs
    visited.add(lba);

    const data = await this.read(lba * SECTOR, size);
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const subdirs: { lba: number; size: number; path: string }[] = [];

    let pos = 0;
    while (pos < data.length) {
      const recLen = dv.getUint8(pos);
      if (recLen === 0) {
        // Records never span a sector boundary: jump to the next sector.
        pos = (Math.floor(pos / SECTOR) + 1) * SECTOR;
        if (pos >= data.length) break;
        continue;
      }
      const extLba = dv.getUint32(pos + 2, true);
      const dataLen = dv.getUint32(pos + 10, true);
      const flags = dv.getUint8(pos + 25);
      const idLen = dv.getUint8(pos + 32);
      const idBytes = data.subarray(pos + 33, pos + 33 + idLen);

      // 0x00 = ".", 0x01 = ".." — skip both
      const isSpecial = idLen === 1 && (idBytes[0] === 0 || idBytes[0] === 1);
      if (!isSpecial) {
        let name = "";
        for (let i = 0; i < idLen; i++) name += String.fromCharCode(idBytes[i]!);
        const semi = name.indexOf(";");
        if (semi !== -1) name = name.slice(0, semi);
        const path = `${prefix}/${name}`;
        if (flags & 0x02) {
          subdirs.push({ lba: extLba, size: dataLen, path });
        } else {
          out.push({ name, path, lba: extLba, size: dataLen });
        }
      }
      pos += recLen;
    }

    for (const d of subdirs) {
      await this.walk(d.lba, d.size, d.path, out, visited);
    }
  }
}
