// SSL (ProtoAries secure) bypass detection for EA PS2 ELFs.
//
// The secure-lobby path in _LobbyApiUpdateInit compiles to:
//     ...
//     jal   ProtoAriesConnect          ; connect to the lobby
//     addiu a3, a3, 0x1                 ; delay slot: a3 = port + 1  (SSL port)
//     lw    a0, 0x0(rX)                 ; reload the api handle
//     jal   ProtoAriesSecure            ; turn the link into SSL
//     addiu a1, zero, 0x1               ; delay slot: secure = 1
//
// Two edits disable SSL while keeping the plaintext lobby reachable:
//   * port:   `addiu a3,a3,1` -> `addiu a3,a3,0`  (don't bump to the SSL port)
//   * secure: NOP the `jal ProtoAriesSecure`       (never enable encryption)
//
// `a3` ($7, the 4th argument = port) and `a1` ($5, the 2nd argument = the secure
// flag) are ABI-fixed, so those two instruction words are identical across
// builds; only the jump targets and the handle-load register vary. We anchor on
// `addiu a3,a3,1` and confirm the site by the `jal` + `li a1,1` that follow.
// Validated unique in FIFA 07 US (main + EA_DASH) and PAL.

import { Elf } from "./elf.js";

const ADDIU_A3_1 = 0x24e70001; // addiu a3,a3,1   (bump to SSL port)
const PORT_KEEP = 0x24e70000; // addiu a3,a3,0   (keep the plain port)
const LI_A1_1 = 0x24050001; // addiu a1,zero,1 (secure flag = 1)
const ORI_A1_1 = 0x34050001; // ori   a1,zero,1 (same, alternate codegen)
const NOP = 0x00000000;

export interface SslPatch {
  vaddr: number;
  original: number; // current opcode word
  value: number; // word to write
}

export interface SslAnalysis {
  port: SslPatch | null; // the `addiu a3,a3,1` -> +0 edit
  secure: SslPatch | null; // the `jal ProtoAriesSecure` -> NOP edit
}

export function analyzeSsl(elf: Elf): SslAnalysis {
  const seg = elf.codeSegment;
  for (let fo = seg.off; fo + 16 <= seg.off + seg.filesz; fo += 4) {
    if (elf.readU32(fo) !== ADDIU_A3_1) continue;
    const jal = elf.readU32(fo + 8);
    const li = elf.readU32(fo + 12);
    if (jal >>> 26 !== 3 /* JAL */) continue;
    if (li !== LI_A1_1 && li !== ORI_A1_1) continue;

    const portVa = elf.fileToVaddr(fo);
    const secVa = elf.fileToVaddr(fo + 8);
    if (portVa === null || secVa === null) continue;
    return {
      port: { vaddr: portVa, original: ADDIU_A3_1, value: PORT_KEEP },
      secure: { vaddr: secVa, original: jal, value: NOP },
    };
  }
  return { port: null, secure: null };
}
