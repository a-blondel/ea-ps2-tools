# EA PS2 — Online Patch Generator

Browser tool (GitHub Pages, fully client-side) that generates the patches to bring
EA PlayStation 2 online titles back online, straight from a game ISO. Four
independent, per-ELF patches:

- **DNAS bypass** — skip Sony's DNAS authentication (mandatory for every game).
- **SSL bypass** — disable ProtoAries SSL on the lobby link (and keep the plain port).
- **Edit game port** — override the lobby port for the few games that need it.
- **Edit game domain** — rewrite the EA hostname in place.

…in three output formats:

- **Patched ISO** — a full copy with the bytes rewritten (the disc patches itself).
- **OPL `.cht`** — one cheat file per game, with the runtime `9x` hooks the dashboard
  patch needs.
- **PCSX2 `.pnach`** — one file per ELF (CRC computed automatically).

The ISO never leaves your machine: only the directory tree and target ELFs are read
via `File.slice`, and the full image is streamed (never held in memory). A Node CLI
(`bin/patch-iso.mjs`) shares the exact same engine for scripted / large-ISO patching.

## Link

https://a-blondel.github.io/ea-ps2-tools/

## Which patches to enable

- **DNAS bypass** — always **on**. Mandatory for all games.
- **SSL bypass** — **off**, except: the `Arena Football` & `NASCAR 07` dashboards need it,
  and it's required whenever you override the game domain.
- **Roster download bypass** — **off**, unless the game stalls on a roster update.
- **Edit game port** — **off**, except the few games that need a specific port to reach
  EA Nation Hub (`NASCAR 06` → `40600`, `NCAA Football 06` → `40500`).
- **Edit game domain** — **off** unless you can't run a custom DNS. If you enable it, keep
  the default `eahub.eu` and turn **SSL bypass** on as well.

## CLI

`bin/patch-iso.mjs` reuses the same engine (the reliable path for multi-GB ISOs — a plain
copy + seek-write, no browser file-API limits):

```sh
npm run patch -- "<iso>" [--out <path>] [--in-place]
                         [--port <n>] [--domain <host>] [--no-dnas] [--ssl]
                         [--cht] [--pnach] [--no-iso]
```

DNAS is on by default; SSL is off (add `--ssl` to enable it). `--cht`/`--pnach` also
write the cheat files next to the output; `--no-iso` skips building the patched ISO
(cheats only).

## How it works

### DNAS bypass — detection order

The DNAS check takes different forms across EA titles, so the tool tries these in
order and keeps the first that matches:

1. **DNASSKIP (in-ELF)** — the common EA check: a `BNE` after `JAL <dnas_fn>`,
   disambiguated by the `DNASSKIP` string. NOP the branch.
2. **DirtyDnas (older reloc engine)** — ~2003–2005 titles with no DNASSKIP (e.g. The
   Sims Bustin' Out): DNAS runs in a relocated `dirtydnas.elf`; the tool traces the
   wrapper to the result gate and NOPs it.
3. **Sony main-ELF poll gate** — stock Sony DNAS titles with no EA check (Burnout 3 =
   DNAS 2.8, Burnout Revenge = DNAS 3.0): anchor on the retry codes and force the poll
   result to success.
4. **Embedded module accessor (fallback)** — when none of the above match: patch the
   DNAS module's auth accessor embedded on the disc.

Methods 1–3 are in-ELF, so they ship as `.cht` / `.pnach` / ISO patch; method 4 is a
raw disc edit, so it's **ISO-only**. The rest of this section details each.

### DNASSKIP (method 1)

DNAS verification compiles to a `JAL <dnas_fn>` followed by a
`BNE $v0, $s0, <error>` that branches away when the check fails. NOP-ing that
BNE (`00000000`) forces fall-through.

The BNE shows up in the file as `2D 28 00 00 06/07 00 50 14`. Larger games
contain **several** copies of that byte sequence, so the tool disambiguates by
finding the code reference (`lui`/`addiu`) to the `"DNASSKIP"` string — the real
check sits a few instructions after it (empirically `0x20` bytes). The
best-anchored match wins.

For OPL, `EA_DASH.ELF` isn't in RAM at boot, so a static write would be
clobbered when the dashboard loads. Each cheat therefore carries a `9x` runtime
hook: the original `JAL` found right after the fixed `_sceSifSendCmd` wrapper
prologue. When that instruction executes (network code is running, dashboard is
in RAM), OPL applies the patches.

File offsets map to EE virtual addresses through the ELF's `PT_LOAD` program
headers (not a hardcoded delta), so it stays correct across builds.

### DirtyDnas (method 2)

Older EA titles (~2003–2005, e.g. The Sims Bustin' Out) use the "DirtySock" reloc
engine: no `DNASSKIP` string and no inline `JAL`/`BNE`. DNAS auth runs in a relocated
`dirtydnas.elf` (symbols `DirtyDnasRelInit/Updt/Exit`) polled through a thin wrapper,
and the state machine branches on its result. The tool traces it purely by structure
(no hardcoded addresses): from the `"DirtyDnasRelUpdt"` string to the store of the
resolved function pointer, to the `lui/lw/…/jalr` wrapper that calls it, to that
wrapper's `jal` site — then scans the next few instructions for the result gate
`lw v?,off(sp)` immediately followed by `bne v?,zero,<fail>`. NOP-ing that BNE makes
DNAS always report success. Validated against The Sims Bustin' Out (US).

### Sony DNAS titles — gate & module accessor (methods 3–4)

Some titles use the stock Sony DNAS engine instead of EA's in-ELF check.
The tool handles them two ways, preferring the first:

**Method 3 — main-ELF poll gate (preferred, becomes a cheat).** The main ELF still
consumes the verdict: an async DNAS module is polled and the game branches on the
result. The tool anchors on the DNAS retry codes (`-0x69/-0x269/-0x25b`, stable
across DNAS versions), finds the result gate (`lw v?,off(sp)` then a sign branch)
and the busy branch, and emits two writes that force success on the first frame
(skipping the ~20 s auth wait): the gate becomes always-success (NOP a
`bltz…,fail`, or turn a `bgez…,success` into an unconditional branch), and the
busy check is neutralised. Both are main-ELF addresses, so this ships as `.cht` /
`.pnach` / ISO patch. Validated live in PCSX2, online-confirmed, on **Burnout 3
(DNAS 2.8)** and **Burnout Revenge (DNAS 3.0)**.

**Method 4 — embedded module accessor (ISO-only fallback).** When no in-ELF check
is found at all, authentication runs in a relocated module whose plaintext code is
embedded on the disc (on Burnout 3, inside a decoy-named data file, **not** the
plaintext Sony IOP bundle `/IOP/DNAS280.IMG`, which doesn't carry this accessor).
The tool locates that module's auth-status accessor (a unique 12-byte code
signature) — triaging `*.IMG` files and files with an embedded ELF first, so it
rarely reads the whole image — and rewrites its tail to always report
*authenticated* —
the same byte patch the community `DNAS_PATCHER21` produces (verified
byte-identical). This is a **raw disc edit**, so it's applied only to the
**patched ISO** — it can't be an OPL `.cht` or PCSX2 `.pnach` (the code runs on
the IOP, not the EE). See `src/dnasimg.ts`.

## Develop

```sh
npm install
npm run dev       # local dev server
npm run build     # -> dist/  (deployed to Pages by .github/workflows/deploy.yml - or run locally with `python -m http.server 4179 --directory dist`)
npm test          # validation tests (reads paths from .env)
```

Tests in `test/` assert the generated output is byte-identical to known-good patches
(community cheats, the real `DNAS_PATCHER21` image, the live-validated Sony gate) and
run the ISO walker end-to-end. They need local game files, so paths are **not
committed** — copy `.env.example` to `.env` (git-ignored) and fill in the paths you
have (FIFA 07, Sims Bustin' Out, Burnout 3, Burnout Revenge). Each test whose var is
unset skips cleanly.
