# EA PS2 — DNAS Bypass Patch Generator

Browser tool (GitHub Pages, fully client-side) that generates **DNAS bypass**
patches for EA PlayStation 2 online titles straight from a game ISO:

- **OPL `.cht`** — single file per game, with the runtime `9x` hooks the
  dashboard patch needs.
- **PCSX2 `.pnach`** — one direct patch line per ELF.

The ISO never leaves your machine: only the directory tree and the two target
ELFs (a few MB) are read, via `File.slice` — never the whole multi-GB image.

## Link

https://a-blondel.github.io/ea-ps2-tools/

## How it works

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

## Develop

```sh
npm install
npm run dev       # local dev server
npm run build     # -> dist/  (deployed to Pages by .github/workflows/deploy.yml)
npm test          # validation tests (reads paths from .env)
```

Tests in `test/` assert the generated `.cht` is byte-identical to the community
cheat and run the ISO walker end-to-end against a real image. They need local
game files, so paths are **not committed** — copy `.env.example` to `.env`
(git-ignored) and set `TEST_PS2_DIR` / `TEST_PS2_ISO` before running `npm test`.
If a var is left unset, that test skips cleanly.

## Deploy

Push to `main`. The workflow builds and publishes `dist/` to GitHub Pages.
Enable Pages → Source: GitHub Actions in the repo settings once.
