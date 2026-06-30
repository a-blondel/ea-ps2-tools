import "./style.css";
import { Iso } from "./iso9660.js";
import { Elf } from "./elf.js";
import { parseSerial, analyzeGame, type GameAnalysis } from "./analyze.js";
import { buildCht, buildPnach, chtFilename, targetWrites, type ElfTarget, type PnachFile } from "./cheats.js";
import { buildIsoWrites, type IsoPatchTarget } from "./isopatch.js";
import { applyPatchesToChunk } from "./isostream.js";
import { hex8 } from "./bytes.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const fileInput = $<HTMLInputElement>("file");
const drop = $<HTMLLabelElement>("drop");
const statusEl = $<HTMLParagraphElement>("status");
const resultEl = $<HTMLElement>("result");
const titleInput = $<HTMLInputElement>("title");
const serialEl = $<HTMLElement>("serial");
const portField = $<HTMLLabelElement>("port-field");
const portInput = $<HTMLInputElement>("port");
const domainField = $<HTMLLabelElement>("domain-field");
const domainInput = $<HTMLInputElement>("domain");
const warningsEl = $<HTMLDivElement>("warnings");
const targetsEl = $<HTMLDivElement>("targets");
const chtNameEl = $<HTMLElement>("cht-name");
const chtEl = $<HTMLPreElement>("cht");
const pnachEl = $<HTMLDivElement>("pnach");
const patchBtn = $<HTMLButtonElement>("patch-iso");
const patchStatusEl = $<HTMLParagraphElement>("patch-status");
const patchProgressEl = $<HTMLProgressElement>("patch-progress");
const crswapHelpEl = $<HTMLDivElement>("crswap-help");

type Feat = "dnas" | "ssl" | "port" | "domain";
const SHARED: Feat[] = ["port", "domain"]; // one edit field drives every ELF

let current: GameAnalysis | null = null;
let currentFile: File | null = null; // source ISO, kept so we can copy + patch it
let currentLoaded: LoadedIso | null = null; // its walked ELFs (lba + bytes)
let pnachFiles: PnachFile[] = [];

function setStatus(msg: string, error = false) {
  statusEl.hidden = false;
  statusEl.textContent = msg;
  statusEl.classList.toggle("error", error);
}

function targetRow(t: ElfTarget, i: number): string {
  const a = t.dnas;
  const bne = a.bne
    ? `${hex8(a.bne.vaddr)} <span class="k">(orig ${hex8(a.bne.original)}, ${
        a.method === "dirtydnas"
          ? "DirtyDnas reloc"
          : "anchor " + (a.bne.anchorDist === null ? "none" : "0x" + a.bne.anchorDist.toString(16))
      })</span>`
    : `<span class="miss">not found</span>`;
  const hook = a.hook
    ? `${hex8(a.hook.vaddr)} <span class="k">= ${hex8(a.hook.value)}</span>`
    : `<span class="miss">not found</span>`;
  const ssl = t.ssl.port
    ? `${hex8(t.ssl.port.vaddr)} <span class="k">port +0, NOP ${
        t.ssl.secure ? hex8(t.ssl.secure.vaddr) : "?"
      }</span>`
    : `<span class="miss">not found</span>`;
  const port = t.port
    ? t.port.kind === "data"
      ? `${hex8(t.port.sites[0]!)} <span class="k">= ${t.port.value} (data word)</span>`
      : `${t.port.sites.map((a) => hex8(a)).join(", ")} <span class="k">(connect rewrite)</span>`
    : `<span class="miss">not found</span>`;
  const domain = t.domain
    ? `${t.domain.host} <span class="k">(${t.domain.sites.length}×, ${t.domain.capacity} B max)</span>`
    : `<span class="miss">not found</span>`;
  const crc = t.crc !== undefined ? hex8(t.crc) : "—";
  const extra =
    a.candidates.length > 1
      ? `<div class="k">${a.candidates.length} pattern matches; chose the DNASSKIP-anchored one</div>`
      : "";
  const labels = {
    dnas: "DNAS bypass",
    ssl: "SSL bypass",
    port: "Edit game port",
    domain: "Edit game domain",
  };
  const chk = (feat: Feat, found: boolean) =>
    `<label class="toggle">
        <input type="checkbox" data-feat="${feat}" data-i="${i}"${
          t.enable[feat] && found ? " checked" : ""
        }${found ? "" : " disabled"} />
        ${labels[feat]}
      </label>`;
  return `<div class="target">
      <h3>${t.label}</h3>
      <div class="toggles">${chk("dnas", !!a.bne)}${chk("ssl", !!t.ssl.port)}${chk("port", !!t.port)}${chk("domain", !!t.domain)}</div>
      <div class="grid">
        <span class="k">DNAS BNE</span><span>${bne}</span>
        <span class="k">Hook (9x)</span><span>${hook}</span>
        <span class="k">SSL site</span><span>${ssl}</span>
        <span class="k">Game port</span><span>${port}</span>
        <span class="k">EA domain</span><span>${domain}</span>
        <span class="k">ELF CRC</span><span>${crc}</span>
      </div>${extra}
    </div>`;
}

function render(game: GameAnalysis) {
  current = game;
  serialEl.textContent = game.serial;
  if (!titleInput.value) titleInput.value = game.title;
  const hasPort = game.targets.some((t) => t.port);
  portField.hidden = !hasPort;
  portInput.value = game.port !== null ? String(game.port) : "";
  portInput.placeholder = "e.g. 40000";
  portInput.classList.remove("bad");

  const hasDomain = game.targets.some((t) => t.domain);
  domainField.hidden = !hasDomain;
  domainInput.value = "eahub.eu"; // default replacement; original host shown per ELF
  domainInput.placeholder = "eahub.eu";
  domainInput.classList.remove("bad");

  syncSharedField("port"); // both locked until their "Edit …" box is ticked
  syncSharedField("domain");
  chtNameEl.textContent = chtFilename(game.serial);

  if (game.warnings.length) {
    warningsEl.hidden = false;
    warningsEl.innerHTML =
      "<strong>Heads-up</strong><ul>" +
      game.warnings.map((w) => `<li>${w}</li>`).join("") +
      "</ul>";
  } else {
    warningsEl.hidden = true;
  }

  targetsEl.innerHTML = game.targets.map(targetRow).join("");
  refreshOutputs();
  resultEl.hidden = false;
}

/** Whether a target carries the analysis a feature needs. */
function featAvail(t: ElfTarget, feat: Feat): boolean {
  return feat === "port" ? !!t.port : feat === "domain" ? !!t.domain : feat === "ssl" ? !!t.ssl.port : !!t.dnas.bne;
}

targetsEl.addEventListener("change", (e) => {
  const cb = (e.target as HTMLElement).closest<HTMLInputElement>("input[data-feat]");
  if (!cb || !current) return;
  const t = current.targets[Number(cb.dataset.i)];
  if (!t) return;
  const feat = cb.dataset.feat as Feat;
  if (SHARED.includes(feat)) {
    // Port/domain patches are shared across ELFs — keep every box in sync.
    for (const x of current.targets) if (featAvail(x, feat)) x.enable[feat] = cb.checked;
    syncSharedToggles(feat);
  } else {
    t.enable[feat] = cb.checked;
  }
  syncSharedField(feat);
  refreshOutputs();
});

const sharedInput = (feat: Feat): HTMLInputElement => (feat === "port" ? portInput : domainInput);

/** Reflect a shared enable.<feat> state onto every rendered toggle for it. */
function syncSharedToggles(feat: Feat) {
  targetsEl
    .querySelectorAll<HTMLInputElement>(`input[data-feat="${feat}"]`)
    .forEach((box) => {
      const t = current?.targets[Number(box.dataset.i)];
      if (t) box.checked = t.enable[feat];
    });
}

/** A shared edit field is unlocked only while at least one of its boxes is ticked. */
function syncSharedField(feat: Feat) {
  if (!SHARED.includes(feat)) return;
  const input = sharedInput(feat);
  const on = !!current?.targets.some((t) => t.enable[feat]);
  input.disabled = !on;
  if (!on) input.classList.remove("bad");
}

/** Desired port from the field (1..65535), or null when locked/empty/invalid. */
function desiredPort(): number | null {
  if (portInput.disabled) return null;
  const raw = portInput.value.trim();
  if (raw === "") {
    portInput.classList.remove("bad");
    return null;
  }
  const v = parseInt(raw, 10);
  const ok = Number.isFinite(v) && v >= 1 && v <= 65535;
  portInput.classList.toggle("bad", !ok);
  return ok ? v : null;
}

/** Desired domain from the field, or null when locked/empty/invalid (too long
 *  for any enabled ELF, or not a valid hostname). */
function desiredDomain(): string | null {
  if (domainInput.disabled) return null;
  const raw = domainInput.value.trim();
  if (raw === "") {
    domainInput.classList.remove("bad");
    return null;
  }
  const caps = (current?.targets ?? [])
    .filter((t) => t.enable.domain && t.domain)
    .map((t) => t.domain!.capacity);
  const minCap = caps.length ? Math.min(...caps) : Infinity;
  const ok = /^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(raw) && raw.length + 1 <= minCap;
  domainInput.classList.toggle("bad", !ok);
  return ok ? raw : null;
}

function refreshOutputs() {
  if (!current) return;
  const title = titleInput.value || current.serial;
  const port = desiredPort();
  const domain = desiredDomain();
  chtEl.textContent = buildCht(current.serial, title, current.targets, port, domain);

  pnachFiles = buildPnach(current.serial, current.targets, port, domain);
  if (pnachFiles.length === 0) {
    pnachEl.innerHTML = `<p class="note">No patches found.</p>`;
    return;
  }
  pnachEl.innerHTML = pnachFiles
    .map(
      (f, i) => `<div class="output">
        <div class="output-head">
          <h2><code>${f.filename}</code></h2>
          <div class="btns">
            <button type="button" data-copy="${i}">Copy</button>
            <button type="button" data-pnach="${i}" class="primary">Download</button>
          </div>
        </div>
        <pre class="code">${f.content.replace(/</g, "&lt;")}</pre>
      </div>`,
    )
    .join("");
}

titleInput.addEventListener("input", refreshOutputs);
portInput.addEventListener("input", refreshOutputs);
domainInput.addEventListener("input", refreshOutputs);

// One ELF pulled out of an ISO: its bytes plus the sector (lba) they start at,
// so the in-place patcher can turn a file offset into an absolute ISO offset.
interface LoadedElf {
  name: string;
  path: string;
  lba: number;
  data: Uint8Array;
}
interface LoadedIso {
  serial: string;
  elfs: LoadedElf[]; // the main ELF and EA_DASH.ELF, if present
}

/** Walk an ISO, read its BOOT2 serial, and pull out the main + dashboard ELFs.
 *  Shared by the analysis flow and the in-place patcher. */
async function loadIso(file: File): Promise<LoadedIso> {
  const iso = new Iso(file);
  const files = await iso.listFiles();

  const cnf = files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF");
  if (!cnf) throw new Error("SYSTEM.CNF not found — is this a PS2 ISO?");
  const serial = parseSerial(new TextDecoder().decode(await iso.readFileData(cnf)));
  if (!serial) throw new Error("Could not read BOOT2 serial from SYSTEM.CNF.");

  const wanted = files.filter(
    (f) => f.name.toUpperCase() === serial.toUpperCase() || f.name.toUpperCase() === "EA_DASH.ELF",
  );
  const elfs: LoadedElf[] = [];
  for (const f of wanted) {
    elfs.push({ name: f.name, path: f.path, lba: f.lba, data: await iso.readFileData(f) });
  }
  return { serial, elfs };
}

/** The loaded ELF backing a target (main vs dashboard), matched by label. */
function elfForTarget(t: ElfTarget, loaded: LoadedIso): LoadedElf | null {
  const want = t.label === "EA Dashboard" ? "EA_DASH.ELF" : loaded.serial.toUpperCase();
  return loaded.elfs.find((e) => e.name.toUpperCase() === want) ?? null;
}

async function handleFile(file: File) {
  resultEl.hidden = true;
  titleInput.value = "";
  setStatus(`Reading ${file.name} …`);
  try {
    const loaded = await loadIso(file);
    setStatus(`Extracting ${loaded.elfs.map((e) => e.name).join(", ")} …`);
    const blobs = loaded.elfs.map((e) => ({ name: e.name, path: e.path, data: e.data }));
    const game = analyzeGame(loaded.serial, blobs);
    currentFile = file;
    currentLoaded = loaded;
    setStatus(`Done — ${loaded.serial}.`);
    render(game);
  } catch (e) {
    setStatus((e as Error).message, true);
  }
}

function setPatchStatus(msg: string, error = false) {
  patchStatusEl.hidden = false;
  patchStatusEl.textContent = msg;
  patchStatusEl.classList.toggle("error", error);
}

/** Show the copy progress (0..1), or hide the bar when passed null. */
function setPatchProgress(frac: number | null) {
  if (frac === null) {
    patchProgressEl.hidden = true;
    return;
  }
  patchProgressEl.hidden = false;
  patchProgressEl.value = frac;
}

// A File System Access save handle, minimally typed (Chrome/Edge only).
interface SaveHandle {
  createWritable(): Promise<{
    write(data: Blob | Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort?(reason?: unknown): Promise<void>;
  }>;
}

/**
 * Ask the user where to save, NOW — must run inside the click handler because
 * showSaveFilePicker requires a fresh user gesture and can't be called after the
 * minutes-long build. Returns the handle, or null on Firefox (no picker → we'll
 * fall back to a blob-URL download), or "cancel" if the user dismissed it.
 */
async function pickSaveHandle(suggestedName: string): Promise<SaveHandle | null | "cancel"> {
  const picker = (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker as
    | ((opts: object) => Promise<SaveHandle>)
    | undefined;
  if (!picker) return null;
  try {
    return await picker({
      suggestedName,
      types: [{ description: "PS2 ISO", accept: { "application/octet-stream": [".iso"] } }],
    });
  } catch (e) {
    if ((e as DOMException)?.name === "AbortError") return "cancel";
    throw e;
  }
}

/**
 * Save a patched copy of the loaded ISO. We assemble the WHOLE patched image
 * first — reading the source in chunks, overlaying the few patch bytes inline,
 * and collecting each chunk as a browser-managed Blob (which the browser spills
 * to disk, so the JS heap stays small) — then write the finished file out.
 * Building it fully before saving is what killed the earlier corruption: a live
 * streamed download let the user confirm the save dialog mid-copy and truncate
 * the file. On Chrome/Edge we ask where to save up front (their blob-URL
 * downloads are capped at ~2 GB and fail with "network error") then write the
 * complete blob there; Firefox just downloads the finished blob URL. The
 * original disc is never touched. Works under `vite dev` too (no service worker).
 */
async function patchIso() {
  if (!current || !currentFile || !currentLoaded) return;

  // Build the patch byte-writes from the current toggles + the loaded ELFs.
  const port = desiredPort();
  const domain = desiredDomain();
  const targets: IsoPatchTarget[] = [];
  for (const t of current.targets) {
    const e = elfForTarget(t, currentLoaded);
    if (!e) continue;
    targets.push({ elf: new Elf(e.data), lba: e.lba, writes: targetWrites(t, port, domain) });
  }
  const { writes, warnings } = buildIsoWrites(targets);
  if (writes.length === 0) {
    setPatchStatus("No patches are enabled — tick at least one feature first.", true);
    return;
  }

  const src = currentFile;
  const outName = src.name.replace(/(\.[^./\\]+)?$/, "") + "-patched.iso";

  // Pick the destination NOW, while the click gesture is still valid — the long
  // build below would invalidate the gesture showSaveFilePicker requires.
  let handle: SaveHandle | null;
  try {
    const picked = await pickSaveHandle(outName);
    if (picked === "cancel") return;
    handle = picked;
  } catch (e) {
    setPatchStatus((e as Error).message, true);
    return;
  }

  const sorted = [...writes].sort((a, b) => a.offset - b.offset);
  const CHUNK = 8 * 1024 * 1024;
  patchBtn.disabled = true;
  crswapHelpEl.hidden = true;
  try {
    if (handle) {
      // Chrome/Edge: stream the source straight into the picked file, patching
      // inline. No giant blob — that dodges the ~2 GB blob-URL cap and Chrome's
      // blob-storage limits. Destination was picked up front, so nothing races.
      setPatchStatus("Saving … 0%");
      const writable = await handle.createWritable();
      try {
        let pos = 0;
        while (pos < src.size) {
          const end = Math.min(pos + CHUNK, src.size);
          const chunk = new Uint8Array(await src.slice(pos, end).arrayBuffer());
          applyPatchesToChunk(chunk, pos, sorted);
          await writable.write(chunk);
          pos = end;
          setPatchProgress(pos / src.size);
          setPatchStatus(`Saving … ${Math.floor((pos / src.size) * 100)}%`);
        }
        await writable.close(); // only on success — closing an errored stream masks the real error
      } catch (err) {
        await writable.abort?.(err).catch(() => {});
        throw err;
      }
    } else {
      // Firefox: build the whole patched image as a (disk-backed) Blob, then a
      // blob-URL download — Firefox handles multi-GB blobs fine and has no picker.
      setPatchStatus("Building patched ISO … 0%");
      const parts: Blob[] = [];
      let pos = 0;
      while (pos < src.size) {
        const end = Math.min(pos + CHUNK, src.size);
        const chunk = new Uint8Array(await src.slice(pos, end).arrayBuffer());
        applyPatchesToChunk(chunk, pos, sorted);
        parts.push(new Blob([chunk]));
        pos = end;
        setPatchProgress(pos / src.size);
        setPatchStatus(`Building patched ISO … ${Math.floor((pos / src.size) * 100)}%`);
        await Promise.resolve(); // yield so the progress bar repaints
      }
      download(outName, new Blob(parts, { type: "application/octet-stream" }));
    }

    setPatchProgress(null);
    if (warnings.length) console.warn("ISO patch — skipped writes:", warnings);
    const skipped = warnings.length ? ` (${warnings.length} skipped — see console)` : "";
    setPatchStatus(`Done — saved ${outName} (${writes.length} change(s))${skipped}.`);
  } catch (e) {
    setPatchProgress(null);
    // Chrome's File System Access write can fail at commit on Windows when an
    // antivirus/indexer touches the temp file (InvalidStateError) — but the full
    // patched ISO has already been written as the .crswap file, so show the user
    // how to finish it by hand. (Firefox has no handle and won't hit this.)
    if (handle) {
      patchStatusEl.hidden = true; // the crswap-help block below says it all
      crswapHelpEl.hidden = false;
    } else {
      setPatchStatus((e as Error).message, true);
    }
  } finally {
    patchBtn.disabled = false;
  }
}

patchBtn.addEventListener("click", () => void patchIso());

fileInput.addEventListener("change", () => {
  const f = fileInput.files?.[0];
  if (f) void handleFile(f);
});

drop.addEventListener("dragover", (e) => {
  e.preventDefault();
  drop.classList.add("over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  const f = e.dataTransfer?.files?.[0];
  if (f) void handleFile(f);
});

function download(name: string, content: string | Blob) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  // Keep the object URL alive long enough for the browser to start reading the
  // blob; revoking it immediately can abort a large (multi-GB) download.
  setTimeout(() => URL.revokeObjectURL(url), 120000);
}

$<HTMLButtonElement>("dl-cht").addEventListener("click", () => {
  if (current) download(chtFilename(current.serial), chtEl.textContent ?? "");
});
pnachEl.addEventListener("click", async (e) => {
  const target = e.target as HTMLElement;
  const dlBtn = target.closest<HTMLButtonElement>("[data-pnach]");
  if (dlBtn) {
    const f = pnachFiles[Number(dlBtn.dataset.pnach)];
    if (f) download(f.filename, f.content);
    return;
  }
  const copyBtn = target.closest<HTMLButtonElement>("[data-copy]");
  if (copyBtn) {
    const f = pnachFiles[Number(copyBtn.dataset.copy)];
    if (!f) return;
    await navigator.clipboard.writeText(f.content);
    copyBtn.textContent = "Copied";
    setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
  }
});

$<HTMLButtonElement>("copy-cht").addEventListener("click", async () => {
  await navigator.clipboard.writeText(chtEl.textContent ?? "");
  const b = $<HTMLButtonElement>("copy-cht");
  b.textContent = "Copied";
  setTimeout(() => (b.textContent = "Copy"), 1200);
});
