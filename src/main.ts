import "./style.css";
import { Iso, type IsoFile } from "./iso9660.js";
import { parseSerial, analyzeGame, type GameAnalysis } from "./analyze.js";
import { buildCht, buildPnach, chtFilename, type ElfTarget, type PnachFile } from "./cheats.js";
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
const warningsEl = $<HTMLDivElement>("warnings");
const targetsEl = $<HTMLDivElement>("targets");
const chtNameEl = $<HTMLElement>("cht-name");
const chtEl = $<HTMLPreElement>("cht");
const pnachEl = $<HTMLDivElement>("pnach");

let current: GameAnalysis | null = null;
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
  const crc = t.crc !== undefined ? hex8(t.crc) : "—";
  const extra =
    a.candidates.length > 1
      ? `<div class="k">${a.candidates.length} pattern matches; chose the DNASSKIP-anchored one</div>`
      : "";
  const labels = { dnas: "DNAS bypass", ssl: "SSL bypass", port: "Edit game port" };
  const chk = (feat: "dnas" | "ssl" | "port", found: boolean) =>
    `<label class="toggle">
        <input type="checkbox" data-feat="${feat}" data-i="${i}"${
          t.enable[feat] && found ? " checked" : ""
        }${found ? "" : " disabled"} />
        ${labels[feat]}
      </label>`;
  return `<div class="target">
      <h3>${t.label}</h3>
      <div class="toggles">${chk("dnas", !!a.bne)}${chk("ssl", !!t.ssl.port)}${chk("port", !!t.port)}</div>
      <div class="grid">
        <span class="k">DNAS BNE</span><span>${bne}</span>
        <span class="k">Hook (9x)</span><span>${hook}</span>
        <span class="k">SSL site</span><span>${ssl}</span>
        <span class="k">Game port</span><span>${port}</span>
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
  syncPortField(); // locked until an "Edit game port" box is ticked
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

targetsEl.addEventListener("change", (e) => {
  const cb = (e.target as HTMLElement).closest<HTMLInputElement>("input[data-feat]");
  if (!cb || !current) return;
  const t = current.targets[Number(cb.dataset.i)];
  if (!t) return;
  const feat = cb.dataset.feat as "dnas" | "ssl" | "port";
  if (feat === "port") {
    // Port patch is shared across ELFs — keep every "Edit game port" box in sync.
    for (const x of current.targets) if (x.port) x.enable.port = cb.checked;
    syncPortToggles();
  } else {
    t.enable[feat] = cb.checked;
  }
  syncPortField();
  refreshOutputs();
});

/** Reflect the shared enable.port state onto every rendered "Edit game port" box. */
function syncPortToggles() {
  targetsEl
    .querySelectorAll<HTMLInputElement>('input[data-feat="port"]')
    .forEach((box) => {
      const t = current?.targets[Number(box.dataset.i)];
      if (t) box.checked = t.enable.port;
    });
}

/** The port field is unlocked only while at least one "Edit game port" is ticked. */
function syncPortField() {
  const on = !!current?.targets.some((t) => t.enable.port);
  portInput.disabled = !on;
  if (!on) portInput.classList.remove("bad");
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

function refreshOutputs() {
  if (!current) return;
  const title = titleInput.value || current.serial;
  const port = desiredPort();
  chtEl.textContent = buildCht(current.serial, title, current.targets, port);

  pnachFiles = buildPnach(current.serial, current.targets, port);
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

async function handleFile(file: File) {
  resultEl.hidden = true;
  titleInput.value = "";
  setStatus(`Reading ${file.name} …`);
  try {
    const iso = new Iso(file);
    const files = await iso.listFiles();

    const cnf = files.find((f) => f.name.toUpperCase() === "SYSTEM.CNF");
    if (!cnf) throw new Error("SYSTEM.CNF not found — is this a PS2 ISO?");
    const serial = parseSerial(new TextDecoder().decode(await iso.readFileData(cnf)));
    if (!serial) throw new Error("Could not read BOOT2 serial from SYSTEM.CNF.");

    const wanted = files.filter(
      (f) =>
        f.name.toUpperCase() === serial.toUpperCase() ||
        f.name.toUpperCase() === "EA_DASH.ELF",
    );
    setStatus(`Extracting ${wanted.map((f) => f.name).join(", ")} …`);

    const blobs = [];
    for (const f of wanted) {
      blobs.push({ name: f.name, path: f.path, data: await iso.readFileData(f as IsoFile) });
    }

    const game = analyzeGame(serial, blobs);
    setStatus(`Done — ${serial}.`);
    render(game);
  } catch (e) {
    setStatus((e as Error).message, true);
  }
}

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

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
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
