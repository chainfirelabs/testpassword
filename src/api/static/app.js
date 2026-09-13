// TestPassword web client.
//
// Mirrors the Go CLI's three modes:
//   plaintext -> POST /check {"password", "formats": ["sha1","ntlm"]}  (server hashes both)
//   sha1      -> GET  /lookup/sha1/<40-hex>
//   ntlm      -> GET  /lookup/ntlm/<32-hex>

const form = document.getElementById("check-form");
const modeSel = document.getElementById("mode");
const valueInput = document.getElementById("value");
const valueLabel = document.getElementById("value-label");
const btn = document.getElementById("check-btn");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

const FORMATS = ["sha1", "ntlm"];

const MODES = {
  plaintext: {
    label: "Password",
    type: "password",
    placeholder: "Enter a password to check",
    autocomplete: "new-password",
  },
  sha1: {
    label: "SHA1 hash",
    type: "text",
    placeholder: "Enter a 40-character SHA1 hash",
    autocomplete: "off",
    hexLen: 40,
    hexName: "SHA1",
  },
  ntlm: {
    label: "NTLM hash",
    type: "text",
    placeholder: "Enter a 32-character NTLM hash",
    autocomplete: "off",
    hexLen: 32,
    hexName: "NTLM",
  },
};

modeSel.addEventListener("change", applyMode);
form.addEventListener("submit", onCheck);
applyMode();

function applyMode() {
  const cfg = MODES[modeSel.value];
  valueLabel.textContent = cfg.label;
  valueInput.type = cfg.type;
  valueInput.placeholder = cfg.placeholder;
  valueInput.autocomplete = cfg.autocomplete;
  valueInput.spellcheck = false;
  valueInput.classList.toggle("mono", cfg.type === "text");
  valueInput.maxLength = cfg.hexLen || 1024;
  valueInput.required = modeSel.value !== "plaintext";
  valueInput.value = "";
  clearOutput();
}

async function onCheck(e) {
  e.preventDefault();
  const mode = modeSel.value;
  const cfg = MODES[mode];
  // Plaintext is used verbatim (spaces are significant); hashes are trimmed.
  const value = mode === "plaintext" ? valueInput.value : valueInput.value.trim();
  if (!value && mode !== "plaintext") return;

  setBusy(true);
  clearOutput();
  try {
    const results = mode === "plaintext"
      ? await checkPlaintext(value)
      : await lookupHash(mode, cfg, value);
    renderResults(results, mode === "plaintext" ? FORMATS : [mode]);
  } catch (err) {
    showError(err.message || String(err));
  } finally {
    if (mode === "plaintext") valueInput.value = "";
    setBusy(false);
  }
}

async function checkPlaintext(password) {
  const resp = await fetch("/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, formats: FORMATS }),
    signal: AbortSignal.timeout(15000),
  });
  const data = await resp.json().catch(() => null);
  if (!resp.ok) throw new Error(data?.detail || `API error ${resp.status}`);
  return data?.results || {};
}

async function lookupHash(mode, cfg, raw) {
  const hash = raw.toUpperCase();
  if (!/^[0-9A-F]+$/.test(hash) || hash.length !== cfg.hexLen) {
    throw new Error(`${cfg.hexName} hash must be exactly ${cfg.hexLen} hex characters`);
  }
  const resp = await fetch(`/lookup/${mode}/${hash}`, { signal: AbortSignal.timeout(15000) });
  const data = await resp.json().catch(() => null);
  if (!resp.ok) throw new Error(data?.detail || `API error ${resp.status}`);
  if (data?.hash !== hash) throw new Error("Invalid API response: hash mismatch");
  return { [mode]: data };
}

function setBusy(busy) {
  btn.disabled = busy;
  modeSel.disabled = busy;
  btn.textContent = busy ? "Checking…" : "Check";
}

function clearOutput() {
  statusEl.hidden = true;
  statusEl.textContent = "";
  resultsEl.hidden = true;
  resultsEl.innerHTML = "";
}

function showError(msg) {
  statusEl.className = "status error";
  statusEl.textContent = msg;
  statusEl.hidden = false;
}

function validResult(r, fmt) {
  return r && r.format === fmt && typeof r.hash === "string"
    && new RegExp(`^[0-9A-F]{${fmt === "sha1" ? 40 : 32}}$`).test(r.hash)
    && typeof r.pwned === "boolean" && Number.isSafeInteger(r.count) && r.count >= 0
    && r.pwned === (r.count > 0)
    && typeof r.data_loaded === "boolean" && typeof r.data_complete === "boolean";
}

function renderResults(results, requested) {
  for (const fmt of requested) {
    const r = results?.[fmt];
    if (!validResult(r, fmt)) {
      const el = document.createElement("div");
      el.className = "result inconclusive";
      el.textContent = `${fmt.toUpperCase()}: INCONCLUSIVE — missing or invalid API result.`;
      resultsEl.appendChild(el);
    } else {
      resultsEl.appendChild(resultCard(r));
    }
  }
  if (resultsEl.children.length === 0) {
    showError("No results returned.");
    return;
  }
  resultsEl.hidden = false;
}

function resultCard(r) {
  const el = document.createElement("div");
  const state = r.pwned ? "pwned" : (r.data_loaded && r.data_complete ? "clean" : "inconclusive");
  el.className = "result " + state;

  const head = document.createElement("div");
  head.className = "result-head";

  const fmt = document.createElement("span");
  fmt.className = "result-fmt";
  fmt.textContent = r.format;

  const badge = document.createElement("span");
  badge.className = "badge " + state;
  badge.textContent = state === "pwned" ? "PWNED" : state === "clean" ? "NOT PWNED" : "INCONCLUSIVE";

  head.append(fmt, badge);

  const hash = document.createElement("div");
  hash.className = "result-hash";
  hash.textContent = r.hash;

  el.append(head, hash);

  if (r.pwned) {
    const count = document.createElement("div");
    count.className = "result-count";
    count.textContent = `Seen ${withCommas(r.count)} times in breach data.`;
    el.appendChild(count);
  }

  if (!r.data_loaded) {
    el.appendChild(note(`${r.format} dataset not loaded.`));
  } else if (!r.data_complete) {
    el.appendChild(note(`${r.format} dataset incomplete — download in progress.`));
  }

  return el;
}

function note(text) {
  const el = document.createElement("div");
  el.className = "result-note";
  el.textContent = text;
  return el;
}

function withCommas(n) {
  const s = String(n);
  if (s.length <= 3) return s;
  let out = "";
  const rem = s.length % 3;
  if (rem) out += s.slice(0, rem);
  for (let i = rem; i < s.length; i += 3) {
    if (out) out += ",";
    out += s.slice(i, i + 3);
  }
  return out;
}
