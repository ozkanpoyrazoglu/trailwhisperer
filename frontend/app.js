/* TrailWhisperer — frontend logic (vanilla, no build step).
   Flow: question -> POST /api/generate-sql -> approve in modal ->
   POST /api/execute-sql -> poll GET /api/results/{id} -> render narrative + table. */

"use strict";

const API = new URLSearchParams(location.search).get("api") || "http://localhost:8000";
const TOKEN_KEY = "trailwhisperer.token";
const MODEL_KEY = "trailwhisperer.model";
const CUSTOM_MODEL_KEY = "trailwhisperer.model.custom";
const CUSTOM = "__custom__";
const POLL_MS = 1300;
const POLL_MAX = 90; // ~2 min ceiling

const $ = (id) => document.getElementById(id);
const el = {
  thread: $("thread"), hero: $("hero"), composer: $("composer"),
  question: $("question"), askBtn: $("askBtn"),
  health: $("health"), keyBtn: $("keyBtn"),
  modelSelect: $("modelSelect"), customModel: $("customModel"), customBack: $("customBack"),
  authScrim: $("authScrim"), authForm: $("authForm"), tokenInput: $("tokenInput"),
  saveToken: $("saveToken"), revealToken: $("revealToken"), authNote: $("authNote"),
  sqlScrim: $("sqlScrim"), sqlBox: $("sqlBox"), warrantMeta: $("warrantMeta"),
  approveSql: $("approveSql"), cancelSql: $("cancelSql"), scopeText: $("scopeText"),
  toasts: $("toasts"),
  caseLogBtn: $("caseLogBtn"), caseCount: $("caseCount"), caseWrap: $("caseWrap"),
  caseList: $("caseList"), caseEmpty: $("caseEmpty"), closeCase: $("closeCase"), clearCase: $("clearCase"),
};

let token = localStorage.getItem(TOKEN_KEY) || "";
let pending = null; // { question } awaiting SQL approval
let busy = false;

/* ------------------------------- helpers -------------------------------- */
const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function fmtBytes(n) {
  if (n == null) return "—";
  if (n === 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}
// Athena on-demand pricing: ~$5 per TB scanned.
const fmtCost = (n) => (n == null ? "—" : `$${((n / 1024 ** 4) * 5).toFixed(4)}`);
const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/* Severity — classify flag/row text into triage levels. The words carry the
   signal, so this reads it rather than inventing it. */
const SEV_RANK = { clear: 0, info: 1, warn: 2, critical: 3 };
const SEV_LABEL = { clear: "clear", info: "info", warn: "review", critical: "critical" };
const CRITICAL_RE = /\broot\b|brute|unauthor|access ?denied|\bdenied\b|escalat|administratoraccess|admin access|stoplogging|deletetrail|disabl\w* ?(logging|mfa|cloudtrail|trail)|exfil|0\.0\.0\.0\/0|\btor\b|malicious/;
const WARN_RE = /fail|error|off.?hours|unusual|new ip|multiple|repeat|revoke|delete|remove|\bpolicy\b|attach|create\w* key|\bmfa\b|anomal|rapid|suspicious/;

function severityOf(text) {
  const t = String(text).toLowerCase();
  if (CRITICAL_RE.test(t)) return "critical";
  if (WARN_RE.test(t)) return "warn";
  return "info";
}
const maxSev = (list) => list.reduce((m, s) => (SEV_RANK[s] > SEV_RANK[m] ? s : m), "info");

function rowSeverity(row) {
  const s = severityOf(Object.values(row).join(" "));
  const hasErr = Object.keys(row).some((k) => /error/i.test(k) && row[k]);
  return s === "info" && hasErr ? "warn" : s;
}

function sevMark(sev) {
  const shape = sev === "critical" ? '<path d="M6 1 11 10.5 1 10.5Z"/>'
    : sev === "warn" ? '<path d="M6 1 11 6 6 11 1 6Z"/>'
    : sev === "clear" ? '<path d="m2 6 3 3 5-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
    : '<circle cx="6" cy="6" r="3.4"/>';
  return `<svg class="sev-mark" viewBox="0 0 12 12" fill="currentColor" aria-hidden="true">${shape}</svg>`;
}

/* API wrapper — injects bearer token, normalizes errors. */
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    openAuth(true);
    throw new Error("Unauthorized — check your access token.");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error(data?.detail || data?.error || `Request failed (${res.status}).`);
  return data;
}

/* ------------------------------- toasts --------------------------------- */
function toast(msg, kind = "error") {
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.innerHTML = `<span class="bar"></span><span>${esc(msg)}</span>`;
  el.toasts.appendChild(t);
  setTimeout(() => {
    t.style.transition = "opacity .3s, transform .3s";
    t.style.opacity = "0";
    t.style.transform = "translateY(8px)";
    setTimeout(() => t.remove(), 300);
  }, 4600);
}

/* ------------------------------- thread --------------------------------- */
function clearHero() { if (el.hero) { el.hero.remove(); el.hero = null; } }

function append(node) {
  clearHero();
  el.thread.appendChild(node);
  el.thread.scrollTop = el.thread.scrollHeight;
  return node;
}

function addEntry(html) {
  const div = document.createElement("div");
  div.className = "entry";
  div.innerHTML = html;
  return append(div);
}

function addAsk(question) {
  return addEntry(`<div class="ask-row"><div class="ask-bubble">${esc(question)}</div></div>`);
}

function addStatus(text) {
  return addEntry(`<div class="status"><span class="spinner"></span><span>${esc(text)}</span></div>`);
}

function addError(title, detail) {
  return addEntry(`
    <div class="card error">
      <div class="card-head"><span class="tick"></span>${esc(title)}</div>
      <div class="body">${esc(detail)}</div>
    </div>`);
}

function addNote(text) {
  return addEntry(`<div class="status" style="border-style:dashed">${esc(text)}</div>`);
}

function renderResults(data, question) {
  const rawFlags = data.flags || [];
  const flagSevs = rawFlags.map(severityOf);
  const flags = rawFlags.map((f, i) =>
    `<span class="flag" data-sev="${flagSevs[i]}" title="${SEV_LABEL[flagSevs[i]]}">${sevMark(flagSevs[i])}${esc(f)}</span>`
  ).join("");
  const cols = data.columns || [];
  const rows = data.rows || [];
  const cardSev = rawFlags.length ? maxSev(flagSevs) : "clear";

  let table = "";
  if (rows.length) {
    const head = cols.map((c) => `<th>${esc(c)}</th>`).join("");
    const bodyRows = rows.slice(0, 200).map((r) => {
      const rs = rowSeverity(r);
      const attr = rs === "warn" || rs === "critical" ? ` data-sev="${rs}"` : "";
      return `<tr${attr}>${cols.map((c) => `<td title="${esc(r[c])}">${esc(r[c] ?? "")}</td>`).join("")}</tr>`;
    }).join("");
    const shown = Math.min(rows.length, 200);
    const foot = `${data.row_count} row${data.row_count === 1 ? "" : "s"}` +
      (shown < rows.length ? ` · showing first ${shown}` : "") +
      (data.truncated ? ` · <span class="warn">result set capped at 1000</span>` : "");
    table = `
      <div class="table-wrap"><table>
        <thead><tr>${head}</tr></thead>
        <tbody>${bodyRows}</tbody>
      </table></div>
      <div class="table-foot">${foot}</div>`;
  } else {
    table = `<div class="empty-note">No matching events were found in the selected window.</div>`;
  }

  const meta = `${fmtBytes(data.bytes_scanned)} scanned · ${fmtCost(data.bytes_scanned)}`;
  const node = addEntry(`
    <div class="card" data-sev="${cardSev}">
      <div class="card-head"><span class="tick"></span>Findings<span class="meta">${meta}</span></div>
      ${data.summary ? `<div class="narrative"><p>${esc(data.summary)}</p></div>` : ""}
      ${flags ? `<div class="flags">${flags}</div>` : ""}
      ${table}
    </div>`);
  recordCase(question, data, cardSev, node);
}

/* ------------------------------ case log -------------------------------- */
const history = [];
let caseSeq = 0;

function recordCase(question, data, sev, entryNode) {
  const id = `case-${++caseSeq}`;
  entryNode.dataset.caseId = id;
  history.unshift({ id, question, sev, rows: data.row_count || 0, bytes: data.bytes_scanned, ts: Date.now() });
  updateCaseCount();
  if (!el.caseWrap.hidden) renderCaseList();
}

function updateCaseCount() {
  el.caseCount.textContent = history.length;
  el.caseCount.dataset.empty = history.length === 0;
}

function renderCaseList() {
  el.caseEmpty.hidden = history.length > 0;
  el.caseList.hidden = history.length === 0;
  el.caseList.innerHTML = history.map((h) => `
    <div class="case-item" data-sev="${h.sev}" data-id="${h.id}" role="button" tabindex="0">
      ${sevMark(h.sev)}
      <span class="case-body">
        <span class="case-q">${esc(h.question)}</span>
        <span class="case-meta"><span class="case-sev-tag">${SEV_LABEL[h.sev]}</span> · ${fmtTime(h.ts)} · ${h.rows} row${h.rows === 1 ? "" : "s"} · ${fmtBytes(h.bytes)}</span>
      </span>
      <span class="case-rerun" role="button" tabindex="0" title="Run this question again" aria-label="Run again" data-rerun="${h.id}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12a9 9 0 1 1-2.6-6.4M21 3v5h-5" />
        </svg>
      </span>
    </div>`).join("");
}

function openCase() { renderCaseList(); el.caseWrap.hidden = false; setTimeout(() => el.closeCase.focus(), 60); }
function closeCase() { el.caseWrap.hidden = true; }

function jumpToCase(id) {
  const node = [...el.thread.querySelectorAll(".entry")].find((n) => n.dataset.caseId === id);
  closeCase();
  if (!node) return;
  node.scrollIntoView({ behavior: "smooth", block: "center" });
  node.classList.remove("flash");
  void node.offsetWidth; // restart the animation
  node.classList.add("flash");
}

function rerunCase(question) { closeCase(); investigate(question); }

/* --------------------------- auth token modal --------------------------- */
function openAuth(force = false) {
  el.tokenInput.value = token;
  el.authNote.textContent = force
    ? "That token was rejected. Paste a valid one to continue."
    : "Find it in Secrets Manager under the secret this stack created.";
  el.authNote.classList.toggle("field-error", force);
  el.authScrim.hidden = false;
  setTimeout(() => el.tokenInput.focus(), 60);
}
function closeAuth() { el.authScrim.hidden = true; }

function saveToken() {
  const v = el.tokenInput.value.trim();
  if (!v) { el.tokenInput.focus(); return; }
  token = v;
  localStorage.setItem(TOKEN_KEY, token);
  el.keyBtn.dataset.set = "true";
  closeAuth();
  toast("Access token saved.", "info");
  checkHealth();
}

/* ---------------------------- SQL warrant ------------------------------- */
function openSql(sql, question) {
  pending = { question };
  el.sqlBox.value = sql;
  const source = /vpc_flow_logs/i.test(sql) ? "VPC Flow Logs" : "CloudTrail";
  el.warrantMeta.innerHTML = `
    <span class="tag">engine <b>Athena · Trino</b></span>
    <span class="tag">mode <b>read-only</b></span>
    <span class="tag">source <b>${source}</b></span>`;
  el.scopeText.textContent = "bounded by workgroup cutoff";
  el.sqlScrim.hidden = false;
  setTimeout(() => el.sqlBox.focus(), 60);
}
function closeSql() { el.sqlScrim.hidden = true; pending = null; }

/* ------------------------------ actions --------------------------------- */
function setBusy(state) {
  busy = state;
  el.askBtn.disabled = state;
}

async function investigate(question) {
  if (busy) return;
  if (!token) { openAuth(); return; }
  addAsk(question);
  el.question.value = "";
  autoGrow();
  setBusy(true);
  const status = addStatus("Drafting an Athena query from your question…");
  try {
    const { sql } = await api("/api/generate-sql", { method: "POST", body: { question, model_id: currentModel() } });
    status.remove();
    openSql(sql, question);
  } catch (e) {
    status.remove();
    addError("Couldn't draft a safe query", e.message);
  } finally {
    setBusy(false);
  }
}

async function runApproved() {
  const question = pending?.question || "";
  const sql = el.sqlBox.value.trim();
  if (!sql) return;
  closeSql();
  setBusy(true);
  const status = addStatus("Running the approved query on Athena…");
  try {
    const { execution_id } = await api("/api/execute-sql", { method: "POST", body: { sql } });
    const data = await pollResults(execution_id, question, status);
    status.remove();
    if (data.status === "failed") {
      addError("Athena query failed", data.error || "The query did not succeed.");
    } else {
      renderResults(data, question);
    }
  } catch (e) {
    status.remove();
    addError("Execution error", e.message);
  } finally {
    setBusy(false);
  }
}

async function pollResults(id, question, status) {
  const q = `?question=${encodeURIComponent(question)}&model_id=${encodeURIComponent(currentModel())}`;
  for (let i = 0; i < POLL_MAX; i++) {
    const data = await api(`/api/results/${id}${q}`);
    if (data.status !== "running") return data;
    if (status) status.querySelector("span:last-child").textContent =
      `Scanning CloudTrail on Athena… (${i + 1})`;
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  throw new Error("Timed out waiting for Athena results.");
}

/* ------------------------------ health ---------------------------------- */
async function checkHealth() {
  try {
    const res = await fetch(`${API}/api/health`);
    const d = await res.json();
    el.health.dataset.state = "ok";
    el.health.querySelector(".label").textContent = d.model ? `online · ${shortModel(d.model)}` : "online";
    el.health.title = `Backend online — ${(d.tables || [d.table]).filter(Boolean).join(", ")}`;
  } catch {
    el.health.dataset.state = "down";
    el.health.querySelector(".label").textContent = "backend offline";
    el.health.title = `Cannot reach ${API}`;
  }
}
const shortModel = (m) => (m.includes("claude") ? m.replace(/^.*?(claude[\w.-]*?)(?:-v\d.*|:.*)?$/i, "$1").slice(0, 22) : m.slice(0, 22));

/* ----------------------------- model picker ----------------------------- */
let lastRealModel = el.modelSelect.value;
const chevron = document.querySelector(".model-picker .chevron");

// Selected model: the dropdown value, or the free-text field in custom mode.
function currentModel() {
  return el.modelSelect.value === CUSTOM ? el.customModel.value.trim() : el.modelSelect.value;
}
function setCustomMode(on) {
  // toggleAttribute (not .hidden) because the chevron is an SVGElement, which
  // has no reflecting `hidden` property — setting .hidden on it does nothing.
  el.modelSelect.toggleAttribute("hidden", on);
  chevron.toggleAttribute("hidden", on);
  el.customModel.toggleAttribute("hidden", !on);
  el.customBack.toggleAttribute("hidden", !on);
  if (on) el.customModel.focus();
}
function persistModel() {
  localStorage.setItem(MODEL_KEY, el.modelSelect.value);
  localStorage.setItem(CUSTOM_MODEL_KEY, el.customModel.value.trim());
}

/* ---------------------------- composer UX ------------------------------- */
function autoGrow() {
  el.question.style.height = "auto";
  el.question.style.height = Math.min(el.question.scrollHeight, 160) + "px";
}

/* ------------------------------ events ---------------------------------- */
el.composer.addEventListener("submit", (e) => {
  e.preventDefault();
  const q = el.question.value.trim();
  if (q) investigate(q);
});
el.question.addEventListener("input", autoGrow);
el.question.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); el.composer.requestSubmit(); }
});

document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => { el.question.value = c.textContent; autoGrow(); el.question.focus(); })
);

el.modelSelect.addEventListener("change", () => {
  if (el.modelSelect.value === CUSTOM) setCustomMode(true);
  else { lastRealModel = el.modelSelect.value; setCustomMode(false); }
  persistModel();
});
el.customModel.addEventListener("input", () => localStorage.setItem(CUSTOM_MODEL_KEY, el.customModel.value.trim()));
el.customBack.addEventListener("click", () => {
  el.modelSelect.value = lastRealModel;
  setCustomMode(false);
  persistModel();
});

el.caseLogBtn.addEventListener("click", openCase);
el.closeCase.addEventListener("click", closeCase);
el.clearCase.addEventListener("click", () => { history.length = 0; updateCaseCount(); renderCaseList(); });
el.caseWrap.addEventListener("click", (e) => { if (e.target.matches("[data-close]")) closeCase(); });
el.caseList.addEventListener("click", (e) => {
  const rerun = e.target.closest("[data-rerun]");
  if (rerun) { e.stopPropagation(); const h = history.find((x) => x.id === rerun.dataset.rerun); if (h) rerunCase(h.question); return; }
  const item = e.target.closest(".case-item");
  if (item) jumpToCase(item.dataset.id);
});
el.caseList.addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const rerun = e.target.closest("[data-rerun]");
  const item = e.target.closest(".case-item");
  if (!rerun && !item) return;
  e.preventDefault();
  if (rerun) { const h = history.find((x) => x.id === rerun.dataset.rerun); if (h) rerunCase(h.question); }
  else jumpToCase(item.dataset.id);
});

el.keyBtn.addEventListener("click", () => openAuth());
el.saveToken.addEventListener("click", saveToken);
el.authForm.addEventListener("submit", (e) => { e.preventDefault(); saveToken(); });
el.revealToken.addEventListener("click", () => {
  el.tokenInput.type = el.tokenInput.type === "password" ? "text" : "password";
});

el.approveSql.addEventListener("click", runApproved);
el.cancelSql.addEventListener("click", () => { closeSql(); addNote("Query cancelled — nothing was run."); });

// Backdrop click + Escape close whichever modal is open.
[el.authScrim, el.sqlScrim].forEach((s) =>
  s.addEventListener("click", (e) => {
    if (e.target !== s) return;
    if (s === el.authScrim && token) closeAuth();
    if (s === el.sqlScrim) { closeSql(); addNote("Query cancelled — nothing was run."); }
  })
);
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!el.caseWrap.hidden) closeCase();
  else if (!el.sqlScrim.hidden) { closeSql(); addNote("Query cancelled — nothing was run."); }
  else if (!el.authScrim.hidden && token) closeAuth();
});

/* ------------------------------- boot ----------------------------------- */
const savedModel = localStorage.getItem(MODEL_KEY);
if (savedModel && [...el.modelSelect.options].some((o) => o.value === savedModel)) el.modelSelect.value = savedModel;
el.customModel.value = localStorage.getItem(CUSTOM_MODEL_KEY) || "";
if (el.modelSelect.value === CUSTOM) setCustomMode(true);
else lastRealModel = el.modelSelect.value;

if (token) el.keyBtn.dataset.set = "true";
else openAuth();
autoGrow();
updateCaseCount();
checkHealth();
