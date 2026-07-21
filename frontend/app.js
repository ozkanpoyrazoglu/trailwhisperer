/* TrailWhisperer — frontend logic (vanilla, no build step).
   Flow: question -> POST /api/generate-sql -> approve in modal ->
   POST /api/execute-sql -> poll GET /api/results/{id} -> render narrative + table. */

"use strict";

// API base resolution order: deploy-time config.js (set by the stack) → ?api= override → local dev.
const API =
  (window.TRAILWHISPERER_CONFIG && window.TRAILWHISPERER_CONFIG.apiBase) ||
  new URLSearchParams(location.search).get("api") ||
  "http://localhost:8000";
const TOKEN_KEY = "trailwhisperer.token";
const SESSION_KEY = "trailwhisperer.session";
const AUTO_KEY = "trailwhisperer.autorun";
const MODEL_KEY = "trailwhisperer.model";
const CUSTOM_MODEL_KEY = "trailwhisperer.model.custom";
const HELP_KEY = "trailwhisperer.helppanel";
const THEME_KEY = "trailwhisperer.theme";
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
  warrantExplain: $("warrantExplain"), explainText: $("explainText"),
  approveSql: $("approveSql"), cancelSql: $("cancelSql"), scopeText: $("scopeText"),
  autoRun: $("autoRun"),
  toasts: $("toasts"),
  caseCount: $("caseCount"), caseList: $("caseList"), caseEmpty: $("caseEmpty"), clearCase: $("clearCase"),
  app: $("app"), helpToggle: $("helpToggle"), helpClose: $("helpClose"),
  themeToggle: $("themeToggle"),
};

let token = localStorage.getItem(TOKEN_KEY) || "";
let pending = null; // { question } awaiting SQL approval
let busy = false;

// Stable per-browser session id ties this thread's turns to server-side
// conversational memory (DynamoDB). Persisted so a reload keeps the context.
let sessionId = localStorage.getItem(SESSION_KEY);
if (!sessionId) {
  sessionId = (crypto.randomUUID && crypto.randomUUID()) ||
    `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  localStorage.setItem(SESSION_KEY, sessionId);
}

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
  return addEntry(`<div class="turn user"><div class="bubble">${esc(question)}</div></div>`);
}

/* Analyst turn scaffold — a signal monogram in the left rail + content body.
   Used by the thinking status, plain-text replies, findings, and errors so
   every non-user message shares one conversational rhythm. */
const AVATAR = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h3l2-7 3 15 3-11 2 5h7"/></svg>`;
function agentTurn(inner, thinking = false) {
  return `<div class="turn agent${thinking ? " is-thinking" : ""}"><span class="avatar" aria-hidden="true">${AVATAR}</span><div class="turn-body">${inner}</div></div>`;
}

/* Rotating "thinking" status — cycles through analyst-style lines with a
   shimmer + fade so a wait feels alive (like a model reasoning out loud).
   Returns the entry node with a .stop() to clear its timer before removal. */
const THINK_GENERATE = [
  "Reading your question…",
  "Consulting the CloudTrail & VPC Flow Logs schema…",
  "Choosing the right table and time window…",
  "Drafting a safe, read-only Athena query…",
];
const THINK_EXECUTE = [
  "Pruning partitions to your time window…",
  "Scanning matching log records on Athena…",
  "Correlating events across the trail…",
  "Distilling what the logs actually say…",
];

function addThinking(messages) {
  const node = addEntry(
    agentTurn(`<div class="thinking"><span class="status-msg swap">${esc(messages[0])}</span></div>`, true)
  );
  const msgEl = node.querySelector(".status-msg");
  let i = 0;
  const timer = setInterval(() => {
    i = (i + 1) % messages.length;
    msgEl.classList.remove("swap");
    void msgEl.offsetWidth; // restart the fade animation
    msgEl.textContent = messages[i];
    msgEl.classList.add("swap");
  }, 2400);
  node.stop = () => clearInterval(timer);
  return node;
}

function addError(title, detail) {
  return addEntry(agentTurn(`
    <div class="card error">
      <div class="card-head"><span class="tick"></span>${esc(title)}</div>
      <div class="body">${esc(detail)}</div>
    </div>`));
}

function addNote(text) {
  return addEntry(`<div class="note">${esc(text)}</div>`);
}

// A plain-text analyst reply (model answered from conversation memory — no query).
function addAssistant(text) {
  return addEntry(agentTurn(`<div class="reply"><p>${esc(text)}</p></div>`));
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
  const node = addEntry(agentTurn(`
    <div class="card" data-sev="${cardSev}">
      <div class="card-head"><span class="tick"></span>Findings<span class="meta">${meta}</span></div>
      ${data.summary ? `<div class="narrative"><p>${esc(data.summary)}</p></div>` : ""}
      ${flags ? `<div class="flags">${flags}</div>` : ""}
      ${table}
    </div>`));
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
  renderCaseList();
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

function jumpToCase(id) {
  const node = [...el.thread.querySelectorAll(".entry")].find((n) => n.dataset.caseId === id);
  if (!node) return;
  node.scrollIntoView({ behavior: "smooth", block: "center" });
  node.classList.remove("flash");
  void node.offsetWidth; // restart the animation
  node.classList.add("flash");
}

function rerunCase(question) { investigate(question); }

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
function openSql(sql, question, explanation) {
  pending = { question };
  el.sqlBox.value = sql;
  const expl = (explanation || "").trim();
  el.explainText.textContent = expl;
  el.warrantExplain.hidden = !expl;
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
  const status = addThinking(THINK_GENERATE);
  try {
    const resp = await api("/api/generate-sql", { method: "POST", body: { question, model_id: currentModel(), session_id: sessionId } });
    status.stop(); status.remove();
    // Agentic routing: the model either answered from memory (chat_response) or
    // proposed a query (sql). With auto-run ON the query runs immediately with
    // no approval step; otherwise it's shown in the warrant modal for approval.
    if (resp.chat_response) addAssistant(resp.chat_response);
    else if (el.autoRun.checked) await executeSql(resp.sql, question);
    else openSql(resp.sql, question, resp.explanation);
  } catch (e) {
    status.stop(); status.remove();
    addError("Couldn't draft a safe query", e.message);
  } finally {
    setBusy(false);
  }
}

// Manual approval path: run the SQL currently shown in the warrant modal.
async function runApproved() {
  const question = pending?.question || "";
  const sql = el.sqlBox.value.trim();
  if (!sql) return;
  closeSql();
  await executeSql(sql, question);
}

// Execute an (already validated) query on Athena and render the results.
// Shared by manual approval and the auto-run path.
async function executeSql(sql, question) {
  if (!sql) return;
  setBusy(true);
  const status = addThinking(THINK_EXECUTE);
  try {
    const { execution_id } = await api("/api/execute-sql", { method: "POST", body: { sql } });
    const data = await pollResults(execution_id, question);
    status.stop(); status.remove();
    if (data.status === "failed") {
      addError("Athena query failed", data.error || "The query did not succeed.");
    } else {
      renderResults(data, question);
    }
  } catch (e) {
    status.stop(); status.remove();
    addError("Execution error", e.message);
  } finally {
    setBusy(false);
  }
}

async function pollResults(id, question) {
  const q = `?question=${encodeURIComponent(question)}&model_id=${encodeURIComponent(currentModel())}&session_id=${encodeURIComponent(sessionId)}`;
  for (let i = 0; i < POLL_MAX; i++) {
    const data = await api(`/api/results/${id}${q}`);
    if (data.status !== "running") return data;
    // The rotating thinking-status conveys progress; no per-poll text needed.
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
    // Connectivity only — the model in use is the picker selection (sent per
    // request), not the backend default, so showing d.model here misleads.
    el.health.querySelector(".label").textContent = "online";
    const tables = (d.tables || [d.table]).filter(Boolean).join(", ");
    el.health.title = `Backend online${d.model ? ` · default model ${d.model}` : ""}${tables ? ` — ${tables}` : ""}`;
  } catch {
    el.health.dataset.state = "down";
    el.health.querySelector(".label").textContent = "backend offline";
    el.health.title = `Cannot reach ${API}`;
  }
}

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

/* ------------------------------- theme ---------------------------------- */
// Resolve the initial theme: explicit saved choice wins, else follow the OS.
function initialTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light" : "dark";
}
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  el.themeToggle.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
}
function toggleTheme() {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
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

// Hero chips + right-sidebar "What can you ask?" prompts both fill the composer.
document.querySelectorAll(".chip, .sample-q").forEach((c) =>
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

el.clearCase.addEventListener("click", () => { history.length = 0; updateCaseCount(); renderCaseList(); });
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

// "What can you ask?" panel: collapsed by default, toggled + persisted.
function setHelp(open) {
  el.app.classList.toggle("help-open", open);
  el.helpToggle.setAttribute("aria-expanded", open ? "true" : "false");
  localStorage.setItem(HELP_KEY, open ? "1" : "0");
}
el.helpToggle.addEventListener("click", () => setHelp(true));
el.helpClose.addEventListener("click", () => setHelp(false));

el.themeToggle.addEventListener("click", toggleTheme);

el.keyBtn.addEventListener("click", () => openAuth());
el.saveToken.addEventListener("click", saveToken);
el.authForm.addEventListener("submit", (e) => { e.preventDefault(); saveToken(); });
el.revealToken.addEventListener("click", () => {
  el.tokenInput.type = el.tokenInput.type === "password" ? "text" : "password";
});

el.approveSql.addEventListener("click", runApproved);
el.cancelSql.addEventListener("click", () => { closeSql(); addNote("Query cancelled — nothing was run."); });

// Auto-run toggle: persist. When on, approved queries run immediately with no
// approval step (see investigate()).
el.autoRun.addEventListener("change", () => {
  localStorage.setItem(AUTO_KEY, el.autoRun.checked ? "1" : "0");
});

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
  if (!el.sqlScrim.hidden) { closeSql(); addNote("Query cancelled — nothing was run."); }
  else if (!el.authScrim.hidden && token) closeAuth();
  else if (el.app.classList.contains("help-open")) setHelp(false);
});

/* ------------------------------- boot ----------------------------------- */
applyTheme(initialTheme());

const savedModel = localStorage.getItem(MODEL_KEY);
if (savedModel && [...el.modelSelect.options].some((o) => o.value === savedModel)) el.modelSelect.value = savedModel;
el.customModel.value = localStorage.getItem(CUSTOM_MODEL_KEY) || "";
if (el.modelSelect.value === CUSTOM) setCustomMode(true);
else lastRealModel = el.modelSelect.value;

el.autoRun.checked = localStorage.getItem(AUTO_KEY) === "1";
setHelp(localStorage.getItem(HELP_KEY) === "1"); // default: collapsed

if (token) el.keyBtn.dataset.set = "true";
else openAuth();
autoGrow();
updateCaseCount();
renderCaseList();
checkHealth();
