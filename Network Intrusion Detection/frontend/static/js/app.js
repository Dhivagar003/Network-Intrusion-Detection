/**
 * app.js — NIDS Frontend Application Logic
 */

"use strict";

/* ────────────────────────────────── State ───────────────────────────────── */
const state = {
  history    : [],   // last 20 predictions
  simCounts  : { Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0 },
  simTimer   : null,
  batchData  : null,
  featureNames: []
};

/* ────────────────────────────────── Feature form ────────────────────────── */
const KEY_FEATURES = [
  "duration","protocol_type","service","flag",
  "src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
  "num_failed_logins","logged_in","num_compromised","root_shell",
  "su_attempted","num_root","num_file_creations","num_shells",
  "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
  "count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
  "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
  "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
  "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
  "dst_host_srv_diff_host_rate","dst_host_serror_rate",
  "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
];

const PRESETS = {
  normal : { duration:2,  src_bytes:4500,  dst_bytes:3100, serror_rate:0.02, rerror_rate:0.01, same_srv_rate:0.95, count:25,  srv_count:25,  logged_in:1 },
  dos    : { duration:0,  src_bytes:120,   dst_bytes:0,    serror_rate:0.92, rerror_rate:0.88, same_srv_rate:0.99, count:500, srv_count:500, logged_in:0 },
  probe  : { duration:1,  src_bytes:180,   dst_bytes:200,  serror_rate:0.10, rerror_rate:0.75, same_srv_rate:0.10, count:150, srv_count:30,  logged_in:0 },
  r2l    : { duration:15, src_bytes:15000, dst_bytes:8000, serror_rate:0.02, rerror_rate:0.01, same_srv_rate:0.80, count:3,   srv_count:3,   logged_in:1 },
  u2r    : { duration:8,  src_bytes:3200,  dst_bytes:2000, serror_rate:0.05, rerror_rate:0.05, same_srv_rate:0.60, count:10,  srv_count:10,  root_shell:1, su_attempted:1 }
};

function buildFeatureForm() {
  const container = document.getElementById("featureForm");
  if (!container) return;
  container.innerHTML = KEY_FEATURES.map(f =>
    `<div class="form-group">
       <label>${f}</label>
       <input type="number" id="f_${f}" name="${f}" value="0" step="any" />
     </div>`
  ).join("");
}

function getFormValues() {
  const vals = {};
  KEY_FEATURES.forEach(f => {
    const el = document.getElementById(`f_${f}`);
    vals[f] = el ? parseFloat(el.value) || 0 : 0;
  });
  return vals;
}

function loadPreset(name) {
  const p = PRESETS[name];
  if (!p) return;
  KEY_FEATURES.forEach(f => {
    const el = document.getElementById(`f_${f}`);
    if (el) el.value = p[f] !== undefined ? p[f] : 0;
  });
}

/* ────────────────────────────────── API helpers ─────────────────────────── */
async function apiFetch(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

/* ────────────────────────────────── Health check ────────────────────────── */
async function checkHealth() {
  try {
    await apiFetch("/api/health");
    document.getElementById("statusDot").className  = "fa-solid fa-circle status-dot online";
    document.getElementById("statusText").textContent = "Online";
  } catch {
    document.getElementById("statusDot").className  = "fa-solid fa-circle status-dot offline";
    document.getElementById("statusText").textContent = "Offline";
  }
}

/* ────────────────────────────────── Navigation ──────────────────────────── */
function navigate(section) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const el = document.getElementById(`section-${section}`);
  if (el) el.classList.add("active");
  const navEl = document.querySelector(`[data-section="${section}"]`);
  if (navEl) navEl.classList.add("active");
  const titles = { dashboard:"Dashboard", predict:"Single Predict", batch:"Batch Upload",
                   simulate:"Live Simulate", alerts:"Alert Log", chat:"AI Chat", about:"About" };
  document.getElementById("pageTitle").textContent = titles[section] || section;

  if (section === "dashboard") refreshDashboard();
  if (section === "alerts")    refreshAlerts();
}

/* ────────────────────────────────── Dashboard ────────────────────────────── */
async function refreshDashboard() {
  try {
    const stats = await apiFetch("/api/stats");
    const bt = stats.by_type || {};

    document.getElementById("kpi-total").textContent   = stats.total_attacks || 0;
    document.getElementById("kpi-attacks").textContent = stats.total_attacks || 0;
    document.getElementById("kpi-dos").textContent     = bt.DoS   || 0;
    document.getElementById("kpi-probe").textContent   = bt.Probe || 0;
    document.getElementById("kpi-r2l").textContent     = (bt.R2L  || 0) + (bt.U2R || 0);

    drawDonut("donutChart", bt, "donutLegend");
    drawTimeline("timelineChart", state.history);
  } catch (e) {
    console.warn("Dashboard refresh:", e.message);
  }

  try {
    const alertsData = await apiFetch("/api/alerts?limit=10");
    const alerts = alertsData.alerts || [];
    updateAlertBadge(alertsData.total || 0);
    renderAlertTable("alertTableBody", alerts);
    document.getElementById("alertCount").textContent = `${alertsData.total || 0} alerts`;
  } catch (e) {
    console.warn("Alerts fetch:", e.message);
  }
}

function updateAlertBadge(n) {
  const badge = document.getElementById("alertBadge");
  badge.textContent = n;
  badge.classList.toggle("show", n > 0);
}

/* ────────────────────────────────── Alert table ─────────────────────────── */
function renderAlertTable(tbodyId, alerts) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row">No alerts yet</td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map((a, i) =>
    `<tr>
       <td>${i + 1}</td>
       <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
       <td><span class="tag tag-${a.label.toLowerCase()}">${a.label}</span></td>
       <td>${a.confidence}%</td>
       <td><span class="sev-${a.severity}">${a.severity.toUpperCase()}</span></td>
       <td><code>${a.source}</code></td>
     </tr>`
  ).join("");
}

/* ────────────────────────────────── Single predict ──────────────────────── */
async function runPredict() {
  const btn = document.getElementById("predictBtn");
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analysing…`;

  const placeholder = document.getElementById("resultPlaceholder");
  const content     = document.getElementById("resultContent");
  placeholder.classList.add("hidden");
  content.classList.add("hidden");

  try {
    const features = getFormValues();
    const result   = await apiFetch("/api/predict", {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify(features)
    });

    // Store in history
    state.history.push({ label: result.label, ts: Date.now() });
    if (state.history.length > 20) state.history.shift();

    renderPredictionResult(result);
    content.classList.remove("hidden");
  } catch (e) {
    alert("Prediction error: " + e.message);
    placeholder.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-wand-magic-sparkles"></i> Analyse Traffic`;
  }
}

function renderPredictionResult(r) {
  const label = r.label;
  const cls   = label.toLowerCase().replace("/", "");

  // Verdict
  const vb = document.getElementById("verdictBadge");
  vb.textContent = r.is_attack
    ? `⚠ ATTACK DETECTED: ${label}`
    : `✓ NORMAL TRAFFIC`;
  vb.className = `verdict ${cls}`;

  // Confidence bar
  document.getElementById("confFill").style.width  = `${r.confidence}%`;
  document.getElementById("confValue").textContent = `${r.confidence}%`;

  // Probability grid
  const pg = document.getElementById("probGrid");
  const colorMap = { Normal:"#3fb950", DoS:"#f85149", Probe:"#e3b341", R2L:"#d29922", U2R:"#bc8cff" };
  pg.innerHTML = Object.entries(r.probabilities || {}).map(([k, v]) =>
    `<div class="prob-item">
       <div class="prob-item-label">${k}</div>
       <div class="prob-item-bar">
         <div class="prob-item-fill" style="width:${(v*100).toFixed(1)}%;background:${colorMap[k]||'#58a6ff'}"></div>
       </div>
       <small style="color:var(--muted)">${(v*100).toFixed(1)}%</small>
     </div>`
  ).join("");

  // AI explanation
  const aiBody = document.getElementById("aiBody");
  aiBody.textContent = r.explanation || "No explanation available.";
}

/* ────────────────────────────────── Batch upload ────────────────────────── */
function setupBatchUpload() {
  const zone    = document.getElementById("uploadZone");
  const input   = document.getElementById("csvInput");

  zone.addEventListener("dragover",  e => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", e => {
    e.preventDefault(); zone.classList.remove("drag-over");
    if (e.dataTransfer.files[0]) uploadCSV(e.dataTransfer.files[0]);
  });
  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => { if (input.files[0]) uploadCSV(input.files[0]); });
}

async function uploadCSV(file) {
  const prog   = document.getElementById("batchProgress");
  const fill   = document.getElementById("batchFill");
  const status = document.getElementById("batchStatus");
  prog.classList.remove("hidden");
  fill.style.width = "30%";
  status.textContent = "Uploading…";

  const form = new FormData();
  form.append("file", file);

  try {
    fill.style.width = "60%";
    status.textContent = "Analysing…";

    const result = await apiFetch("/api/predict/batch", { method: "POST", body: form });

    fill.style.width = "100%";
    status.textContent = `Done — ${result.total} records processed.`;

    state.batchData = result;
    renderBatchResults(result);

    setTimeout(() => prog.classList.add("hidden"), 2000);
  } catch (e) {
    fill.style.width = "100%";
    fill.style.background = "var(--red)";
    status.textContent = "Error: " + e.message;
  }
}

function renderBatchResults(data) {
  const card = document.getElementById("batchResultCard");
  card.classList.remove("hidden");

  // KPIs
  const kpis    = document.getElementById("batchKpis");
  const summary = data.summary || {};
  const colorMap = { Normal:"bg-green", DoS:"bg-red", Probe:"bg-yellow", R2L:"bg-orange", U2R:"bg-purple" };
  kpis.innerHTML = Object.entries(summary).map(([k, v]) =>
    `<div class="kpi-card">
       <div class="kpi-icon ${colorMap[k]||'bg-blue'}"><i class="fa-solid fa-circle"></i></div>
       <div class="kpi-body">
         <span class="kpi-label">${k}</span>
         <span class="kpi-value">${v}</span>
       </div>
     </div>`
  ).join("");

  drawBatchBar("batchChart", summary);

  // Table (first 100 rows)
  const tbody   = document.getElementById("batchTableBody");
  const results = (data.results || []).slice(0, 100);
  tbody.innerHTML = results.map((r, i) =>
    `<tr>
       <td>${i+1}</td>
       <td><span class="tag tag-${r.label.toLowerCase()}">${r.label}</span></td>
       <td>${r.confidence}%</td>
       <td><span class="sev-${r.severity}">${r.severity.toUpperCase()}</span></td>
       <td>${r.is_attack ? "⚠ Yes" : "✓ No"}</td>
     </tr>`
  ).join("");

  // Export button
  document.getElementById("exportBtn").onclick = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a    = document.createElement("a");
    a.href     = URL.createObjectURL(blob);
    a.download = "nids_batch_results.json";
    a.click();
  };
}

/* ────────────────────────────────── Simulation ──────────────────────────── */
function startSimulation() {
  const interval = parseInt(document.getElementById("simInterval").value, 10);
  document.getElementById("simStartBtn").disabled = true;
  document.getElementById("simStopBtn").disabled  = false;

  state.simTimer = setInterval(runSimTick, interval);
  runSimTick();   // immediate first tick
}

function stopSimulation() {
  clearInterval(state.simTimer);
  state.simTimer = null;
  document.getElementById("simStartBtn").disabled = false;
  document.getElementById("simStopBtn").disabled  = true;
}

async function runSimTick() {
  try {
    const r = await apiFetch("/api/simulate");
    const label = r.label;

    // Update counts
    state.simCounts[label] = (state.simCounts[label] || 0) + 1;
    state.history.push({ label, ts: Date.now() });
    if (state.history.length > 20) state.history.shift();

    drawSimPie("simPieChart", state.simCounts);

    // Live feed
    const feed = document.getElementById("liveFeed");
    const item = document.createElement("div");
    item.className = `feed-item ${label.toLowerCase()}`;
    item.innerHTML =
      `<span><strong>${label}</strong> — ${r.confidence}% confidence</span>
       <span style="font-size:11px;color:var(--muted)">${new Date().toLocaleTimeString()}</span>`;
    feed.prepend(item);

    // Keep feed to 30 items
    while (feed.children.length > 30) feed.removeChild(feed.lastChild);

    // Alert badge refresh
    if (r.is_attack) {
      const badge = document.getElementById("alertBadge");
      const n = (parseInt(badge.textContent, 10) || 0) + 1;
      badge.textContent = n;
      badge.classList.add("show");
    }
  } catch (e) {
    console.warn("Sim tick error:", e.message);
  }
}

/* ────────────────────────────────── Alerts page ─────────────────────────── */
async function refreshAlerts() {
  try {
    const data   = await apiFetch("/api/alerts?limit=200");
    const alerts = data.alerts || [];
    document.getElementById("alertLogCount").textContent = alerts.length;
    const tbody = document.getElementById("alertLogBody");
    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-row">No alerts</td></tr>`;
      return;
    }
    tbody.innerHTML = alerts.map((a, i) =>
      `<tr>
         <td><code>${a.id}</code></td>
         <td>${new Date(a.timestamp).toLocaleString()}</td>
         <td><span class="tag tag-${a.label.toLowerCase()}">${a.label}</span></td>
         <td>${a.confidence}%</td>
         <td><span class="sev-${a.severity}">${a.severity.toUpperCase()}</span></td>
         <td><code>${a.source}</code></td>
       </tr>`
    ).join("");
  } catch (e) {
    console.warn("Alert refresh:", e.message);
  }
}

/* ────────────────────────────────── Chat ────────────────────────────────── */
const chatState = {
  history   : [],   // { role: "user"|"assistant", content: str }
  session_id: "sess-" + Math.random().toString(36).slice(2, 10)  // stable per page-load
};

function appendChatMessage(role, text) {
  const window_ = document.getElementById("chatWindow");
  const wrap = document.createElement("div");
  wrap.className = `chat-msg ${role}`;
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  bubble.textContent = text;
  wrap.appendChild(bubble);
  window_.appendChild(wrap);
  window_.scrollTop = window_.scrollHeight;
}

function appendChatTyping() {
  const window_ = document.getElementById("chatWindow");
  const wrap = document.createElement("div");
  wrap.className = "chat-msg assistant typing-wrap";
  wrap.innerHTML = `<div class="chat-bubble typing"><span></span><span></span><span></span></div>`;
  window_.appendChild(wrap);
  window_.scrollTop = window_.scrollHeight;
  return wrap;
}

async function sendChatMessage() {
  const input = document.getElementById("chatInput");
  const btn   = document.getElementById("chatSendBtn");
  const text  = input.value.trim();
  if (!text) return;

  input.value = "";
  input.disabled = true;
  btn.disabled   = true;

  appendChatMessage("user", text);
  const typingEl = appendChatTyping();

  try {
    const data = await apiFetch("/api/chat", {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({
        message   : text,
        history   : chatState.history,
        session_id: chatState.session_id
      })
    });

    typingEl.remove();
    const reply = data.reply || "No response.";
    appendChatMessage("assistant", reply);

    // Keep history (last 10 turns to avoid prompt bloat)
    chatState.history.push({ role: "user",      content: text  });
    chatState.history.push({ role: "assistant", content: reply });
    if (chatState.history.length > 20) chatState.history.splice(0, 2);
  } catch (e) {
    typingEl.remove();
    appendChatMessage("assistant", `⚠ Error: ${e.message}`);
  } finally {
    input.disabled = false;
    btn.disabled   = false;
    input.focus();
  }
}

function clearChat() {
  chatState.history = [];
  const window_ = document.getElementById("chatWindow");
  window_.innerHTML = `<div class="chat-msg assistant">
    <div class="chat-bubble">Conversation cleared. How can I help you with network security?</div>
  </div>`;
}

/* ────────────────────────────────── Init ────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  buildFeatureForm();
  checkHealth();
  refreshDashboard();

  // Navigation
  document.querySelectorAll(".nav-item").forEach(el => {
    el.addEventListener("click", e => {
      e.preventDefault();
      navigate(el.dataset.section);
      // Close mobile sidebar
      document.getElementById("sidebar").classList.remove("open");
    });
  });

  // Mobile menu toggle
  document.getElementById("menuToggle").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });

  // Predict button
  document.getElementById("predictBtn").addEventListener("click", runPredict);

  // Refresh button
  document.getElementById("refreshBtn").addEventListener("click", refreshDashboard);

  // Clear alerts
  document.getElementById("clearAlertsBtn").addEventListener("click", async () => {
    if (!confirm("Clear all alerts?")) return;
    await apiFetch("/api/alerts/clear", { method: "DELETE" });
    state.history = [];
    updateAlertBadge(0);
    refreshDashboard();
  });

  // Simulation controls
  document.getElementById("simStartBtn").addEventListener("click", startSimulation);
  document.getElementById("simStopBtn").addEventListener("click", stopSimulation);

  // Chat
  document.getElementById("chatSendBtn").addEventListener("click", sendChatMessage);
  document.getElementById("chatInput").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
  });
  document.getElementById("chatClearBtn").addEventListener("click", clearChat);

  // Batch upload
  setupBatchUpload();

  // Auto-refresh dashboard every 30s
  setInterval(refreshDashboard, 30_000);
});

// Expose loadPreset globally (called from HTML)
window.loadPreset = loadPreset;
