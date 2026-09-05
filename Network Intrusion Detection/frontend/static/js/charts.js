/**
 * charts.js — Lightweight canvas-based chart renderers
 * (No external dependencies — works without internet)
 */

"use strict";

const CHART_COLORS = {
  Normal : "#3fb950",
  DoS    : "#f85149",
  Probe  : "#e3b341",
  R2L    : "#d29922",
  U2R    : "#bc8cff"
};

/* ── Donut chart ─────────────────────────────────────────────────────────── */
function drawDonut(canvasId, data, legendId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2;
  const R = Math.min(W, H) / 2 - 20;
  const r = R * 0.55;
  ctx.clearRect(0, 0, W, H);

  const total  = Object.values(data).reduce((a, b) => a + b, 0);
  const keys   = Object.keys(data).filter(k => data[k] > 0);

  if (total === 0) {
    ctx.fillStyle = "#8b949e";
    ctx.font = "13px Segoe UI,sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No data yet", cx, cy);
    return;
  }

  let angle = -Math.PI / 2;
  keys.forEach(k => {
    const slice = (data[k] / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, angle, angle + slice);
    ctx.closePath();
    ctx.fillStyle = CHART_COLORS[k] || "#58a6ff";
    ctx.fill();
    angle += slice;
  });

  // Donut hole
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.fillStyle = "#161b22";
  ctx.fill();

  // Centre text
  ctx.fillStyle = "#e6edf3";
  ctx.font = `bold 20px Segoe UI,sans-serif`;
  ctx.textAlign = "center";
  ctx.fillText(total, cx, cy + 4);
  ctx.font = "11px Segoe UI,sans-serif";
  ctx.fillStyle = "#8b949e";
  ctx.fillText("total", cx, cy + 18);

  // Legend
  if (legendId) {
    const legend = document.getElementById(legendId);
    if (legend) {
      legend.innerHTML = keys.map(k =>
        `<div class="legend-item">
           <div class="legend-dot" style="background:${CHART_COLORS[k] || '#58a6ff'}"></div>
           ${k} (${data[k]})
         </div>`
      ).join("");
    }
  }
}

/* ── Bar / timeline chart ────────────────────────────────────────────────── */
function drawTimeline(canvasId, items) {
  // items: [{label, timestamp}]
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  if (!items || items.length === 0) {
    ctx.fillStyle = "#8b949e";
    ctx.font = "13px Segoe UI,sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No prediction history yet", W / 2, H / 2);
    return;
  }

  // Count by category
  const cats = ["Normal", "DoS", "Probe", "R2L", "U2R"];
  const counts = {};
  cats.forEach(c => counts[c] = 0);
  items.forEach(i => { if (counts[i.label] !== undefined) counts[i.label]++; });

  const barW   = 48;
  const gap    = 20;
  const totalW = cats.length * (barW + gap) - gap;
  const startX = (W - totalW) / 2;
  const maxVal = Math.max(...Object.values(counts), 1);
  const chartH = H - 50;

  // Gridlines
  ctx.strokeStyle = "#30363d";
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = 10 + ((chartH - 10) / 4) * i;
    ctx.beginPath(); ctx.moveTo(startX - 10, y); ctx.lineTo(startX + totalW + 10, y); ctx.stroke();
    ctx.fillStyle = "#8b949e"; ctx.font = "10px Segoe UI,sans-serif"; ctx.textAlign = "right";
    ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), startX - 14, y + 4);
  }

  cats.forEach((c, i) => {
    const x   = startX + i * (barW + gap);
    const val = counts[c];
    const bh  = val === 0 ? 2 : ((val / maxVal) * (chartH - 15));
    const y   = chartH - bh + 5;

    ctx.fillStyle = CHART_COLORS[c];
    ctx.beginPath();
    ctx.roundRect(x, y, barW, bh, [4, 4, 0, 0]);
    ctx.fill();

    ctx.fillStyle = "#e6edf3"; ctx.font = "11px Segoe UI,sans-serif"; ctx.textAlign = "center";
    ctx.fillText(c, x + barW / 2, H - 8);
    if (val > 0) {
      ctx.fillStyle = "#e6edf3";
      ctx.fillText(val, x + barW / 2, y - 4);
    }
  });
}

/* ── Simple horizontal bar (batch) ─────────────────────────────────────────  */
function drawBatchBar(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cats   = Object.keys(data);
  const total  = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const rowH   = Math.floor((H - 20) / cats.length);
  const labelW = 80;
  const barMaxW= W - labelW - 60;

  cats.forEach((c, i) => {
    const y   = 10 + i * rowH;
    const val = data[c];
    const bw  = (val / total) * barMaxW;

    ctx.fillStyle = "#21262d";
    ctx.fillRect(labelW, y + 6, barMaxW, rowH - 14);

    ctx.fillStyle = CHART_COLORS[c] || "#58a6ff";
    ctx.beginPath();
    ctx.roundRect(labelW, y + 6, bw, rowH - 14, 4);
    ctx.fill();

    ctx.fillStyle = "#e6edf3"; ctx.font = "12px Segoe UI,sans-serif"; ctx.textAlign = "right";
    ctx.fillText(c, labelW - 8, y + rowH / 2 + 4);

    ctx.textAlign = "left";
    ctx.fillText(`${val} (${Math.round(val/total*100)}%)`, labelW + bw + 8, y + rowH / 2 + 4);
  });
}

/* ── Simulation pie (small) ─────────────────────────────────────────────── */
function drawSimPie(canvasId, data) {
  drawDonut(canvasId, data, null);
}
