// Canvas charts: table sparklines, the radio utilization stack and the line
// charts of a client's session. Each draws at the device's pixel ratio from
// the colour tokens of the current theme.

import { hm, palette, time } from './util.js';

/** The canvas sized to its box at the pixel ratio, cleared; null if hidden. */
function setup(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const ht = canvas.clientHeight;
  if (!w || !ht) return null;
  const pw = Math.round(w * dpr);
  const ph = Math.round(ht * dpr);
  if (canvas.width !== pw || canvas.height !== ph) {
    canvas.width = pw;
    canvas.height = ph;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, ht);
  return { ctx, w, h: ht };
}

/** A line of `values` (nulls are gaps) between `min` and `max`. */
export function sparkline(canvas, values, { color, min, max }) {
  const c = setup(canvas);
  if (!c) return;
  const { ctx, w, h } = c;
  const known = values.filter((v) => v !== null && v !== undefined);
  if (known.length < 2) return;
  const lo = min ?? Math.min(...known);
  const hi = Math.max(max ?? Math.max(...known), lo + 1);
  const x = (i) => 1 + (i / (values.length - 1)) * (w - 4);
  const y = (v) => h - 2 - ((Math.min(Math.max(v, lo), hi) - lo) / (hi - lo)) * (h - 5);
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  ctx.strokeStyle = color;
  ctx.beginPath();
  let pen = false;
  values.forEach((v, i) => {
    if (v === null || v === undefined) {
      pen = false;
      return;
    }
    if (pen) ctx.lineTo(x(i), y(v));
    else ctx.moveTo(x(i), y(v));
    pen = true;
  });
  ctx.stroke();
  const last = values.length - 1;
  if (values[last] !== null && values[last] !== undefined) {
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x(last), y(values[last]), 2.2, 0, Math.PI * 2);
    ctx.fill();
  }
}

/** Segments `{ value, color, alpha }` of a 0–100 % bar, left to right. */
export function stack(canvas, segments) {
  const c = setup(canvas);
  if (!c) return;
  const { ctx, w, h } = c;
  const p = palette();
  ctx.save();
  ctx.beginPath();
  ctx.roundRect(0, 0, w, h, h / 2);
  ctx.clip();
  ctx.fillStyle = p.rule2;
  ctx.fillRect(0, 0, w, h);
  let at = 0;
  for (const s of segments) {
    const width = (Math.max(0, s.value) / 100) * w;
    if (width <= 0) continue;
    ctx.fillStyle = s.color;
    ctx.globalAlpha = s.alpha ?? 1;
    ctx.fillRect(at, 0, width, h);
    ctx.globalAlpha = 1;
    at += width;
    // A hairline of the track between segments keeps them apart.
    ctx.fillStyle = p.surface;
    ctx.fillRect(at - 0.5, 0, 1, h);
  }
  ctx.restore();
}

/** Round tick values covering `lo`–`hi`, about `n` of them. */
function ticks(lo, hi, n = 4) {
  const span = hi - lo || 1;
  const raw = span / n;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw);
  const out = [];
  for (let v = Math.floor(lo / step) * step; ; v += step) {
    out.push(+v.toFixed(6));
    if (v >= hi - step * 1e-6) return out;
  }
}

/**
 * A line chart of samples over time:
 * `{ times, series: [{ label, color, values }], min, max, format, zones }`,
 * zones being shaded value ranges `{ from, to, color }`. Pointing at it
 * reads out the nearest sample.
 */
export function lineChart(canvas, opts) {
  canvas.chart = opts;
  if (!canvas.pointing) {
    canvas.pointing = true;
    const at = (e) => {
      canvas.hoverX = e.offsetX;
      drawLine(canvas);
    };
    canvas.addEventListener('pointermove', at);
    canvas.addEventListener('pointerdown', at);
    canvas.addEventListener('pointerleave', () => {
      canvas.hoverX = null;
      drawLine(canvas);
    });
  }
  drawLine(canvas);
}

function drawLine(canvas) {
  const opts = canvas.chart;
  const c = setup(canvas);
  if (!c || !opts || opts.times.length < 2) return;
  const { ctx, w, h } = c;
  const p = palette();
  const { times, series, format } = opts;
  const all = series.flatMap((s) => s.values).filter((v) => v !== null && v !== undefined);
  let lo = opts.min ?? Math.min(...all);
  let hi = opts.max ?? Math.max(...all);
  if (opts.min === undefined) lo = Math.min(lo, hi - 1);
  if (hi <= lo) hi = lo + 1;
  const ys = ticks(lo, hi);
  lo = Math.min(lo, ys[0]);
  hi = Math.max(hi, ys[ys.length - 1]);

  ctx.font = '11px system-ui, -apple-system, "Segoe UI", sans-serif';
  const left = Math.max(...ys.map((v) => ctx.measureText(format(v)).width)) + 10;
  const box = { l: left, r: w - 4, t: 6, b: h - 20 };
  const t0 = times[0];
  const t1 = times[times.length - 1];
  const x = (t) => box.l + ((t - t0) / (t1 - t0)) * (box.r - box.l);
  const y = (v) => box.b - ((v - lo) / (hi - lo)) * (box.b - box.t);

  for (const z of opts.zones || []) {
    const top = y(Math.min(z.to, hi));
    const bottom = y(Math.max(z.from, lo));
    if (bottom <= top) continue;
    ctx.fillStyle = z.color;
    ctx.globalAlpha = 0.1;
    ctx.fillRect(box.l, top, box.r - box.l, bottom - top);
    ctx.globalAlpha = 1;
  }

  ctx.textBaseline = 'middle';
  ctx.textAlign = 'right';
  ctx.lineWidth = 1;
  for (const v of ys) {
    const yy = Math.round(y(v)) + 0.5;
    ctx.strokeStyle = p.rule2;
    ctx.beginPath();
    ctx.moveTo(box.l, yy);
    ctx.lineTo(box.r, yy);
    ctx.stroke();
    ctx.fillStyle = p.ink3;
    ctx.fillText(format(v), box.l - 8, yy);
  }
  ctx.textBaseline = 'top';
  // Minutes repeat over a short session; seconds then tell the labels apart.
  const label = t1 - t0 < 600e3 ? time : hm;
  const labels = Math.max(2, Math.min(5, Math.floor((box.r - box.l) / 110)));
  for (let i = 0; i < labels; i++) {
    const t = t0 + ((t1 - t0) * i) / (labels - 1);
    ctx.textAlign = i === 0 ? 'left' : i === labels - 1 ? 'right' : 'center';
    ctx.fillText(label(t), x(t), box.b + 6);
  }

  ctx.lineJoin = 'round';
  ctx.lineWidth = 1.8;
  for (const s of series) {
    ctx.strokeStyle = s.color;
    ctx.beginPath();
    let pen = false;
    s.values.forEach((v, i) => {
      if (v === null || v === undefined) {
        pen = false;
        return;
      }
      if (pen) ctx.lineTo(x(times[i]), y(v));
      else ctx.moveTo(x(times[i]), y(v));
      pen = true;
    });
    ctx.stroke();
  }

  if (canvas.hoverX === null || canvas.hoverX === undefined) return;
  const want = t0 + ((canvas.hoverX - box.l) / (box.r - box.l)) * (t1 - t0);
  let i = 0;
  for (let k = 1; k < times.length; k++) if (Math.abs(times[k] - want) < Math.abs(times[i] - want)) i = k;
  const xx = Math.round(x(times[i])) + 0.5;
  ctx.strokeStyle = p.ink3;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(xx, box.t);
  ctx.lineTo(xx, box.b);
  ctx.stroke();
  const lines = [time(times[i])];
  for (const s of series) {
    const v = s.values[i];
    if (v === null || v === undefined) continue;
    ctx.fillStyle = s.color;
    ctx.beginPath();
    ctx.arc(xx, y(v), 3.2, 0, Math.PI * 2);
    ctx.fill();
    lines.push(`${s.label} ${format(v)}`);
  }
  ctx.font = '12px system-ui, -apple-system, "Segoe UI", sans-serif';
  const tw = Math.max(...lines.map((l) => ctx.measureText(l).width)) + 16;
  const th = lines.length * 17 + 8;
  const tx = xx + 10 + tw > box.r ? xx - 10 - tw : xx + 10;
  ctx.fillStyle = p.surface;
  ctx.strokeStyle = p.rule;
  ctx.beginPath();
  ctx.roundRect(tx, box.t + 4, tw, th, 6);
  ctx.fill();
  ctx.stroke();
  ctx.textAlign = 'left';
  lines.forEach((l, k) => {
    ctx.fillStyle = k ? p.ink : p.ink3;
    ctx.fillText(l, tx + 8, box.t + 9 + k * 17);
  });
}
