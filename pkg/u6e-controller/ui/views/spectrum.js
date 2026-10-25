// Spectrum: a radio's own channel as its spectral-scan hardware hears it, so
// that what is not Wi-Fi (a microwave oven, a video sender, Bluetooth) shows
// beside what is. The spectrum now and its highest since the scan began, with
// the channel's 20 MHz parts and the primary one marked, over a waterfall of
// the last minute. A scan takes a little of the radio's airtime, so only an
// admin starts one; it runs while someone watches, 10 minutes at most.

import { h, icon, bandName, palette } from '../util.js';

const ADMIN_GROUP = 'wifi-admins';
/** The radios that scan, by the names the image gives them, and their bands. */
const RADIOS = [['radio24', '2.4'], ['radio5', '5'], ['radio6', '6']];
/** The waterfall: a row each eighth of a second, a frame's period, a minute
 * of them. */
const ROW_MS = 125;
const ROWS = 480;
/** The power scale of the chart and the colours, dBm. */
const LOW = -100;
const HIGH = -30;
/** The plots' left gutter, where the power and time labels go. */
const GUTTER = 46;
const LOCK = 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4';
const PLAY = 'M7 4l13 8-13 8z';
const STOP = 'M6 6h12v12H6z';

/** A frame in the layout the controller sends (its `spectrum` module): the
 * key it is of, the segment scanned, and dBm per bin; null for another layout.
 * The step between bins is the width over their number: the frame's own is
 * rounded to the kHz, which would drift across 512 bins. */
export function decodeFrame(buf) {
  const v = new DataView(buf);
  if (v.byteLength < 25 || v.getUint8(0) !== 1) return null;
  const n = v.getUint16(6, true);
  const k = v.getUint8(24);
  if (v.byteLength !== 25 + k + n || !n) return null;
  const width = v.getUint16(4, true);
  return {
    noise: v.getInt8(1),
    center: v.getUint16(2, true),
    width,
    first: v.getUint32(8, true) / 10,
    step: width / n,
    at: v.getUint32(16, true) + v.getUint32(20, true) * 2 ** 32,
    key: new TextDecoder().decode(new Uint8Array(buf, 25, k)),
    bins: new Int8Array(buf, 25 + k, n),
  };
}

/** The centre frequency of a 20 MHz channel, MHz. */
function channelMhz(band, ch) {
  if (band === '2.4') return ch === 14 ? 2484 : 2407 + 5 * ch;
  return (band === '6' ? 5950 : 5000) + 5 * ch;
}

// Colour scales whose lightness runs one way only, from the plot's own
// background: brighter with power on dark (viridis), darker on light (magma).
const RAMPS = {
  dark: ['#46327e', '#365c8d', '#277f8e', '#1fa187', '#4ac16d', '#a0da39', '#fde725'],
  light: ['#fcfdbf', '#fec287', '#fb8761', '#e55964', '#b5367a', '#812581', '#4f127b', '#1c1044'],
};

function rgb(hex) {
  const v = parseInt(hex.replace('#', ''), 16);
  return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
}

/** Whether the theme's surfaces are dark. */
function isDark(p) {
  const [r, g, b] = rgb(p.surface);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 128;
}

/** The colour of every dBm from -128 to 127, as RGBA bytes. */
function colourTable(p) {
  const dark = isDark(p);
  const stops = [p.sunken, ...RAMPS[dark ? 'dark' : 'light']].map(rgb);
  const table = new Uint8ClampedArray(256 * 4);
  for (let i = 0; i < 256; i++) {
    const t = Math.min(1, Math.max(0, (i - 128 - LOW) / (HIGH - LOW))) * (stops.length - 1);
    const j = Math.min(stops.length - 2, Math.floor(t));
    const f = t - j;
    for (let c = 0; c < 3; c++) table[i * 4 + c] = stops[j][c] + (stops[j + 1][c] - stops[j][c]) * f;
    table[i * 4 + 3] = 255;
  }
  return table;
}

/** The canvas sized to its box at the pixel ratio; null if hidden. */
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
  ctx.font = '11px system-ui, -apple-system, "Segoe UI", sans-serif';
  return { ctx, w, h: ht };
}

/** Frequency ticks for a segment `lo`–`hi` MHz about `px` wide. */
function freqTicks(lo, hi, px) {
  const step = [2, 5, 10, 20, 40, 80].find((s) => (hi - lo) / s <= Math.max(2, px / 60)) || 160;
  const out = [];
  for (let f = Math.ceil(lo / step) * step; f <= hi; f += step) out.push(f);
  return out;
}

/**
 * The last minute of a radio's frames, a row each eighth of a second: kept as
 * dBm so that a change of theme repaints it, and drawn into an image a row at
 * a time (the rows already there move down one, the new one is put on top).
 * A gap is a row of -128 dBm, far below any radio's noise floor.
 */
class Waterfall {
  constructor() {
    this.n = 0;
    this.image = document.createElement('canvas');
    this.table = null;
  }

  /** Starts over for frames of `n` bins. */
  reset(n) {
    this.n = n;
    this.rows = new Int8Array(ROWS * n).fill(-128);
    this.head = 0;
    this.image.width = n;
    this.image.height = ROWS;
    this.image.getContext('2d').clearRect(0, 0, n, ROWS);
  }

  /** The colours of the current theme; true when they changed. */
  theme(p) {
    const key = `${p.sunken}|${p.surface}`;
    if (key === this.themeKey) return false;
    this.themeKey = key;
    this.table = colourTable(p);
    return true;
  }

  /** One row: `bins`, or none (a gap, drawn as the background). */
  push(bins) {
    if (!this.n) return;
    this.head = (this.head + 1) % ROWS;
    const row = this.rows.subarray(this.head * this.n, (this.head + 1) * this.n);
    if (bins) row.set(bins);
    else row.fill(-128);
    const ctx = this.image.getContext('2d');
    ctx.drawImage(this.image, 0, 0, this.n, ROWS - 1, 0, 1, this.n, ROWS - 1);
    ctx.putImageData(this.paint(row, bins !== null), 0, 0);
  }

  paint(row, seen) {
    const img = new ImageData(this.n, 1);
    if (!seen) return img;
    for (let i = 0; i < this.n; i++) img.data.set(this.table.subarray((row[i] + 128) * 4, (row[i] + 128) * 4 + 4), i * 4);
    return img;
  }

  /** Paints every row again, after a change of colours. */
  repaint() {
    if (!this.n) return;
    const ctx = this.image.getContext('2d');
    ctx.clearRect(0, 0, this.n, ROWS);
    for (let y = 0; y < ROWS; y++) {
      const r = (this.head - y + ROWS) % ROWS;
      const row = this.rows.subarray(r * this.n, (r + 1) * this.n);
      if (row.some((v) => v !== -128)) ctx.putImageData(this.paint(row, true), 0, y);
    }
  }
}

function drawSpectrum(canvas, frame, hold, band, primary) {
  const c = setup(canvas);
  if (!c) return;
  const { ctx, w, h } = c;
  const p = palette();
  const colour = p.band[band] || p.accent;
  const box = { l: GUTTER, r: w - 8, t: 24, b: h - 22 };
  const y = (v) => box.b - ((Math.min(Math.max(v, LOW), HIGH) - LOW) / (HIGH - LOW)) * (box.b - box.t);

  ctx.textBaseline = 'middle';
  ctx.textAlign = 'right';
  ctx.lineWidth = 1;
  for (let v = LOW; v <= HIGH; v += 10) {
    const yy = Math.round(y(v)) + 0.5;
    ctx.strokeStyle = p.rule2;
    ctx.beginPath();
    ctx.moveTo(box.l, yy);
    ctx.lineTo(box.r, yy);
    ctx.stroke();
    ctx.fillStyle = p.ink3;
    ctx.fillText(String(v), box.l - 8, yy);
  }
  // The units, in the gutter: power at its top, frequency at its foot.
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';
  ctx.fillText('dBm', 4, 0);
  if (!frame) {
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '13px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.fillText('Shown while the radio scans.', (box.l + box.r) / 2, (box.t + box.b) / 2);
    return;
  }
  ctx.fillText('MHz', 4, box.b + 6);

  const lo = frame.center - frame.width / 2;
  const hi = frame.center + frame.width / 2;
  const x = (f) => box.l + ((f - lo) / (hi - lo)) * (box.r - box.l);
  // The channel's 20 MHz parts, the primary one tinted with its band.
  if (primary) {
    ctx.fillStyle = colour;
    ctx.globalAlpha = 0.1;
    ctx.fillRect(x(primary - 10), box.t, x(primary + 10) - x(primary - 10), box.b - box.t);
    ctx.globalAlpha = 1;
    ctx.fillStyle = colour;
    ctx.textAlign = 'center';
    ctx.font = '600 11px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.fillText('Primary', x(primary), box.t - 5);
    ctx.font = '11px system-ui, -apple-system, "Segoe UI", sans-serif';
  }
  ctx.strokeStyle = p.rule;
  ctx.setLineDash([2, 3]);
  for (let f = lo + 20; f < hi; f += 20) {
    const xx = Math.round(x(f)) + 0.5;
    ctx.beginPath();
    ctx.moveTo(xx, box.t);
    ctx.lineTo(xx, box.b);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  ctx.fillStyle = p.ink3;
  ctx.textBaseline = 'top';
  const ticks = freqTicks(lo, hi, box.r - box.l);
  ticks.forEach((f, i) => {
    ctx.textAlign = i === 0 && x(f) - box.l < 20 ? 'left' : i === ticks.length - 1 && box.r - x(f) < 20 ? 'right' : 'center';
    ctx.fillText(String(f), x(f), box.b + 6);
  });

  const bx = (i) => x(frame.first + i * frame.step);
  const line = (bins) => {
    ctx.beginPath();
    for (let i = 0; i < bins.length; i++) {
      if (i) ctx.lineTo(bx(i), y(bins[i]));
      else ctx.moveTo(bx(i), y(bins[i]));
    }
  };
  if (hold) {
    ctx.strokeStyle = p.ink3;
    ctx.lineWidth = 1;
    line(hold);
    ctx.stroke();
  }
  line(frame.bins);
  ctx.lineTo(bx(frame.bins.length - 1), box.b);
  ctx.lineTo(bx(0), box.b);
  ctx.closePath();
  ctx.fillStyle = colour;
  ctx.globalAlpha = 0.16;
  ctx.fill();
  ctx.globalAlpha = 1;
  ctx.strokeStyle = colour;
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  line(frame.bins);
  ctx.stroke();

  // The noise floor the radio reports, dashed across.
  const ny = Math.round(y(frame.noise)) + 0.5;
  ctx.strokeStyle = p.ink2;
  ctx.lineWidth = 1;
  ctx.setLineDash([5, 4]);
  ctx.beginPath();
  ctx.moveTo(box.l, ny);
  ctx.lineTo(box.r, ny);
  ctx.stroke();
  ctx.setLineDash([]);
  // Its label under it, where the trace seldom goes, on a patch of the
  // panel so that the trace never crosses the words.
  const label = `noise floor ${frame.noise} dBm`;
  const tw = ctx.measureText(label).width + 8;
  const ty = box.b - ny >= 15 ? ny + 2 : ny - 16;
  ctx.fillStyle = p.surface;
  ctx.fillRect(box.r - tw, ty, tw, 14);
  ctx.fillStyle = p.ink2;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'top';
  ctx.fillText(label, box.r - 4, ty + 1);
}

function drawWaterfall(canvas, wf) {
  const c = setup(canvas);
  if (!c) return;
  const { ctx, w, h } = c;
  const p = palette();
  const box = { l: GUTTER, r: w - 8, t: 0, b: h };
  ctx.fillStyle = p.sunken;
  ctx.fillRect(box.l, box.t, box.r - box.l, box.b - box.t);
  if (wf.n) {
    ctx.imageSmoothingEnabled = true;
    ctx.drawImage(wf.image, box.l, box.t, box.r - box.l, box.b - box.t);
  }
  ctx.fillStyle = p.ink3;
  ctx.textAlign = 'right';
  for (let s = 0; s <= 60; s += 15) {
    const yy = box.t + (s / 60) * (box.b - box.t);
    ctx.textBaseline = s === 0 ? 'top' : s === 60 ? 'bottom' : 'middle';
    ctx.fillText(s ? `${s} s` : 'now', box.l - 8, yy);
  }
}

function drawScale(canvas, wf) {
  const c = setup(canvas);
  if (!c || !wf.table) return;
  const { ctx, w, h } = c;
  const img = new ImageData(256, 1);
  img.data.set(wf.table.subarray(0, 256 * 4));
  const strip = document.createElement('canvas');
  strip.width = HIGH - LOW;
  strip.height = 1;
  strip.getContext('2d').putImageData(img, -(LOW + 128), 0);
  ctx.imageSmoothingEnabled = true;
  ctx.drawImage(strip, 0, 0, w, h);
}

/** m:ss of `ms`. */
function clock(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** The strongest bin of `bins` and its frequency. */
function strongest(frame, bins) {
  let i = 0;
  for (let k = 1; k < bins.length; k++) if (bins[k] > bins[i]) i = k;
  return { dbm: bins[i], mhz: frame.first + i * frame.step };
}

function reading(label, value, detail) {
  return h('div', {}, h('dt', {}, label), h('dd', {}, value, detail ? h('small', {}, detail) : null));
}

/** The radio's band, from its state or else its name. */
function bandOf(radio, r) {
  return r?.band || RADIOS.find(([n]) => n === radio)?.[1];
}

export default {
  mount(root, store, arg) {
    // The radio shown: the address's, else the one shown last.
    const ui = (store.ui.spectrum ||= {});
    if (arg) [ui.ap, ui.radio] = arg.split('/');
    const sub = h('p', {}, 'What each radio hears on its own channel, Wi-Fi or not');
    const apPick = h('select', { 'aria-label': 'Access point' });
    const radioPick = h('div', { class: 'seg', role: 'group', 'aria-label': 'Radio' });
    const title = h('div', { class: 'rf-title' });
    const button = h('button', { type: 'button', class: 'btn primary' });
    const status = h('p', { class: 'rf-status' });
    const spectrum = h('canvas', { class: 'rf-spectrum', role: 'img' });
    const waterfall = h('canvas', { class: 'rf-waterfall', role: 'img', 'aria-label': 'Waterfall of the last minute: frequency across, time down, power as colour' });
    const scale = h('canvas', { class: 'rf-scale', 'aria-hidden': 'true' });
    const clear = h('button', { type: 'button', class: 'btn quiet' }, 'Clear peaks');
    const readings = h('dl', { class: 'readings rf-readings' });
    const parts = [
      h('div', { class: 'rf-top' }, title, button),
      status,
      h('div', { class: 'rf-body' },
        h('div', { class: 'rf-plot-head' },
          h('h3', {}, 'Spectrum'),
          h('span', { class: 'legend' },
            h('span', {}, h('i', { class: 'sw-now' }), 'Now'),
            h('span', {}, h('i', { class: 'sw-hold' }), 'Highest since the scan began')),
          clear),
        spectrum,
        h('div', { class: 'rf-plot-head' },
          h('h3', {}, 'Last minute'),
          h('span', { class: 'rf-key' }, `${LOW} dBm`, scale, `${HIGH} dBm`)),
        waterfall),
      readings,
    ];
    const panel = h('section', { class: 'panel rf' }, ...parts);
    root.append(h('div', { class: 'head' }, h('h1', {}, 'Spectrum'), sub), h('div', { class: 'tools' }, apPick, radioPick), panel);

    const wf = new Waterfall();
    /** The latest frame and when it came, the highest per bin since the
     * scan began, and when the last two seconds' frames came. */
    let frame = null;
    let seen = 0;
    let hold = null;
    let arrivals = [];
    /** Start was pressed and the controller has not answered yet. */
    let asked = false;

    const key = () => `${ui.ap}/${ui.radio}`;
    const state = () => (store.spectrum.key === key() ? store.spectrum.state : null);
    const scanning = () => !!state()?.scanning;

    /** Keeps the radio shown one that there is: of a configured AP, and of
     * its radios once it has reported them. */
    function pick() {
      const aps = Object.keys(store.state.aps).sort();
      if (!aps.includes(ui.ap)) ui.ap = aps[0];
      const radios = store.state.aps[ui.ap]?.radios || {};
      const names = RADIOS.map(([n]) => n);
      const there = names.filter((n) => radios[n]);
      if (!names.includes(ui.radio) || (there.length && !there.includes(ui.radio))) ui.radio = there[0] || 'radio5';
    }

    function forget() {
      frame = hold = null;
      arrivals = [];
      wf.reset(0);
    }

    function show(ap, radio) {
      if (ap === ui.ap && radio === ui.radio) return;
      // A scan carries over to the radio picked; the one left stops by itself.
      const carry = scanning() || asked;
      ui.ap = ap;
      ui.radio = radio;
      forget();
      history.replaceState(null, '', `#/spectrum/${key()}`);
      store.watchSpectrum(carry ? key() : null);
      asked = carry;
      view.update();
    }

    apPick.addEventListener('change', () => show(apPick.value, ui.radio));
    clear.addEventListener('click', () => {
      hold = frame ? Int8Array.from(frame.bins) : null;
      draw();
    });
    button.addEventListener('click', () => {
      if (scanning() || asked) {
        asked = false;
        store.watchSpectrum(null);
      } else {
        asked = true;
        forget();
        store.watchSpectrum(key());
      }
      view.update();
    });

    // A row each eighth of a second while the scan runs: the latest frame,
    // unless it is too old to stand for this eighth, then a gap.
    const rows = setInterval(() => {
      if (!scanning()) return;
      wf.push(frame && Date.now() - seen < 300 ? frame.bins : null);
      draw();
    }, ROW_MS);
    // The countdown to the scan's limit.
    const countdown = setInterval(() => scanning() && view.update(), 1000);

    store.spectrum.onFrame = (f) => {
      if (f.key !== key()) return;
      if (wf.n !== f.bins.length) wf.reset(f.bins.length);
      if (!hold || hold.length !== f.bins.length) hold = Int8Array.from(f.bins);
      else for (let i = 0; i < hold.length; i++) hold[i] = Math.max(hold[i], f.bins[i]);
      frame = f;
      seen = Date.now();
      arrivals.push(seen);
      while (arrivals[0] < seen - 2000) arrivals.shift();
      draw();
      fillReadings();
    };

    let drawing = false;
    function draw() {
      if (drawing) return;
      drawing = true;
      requestAnimationFrame(() => {
        drawing = false;
        const r = store.state.aps[ui.ap]?.radios?.[ui.radio];
        const band = bandOf(ui.radio, r);
        if (wf.theme(palette())) {
          wf.repaint();
          drawScale(scale, wf);
        }
        drawSpectrum(spectrum, frame, hold, band, r && channelMhz(band, r.channel));
        drawWaterfall(waterfall, wf);
      });
    }

    function fillReadings() {
      const s = state();
      const now = frame && strongest(frame, frame.bins);
      const top = frame && hold && strongest(frame, hold);
      const span = (arrivals[arrivals.length - 1] - arrivals[0]) / 1000;
      const rate = span > 0 ? (arrivals.length - 1) / span : 0;
      clear.hidden = !frame;
      readings.replaceChildren(
        reading('Noise floor', frame ? `${frame.noise} dBm` : '–', frame ? 'as the radio reports it' : null),
        reading('Strongest now', now ? `${now.dbm} dBm` : '–', now ? `at ${now.mhz.toFixed(1)} MHz` : null),
        reading('Strongest since the start', top ? `${top.dbm} dBm` : '–', top ? `at ${top.mhz.toFixed(1)} MHz` : null),
        reading('Frames', frame && scanning() ? `${rate.toFixed(1)} a second` : '–',
          s?.watchers ? `${s.watchers} ${s.watchers === 1 ? 'page' : 'pages'} watching` : null));
    }

    /** What the scan is doing, as [tone, sentence]; tone `lock` for a user
     * who may not start one. */
    function sentence(ap, r) {
      const s = state();
      const minutes = Math.round((s?.limit ?? 600) / 60);
      if (!ap?.up) return ['bad', `${ui.ap} is not connected to the controller, so its radios cannot scan. Wi-Fi on it keeps working.`];
      if (!r) return ['bad', `${ui.ap} has not reported a ${ui.radio}.`];
      if (!r.up) return ['bad', `${ui.radio} is down: it has no channel to scan.`];
      if (s?.error === 'not an admin' || (store.me && !store.me.admin)) return ['lock', ''];
      if (s?.error) return ['bad', `The scan did not start: ${s.error}.`];
      if (s?.scanning) {
        if (!s.running) return ['wait', `Waiting for ${ui.ap} to start the scan…`];
        const left = s.since + s.limit * 1000 - Date.now();
        return ['ok', `Scanning. It stops in ${clock(left)}, after ${minutes} minutes, or 4 s after the last page watching it closes.`];
      }
      if (asked) return ['wait', `Asking ${ui.ap} to scan…`];
      switch (s?.stopped) {
        case 'limit': return ['', `Stopped after ${minutes} minutes, the longest a scan runs. Start it again to keep watching.`];
        case 'link': return ['bad', `Stopped: ${ui.ap}’s link to the controller went down.`];
        case 'ap': return ['bad', `${ui.ap} is not scanning${s.detail ? `: ${s.detail}` : ''}.`];
        default: return ['', `Not scanning. While it scans, the radio gives a little of its airtime to listening, ${minutes} minutes at most.`];
      }
    }

    let picks = '';
    const view = {
      update() {
        if (!store.keyed) {
          const [head, text] = store.waiting();
          panel.replaceChildren(h('div', { class: 'empty' }, h('strong', {}, head), h('p', {}, text)));
          return;
        }
        if (panel.firstChild !== parts[0]) panel.replaceChildren(...parts);
        pick();
        // The controller's answer to Start, or to the pick of another radio.
        const s = state();
        if (s?.scanning || s?.stopped || s?.error) asked = false;
        const aps = Object.keys(store.state.aps).sort();
        const ap = store.state.aps[ui.ap];
        const radios = ap?.radios || {};
        const now = `${aps}|${key()}|${RADIOS.map(([n]) => !!radios[n])}`;
        if (now !== picks) {
          picks = now;
          apPick.replaceChildren(...aps.map((a) => h('option', { value: a }, a)));
          radioPick.replaceChildren(...RADIOS.map(([name, band]) => h('button', {
            type: 'button',
            'aria-pressed': String(name === ui.radio),
            disabled: !radios[name],
            title: radios[name] ? name : `${ui.ap} has not reported a ${name}`,
            onclick: () => show(ui.ap, name),
          }, bandName(band))));
        }
        apPick.value = ui.ap;
        const r = radios[ui.radio];
        const band = bandOf(ui.radio, r);
        panel.dataset.band = band;
        title.replaceChildren(
          h('h2', {}, ui.ap),
          h('span', { class: 'chip', 'data-band': band }, bandName(band)),
          h('span', { class: 'muted' }, ui.radio),
          ...(r ? [h('span', { class: 'rf-chan' }, `Channel ${r.channel}, ${r.width} MHz`)] : []));
        const on = scanning() || asked;
        const may = ap?.up && r?.up && !(store.me && !store.me.admin);
        button.replaceChildren(icon(on ? STOP : PLAY), h('span', {}, on ? 'Stop' : 'Start scan'));
        button.className = on ? 'btn' : 'btn primary';
        button.disabled = !on && !may;
        const [tone, text] = sentence(ap, r);
        status.dataset.tone = tone;
        if (tone === 'lock') {
          status.replaceChildren(icon(LOCK), h('span', {},
            store.me ? 'Viewing only: a scan takes airtime from the radio’s clients, so starting one needs membership of ' : 'Starting a scan needs membership of ',
            h('b', {}, ADMIN_GROUP), '.'));
        } else {
          status.replaceChildren(h('span', {}, text));
        }
        const done = s?.scanning && s.running ? Math.min(1, (Date.now() - s.since) / (s.limit * 1000)) : 0;
        status.style.setProperty('--done', `${(done * 100).toFixed(2)}%`);
        spectrum.setAttribute('aria-label', `Spectrum of ${ui.radio} on ${ui.ap}${r ? `, channel ${r.channel}, ${r.width} MHz wide` : ''}`);
        fillReadings();
        draw();
      },
      unmount() {
        clearInterval(rows);
        clearInterval(countdown);
        store.spectrum.onFrame = null;
        store.watchSpectrum(null);
      },
    };
    return view;
  },
};
