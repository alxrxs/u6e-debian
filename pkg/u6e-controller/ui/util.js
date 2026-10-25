// DOM building and the formats every view shares.

/** An element with attributes, properties (`on*` handlers, `class`) and children. */
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  el.append(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
  return el;
}

/** An inline SVG icon from path data, sized by CSS. */
export function icon(d) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('d', d);
  p.setAttribute('fill', 'none');
  p.setAttribute('stroke', 'currentColor');
  p.setAttribute('stroke-width', '2');
  p.setAttribute('stroke-linecap', 'round');
  p.setAttribute('stroke-linejoin', 'round');
  svg.append(p);
  return svg;
}

export const BANDS = ['2.4', '5', '6'];

export function bandName(b) {
  return b ? `${b} GHz` : 'Unknown band';
}

/** A duration in seconds, to its two largest units. */
export function duration(s) {
  if (s === undefined || s === null) return '';
  s = Math.max(0, Math.floor(s));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const hr = Math.floor(m / 60);
  if (hr < 24) return m % 60 ? `${hr} h ${m % 60} min` : `${hr} h`;
  const d = Math.floor(hr / 24);
  return hr % 24 ? `${d} d ${hr % 24} h` : `${d} d`;
}

/** How long ago a Unix time in milliseconds was. */
export function ago(ms) {
  return `${duration((Date.now() - ms) / 1000)} ago`;
}

export function bits(bps) {
  if (bps === undefined) return '';
  const units = ['bps', 'kbps', 'Mbps', 'Gbps'];
  let i = 0;
  while (bps >= 1000 && i < units.length - 1) {
    bps /= 1000;
    i++;
  }
  return `${bps < 10 && i ? bps.toFixed(1) : Math.round(bps)} ${units[i]}`;
}

export function bytes(n) {
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

export function mbps(r) {
  if (!r) return '';
  const v = r.mbps;
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} Mbps`;
}

/** What a rate's MCS means: "HE MCS 11, 2 streams", or "Legacy". */
export function phy(r) {
  if (!r) return '';
  if (!r.mode) return 'Legacy';
  return `${r.mode} MCS ${r.mcs}${r.nss ? ` ×${r.nss}` : ''}`;
}

export function pct(v) {
  return v === undefined ? '' : `${v.toFixed(v < 10 ? 1 : 0)} %`;
}

/** good, fair or poor, for the signal's colour. */
export function quality(dbm) {
  return dbm >= -62 ? 'good' : dbm >= -72 ? 'fair' : 'poor';
}

const clock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const minutes = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const day = new Intl.DateTimeFormat(undefined, { weekday: 'long', day: 'numeric', month: 'long' });

export function time(ms) {
  return clock.format(ms);
}

export function hm(ms) {
  return minutes.format(ms);
}

export function dayOf(ms) {
  const d = new Date(ms);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400e3);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return day.format(d);
}

/** The current value of each colour token, for the canvas. */
export function palette() {
  const css = getComputedStyle(document.documentElement);
  const get = (n) => css.getPropertyValue(`--${n}`).trim();
  return {
    ink: get('ink'), ink2: get('ink-2'), ink3: get('ink-3'), rule: get('rule'), rule2: get('rule-2'),
    surface: get('surface'), sunken: get('sunken'), other: get('other'), accent: get('accent'),
    ok: get('ok'), warn: get('warn'), bad: get('bad'),
    band: { '2.4': get('b24'), 5: get('b5'), 6: get('b6') },
  };
}

/** The name a client goes by: its DNS name, else its MAC. */
export function clientName(store, mac) {
  return store.state.clients[mac]?.name || mac;
}

/** What each client action did, as the feed and the results say it. */
export const DID = { kick: 'kicked', block: 'blocked', unblock: 'unblocked', steer: 'steered' };

/** What an event says, as the feed and a client's history show it. */
export function describe(ev) {
  const on = ev.ssid ? ` ${ev.ssid}` : '';
  const band = ev.band ? ` on ${ev.band} GHz` : '';
  switch (ev.kind) {
    case 'assoc': return { text: `joined${on}${band}`, tone: 'ok', group: 'conn' };
    case 'disassoc': return { text: `left${on}`, tone: '', group: 'conn' };
    case 'eap-ok': return { text: `signed in to${on}`, tone: 'ok', group: 'auth' };
    case 'eap-fail': return { text: `failed to sign in to${on}`, tone: 'bad', group: 'auth' };
    case 'radio-up': return { text: `${ev.phy} came up`, tone: 'ok', group: 'radio' };
    case 'radio-down': return { text: `${ev.phy} went down`, tone: 'bad', group: 'radio' };
    case 'fw-crash': return { text: `${ev.phy} firmware crashed`, tone: 'bad', group: 'radio' };
    case 'action': return { text: DID[ev.action] || ev.action, tone: ev.ok ? 'ok' : 'bad', group: 'action' };
    default: return { text: ev.kind, tone: '', group: 'other' };
  }
}
