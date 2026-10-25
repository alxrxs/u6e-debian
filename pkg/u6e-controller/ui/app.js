// The controller's single-page UI: one WebSocket brings the state of every AP
// (a key, then merge patches of what changed) and their events as they
// happen; the views render from that, and the samples taken here every two
// seconds draw the charts of each client's session. While a view shows flows
// the socket asks for them too, which makes the APs send them every 10 s;
// the client actions are POSTs, answered with their result. The socket also
// watches the one radio whose spectrum is shown, if any: its scan's state
// comes as JSON, its frames as binary messages straight to the view.

import { icon } from './util.js';
import devices from './views/devices.js';
import clients from './views/clients.js';
import client from './views/client.js';
import events from './views/events.js';
import flows from './views/flows.js';
import spectrum, { decodeFrame } from './views/spectrum.js';

/** Samples kept per client and radio: an hour at one per tick. */
const HISTORY = 1800;
const SAMPLE_MS = 2000;
const EVENTS_KEPT = 5000;

const store = {
  state: { aps: {}, clients: {} },
  user: null,
  /** `{ user, admin }` from `/api/me`; null until known. */
  me: null,
  live: 'connecting',
  /** The state has arrived at least once. */
  keyed: false,
  /** Why there is no state yet, for the views' empty states. */
  waiting() {
    return this.live === 'down'
      ? ['The controller cannot be reached', 'This page keeps trying, and shows the access points as soon as it gets through.']
      : ['Connecting to the controller', 'The access points and their clients appear as soon as their state arrives.'];
  },
  /** Every event seen, oldest first. */
  events: [],
  eventKeys: new Set(),
  historyLoaded: false,
  /** Per client: its session's samples. */
  samples: new Map(),
  /** Per `ap/phy`: busy % samples. */
  radio: new Map(),
  /** Per AP: its latest flows, `{ at, complete, clients: { mac: flows } }`,
   * each client's with its `mac`, and `down` and `up` in bit/s since the
   * AP's previous. */
  flows: {},
  /** Whether the flows asked for have come. */
  flowsKeyed: false,
  /** What the views remember across visits: sort, filters, open details. */
  ui: {},
  /** The radio whose scan the socket watches (`<ap>/<radio>`, or null), its
   * state as the controller last told it, and who takes its frames. */
  spectrum: { key: null, state: null, onFrame: null },
  /** Fetches the events held before this page opened, once. */
  loadHistory,
  act,
  fullFlows,
  watchSpectrum,
};

const views = { devices, clients, client, flows, events, spectrum };
let current = null;
let currentName = '';

/** Applies a JSON merge patch (RFC 7386) to `target`. */
function merge(target, patch) {
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete target[k];
    else if (typeof v === 'object' && !Array.isArray(v) && typeof target[k] === 'object' && target[k] !== null) merge(target[k], v);
    else target[k] = v;
  }
}

function eventKey(e) {
  return `${e.ap}|${e.at}|${e.kind}|${e.action || ''}|${e.mac || e.phy || ''}`;
}

function addEvents(list) {
  let added = false;
  for (const e of list) {
    const k = eventKey(e);
    if (store.eventKeys.has(k)) continue;
    store.eventKeys.add(k);
    store.events.push(e);
    added = true;
  }
  if (!added) return;
  store.events.sort((a, b) => a.at - b.at);
  if (store.events.length > EVENTS_KEPT) {
    for (const e of store.events.splice(0, store.events.length - EVENTS_KEPT)) store.eventKeys.delete(eventKey(e));
  }
}

async function loadHistory(again = false) {
  if (store.historyLoaded && !again) return;
  store.historyLoaded = true;
  try {
    const r = await fetch('/api/events', { cache: 'no-store' });
    if (!r.ok) throw new Error(r.status);
    addEvents(await r.json());
    changed();
  } catch {
    store.historyLoaded = false;
  }
}

async function loadMe() {
  try {
    const r = await fetch('/api/me', { cache: 'no-store' });
    if (!r.ok) throw new Error(r.status);
    store.me = await r.json();
  } catch {
    store.me = null;
  }
  changed();
}

/** The response of a POST of `body` to `path`: its status and JSON body;
 * status 0 when the controller could not be reached. Every POST says it is
 * JSON, as the controller requires of a request that changes anything. */
async function post(path, body) {
  try {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
    });
    let data = {};
    try {
      data = await r.json();
    } catch {}
    return { status: r.status, ...data };
  } catch {
    return { status: 0 };
  }
}

/** Takes `action` (kick, block, unblock, steer) on client `mac`. */
async function act(mac, action, body = {}) {
  const res = await post(`/api/clients/${encodeURIComponent(mac)}/${action}`, body);
  if (res.status === 403 && res.error === 'not an admin' && store.me) store.me.admin = false;
  return res;
}

/** Every connection `ap` forwards, which it is asked for: `{ status, at,
 * complete, clients }` (each client with its `mac`), or `{ status, error }`. */
async function fullFlows(ap) {
  try {
    const r = await fetch(`/api/flows/full?ap=${encodeURIComponent(ap)}`, { cache: 'no-store' });
    let data = {};
    try {
      data = await r.json();
    } catch {}
    const f = data[ap];
    if (!r.ok || !f) return { status: r.status, error: data.error };
    return { status: r.status, at: f.at, complete: f.complete, clients: withMacs(f.clients) };
  } catch {
    return { status: 0 };
  }
}

/** Each client's flows of an AP's (by MAC) with its MAC in them. */
function withMacs(clients) {
  return Object.entries(clients || {}).map(([mac, c]) => ({ ...c, mac }));
}

/** Takes the flows the socket keeps: each AP's as before, unless it sent new
 * ones, whose clients then get their rates from the bytes since the previous. */
function takeFlows() {
  const next = {};
  for (const [ap, f] of Object.entries(store.state.flows || {})) {
    const stamp = `${f.seq}|${f.at}`;
    const prev = store.flows[ap];
    if (prev?.stamp === stamp) {
      next[ap] = prev;
      continue;
    }
    const secs = prev ? (f.at - prev.at) / 1000 : 0;
    const clients = {};
    for (const c of withMacs(f.clients)) {
      const was = prev?.clients[c.mac];
      if (was && secs > 0 && c.rx_bytes >= was.rx_bytes && c.tx_bytes >= was.tx_bytes) {
        c.down = Math.round(((c.rx_bytes - was.rx_bytes) * 8) / secs);
        c.up = Math.round(((c.tx_bytes - was.tx_bytes) * 8) / secs);
      }
      clients[c.mac] = c;
    }
    next[ap] = { at: f.at, stamp, complete: f.complete, clients };
  }
  store.flows = next;
}

let socket = null;
/** Whether the view shows flows, and so the socket asks for them. */
let withFlows = false;

/** Tells the socket whether the view shows flows; one still opening says so
 * in its subscription. */
function watchFlows(want) {
  if (want === withFlows) return;
  withFlows = want;
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ flows: want }));
}

/** Watches the scan of `key` (`<ap>/<radio>`), which starts it if it is not
 * running, or none (null); the controller stops a scan nobody watches. */
function watchSpectrum(key) {
  const s = store.spectrum;
  if (key === null && s.key === null) return;
  s.key = key;
  s.state = null;
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ spectrum: key }));
}

let backoff = 1;

function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.binaryType = 'arraybuffer';
  socket = ws;
  ws.onopen = () => {
    ws.send(JSON.stringify({ subscribe: '*', flows: withFlows }));
    // A scan watched when the socket dropped is watched again, unless it
    // had stopped: a new socket never starts one by itself.
    const s = store.spectrum;
    if (s.key && !s.state?.stopped && !s.state?.error) ws.send(JSON.stringify({ spectrum: s.key }));
  };
  ws.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      const f = decodeFrame(e.data);
      if (f && f.key === store.spectrum.key) store.spectrum.onFrame?.(f);
      return;
    }
    const m = JSON.parse(e.data);
    if (m.spectrum && m.spectrum.key === store.spectrum.key) store.spectrum.state = m.spectrum;
    if (m.key) {
      store.state = m.key;
      store.keyed = true;
      store.user = m.user ?? null;
      // Events may have passed while the socket was down.
      if (store.historyLoaded && store.live === 'down') loadHistory(true);
      store.live = 'live';
      backoff = 1;
      if (!store.me) loadMe();
    }
    if (m.patch) merge(store.state, m.patch);
    if (m.key || (m.patch && 'flows' in m.patch)) {
      takeFlows();
      store.flowsKeyed = 'flows' in store.state;
    }
    if (m.events) addEvents(m.events);
    if (m.lost && store.historyLoaded) loadHistory(true);
    changed();
  };
  ws.onclose = () => {
    store.live = 'down';
    store.retryAt = Date.now() + backoff * 1000;
    setTimeout(connect, backoff * 1000);
    backoff = Math.min(backoff * 2, 15);
    changed();
  };
}

function push(list, v) {
  list.push(v);
  if (list.length > HISTORY) list.shift();
}

/** One sample of every client and radio; a client whose connected time went
 * back has started a new session, and its charts start over. */
function sample() {
  if (store.live !== 'live') return;
  const now = Date.now();
  const { aps, clients: all } = store.state;
  for (const [mac, c] of Object.entries(all)) {
    let s = store.samples.get(mac);
    if (!s || c.connected < s.connected || c.ap !== s.ap) {
      s = { ap: c.ap, times: [], signal: [], tx: [], rx: [], down: [], up: [] };
      store.samples.set(mac, s);
    }
    s.connected = c.connected;
    push(s.times, now);
    push(s.signal, c.signal);
    push(s.tx, c.tx?.mbps ?? null);
    push(s.rx, c.rx?.mbps ?? null);
    push(s.down, c.down ?? null);
    push(s.up, c.up ?? null);
  }
  for (const mac of store.samples.keys()) if (!(mac in all)) store.samples.delete(mac);
  for (const [name, ap] of Object.entries(aps)) {
    for (const [phy, r] of Object.entries(ap.radios || {})) {
      const k = `${name}/${phy}`;
      if (!store.radio.has(k)) store.radio.set(k, []);
      push(store.radio.get(k), r.up ? r.util?.busy ?? null : null);
    }
  }
  changed();
}

/** The view the address names, and its argument. */
function route() {
  const [, name = 'devices', arg] = location.hash.match(/^#\/([a-z]+)(?:\/(.+))?/) || [];
  return views[name] ? [name, arg && decodeURIComponent(arg)] : ['devices'];
}

function show() {
  const [name, arg] = route();
  currentName = name;
  const root = document.getElementById('view');
  // A view that holds something open (the spectrum's scan) lets it go.
  current?.unmount?.();
  root.replaceChildren();
  current = views[name].mount(root, store, arg);
  watchFlows(!!views[name].flows);
  for (const a of document.querySelectorAll('.tabs a')) {
    const on = a.dataset.view === name || (name === 'client' && a.dataset.view === 'clients');
    if (on) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  window.scrollTo(0, 0);
  render();
}

let pending = false;

function changed() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => {
    pending = false;
    render();
  });
}

const LIVE = { connecting: 'Connecting', live: 'Live', down: 'Offline' };

function render() {
  const live = document.getElementById('live');
  live.dataset.state = store.live;
  live.textContent = LIVE[store.live];
  const name = store.user || store.me?.user;
  const user = document.getElementById('user');
  user.hidden = !name;
  user.textContent = name || '';
  user.title = name ? `Signed in as ${name}${store.me?.admin ? ', a member of wifi-admins' : ''}` : '';
  const n = Object.keys(store.state.clients).length;
  document.getElementById('tally').textContent = store.live === 'live' ? String(n) : '';
  const banner = document.getElementById('banner');
  banner.hidden = store.live !== 'down';
  if (store.live === 'down') {
    const s = Math.max(1, Math.round((store.retryAt - Date.now()) / 1000));
    banner.textContent = store.keyed
      ? `Live updates stopped: the controller cannot be reached. Trying again in ${s} s; the figures shown are the last received.`
      : `The controller cannot be reached. Trying again in ${s} s.`;
  }
  const title = { devices: 'Devices', clients: 'Clients', client: 'Client', flows: 'Flows', spectrum: 'Spectrum', events: 'Events' }[currentName];
  document.title = `${title} – Wi-Fi`;
  current?.update();
}

// The theme button cycles the system's scheme, light and dark.
const THEMES = {
  auto: ['Theme follows the system', 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18v18'],
  light: ['Light theme', 'M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'],
  dark: ['Dark theme', 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8'],
};

function theme() {
  return document.documentElement.dataset.theme || 'auto';
}

function showTheme() {
  const [label, d] = THEMES[theme()];
  const b = document.getElementById('theme');
  b.replaceChildren(icon(d));
  b.title = label;
  b.setAttribute('aria-label', `${label}; change theme`);
}

document.getElementById('theme').addEventListener('click', () => {
  const order = Object.keys(THEMES);
  const next = order[(order.indexOf(theme()) + 1) % order.length];
  if (next === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = next;
  try {
    if (next === 'auto') localStorage.removeItem('theme');
    else localStorage.setItem('theme', next);
  } catch {}
  showTheme();
  changed();
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', changed);
window.addEventListener('resize', changed);
window.addEventListener('hashchange', show);
setInterval(sample, SAMPLE_MS);
// The banner's countdown.
setInterval(() => store.live === 'down' && changed(), 1000);

showTheme();
withFlows = !!views[route()[0]].flows;
show();
connect();
loadMe();
