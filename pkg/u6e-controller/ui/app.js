// The controller's single-page UI: one WebSocket brings the state of every AP
// (a key, then merge patches of what changed) and their events as they
// happen; the views render from that, and the samples taken here every two
// seconds draw the charts of each client's session.

import { icon } from './util.js';
import devices from './views/devices.js';
import clients from './views/clients.js';
import client from './views/client.js';
import events from './views/events.js';

/** Samples kept per client and radio: an hour at one per tick. */
const HISTORY = 1800;
const SAMPLE_MS = 2000;
const EVENTS_KEPT = 5000;

const store = {
  state: { aps: {}, clients: {} },
  user: null,
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
  /** What the views remember across visits: sort, filters, open details. */
  ui: {},
  /** Fetches the events held before this page opened, once. */
  loadHistory,
};

const views = { devices, clients, client, events };
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
  return `${e.ap}|${e.at}|${e.kind}|${e.mac || e.phy || ''}`;
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

let backoff = 1;

function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => ws.send(JSON.stringify({ subscribe: '*' }));
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.key) {
      store.state = m.key;
      store.keyed = true;
      store.user = m.user ?? null;
      store.live = 'live';
      backoff = 1;
      // Events may have passed while the socket was down.
      if (store.historyLoaded) loadHistory(true);
    }
    if (m.patch) merge(store.state, m.patch);
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
  root.replaceChildren();
  current = views[name].mount(root, store, arg);
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
  const user = document.getElementById('user');
  user.hidden = !store.user;
  user.textContent = store.user || '';
  user.title = store.user ? `Signed in as ${store.user}` : '';
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
  const title = { devices: 'Devices', clients: 'Clients', client: 'Client', events: 'Events' }[currentName];
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
show();
connect();
