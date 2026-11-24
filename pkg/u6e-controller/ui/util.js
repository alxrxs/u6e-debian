// DOM building and the formats every view shares.

/** An element with attributes, properties (`on*` handlers, `class`) and
 * children, nested in lists as deep as they come. */
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  el.append(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false));
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

/** A modal question: resolves to what `pick` makes of the dialog (true
 * without one), or null when cancelled. `choices`, given the confirm button,
 * builds what there is to pick from. */
export function ask(root, { title, text, choices, confirm, danger, pick }) {
  return new Promise((resolve) => {
    const ok = h('button', { type: 'button', class: `btn ${danger ? 'danger' : 'primary'}` }, confirm);
    const cancel = h('button', { type: 'button', class: 'btn', autofocus: !choices }, 'Cancel');
    const dlg = h('dialog', { class: 'ask', 'aria-labelledby': 'ask-title' },
      h('h2', { id: 'ask-title' }, title), h('p', {}, text), choices?.(ok),
      h('div', { class: 'ask-buttons' }, cancel, ok));
    let answer = null;
    ok.addEventListener('click', () => {
      answer = pick ? pick(dlg) : true;
      dlg.close();
    });
    cancel.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => {
      dlg.remove();
      resolve(answer);
    });
    root.append(dlg);
    dlg.showModal();
  });
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
export const DID = {
  kick: 'kicked',
  block: 'blocked',
  unblock: 'unblocked',
  steer: 'steered',
  apply: 'applied a Wi-Fi configuration',
  repush: 'signed the latest Wi-Fi configuration again',
  configs: 'set a configuration file aside',
  upgrade: 'asked for an image rollout',
  rollout: 'rolled an image out',
  image: 'kept or pruned an image',
  'rf-plan': 'applied an RF plan',
};

/** The DNS-SD service types a person knows by a name. */
const SERVICES = {
  _airplay: 'AirPlay',
  _raop: 'AirPlay audio',
  '_companion-link': 'Apple companion link',
  _hap: 'HomeKit',
  _homekit: 'HomeKit',
  _googlecast: 'Google Cast',
  '_spotify-connect': 'Spotify Connect',
  _ipp: 'Printer (IPP)',
  _ipps: 'Printer (IPPS)',
  _printer: 'Printer (LPD)',
  '_pdl-datastream': 'Printer (raw)',
  _scanner: 'Scanner',
  _uscan: 'Scanner (eSCL)',
  '_sleep-proxy': 'Sleep proxy',
  _matter: 'Matter',
  _matterc: 'Matter commissioning',
  '_device-info': 'Device info',
  _smb: 'File sharing',
  _afpovertcp: 'File sharing (AFP)',
  _adisk: 'Time Machine',
  _ssh: 'SSH',
  _rfb: 'Screen sharing',
  _mediaremotetv: 'Apple TV remote',
  '_touch-able': 'Apple Remote',
  _remotepairing: 'Remote pairing',
  '_apple-mobdev2': 'Apple device sync',
  _meshcop: 'Thread border router',
  _trel: 'Thread link',
  _http: 'Web',
};

/** The name a service type (`_airplay._tcp.local`) goes by. */
export function serviceName(type) {
  const first = (type || '').split('.')[0].toLowerCase();
  return SERVICES[first] || first.replace(/^_/, '');
}

/** An offer's label as a person reads it: an AirPlay audio instance
 * without the hardware address it starts with (`5E2C3A1B9F04@Kitchen`). */
export function offerLabel(label) {
  return (label || '').replace(/^[0-9a-f]{12}@/i, '');
}

/** DNS record types, as mDNS questions ask for them. */
export const QTYPES = { 1: 'A', 12: 'PTR', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY' };

/** What a service change says, as the feed and a client's timeline show it
 * (`who` names the device that asked). */
export function serviceWords(e, who = (m) => m) {
  const what = `${offerLabel(e.label)} (${serviceName(e.service)})`;
  const after = e.silent_for ? ` after ${duration(e.silent_for / 1000)} of silence` : '';
  switch (e.change) {
    case 'silent': return { text: `stopped answering for ${what}: missed ${e.misses} queries in a row${e.by ? `, the last from ${who(e.by)}` : ''}`, tone: 'bad' };
    case 'answering': return { text: `answers for ${what} again${after}`, tone: 'ok' };
    case 'gone': return { text: `withdrew ${what}${e.goodbye ? ' (said goodbye)' : ': it did not answer a query after its announcement ran out'}`, tone: '' };
    case 'back': return { text: `offers ${what} again`, tone: 'ok' };
    default: return { text: `${e.change} ${what}`, tone: '' };
  }
}

/** Why a client declined to move, by its BSS transition status (IEEE
 * 802.11-2020, table 9-428). */
const BTM_STATUS = {
  1: 'no reason given',
  2: 'too few beacons received',
  3: 'not enough capacity',
  4: 'BSS termination undesired',
  5: 'it asked for a termination delay',
  6: 'it proposed candidates of its own',
  7: 'no suitable candidate',
  8: 'it is leaving the network',
};

/** Why a client asked for candidates, by its transition reason (table
 * 9-427). */
const BTM_REASON = {
  0: 'no reason given',
  1: 'too many frames lost',
  2: 'too much delay',
  3: 'not enough capacity',
  5: 'load balancing',
  6: 'it found a better AP',
  12: 'too many retransmissions',
  15: 'its last transition failed',
  16: 'its signal is low',
  18: 'it was asked to move',
  20: 'it is leaving the network',
};

/** A client's answer to a steering request, in words. */
export function btmAnswer(status, target) {
  if (status === undefined || status === null) return 'no answer';
  if (status === 0) return target ? `accepted, naming ${target}` : 'accepted';
  return `declined: ${BTM_STATUS[status] || `status ${status}`}`;
}

/** Why a client asked for BSS transition candidates, in words. */
export function btmReason(reason) {
  return BTM_REASON[reason] || `reason ${reason}`;
}

/** How a client signed in where it roamed to. */
export const ROAM_KINDS = {
  ft: 'Fast transition',
  eap: 'Full EAP sign-in',
  cached: 'Cached keys',
  psk: 'Passphrase',
  sae: 'SAE',
  open: 'Open',
  unknown: 'Never authorized',
};

/** Why a roam failed. */
export const ROAM_FAILURES = {
  'eap-failed': 'refused by RADIUS',
  'eap-timeout': 'sign-in timed out',
  passphrase: 'passphrase did not match',
  dropped: 'disconnected within 30 s',
};

/** How long a client was between two APs, as the controller could tell:
 * none (the old AP heard it after the new one took it), at most (only the
 * old AP's last report bounds it), between two bounds, or, with both bounds
 * within a quarter of a second, that. */
export function gapText(r) {
  if (r.gap_ms === undefined) return '–';
  const s = (ms) => (ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`);
  if (r.gap_ms === 0) return 'no gap';
  if (!r.gap_min_ms) return `≤ ${s(r.gap_ms)}`;
  if (r.gap_ms - r.gap_min_ms <= 250) return s(r.gap_ms);
  return `${s(r.gap_min_ms)} – ${s(r.gap_ms)}`;
}

/** good, fair or poor, for an experience score's colour. */
export function scoreQuality(score) {
  return score >= 80 ? 'good' : score >= 50 ? 'fair' : 'poor';
}

/** The client guards, by the name the controller gives them. */
export const GUARDS = { arp: 'ARP inspection', dhcp: 'Rogue DHCP guard', ra: 'RA guard', source: 'IP source guard', tag: 'VLAN tag guard' };

/** What an event says, as the feed and a client's history show it. */
export function describe(ev) {
  const on = ev.ssid ? ` ${ev.ssid}` : '';
  const band = ev.band ? ` on ${ev.band} GHz` : '';
  switch (ev.kind) {
    case 'assoc': return { text: `joined${on}${band}`, tone: 'ok', group: 'conn' };
    case 'disassoc': return { text: `left${on}`, tone: '', group: 'conn' };
    case 'eap-start': return { text: `started signing in to${on}`, tone: '', group: 'auth' };
    case 'eap-ok': return { text: `signed in to${on}`, tone: 'ok', group: 'auth' };
    case 'eap-fail': return { text: `was refused by RADIUS on${on}`, tone: 'bad', group: 'auth' };
    case 'eap-timeout': return { text: `timed out signing in to${on}: ${ev.server ? 'RADIUS did not answer' : 'the client stopped answering'}`, tone: 'bad', group: 'auth' };
    case 'psk-mismatch': return { text: `gave a passphrase for${on} that does not match`, tone: 'bad', group: 'auth' };
    case 'radio-up': return { text: `${ev.phy} came up`, tone: 'ok', group: 'radio' };
    case 'radio-down': return { text: `${ev.phy} went down`, tone: 'bad', group: 'radio' };
    case 'fw-crash': return { text: `${ev.phy} firmware crashed`, tone: 'bad', group: 'radio' };
    case 'action': return { text: DID[ev.action] || ev.action, tone: ev.ok ? 'ok' : 'bad', group: 'action' };
    case 'guard': {
      const more = ev.repeats ? `, ${ev.repeats} more times since the last report` : '';
      const fate = ev.dropped ? ' Dropped.' : '';
      return { text: `broke the ${GUARDS[ev.guard] || ev.guard}: ${ev.detail}${more}.${fate}`, tone: 'bad', group: 'guard' };
    }
    case 'service': return { ...serviceWords(ev), group: 'service' };
    case 'btm-query': return { text: `asked${on}${band} for a better access point: ${btmReason(ev.reason)}`, tone: '', group: 'roam' };
    case 'btm-response': return { text: `answered a request to move: ${btmAnswer(ev.status, ev.target)}`, tone: ev.status === 0 ? 'ok' : 'warn', group: 'roam' };
    default: return { text: ev.kind, tone: '', group: 'other' };
  }
}
