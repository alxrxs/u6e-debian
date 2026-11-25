// Devices: one bar per AP, its state, clients and channels; opened, what it
// runs and how it is doing, its clients' Wi-Fi experience, its speed tests
// to the controller, and its radios with channel, power, noise, clients and
// how busy the air is; a radio's name leads to its spectrum.

import { h, ago, bandName, bar, clientName, duration, palette, pct, place } from '../util.js';
import { sparkline, stack } from '../charts.js';
import { apExperience } from './experience.js';
import { apSpeedBox } from './speedtest.js';

/** A temperature with its warning colour; ath11k throttles near 105 °C. */
function temp(c) {
  const cls = c >= 95 ? 'too-hot' : c >= 80 ? 'hot' : '';
  return h('b', { class: cls }, `${c.toFixed(1)} °C`);
}

function fact(label, ...value) {
  return h('div', {}, h('dt', {}, label), h('dd', {}, ...value));
}

/** The draws a panel needs once it is in the page and has a size. */
const draws = [];

function radioPanel(store, name, phy, r, tempC) {
  const p = palette();
  const color = p.band[r.band] || p.ink3;
  const u = r.util;
  const other = u ? Math.max(0, u.busy - u.rx - u.tx) : 0;
  const bar = h('canvas', { class: 'util-bar', role: 'img' });
  const trend = h('canvas', { class: 'util-trend', 'aria-hidden': 'true' });
  if (u) bar.setAttribute('aria-label', `Busy ${u.busy} %: transmit ${u.tx} %, receive ${u.rx} %, other ${other.toFixed(1)} %`);
  draws.push(() => {
    stack(bar, u && r.up ? [
      { value: u.tx, color },
      { value: u.rx, color, alpha: 0.5 },
      { value: other, color: p.other },
    ] : []);
    // On a scale of at least 0–20 %, so that a quiet radio's noise stays flat.
    const busy = store.radio.get(`${name}/${phy}`) || [];
    const top = Math.max(20, Math.ceil(Math.max(0, ...busy.filter((v) => v !== null)) / 10) * 10);
    trend.title = `Air busy over the last ${duration((busy.length * 2))}, 0 to ${top} %`;
    sparkline(trend, busy, { color, min: 0, max: top });
  });
  return h('article', { class: `radio${r.up ? '' : ' down'}`, 'data-band': r.band },
    h('div', { class: 'radio-top' },
      h('span', { class: 'band' }, bandName(r.band)),
      h('a', { class: 'phy', href: `#/spectrum/${name}/${phy}`, title: `The spectrum ${phy} hears` }, phy)),
    h('div', { class: 'chan', title: `Channel ${r.channel}, ${r.width} MHz wide` },
      h('span', { class: 'muted' }, 'Channel'), h('b', {}, String(r.channel)), h('span', {}, `${r.width} MHz`)),
    r.up ? null : h('p', { class: 'note' }, 'Radio down: no clients can join it.'),
    h('div', { class: 'util-head' },
      h('span', {}, 'Air busy'),
      h('b', {}, u && r.up ? pct(u.busy) : '–')),
    bar,
    h('div', { class: 'legend' },
      h('span', {}, h('i', { class: 'sw-tx' }), `Transmit ${u ? pct(u.tx) : ''}`),
      h('span', {}, h('i', { class: 'sw-rx' }), `Receive ${u ? pct(u.rx) : ''}`),
      h('span', {}, h('i', { class: 'sw-other' }), `Other ${u ? pct(other) : ''}`)),
    trend,
    h('dl', { class: 'radio-stats' },
      fact('Power', `${r.txpower} dBm`),
      fact('Noise', `${r.noise} dBm`),
      fact('Clients', String(r.clients)),
      tempC === undefined ? fact('Temp', h('span', { class: 'muted', title: 'This image reports no radio temperature' }, 'n/a')) : fact('Temp', temp(tempC))));
}

/** The AP's connection state, as [class, words]. */
function connection(ap) {
  if (ap.up) return ['ok', `Connected for ${duration((Date.now() - ap.since) / 1000)}`];
  if (ap.mismatch) return ['bad', 'Protocol mismatch'];
  return ['bad', ap.seen ? `Offline, last seen ${ago(ap.seen)}` : 'Offline'];
}

/** An AP bar's head: its state, clients and channels. */
function apHead(name, ap) {
  const [cls, state] = connection(ap);
  const radios = Object.values(ap.up ? ap.radios || {} : {}).sort((a, b) => Number(a.band) - Number(b.band));
  const clients = radios.reduce((n, r) => n + r.clients, 0);
  return [h('span', { class: `sdot ${cls}`, 'aria-hidden': 'true' }),
    h('span', { class: 'xbar-name' }, h('b', {}, name), h('small', {}, state)),
    h('span', { class: 'xbar-count' }, radios.length ? h('span', { class: 'ap-chans' },
      `${clients} client${clients === 1 ? '' : 's'}`,
      radios.map((r) => h('span', { class: `chip${r.up ? '' : ' bad'}`, 'data-band': r.up ? r.band : null },
        r.up ? `${bandName(r.band)} · ${r.channel}` : `${bandName(r.band)} down`))) : null)];
}

/** An AP bar's body: what it runs, its experience, speed test, radios. */
function apBody(store, name, ap) {
  const open = (store.ui.manifests ||= new Set());
  const m = ap.mismatch;
  if (m) {
    const fix = m.ap < m.controller ? `an image of ${name} built with this controller` : 'a controller as new as its agent';
    return h('p', { class: 'offline' }, `The controller turns ${name}’s agent away: they speak different versions of the link. Wi-Fi keeps working; its figures return with ${fix}.`);
  }
  if (!ap.agent) return h('p', { class: 'offline' }, `${name}’s agent has not dialled in yet.`);

  // Up but not yet reported: the first snapshot is on its way.
  const live = ap.up && ap.uptime !== undefined;
  const radios = ap.radios || {};
  const temps = ap.temps || {};
  const soc = Object.entries(temps).filter(([z]) => !(z in radios));
  const facts = h('dl', { class: 'facts' },
    live ? fact('Uptime', duration(ap.uptime)) : null,
    fact('Image', ap.image || 'unnamed', ' ', h('small', {}, `agent ${ap.agent}`)),
    fact('Kernel', ap.kernel),
    live ? fact('CPU load', ap.load.toFixed(2)) : null,
    live ? fact('Memory free', `${Math.round(ap.mem_kb / 1024)} MB`) : null,
    live ? fact('NSS load', nssMeter(ap.nss)) : null,
    soc.length ? fact('Temperatures', h('span', { class: 'temps' },
      soc.map(([z, c]) => h('span', {}, `${z.replace(/-thermal$/, '')} `, temp(c))))) : null);

  const manifest = h('details', { class: 'manifest', open: open.has(name) },
    h('summary', {}, 'Image manifest'),
    h('pre', {}, ap.manifest || ''));
  manifest.addEventListener('toggle', () => (manifest.open ? open.add(name) : open.delete(name)));

  const crashes = Object.entries(ap.crashes || {});
  const body = live
    ? h('div', { class: 'radios' }, Object.entries(radios).map(([phy, r]) => radioPanel(store, name, phy, r, temps[phy])))
    : h('p', { class: 'offline' }, ap.up
      ? 'Its radios show with its first report.'
      : 'No live figures while it is offline. Wi-Fi on it keeps working.');
  const xp = live ? apExperience(ap.experience, (m) => clientName(store, m)) : null;
  return h('div', { class: 'ap-body' }, facts,
    crashes.length ? h('p', { class: 'note' }, crashes.map(([phy, n]) => `${phy} firmware crashed ${n} time${n === 1 ? '' : 's'} since the controller started. `)) : null,
    xp ? h('div', { class: 'ap-xp-box' }, h('h3', {}, 'Experience'), xp) : null,
    apSpeedBox(store, name, ap),
    manifest, body);
}

function nssMeter(v) {
  const c = h('canvas', { 'aria-hidden': 'true' });
  draws.push(() => stack(c, [{ value: v, color: palette().accent }]));
  return h('span', { class: 'meter' }, c, `${v} %`);
}

export default {
  mount(root, store) {
    const sub = h('p');
    const list = h('div', { class: 'xbars' });
    const note = h('div');
    const open = (store.ui.apsOpen ||= new Set());
    const bars = new Map();
    root.append(h('div', { class: 'head' }, h('h1', {}, 'Devices'), sub), note, list);
    const view = {
      update() {
        const aps = Object.entries(store.state.aps).sort(([a], [b]) => a.localeCompare(b));
        const up = aps.filter(([, a]) => a.up).length;
        sub.textContent = aps.length ? `${up} of ${aps.length} access points connected` : '';
        draws.length = 0;
        if (!store.keyed || !aps.length) {
          const [title, text] = store.keyed
            ? ['No access points are configured', 'Each one shows here once its agent dials in.']
            : store.waiting();
          note.replaceChildren(h('div', { class: 'panel empty' }, h('strong', {}, title), h('p', {}, text)));
          list.replaceChildren();
          return;
        }
        note.replaceChildren();
        place(list, aps.map(([name, ap]) => {
          if (!bars.has(name)) bars.set(name, bar(open, name, () => view.update()));
          const b = bars.get(name);
          b.head(apHead(name, ap));
          b.el.classList.toggle('xbar-bad', !ap.up);
          b.body.replaceChildren(...(b.open ? [apBody(store, name, ap)] : []));
          return b.el;
        }));
        for (const d of draws) d();
      },
    };
    return view;
  },
};
