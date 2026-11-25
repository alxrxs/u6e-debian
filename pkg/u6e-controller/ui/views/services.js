// Services: what the access points read of mDNS (Bonjour). One bar per
// AirPlay group and per device, closed by default: what it offers, how
// that answers, who asks for it and what it looks for. Site-wide, or one
// AP's own reading; fetched every 5 s while shown. The client page shows
// its own device's detail the same way.

import { h, ago, bandName, bar, hm, offerLabel, place, serviceName } from '../util.js';

const REFRESH_MS = 5000;

/** The name a device goes by: the controller's for a client, else its mDNS
 * host name, else its first offer's, else its MAC. */
export function deviceName(d) {
  if (!d) return '';
  return d.name || d.host?.replace(/\.local$/i, '') || offerLabel(d.offers?.[0]?.label) || d.mac;
}

/** The devices of a services reading, by MAC. */
export function byMac(data) {
  return new Map((data?.devices || []).map((d) => [d.mac, d]));
}

function deviceLink(macs, mac) {
  return h('a', { href: `#/client/${mac}` }, deviceName(macs.get(mac)) || mac);
}

/** A list in words: "a, b and c". */
function inWords(items) {
  return items.flatMap((x, i) => [i ? (i === items.length - 1 ? ' and ' : ', ') : null, x]);
}

const STATUS = {
  answering: ['ok', 'Answering'],
  missing: ['warn', 'No answer yet'],
  silent: ['bad', 'Not answering'],
  unconfirmed: ['', 'Quiet'],
  gone: ['', 'Gone'],
};

/** Whether an offer stands badly: silent, or missing its last queries. */
const poor = (o) => o.status === 'silent' || o.status === 'missing' || (o.status === 'answering' && o.missed_in_row > 0);

/** A device's tone: bad when a service does not answer, warn when one
 * misses or a query of its own goes unanswered. */
function tone(d) {
  if (d.offers.some((o) => o.status === 'silent')) return 'bad';
  if (d.offers.some(poor) || d.queries.some((q) => q.missed_by.length)) return 'warn';
  return d.offers.length ? 'ok' : '';
}

/** How an offer stands, in a few words. */
function offerWhen(o) {
  switch (o.status) {
    case 'silent': return o.answered_at ? `last answered ${ago(o.answered_at)}` : 'never answered';
    case 'missing': return `missed ${o.missed}`;
    case 'unconfirmed': return 'nobody asked lately';
    case 'gone': return o.withdrawn === 'goodbye' ? `said goodbye ${ago(o.announced)}` : 'stopped answering';
    default:
      if (o.missed_in_row) return h('span', { class: 'q-fair' }, o.missed_in_row === 1 ? 'missed the last query' : `missed the last ${o.missed_in_row} queries`);
      return o.answered_at ? `answered ${ago(o.answered_at)}` : `announced ${ago(o.announced)}`;
  }
}

function offerRow(o) {
  const [t, label] = STATUS[o.status] || ['', o.status];
  const kind = o.service.replace(/\.local$/i, '');
  return h('li', { class: 'svc-row' },
    h('div', { class: 'svc-what' }, h('b', {}, serviceName(o.service)), h('span', {}, offerLabel(o.label)),
      h('small', { class: 'mono' }, kind)),
    h('div', { class: 'svc-how' }, h('span', { class: `chip ${t}`.trim() }, label), h('small', {}, offerWhen(o))));
}

/** Who asked for `d`'s services, and whether it answered each: per asker,
 * a miss outweighs an answer. */
function askers(d, list) {
  const names = new Set(d.offers.flatMap((o) => [o.service.toLowerCase(), o.instance.toLowerCase()]));
  const out = new Map();
  for (const x of list) {
    if (x.mac === d.mac) continue;
    for (const q of x.queries) {
      if (!names.has(q.name.toLowerCase())) continue;
      if (q.missed_by.includes(d.mac)) out.set(x.mac, false);
      else if ((q.answered_by.includes(d.mac) || q.known.includes(d.mac)) && !out.has(x.mac)) out.set(x.mac, true);
    }
  }
  return [...out].sort(([, a], [, b]) => Number(a) - Number(b));
}

/** A device's detail: its services, who asks for them, what it looks for. */
export function deviceDetail(d, data, { link = true } = {}) {
  const list = data?.devices || [];
  const macs = byMac(data);
  const asked = askers(d, list);
  const looks = [...new Set(d.queries.filter((q) => q.qtype === 12 && q.name.startsWith('_')).map((q) => serviceName(q.name)))];
  const unanswering = [...new Set(d.queries.flatMap((q) => q.missed_by))];
  return h('div', { class: 'svc-detail' },
    d.offers.length
      ? h('ul', { class: 'svc-list' }, d.offers.map(offerRow))
      : h('p', { class: 'muted svc-none' }, 'Offers no services.'),
    h('dl', { class: 'svc-rel' },
      asked.length ? h('div', {}, h('dt', {}, 'Asked for by'), h('dd', {}, asked.map(([m, ok]) =>
        h('span', { class: `who-chip ${ok ? 'ok' : 'bad'}` }, deviceLink(macs, m), ok ? ' answered' : ' no answer')))) : null,
      looks.length ? h('div', {}, h('dt', {}, 'Looks for'), h('dd', {}, looks.join(', '),
        unanswering.length ? h('span', { class: 'q-poor' }, `. No answer from `, inWords(unanswering.map((m) => deviceLink(macs, m)))) : null)) : null),
    h('p', { class: 'muted svc-foot' }, h('span', { class: 'mono' }, d.mac), d.host ? ` · ${d.host}` : '', ` · heard ${ago(d.last)}`,
      link ? [' · ', h('a', { href: `#/client/${d.mac}` }, 'Device page')] : null));
}

function dot(t) {
  return h('span', { class: `sdot ${t}`.trim(), 'aria-hidden': 'true' });
}

/** A device bar's head: name, where, and a count of its services. */
function deviceHead(d, macs) {
  const silent = d.offers.filter((o) => o.status === 'silent').length;
  const missing = d.offers.filter((o) => o.status !== 'silent' && poor(o)).length;
  const gone = d.offers.filter((o) => o.status === 'gone').length;
  const unanswered = [...new Set(d.queries.flatMap((q) => q.missed_by))];
  const n = d.offers.length;
  const where = d.band ? `${d.ap} · ${bandName(d.band)}` : `${d.ap} · ${d.wifi ? 'Wi-Fi' : 'wired'}`;
  return [dot(tone(d)),
    h('span', { class: 'xbar-name' }, h('b', {}, deviceName(d)), h('small', {}, where)),
    h('span', { class: 'xbar-count' }, n ? `${n} service${n === 1 ? '' : 's'}` : 'No services',
      silent ? h('span', { class: 'q-poor' }, ` · ${silent} not answering`) : null,
      missing ? h('span', { class: 'q-fair' }, ` · ${missing} missed queries`) : null,
      gone ? ` · ${gone} gone` : null,
      unanswered.length ? h('span', { class: 'q-fair' }, ` · no answer from ${unanswered.length === 1
        ? deviceName(macs.get(unanswered[0])) || unanswered[0] : `${unanswered.length} devices`}`) : null)];
}

/** How a group member stands, in a few words. */
function memberState(m) {
  if (m.status === 'silent') return `not answering${m.since ? ` since ${hm(m.since)}` : ''}`;
  if (m.status === 'gone') return 'gone';
  if (m.status === 'unconfirmed') return 'quiet';
  return 'answering';
}

function groupHead(g, macs) {
  const name = (m) => deviceName(macs.get(m.mac)) || offerLabel(m.label);
  const bad = g.members.filter((m) => m.status !== 'answering' && m.status !== 'missing');
  const t = bad.some((m) => m.status === 'silent') ? 'bad' : bad.length ? 'warn' : 'ok';
  return [dot(t),
    h('span', { class: 'xbar-name' }, h('b', {}, g.name || 'AirPlay group'),
      h('small', {}, g.members.length === 2 ? 'AirPlay pair' : `AirPlay group of ${g.members.length}`)),
    h('span', { class: 'xbar-count' }, bad.length
      ? bad.map((m, i) => h('span', { class: m.status === 'silent' ? 'q-poor' : null }, i ? ' · ' : '', `${name(m)}: ${memberState(m)}`))
      : `${g.members.length} answering`)];
}

function groupDetail(g, macs) {
  return h('ul', { class: 'svc-list' }, g.members.map((m) => {
    const [t, label] = STATUS[m.status] || ['', m.status];
    return h('li', { class: 'svc-row' },
      h('div', { class: 'svc-what' }, macs.has(m.mac) ? deviceLink(macs, m.mac) : h('b', {}, offerLabel(m.label)),
        m.leader ? h('span', { class: 'chip wait' }, 'Leader') : null, h('small', {}, offerLabel(m.label))),
      h('div', { class: 'svc-how' }, h('span', { class: `chip ${t}`.trim() }, label),
        m.status === 'silent' && m.since ? h('small', {}, `since ${hm(m.since)}`) : null));
  }));
}

export default {
  /** `ap` (`#/services/<ap>`) shows that AP's own reading. */
  mount(root, store, ap) {
    const f = (store.ui.services ||= { ap: '', q: '', problems: false });
    const open = (store.ui.servicesOpen ||= new Set());
    if (ap !== undefined) f.ap = ap;
    let data = null;
    let fetched = 0;
    let loading = false;
    let drawn = '';
    const sub = h('p', { class: 'svc-sum' });
    const scope = h('div', { class: 'seg', role: 'group', 'aria-label': 'Scope' });
    const search = h('input', { type: 'search', placeholder: 'Filter by device or service', 'aria-label': 'Filter devices', value: f.q });
    search.addEventListener('input', () => {
      f.q = search.value;
      redraw();
    });
    const problems = h('button', { type: 'button' }, 'Not answering');
    const all = h('button', { type: 'button' }, 'All');
    for (const [b, on] of [[all, false], [problems, true]]) {
      b.addEventListener('click', () => {
        f.problems = on;
        redraw();
      });
    }
    const expand = h('button', { type: 'button', class: 'btn quiet' });
    const bars = new Map();
    let shownBars = [];
    expand.addEventListener('click', () => {
      const on = shownBars.some((b) => !b.open);
      for (const b of shownBars) b.set(on);
      redraw();
    });
    const groups = h('div', { class: 'xbars' });
    const groupsEl = h('section', {}, h('h2', { class: 'section-title' }, 'Groups'), groups);
    const devices = h('div', { class: 'xbars' });
    const devicesEl = h('section', {}, h('h2', { class: 'section-title' }, 'Devices'), devices);
    const empty = h('div', { class: 'panel empty' });
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Services'), sub),
      h('div', { class: 'tools' }, scope, h('div', { class: 'grow' }, search),
        h('div', { class: 'seg', role: 'group', 'aria-label': 'Show' }, all, problems), expand),
      groupsEl, devicesEl, empty);

    function redraw() {
      drawn = '';
      view.update();
    }

    /** The bar of `key`, made once and kept, so it keeps its focus. */
    function barOf(key) {
      if (!bars.has(key)) bars.set(key, bar(open, key, redraw));
      return bars.get(key);
    }

    /** Opens a device's bar and takes the reader to it. */
    function reveal(mac) {
      const b = barOf(mac);
      b.set(true);
      redraw();
      b.el.scrollIntoView({ block: 'nearest' });
      b.btn.focus();
    }

    async function load() {
      loading = true;
      const r = await store.getJson(`/api/services${f.ap ? `?ap=${encodeURIComponent(f.ap)}` : ''}`);
      loading = false;
      fetched = Date.now();
      data = r.status === 200 ? r : { error: r.status, devices: data?.devices || [], groups: data?.groups || [] };
      redraw();
    }

    const view = {
      update() {
        if (!loading && Date.now() - fetched > REFRESH_MS) load();
        const aps = Object.keys(store.state.aps).sort();
        if (scope.childNodes.length !== aps.length + 1) {
          scope.replaceChildren(...['', ...aps].map((ap) => {
            const b = h('button', { type: 'button', 'data-ap': ap }, ap || 'Site');
            b.addEventListener('click', () => {
              f.ap = ap;
              data = null;
              load();
              redraw();
            });
            return b;
          }));
        }
        for (const b of scope.childNodes) b.setAttribute('aria-pressed', String(b.dataset.ap === f.ap));
        all.setAttribute('aria-pressed', String(!f.problems));
        problems.setAttribute('aria-pressed', String(f.problems));
        const stamp = `${fetched}|${f.q}|${f.problems}|${f.ap}`;
        if (stamp === drawn) return;
        drawn = stamp;
        const list = data?.devices || [];
        const macs = byMac(data);
        const silent = list.filter((d) => d.offers.some((o) => o.status === 'silent'));
        const types = new Set(list.flatMap((d) => d.offers.map((o) => o.service.toLowerCase()))).size;
        sub.replaceChildren(...(data && !data.error ? [
          `${list.length} device${list.length === 1 ? '' : 's'} · ${types} service${types === 1 ? '' : 's'}`,
          silent.length ? [' · ', h('span', { class: 'q-poor' }, `${silent.length} not answering: `),
            inWords(silent.map((d) => {
              const b = h('button', { type: 'button', class: 'linkish' }, deviceName(d));
              b.addEventListener('click', () => reveal(d.mac));
              return b;
            }))] : ' · all answering',
        ].flat(Infinity).filter((x) => x !== null) : []));

        const q = f.q.trim().toLowerCase();
        const matches = (...vals) => !q || vals.some((v) => v && v.toLowerCase().includes(q));
        const shown = list.filter((d) => (!f.problems || tone(d) === 'bad' || tone(d) === 'warn')
          && matches(d.mac, deviceName(d), d.host, ...d.offers.flatMap((o) => [o.label, o.service, serviceName(o.service)])));
        const rank = { bad: 0, warn: 1, ok: 2, '': 3 };
        shown.sort((a, b) => rank[tone(a)] - rank[tone(b)] || deviceName(a).localeCompare(deviceName(b)));
        const gShown = (data?.groups || []).filter((g) => (!f.problems || g.members.some((m) => m.status !== 'answering'))
          && matches(g.name, ...g.members.flatMap((m) => [m.label, deviceName(macs.get(m.mac))])));

        const fill = (key, head, detail) => {
          const b = barOf(key);
          b.head(head);
          b.el.classList.toggle('xbar-bad', head[0].classList.contains('bad'));
          if (b.open) b.body.replaceChildren(detail());
          else b.body.replaceChildren();
          return b;
        };
        const gBars = gShown.map((g) => fill(`g:${g.gid || g.tsid}`, groupHead(g, macs), () => groupDetail(g, macs)));
        const dBars = shown.map((d) => fill(d.mac, deviceHead(d, macs), () => deviceDetail(d, data)));
        place(groups, gBars.map((b) => b.el));
        place(devices, dBars.map((b) => b.el));
        shownBars = [...gBars, ...dBars];
        groupsEl.hidden = !gBars.length;
        devicesEl.hidden = !dBars.length;
        expand.hidden = !shownBars.length;
        expand.textContent = shownBars.some((b) => !b.open) ? 'Expand all' : 'Collapse all';

        empty.hidden = !!shown.length;
        empty.replaceChildren(
          h('strong', {}, !data ? 'Loading' : data.error !== undefined ? 'The controller cannot be reached'
            : list.length ? 'No device matches' : 'No mDNS heard yet'),
          h('p', {}, !data || data.error !== undefined ? 'Trying again every few seconds.'
            : list.length ? 'Change the filters to see more.' : 'Devices show up here when they announce or ask for services.'));
      },
    };
    load();
    return view;
  },
};
