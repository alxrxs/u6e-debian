// Services: what the access points read of mDNS (Bonjour): every device
// that speaks it, the services it offers and whether it answers the queries
// for them, what it asks for and who answers; the AirPlay groups (a stereo
// pair) and a "can one device see another" check. Site-wide, each device as
// the access point it is on hears it, or one AP's own reading. Fetched every
// 5 s while shown; a service's changes come with the events. The client
// page shows its own device the same way.

import { h, ago, bandName, hm, offerLabel, QTYPES, serviceName } from '../util.js';
import { when } from './history.js';

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

/** A device's name as a link to its page. */
function deviceLink(macs, mac) {
  return h('a', { href: `#/client/${mac}` }, deviceName(macs.get(mac)) || mac);
}

/** A list of devices' links, joined in words. */
function names(macs, list) {
  return list.flatMap((m, i) => [i ? (i === list.length - 1 ? ' and ' : ', ') : null, deviceLink(macs, m)]);
}

const STATUS = {
  answering: ['ok', 'Answering'],
  missing: ['warn', 'Missed the last'],
  silent: ['bad', 'Not answering'],
  unconfirmed: ['', 'Unconfirmed'],
  gone: ['', 'Gone'],
};

/** How an offer stands, in words beside its chip. */
function offerDetail(o, macs) {
  if (o.status === 'gone') {
    return o.withdrawn === 'goodbye' ? `said goodbye ${ago(o.announced)}`
      : 'did not answer a query after its announcement ran out';
  }
  if (o.status === 'unconfirmed') {
    return `its announcement ran out ${ago(o.announced + o.ttl * 1000)}; nobody has asked for it since`;
  }
  const parts = [];
  if (o.answered) parts.push(`answered ${o.answered}`);
  if (o.missed_in_row) {
    parts.push([`missed ${o.missed_in_row} in a row since ${when(o.missed_at)}`,
      o.missed_by ? [', last asked by ', deviceLink(macs, o.missed_by)] : null]);
  } else if (o.missed) {
    parts.push(`missed ${o.missed} in all`);
  }
  if (!parts.length) parts.push(`announced ${ago(o.announced)}`);
  return parts.flatMap((p, i) => (i ? [' · ', p] : [p]));
}

function offerRow(o, macs) {
  const [tone, label] = STATUS[o.status] || ['', o.status];
  const txt = Object.entries(o.txt || {}).filter(([k]) => k === 'model' || k === 'md').map(([, v]) => v)[0];
  return h('li', { class: 'svc-row' },
    h('div', { class: 'svc-what' }, h('b', {}, serviceName(o.service)), h('span', {}, offerLabel(o.label)),
      h('small', {}, [o.target, o.port ? `:${o.port}` : '', txt ? ` · ${txt}` : ''].join(''))),
    h('div', { class: 'svc-how' }, h('span', { class: `chip ${tone}`.trim() }, label), h('small', {}, offerDetail(o, macs))));
}

/** What a query asks, in words. */
function asking(q) {
  const first = q.name.split('.')[0];
  if (first.startsWith('_') && q.qtype === 12) return `Browses for ${serviceName(q.name)}`;
  if (/\._(tcp|udp)\.local$/i.test(q.name)) {
    const label = q.name.replace(/\\./g, '\u0000').split('.')[0].replace(/\u0000/g, '.');
    return `Resolves ${label} (${serviceName(q.name.slice(q.name.indexOf('._') + 1))})`;
  }
  return `Asks for ${q.name} (${QTYPES[q.qtype] || q.qtype})`;
}

function queryRow(q, macs) {
  const how = [];
  if (q.answered_by.length) how.push(['answered by ', names(macs, q.answered_by)]);
  if (q.missed_by.length) how.push([h('span', { class: 'q-poor' }, 'not by '), names(macs, q.missed_by)]);
  if (q.known.length) how.push(['already holds ', names(macs, q.known)]);
  if (q.unicast) how.push('asked for a unicast answer, which the AP may not see');
  if (q.unanswered) how.push(h('span', { class: 'q-poor' }, `${q.unanswered} asked from scratch got no answer`));
  const tone = q.missed_by.length || q.unanswered ? 'warn' : '';
  return h('li', { class: 'svc-row' },
    h('div', { class: 'svc-what' }, h('b', {}, asking(q)),
      h('small', {}, `${q.count} time${q.count === 1 ? '' : 's'}, last ${ago(q.last)}`)),
    h('div', { class: 'svc-how' }, tone ? h('span', { class: `chip ${tone}` }, q.missed_by.length ? 'Not all answer' : 'Unanswered') : null,
      how.length ? h('small', {}, how.flatMap((x, i) => (i ? [' · ', x] : [x]))) : null));
}

/** A device's card: who and where it is, what it offers, what it asks. */
export function deviceCard(d, macs, { link = true } = {}) {
  const name = deviceName(d);
  const head = h('div', { class: 'svc-head' },
    h('div', { class: 'who', 'data-band': d.band },
      h('div', { class: 'id' },
        link ? h('a', { href: `#/client/${d.mac}` }, name) : h('b', {}, name),
        h('small', {}, [h('span', { class: 'mono' }, d.mac), d.host ? ` · ${d.host}` : ''].filter(Boolean)))),
    h('div', { class: 'svc-where' },
      d.band ? h('span', { class: 'chip', 'data-band': d.band }, bandName(d.band)) : h('span', { class: 'chip' }, d.wifi ? 'Wi-Fi' : 'Wired'),
      h('span', { class: 'muted' }, `${d.ap} · ${d.port}`)));
  const offers = d.offers.length
    ? h('ul', { class: 'svc-list' }, d.offers.map((o) => offerRow(o, macs)))
    : h('p', { class: 'muted svc-none' }, 'Offers nothing.');
  const queries = d.queries.length
    ? h('ul', { class: 'svc-list' }, d.queries.map((q) => queryRow(q, macs)))
    : h('p', { class: 'muted svc-none' }, 'Asked for nothing lately.');
  const silent = d.offers.some((o) => o.status === 'silent');
  return h('article', { class: `panel svc-card${silent ? ' svc-bad' : ''}` }, head,
    h('h3', {}, 'Offers'), offers, h('h3', {}, 'Asks for'), queries,
    h('p', { class: 'muted foot' }, `Heard ${ago(d.last)} · ${d.queries_sent} queries and ${d.responses_sent} responses sent`));
}

/** A group's card: its members and how each answers. */
function groupCard(g, macs, offers) {
  return h('article', { class: 'panel svc-group' },
    h('div', { class: 'svc-head' }, h('b', {}, g.name || 'AirPlay group'), h('span', { class: 'muted' }, `AirPlay group of ${g.members.length}`)),
    h('ul', { class: 'svc-list' }, g.members.map((m) => {
      const o = offers.get(`${m.mac}|${m.instance}`);
      const [tone, label] = STATUS[o?.status] || ['', '–'];
      return h('li', { class: 'svc-row' },
        h('div', { class: 'svc-what' }, deviceLink(macs, m.mac), m.leader ? h('span', { class: 'chip wait' }, 'Leader') : null,
          h('small', {}, offerLabel(m.label))),
        h('div', { class: 'svc-how' }, h('span', { class: `chip ${tone}`.trim() }, label), o ? h('small', {}, offerDetail(o, macs)) : null));
    })));
}

/** The words of a verdict of `/api/services/see`: its tone and text. */
export function verdict(v, from, to) {
  const asked = v.query ? `its last ${v.query.qtype === 12 ? 'browse' : 'query'} (${ago(v.query.last)})` : '';
  switch (v.outcome) {
    case 'answered': return ['ok', [to, ` answered ${asked}.`]];
    case 'known': return ['ok', [from, ' already holds it: ', asked, ' listed it as a known answer, so ', to, ' rightly kept quiet.']];
    case 'missed': return ['bad', [to, ` did not answer ${asked}.`]];
    case 'unclear': return ['', v.offer.status === 'gone'
      ? [to, ' had withdrawn it when ', from, ' last asked.']
      : [from, ' asked for a unicast answer, which the access point cannot always see.']];
    default: return ['', [from, ' has not asked for it since the access points heard it.']];
  }
}

/** The "can one see another" panel: two pickers, then a verdict per
 * service the second offers. */
function seePanel(store) {
  const pick = (store.ui.see ||= { from: '', to: '' });
  const from = h('select', { 'aria-label': 'The device that asks' });
  const to = h('select', { 'aria-label': 'The device that offers' });
  const out = h('div', { class: 'see-out' });
  let result = null;
  let asked = '';
  async function ask() {
    const key = `${pick.from}|${pick.to}`;
    if (!pick.from || !pick.to) return;
    asked = key;
    const r = await store.getJson(`/api/services/see?from=${encodeURIComponent(pick.from)}&to=${encodeURIComponent(pick.to)}`);
    if (asked === key) result = r.status === 200 ? r : { error: r.status };
  }
  from.addEventListener('change', () => {
    pick.from = from.value;
    pick.to = '';
    result = null;
    panel.update(true);
  });
  to.addEventListener('change', () => {
    pick.to = to.value;
    result = null;
    panel.update(true);
  });
  const el = h('section', { class: 'panel see' },
    h('div', { class: 'see-head' }, h('h2', {}, 'Can one device see another?'),
      h('div', { class: 'see-pick' }, from, h('span', { class: 'muted' }, 'sees'), to)), out);
  const panel = {
    el,
    data: null,
    async update(fresh) {
      const data = this.data;
      const macs = byMac(data);
      // Unpicked, an asker some device did not answer, and that device.
      const askers = (data?.devices || []).filter((d) => d.queries.length);
      if (!macs.has(pick.from)) {
        pick.from = (askers.find((d) => d.queries.some((q) => q.missed_by.length)) || askers[0])?.mac || '';
      }
      const queries = macs.get(pick.from)?.queries || [];
      const missed = new Set(queries.flatMap((q) => q.missed_by));
      const wanted = new Set(queries.map((q) => q.name.toLowerCase()));
      const rank = (d) => 2 * Number(missed.has(d.mac)) + Number(d.offers.some((o) => wanted.has(o.service.toLowerCase())));
      const offering = (data?.devices || []).filter((d) => d.offers.length && d.mac !== pick.from);
      offering.sort((a, b) => rank(b) - rank(a) || deviceName(a).localeCompare(deviceName(b)));
      if (!offering.some((d) => d.mac === pick.to)) pick.to = offering[0]?.mac || '';
      const opts = (list, value) => list.map((d) => h('option', { value: d.mac, selected: d.mac === value }, `${deviceName(d)} (${d.mac})`));
      from.replaceChildren(...opts(askers, pick.from));
      to.replaceChildren(...opts(offering, pick.to));
      if (fresh || !result) await ask();
      if (!pick.from || !pick.to) {
        out.replaceChildren(h('p', { class: 'muted' }, 'No device has asked for anything yet.'));
        return;
      }
      if (!result || result.error !== undefined) {
        out.replaceChildren(h('p', { class: 'muted' }, result ? 'The controller cannot be reached.' : 'Asking the controller.'));
        return;
      }
      const a = deviceLink(macs, pick.from);
      const b = deviceLink(macs, pick.to);
      const lines = result.verdicts.map((v) => {
        const [tone, words] = verdict(v, a.cloneNode(true), b.cloneNode(true));
        return h('li', { class: tone || null },
          h('span', { class: 'dot', 'aria-hidden': 'true' }),
          h('span', {}, h('b', {}, serviceName(v.offer.service)), h('span', { class: 'muted' }, ` · ${offerLabel(v.offer.label)}`), h('br'), words,
            v.offer.missed_in_row ? h('small', {}, ` It has missed ${v.offer.missed_in_row} queries in a row since ${hm(v.offer.missed_at)}.`) : null));
      });
      const bad = result.verdicts.some((v) => v.outcome === 'missed');
      const good = result.verdicts.some((v) => v.outcome === 'answered' || v.outcome === 'known');
      const summary = bad
        ? h('p', { class: 'see-sum bad' }, a, ' cannot see all of ', b, ': some of its queries go unanswered.')
        : good ? h('p', { class: 'see-sum ok' }, a, ' sees ', b, '.')
          : h('p', { class: 'see-sum' }, 'Nothing tells yet whether ', a, ' sees ', b, '.');
      out.replaceChildren(summary, h('ul', { class: 'see-list' }, lines));
    },
  };
  return panel;
}

export default {
  /** `ap` (`#/services/<ap>`) shows that AP's own reading. */
  mount(root, store, ap) {
    const f = (store.ui.services ||= { ap: '', q: '', problems: false });
    if (ap !== undefined) f.ap = ap;
    let data = null;
    let fetched = 0;
    let loading = false;
    let drawn = '';
    const sub = h('p');
    const scope = h('div', { class: 'seg', role: 'group', 'aria-label': 'Scope' });
    const search = h('input', { type: 'search', placeholder: 'Filter by device, MAC or service', 'aria-label': 'Filter devices', value: f.q });
    search.addEventListener('input', () => {
      f.q = search.value;
      drawn = '';
      view.update();
    });
    const problems = h('button', { type: 'button' }, 'Not answering');
    const all = h('button', { type: 'button' }, 'All');
    for (const [b, on] of [[all, false], [problems, true]]) {
      b.addEventListener('click', () => {
        f.problems = on;
        drawn = '';
        view.update();
      });
    }
    const see = seePanel(store);
    const groups = h('div', { class: 'svc-grid' });
    const groupsEl = h('section', {}, h('h2', { class: 'section-title' }, 'Groups'), groups);
    const cards = h('div', { class: 'svc-grid' });
    const empty = h('div', { class: 'panel empty' });
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Services'), sub),
      h('div', { class: 'tools' }, scope, h('div', { class: 'grow' }, search), h('div', { class: 'seg', role: 'group', 'aria-label': 'Show' }, all, problems)),
      see.el, groupsEl, h('h2', { class: 'section-title' }, 'Devices'), cards, empty);

    async function load() {
      loading = true;
      const r = await store.getJson(`/api/services${f.ap ? `?ap=${encodeURIComponent(f.ap)}` : ''}`);
      loading = false;
      fetched = Date.now();
      data = r.status === 200 ? r : { error: r.status, devices: data?.devices || [] };
      drawn = '';
      see.data = r.status === 200 ? r : see.data;
      view.update();
      see.update(true);
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
              view.update();
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
        const offers = new Map(list.flatMap((d) => d.offers.map((o) => [`${o.mac}|${o.instance}`, o])));
        const silent = list.filter((d) => d.offers.some((o) => o.status === 'silent')).length;
        const types = data?.services?.filter((s) => s.offered_by.length).length || 0;
        sub.textContent = data && !data.error
          ? `${list.length} devices · ${types} services offered${silent ? ` · ${silent} not answering` : ''}`
          : '';
        const q = f.q.trim().toLowerCase();
        const shown = list.filter((d) => (!f.problems || d.offers.some((o) => o.status === 'silent') || d.queries.some((x) => x.missed_by.length || x.unanswered))
          && (!q || [d.mac, deviceName(d), d.host, ...d.offers.flatMap((o) => [o.label, o.service, serviceName(o.service)])]
            .some((v) => v && v.toLowerCase().includes(q))));
        // The ones not answering first, then by name.
        shown.sort((a, b) => Number(b.offers.some((o) => o.status === 'silent')) - Number(a.offers.some((o) => o.status === 'silent'))
          || deviceName(a).localeCompare(deviceName(b)));
        groupsEl.hidden = !data?.groups?.length;
        groups.replaceChildren(...(data?.groups || []).map((g) => groupCard(g, macs, offers)));
        cards.replaceChildren(...shown.map((d) => deviceCard(d, macs)));
        empty.hidden = !!shown.length;
        empty.replaceChildren(
          h('strong', {}, !data ? 'Loading' : data.error !== undefined ? 'The controller cannot be reached'
            : list.length ? 'No device matches these filters' : 'No mDNS heard yet'),
          h('p', {}, !data || data.error !== undefined ? 'This page tries again every few seconds.'
            : list.length ? 'Change the filters to see more.'
              : 'Devices appear here as the access points hear them announce, answer or ask for services over mDNS (AirPlay, HomeKit, printers…).'));
      },
    };
    load();
    return view;
  },
};
