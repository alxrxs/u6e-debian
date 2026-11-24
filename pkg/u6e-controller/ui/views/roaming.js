// Roaming: how clients move between the access points, from what the
// controller holds since it started (a week at most): per AP the roams into
// it over the last day and how they signed in, those that failed, the
// clients sticky on it now, and what its steering asked and the clients did;
// the clients sticky now (weak on one AP while another last heard them much
// better), the roams, newest first, and the steering requests with their
// answers. Asked for again every 15 s and when a join or a steering answer
// comes. A client's page shows its own, with the same tables.

import { h, ago, bandName, btmAnswer, btmReason, clientName, duration, gapText, quality, ROAM_FAILURES, ROAM_KINDS } from '../util.js';
import { when } from './history.js';

const REFRESH_MS = 15000;

/** Who asked a client to move. */
function asker(s) {
  switch (s.origin) {
    case 'admin': return s.by ? `${s.by}, an admin` : 'an admin';
    case 'query': return s.reason === undefined ? 'the AP, as the client asked' : `the AP, as the client asked: ${btmReason(s.reason)}`;
    default: return 'the AP, of its own accord';
  }
}

/** What a client did after a steering request. */
function then(s) {
  const o = s.outcome;
  if (!o) return h('span', { class: 'chip wait' }, 'waiting');
  if (o === 'stayed') return h('span', { class: 'chip warn' }, 'stayed');
  if (o === 'left') return h('span', { class: 'chip' }, 'left');
  return [h('span', { class: 'chip ok' }, `moved after ${(o.after_ms / 1000).toFixed(1)} s`),
    h('small', {}, `to ${o.moved.ap}, ${bandName(o.moved.band)}`)];
}

function place(p) {
  return [p.ap, ' ', h('span', { class: 'chip', 'data-band': p.band }, bandName(p.band))];
}

function who(store, x) {
  const name = x.name || clientName(store, x.mac);
  return h('a', { href: `#/client/${x.mac}`, class: name === x.mac ? 'mono' : null }, name);
}

function signal(dbm) {
  return dbm === undefined ? '–' : h('span', { class: `q-${quality(dbm)}` }, `${dbm} dBm`);
}

/** `list` as a table of `columns`: [heading, class, cell]. */
function table(cls, columns, list) {
  const c = (k) => k.replace('wrap', '').trim() || null;
  return h('table', { class: `sessions ${cls}` },
    h('thead', {}, h('tr', {}, columns.map(([t, k]) => h('th', { class: c(k) }, h('span', {}, t))))),
    h('tbody', {}, list.map((x) => h('tr', {}, columns.map(([, k, cell]) => h('td', { class: k || null }, cell(x)))))));
}

/** The roams (newest first); the client column unless `client` is false. */
export function roamsTable(store, list, { client = true } = {}) {
  const attempt = (r) => r.gap_ms === undefined;
  return table('roams', [
    ['Time', '', (r) => when(r.at)],
    client ? ['Client', '', (r) => who(store, r)] : null,
    ['From', '', (r) => place(r.from)],
    ['To', '', (r) => place(r.to)],
    ['Signed in by', 'p2', (r) => (attempt(r) ? '–' : ROAM_KINDS[r.kind || 'unknown'])],
    ['Between APs', 'num', gapText],
    ['Signal', 'p2', (r) => [signal(r.before), ' → ', signal(r.after)]],
    ['Steered by', 'p3 wrap', (r) => (r.steered ? asker(r.steered) : '–')],
    ['Result', '', (r) => (r.failure
      ? h('span', { class: 'chip bad' }, attempt(r) ? `tried: ${ROAM_FAILURES[r.failure]}` : ROAM_FAILURES[r.failure])
      : h('span', { class: 'chip ok' }, 'roamed'))],
  ].filter(Boolean), list);
}

/** The steering requests (newest first); the client column unless `client`
 * is false. */
export function steeringTable(store, list, { client = true } = {}) {
  return table('steering', [
    ['Time', '', (s) => when(s.at)],
    ['AP', '', (s) => s.ap],
    client ? ['Client', '', (s) => who(store, s)] : null,
    ['Asked by', 'wrap', asker],
    ['Answer', 'wrap', (s) => h('span', { class: s.status === 0 ? 'q-good' : s.status === undefined ? 'muted' : 'q-fair' }, btmAnswer(s.status, s.target))],
    ['Then', '', then],
  ].filter(Boolean), list);
}

/** A client sticky now, in words: where, how weak, and the view against
 * which. */
export function stickyWords(s, settings) {
  return [
    h('b', { class: 'q-poor' }, `Sticky on ${s.ap} for ${duration((Date.now() - s.since) / 1000)}`),
    ` at ${s.signal} dBm on ${bandName(s.band)}, below ${settings?.sticky_dbm ?? -72} dBm, while ${s.view.ap} last heard it at ${s.view.signal} dBm`,
    h('span', { class: 'muted' }, ` (${ago(s.view.at)})`),
  ];
}

function stickyTable(store, list) {
  return table('sticky', [
    ['Client', '', (s) => who(store, s)],
    ['Stuck on', '', (s) => place(s)],
    ['Signal', 'num', (s) => signal(s.signal)],
    ['Heard better by', '', (s) => [s.view.ap, ' ', signal(s.view.signal), h('small', {}, ago(s.view.at))]],
    ['For', 'num', (s) => duration((Date.now() - s.since) / 1000)],
  ], list);
}

/** One AP's summary card. */
function apCard(name, a) {
  const kinds = Object.entries(a.kinds || {}).sort(([, x], [, y]) => y - x);
  const st = a.steering || {};
  const n = (o, k) => o?.[k] || 0;
  const asked = n(st.asked, 'admin') + n(st.asked, 'query') + n(st.asked, 'ap');
  const rejected = Object.entries(st.rejected || {}).sort(([, x], [, y]) => y - x);
  const fact = (label, value, small) => h('div', {}, h('dt', {}, label), h('dd', {}, value, small ? h('small', {}, small) : null));
  return h('section', { class: 'panel roam-ap' },
    h('h2', {}, name),
    h('dl', { class: 'readings' },
      fact('Roams in, last day', String(a.roams), kinds.length ? kinds.map(([k, v]) => `${ROAM_KINDS[k] || k} ${v}`).join(', ') : 'none'),
      fact('Failed', h('span', { class: a.failed ? 'q-poor' : null }, String(a.failed)), 'sign-ins refused, or gone within 30 s'),
      fact('Sticky now', h('span', { class: a.sticky ? 'q-poor' : null }, String(a.sticky)), 'clients better heard elsewhere'),
      fact('Steering asked', String(asked), asked ? `admins ${n(st.asked, 'admin')}, client queries ${n(st.asked, 'query')}, the AP ${n(st.asked, 'ap')}` : 'none kept'),
      fact('Answers', `${n(st.answers, 'accepted')} accepted`, asked
        ? [`${n(st.answers, 'rejected')} declined${rejected.length ? ` (${rejected.map(([c, v]) => `${btmAnswer(Number(c)).replace('declined: ', '')} ${v}`).join(', ')})` : ''}, ${n(st.answers, 'none')} unanswered`]
        : ''),
      fact('Then', `${n(st.outcomes, 'moved')} moved`, asked ? `${n(st.outcomes, 'stayed')} stayed, ${n(st.outcomes, 'left')} left, ${n(st.outcomes, 'pending')} waiting` : '')));
}

/** The roaming of the site, or of the client `mac`, as the controller last
 * answered (`state.data`), asked for again when due; `loaded` runs when an
 * answer comes. */
export function roamingLoader(store, mac, loaded) {
  const state = { data: null, fetched: 0, loading: false, seen: '' };
  const path = mac ? `/api/roaming?client=${encodeURIComponent(mac)}` : '/api/roaming';
  async function load() {
    state.loading = true;
    const r = await store.getJson(path);
    state.loading = false;
    state.fetched = Date.now();
    state.data = r.status === 200 ? r : state.data || { error: r.status };
    loaded();
  }
  /** Asks again when 15 s passed or a join or steering answer came. */
  state.due = () => {
    const mine = store.events.filter((e) => (e.kind === 'assoc' || e.kind.startsWith('btm')) && (!mac || e.mac === mac));
    const seen = `${mine.length}|${mine.at(-1)?.at}`;
    if (!state.loading && (seen !== state.seen || Date.now() - state.fetched > REFRESH_MS)) {
      state.seen = seen;
      load();
    }
  };
  return state;
}

export default {
  mount(root, store) {
    store.loadHistory();
    const sub = h('p');
    const aps = h('div', { class: 'roam-aps' });
    const stickyBox = h('div', { class: 'panel table-wrap' });
    const roamsBox = h('div', { class: 'panel table-wrap' });
    const steerBox = h('div', { class: 'panel table-wrap' });
    const note = h('p', { class: 'muted foot' });
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Roaming'), sub),
      aps,
      h('h2', { class: 'section-title' }, 'Sticky clients'), stickyBox,
      h('h2', { class: 'section-title' }, 'Roams'), roamsBox,
      h('h2', { class: 'section-title' }, 'Steering'), steerBox,
      note);
    const loader = roamingLoader(store, null, () => view.update());
    let drawn = '';
    const empty = (text) => h('div', { class: 'empty' }, h('p', {}, text));
    const view = {
      update() {
        loader.due();
        const d = loader.data;
        const stamp = `${loader.fetched}|${Math.floor(Date.now() / 60000)}`;
        if (stamp === drawn) return;
        drawn = stamp;
        if (!d || d.error !== undefined) {
          sub.textContent = '';
          aps.replaceChildren(h('div', { class: 'panel empty' }, h('p', {}, !d ? 'Loading the roams.' : 'The controller cannot be reached; this page tries again.')));
          return;
        }
        const s = d.settings;
        sub.textContent = `${d.roams.length} roam${d.roams.length === 1 ? '' : 's'} and ${d.steering.length} steering request${d.steering.length === 1 ? '' : 's'} kept`;
        const names = Object.keys(store.state.aps).concat(Object.keys(d.aps)).filter((x, i, l) => l.indexOf(x) === i).sort();
        aps.replaceChildren(...names.map((n) => apCard(n, d.aps[n] || { roams: 0, failed: 0, sticky: 0 })));
        stickyBox.replaceChildren(d.sticky.length ? stickyTable(store, d.sticky)
          : empty(`No client is sticky: none is below ${s.sticky_dbm} dBm while another AP last heard it ${s.better_db} dB better.`));
        roamsBox.replaceChildren(d.roams.length ? roamsTable(store, d.roams) : empty('No client has roamed since the controller started.'));
        steerBox.replaceChildren(d.steering.length ? steeringTable(store, d.steering)
          : empty('No access point has asked a client to move since the controller started (802.11v BSS transition).'));
        note.textContent = `Kept since the controller started, a week at most. A client is sticky below ${s.sticky_dbm} dBm on one AP while another AP heard it at least ${s.better_db} dB better: that AP’s last reading of it while it was associated there, which stands for ${Math.round(s.view_ms / 3600000)} hours at most, while that AP’s radio runs at the same power and while the client stays within ${s.moved_db} dB of its first reading where it is (no AP can hear a client associated elsewhere). The time between APs runs from the old AP’s last sign of the client to the new AP authorizing it; “≤” where the old AP’s last report is all there is. A client moved if it roamed within ${s.move_ms / 1000} s of its answer.`;
      },
    };
    return view;
  },
};
