// Events: the live feed of what the APs report (joins, leaves, sign-ins,
// radios) and of the operators' actions on clients, newest first, by day; a
// client's own history uses the same list.

import { h, dayOf, describe, time } from '../util.js';

const PAGE = 300;
const GROUPS = [['', 'All'], ['conn', 'Joins and leaves'], ['auth', 'Sign-ins'], ['radio', 'Radios'], ['action', 'Actions']];

/** The radio an event names, with its band where the AP still lists it. */
function radioName(store, e) {
  const band = store.state.aps[e.ap]?.radios?.[e.phy]?.band;
  return band ? `${e.phy} (${band} GHz)` : e.phy;
}

/** An action's line: who did what to which client, and what came of it
 * (hostapd's bare "OK" says nothing a "done" does not). */
function actionText(e, what, showMac) {
  const who = e.user || 'Someone';
  const result = e.ok
    ? h('span', { class: 'muted' }, ` · ${!e.detail || e.detail === 'OK' ? 'done' : e.detail}`)
    : `: failed, ${e.detail || 'no reason given'}`;
  return showMac
    ? [who, ` ${what.text} `, h('a', { href: `#/client/${e.mac}` }, e.mac), result]
    : [`${what.text[0].toUpperCase()}${what.text.slice(1)} by ${who}`, result];
}

/**
 * The feed of `list` (newest first) as list items, a day heading where the
 * date changes. `seen` holds the events already shown, so that those that
 * happen after `since` are marked new the first time they are.
 */
export function feed(store, list, { seen, since = Infinity, showMac = true } = {}) {
  const out = [];
  let lastDay = '';
  for (const e of list) {
    const d = dayOf(e.at);
    if (d !== lastDay) {
      out.push(h('li', { class: 'day' }, d));
      lastDay = d;
    }
    const what = describe(e.phy ? { ...e, phy: radioName(store, e) } : e);
    const key = `${e.ap}|${e.at}|${e.kind}|${e.action || ''}|${e.mac || e.phy}`;
    const fresh = seen && !seen.has(key) && e.at > since;
    seen?.add(key);
    out.push(h('li', { class: [what.tone, fresh ? 'fresh' : ''].join(' ').trim() || null },
      h('time', { datetime: new Date(e.at).toISOString(), title: new Date(e.at).toLocaleString() }, time(e.at)),
      h('span', { class: 'ap-name' }, e.ap || '–'),
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      e.kind === 'action'
        ? h('span', { class: 'what' }, actionText(e, what, showMac))
        : h('span', { class: 'what' },
          e.mac && showMac ? [h('a', { href: `#/client/${e.mac}` }, e.mac), ' '] : null,
          e.mac && !showMac ? `${what.text[0].toUpperCase()}${what.text.slice(1)}` : what.text,
          e.bss ? h('span', { class: 'muted' }, ` via ${e.bss}`) : null)));
  }
  return out;
}

export default {
  mount(root, store) {
    store.loadHistory();
    const f = (store.ui.eventFilter ||= { group: '', ap: '', q: '' });
    let limit = PAGE;
    let drawn = '';
    const seen = new Set();
    const since = Date.now();
    const sub = h('p');
    const groups = GROUPS.map(([g, label]) => {
      const b = h('button', { type: 'button' }, label);
      b.addEventListener('click', () => {
        f.group = g;
        view.update();
      });
      return [g, b];
    });
    const apSelect = h('select', { 'aria-label': 'Access point' });
    apSelect.addEventListener('change', () => {
      f.ap = apSelect.value;
      view.update();
    });
    const search = h('input', { type: 'search', placeholder: 'Filter by MAC, SSID or user', 'aria-label': 'Filter events', value: f.q });
    search.addEventListener('input', () => {
      f.q = search.value;
      view.update();
    });
    const list = h('ol', { class: 'feed panel', reversed: true });
    const empty = h('div', { class: 'panel empty' });
    const more = h('button', { class: 'more', type: 'button' }, 'Show older events');
    more.addEventListener('click', () => {
      limit += PAGE;
      view.update();
    });
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Events'), sub),
      h('div', { class: 'tools' },
        h('div', { class: 'grow' }, search),
        h('div', { class: 'seg', role: 'group', 'aria-label': 'Kind' }, groups.map(([, b]) => b)),
        apSelect),
      list, empty, more);

    const view = {
      update() {
        const aps = Object.keys(store.state.aps).sort();
        if (apSelect.options.length !== aps.length + 1) {
          apSelect.replaceChildren(h('option', { value: '' }, 'All APs'), ...aps.map((a) => h('option', { value: a }, a)));
          apSelect.value = f.ap;
        }
        for (const [g, b] of groups) b.setAttribute('aria-pressed', String(f.group === g));
        const q = f.q.trim().toLowerCase();
        const all = store.events.filter((e) =>
          (!f.group || describe(e).group === f.group)
          && (!f.ap || e.ap === f.ap)
          && (!q || [e.mac, e.ssid, e.bss, e.phy, e.user].some((v) => v && v.toLowerCase().includes(q))));
        const shown = all.slice(-limit).reverse();
        // The feed changes only with the events, so most ticks redraw nothing.
        const stamp = `${f.group}|${f.ap}|${q}|${store.events.length}|${shown[0]?.at}|${limit}|${dayOf(Date.now())}`;
        if (stamp === drawn) return;
        drawn = stamp;
        sub.textContent = store.events.length ? `${all.length} of ${store.events.length} held by the controller` : '';
        list.hidden = !shown.length;
        empty.hidden = !!shown.length;
        more.hidden = all.length <= limit;
        if (!shown.length) {
          empty.replaceChildren(
            h('strong', {}, store.events.length ? 'No event matches these filters' : 'No events yet'),
            h('p', {}, store.events.length ? 'Change the filters to see more.' : 'Joins, leaves, sign-ins, radio changes and actions on clients appear here the moment they happen.'));
          return;
        }
        list.replaceChildren(...feed(store, shown, { seen, since }));
      },
    };
    return view;
  },
};
