// Auth problems: the clients that failed to get on in the last day, each
// with what its AP saw (EAP rejected or timed out, by the client or by
// RADIUS, and whether it reached RADIUS at all; a passphrase that does not
// match) beside RADIUS's own verdict and reason, how often, and whether it
// has got on since. The controller joins the two; this page asks it again
// every 15 seconds while it is open.

import { h, ago } from '../util.js';
import { timedOut, when } from './history.js';

const REFRESH_MS = 15000;

/** What the client's AP saw, in words. */
function apSide(s) {
  if (!s) return h('span', { class: 'muted' }, 'no attempt heard');
  const what = {
    'eap-failed': 'Sign-in rejected',
    'eap-timeout': `Sign-in timed out: ${timedOut(s.server)}`,
    'psk-mismatch': 'Wrong passphrase',
  }[s.kind] || s.kind;
  const never = s.kind === 'eap-timeout' && !s.reached_radius ? 'never reached RADIUS' : '';
  return [what, h('small', {}, [s.ap ? `on ${s.ap}` : '', never].filter(Boolean).join(' · '))];
}

/** What RADIUS said, in words, and the User-Name the client claimed (a
 * MAC-authenticated client's is its MAC, `mac`); `log` is whether its log
 * is read. */
function radiusSide(r, log, mac) {
  if (r) {
    const claimed = r.claimed && r.claimed.replaceAll('-', ':').toLowerCase() !== mac ? `claimed ${r.claimed}` : null;
    return [r.detail, h('small', {}, [claimed, r.node].filter(Boolean).join(' · '))];
  }
  if (log === 'up') return h('span', { class: 'muted' }, 'no rejection');
  return h('span', { class: 'muted' }, 'unknown (log not read)');
}

function status(c) {
  if (c.connected) return h('span', { class: 'chip ok' }, 'Connected');
  if (c.connected_since) return h('span', { class: 'chip' }, `Got on ${when(c.connected_since)}`);
  return h('span', { class: 'chip bad' }, 'Still failing');
}

export default {
  mount(root, store) {
    let data = null;
    let fetched = 0;
    let loading = false;
    const sub = h('p');
    const note = h('p', { class: 'note warn', hidden: true });
    const body = h('tbody');
    const head = ['Client', 'Last try', 'Its AP saw', 'RADIUS said', 'Tries', 'Now'];
    const table = h('div', { class: 'panel table-wrap' },
      h('table', { class: 'problems' },
        h('thead', {}, h('tr', {}, head.map((t) => h('th', { class: t === 'Tries' ? 'num' : null }, h('span', {}, t))))),
        body));
    const empty = h('div', { class: 'panel empty' });
    root.append(h('div', { class: 'head' }, h('h1', {}, 'Auth problems'), sub), note, table, empty);

    async function load() {
      if (loading) return;
      loading = true;
      const r = await store.getJson('/api/auth-problems');
      loading = false;
      fetched = Date.now();
      if (r.status === 200) data = r;
      else if (!data) data = { error: r.status };
      view.update();
    }

    const view = {
      update() {
        if (!loading && Date.now() - fetched > REFRESH_MS) load();
        const rows = data?.clients || [];
        sub.textContent = data?.clients ? `${rows.length} failed client${rows.length === 1 ? '' : 's'} in 24 h` : '';
        note.hidden = !data?.radius || data.radius === 'up';
        note.textContent = data?.radius === 'off'
          ? 'RADIUS log not read. AP view only.'
          : 'RADIUS log unreadable. Its verdicts are missing for now.';
        table.hidden = !rows.length;
        empty.hidden = !!rows.length;
        if (!rows.length) {
          const [title, text] = !data ? ['Loading…', '']
            : data.error !== undefined ? ['Controller unreachable', 'Retrying every 15 s.']
              : ['No auth failures', 'Failed, timed-out and wrong-passphrase sign-ins show here.'];
          empty.replaceChildren(h('strong', {}, title), text ? h('p', {}, text) : null);
          return;
        }
        body.replaceChildren(...rows.map((c) => {
          // Who a client is never comes from the User-Name it claimed.
          const who = c.name || c.mac;
          const under = [who === c.mac ? null : c.mac, c.vendor].filter(Boolean).join(' · ');
          return h('tr', { onclick: (e) => e.target.closest('a') || (location.hash = `#/client/${c.mac}`) },
            h('td', { class: 'c-who' }, h('a', { class: who === c.mac ? 'mono' : null, href: `#/client/${c.mac}` }, who), under ? h('small', {}, under) : null),
            h('td', { class: 'c-when' }, ago(c.last), h('small', {}, when(c.last))),
            h('td', { class: 'wrap c-ap', 'data-label': head[2] }, apSide(c.ap_side)),
            h('td', { class: 'wrap c-radius', 'data-label': head[3] }, radiusSide(c.radius, data.radius, c.mac)),
            h('td', { class: 'num c-tries' }, `${c.attempts}×`),
            h('td', { class: 'c-now' }, status(c)));
        }));
      },
    };
    return view;
  },
};
