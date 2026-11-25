// The Wi-Fi experience score of a client or an access point, as the
// controller works it out (its README has the formula): the score from 0 to
// 100 and each part with its own score and, for a client, the figure it
// comes from. A part without its figure is shown as such, not as 0.

import { h, pct, scoreQuality } from '../util.js';

/** Each part: its name, the figure it comes from in words, and why a
 * client may have none. */
const PARTS = [
  ['signal', 'Signal', (v) => `${v} dBm avg`, ''],
  ['retries', 'Retries', (v) => `${pct(v)} retried`, 'too few frames'],
  ['contention', 'Air contention', (v) => `${pct(v)} busy with others`, 'one report so far'],
  ['rate', 'Rate', (v) => `${pct(v)} of best possible`, 'too few frames'],
  ['roaming', 'Roaming', (v) => (v ? `sticky ${pct(v)} of last hour` : 'not sticky (1 h)'), ''],
];

/** Its failed roams in the last hour, after the roaming part's figure. */
function failures(n) {
  return n ? ` · ${n} failed` : '';
}

/** A score as a bar, coloured by how good it is. */
function bar(score) {
  const fill = h('i');
  fill.style.width = `${score}%`;
  return h('b', { class: `xp-bar q-${scoreQuality(score)}` }, fill);
}

function head(score, note) {
  return h('div', { class: 'xp-score' },
    h('b', { class: `q-${scoreQuality(score)}` }, String(score)),
    h('span', {}, h('span', {}, 'of 100'), note ? h('small', {}, note) : null));
}

/** A client's experience (`e`, as the state carries it), or why it has
 * none yet. */
export function clientExperience(e) {
  if (e?.score === undefined || e.score === null) {
    return h('p', { class: 'xp-none muted' }, 'No score yet. Due with the AP’s next report.');
  }
  return h('div', { class: 'xp' }, head(e.score, 'weakest part weighs most'),
    h('ul', { class: 'xp-parts' }, PARTS.map(([key, label, figure, none]) => {
      const p = e.parts?.[key];
      return h('li', { class: p ? null : 'off' },
        h('span', { class: 'xp-name' }, label),
        p ? bar(p.score) : h('b', { class: 'xp-bar' }),
        h('span', { class: 'xp-val' }, p ? String(p.score) : '–'),
        h('small', {}, p ? figure(p.value) : none, key === 'roaming' && p ? failures(e.failed_roams) : ''));
    })));
}

/** An AP's experience (`a`, as the state carries it): its clients' mean
 * score and parts, and its weakest clients, each named by `name`. */
export function apExperience(a, name) {
  if (a?.score === undefined || a.score === null) return null;
  const clients = `mean of ${a.clients} client${a.clients === 1 ? '' : 's'}`;
  return h('div', { class: 'xp ap-xp' }, head(a.score, clients),
    h('ul', { class: 'xp-parts' }, PARTS.map(([key, label]) => {
      const p = a.parts?.[key];
      return h('li', { class: p === undefined ? 'off' : null },
        h('span', { class: 'xp-name' }, label),
        p === undefined ? h('b', { class: 'xp-bar' }) : bar(p),
        h('span', { class: 'xp-val' }, p === undefined ? '–' : String(p)));
    })),
    a.weakest?.length ? h('p', { class: 'xp-weakest' }, 'Weakest: ', a.weakest.map((w, i) => [
      i ? ', ' : '',
      h('a', { href: `#/client/${w.mac}` }, name(w.mac)),
      h('span', { class: `q-${scoreQuality(w.score)}` }, ` ${w.score}`),
    ])) : null);
}
