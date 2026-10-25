// Clients: every associated client, sortable and filterable, with its signal
// over the session as a sparkline; and the blocked ones no AP lets on, each a
// link to its page, where it can be unblocked.

import { h, BANDS, bits, duration, mbps, palette, pct, phy, quality } from '../util.js';
import { sparkline } from '../charts.js';

/** The columns: what the header says, how a row sorts and what its cell is.
 * `p` is the column's priority: the narrower the screen, the fewer show. */
const COLUMNS = [
  { key: 'mac', label: 'Client', sort: (m, c) => c.name || m, cell: clientCell },
  { key: 'ap', label: 'AP', p: 2, sort: (m, c) => `${c.ap} ${c.bss}`, cell: (m, c) => h('td', {}, c.ap, h('small', {}, c.bss)) },
  { key: 'band', label: 'Band', p: 2, sort: (m, c) => Number(c.band), cell: (m, c) => h('td', {}, h('span', { class: 'chip', 'data-band': c.band }, c.band ? `${c.band} GHz` : '?')) },
  { key: 'ssid', label: 'SSID', p: 3, sort: (m, c) => c.ssid, cell: (m, c) => h('td', {}, c.ssid) },
  { key: 'vlan', label: 'VLAN', p: 3, num: true, sort: (m, c) => c.vlan, cell: (m, c) => h('td', { class: 'num' }, c.vlan ? String(c.vlan) : '–') },
  { key: 'signal', label: 'Signal (dBm)', num: true, desc: true, sort: (m, c) => c.signal, cell: signalCell },
  { key: 'tx', label: 'TX rate', num: true, desc: true, sort: (m, c) => c.tx?.mbps, cell: (m, c) => h('td', { class: 'num' }, mbps(c.tx), h('small', {}, phy(c.tx))) },
  { key: 'rx', label: 'RX rate', p: 3, num: true, desc: true, sort: (m, c) => c.rx?.mbps, cell: (m, c) => h('td', { class: 'num' }, mbps(c.rx), h('small', {}, phy(c.rx))) },
  { key: 'retries', label: 'Retries', p: 4, num: true, desc: true, sort: (m, c) => c.retries ?? -1, cell: (m, c) => h('td', { class: 'num' }, c.retries === undefined ? '–' : pct(c.retries)) },
  { key: 'airtime', label: 'Airtime', p: 4, num: true, desc: true, sort: (m, c) => c.airtime ?? -1, cell: (m, c) => h('td', { class: 'num' }, c.airtime === undefined ? '–' : pct(c.airtime)) },
  { key: 'traffic', label: 'Down / up', p: 3, num: true, desc: true, sort: (m, c) => (c.down ?? 0) + (c.up ?? 0), cell: (m, c) => h('td', { class: 'num' }, c.down === undefined ? '–' : bits(c.down), h('small', {}, c.up === undefined ? '' : bits(c.up))) },
  { key: 'connected', label: 'Connected', p: 2, num: true, desc: true, sort: (m, c) => c.connected, cell: (m, c) => h('td', { class: 'num' }, duration(c.connected)) },
  { key: 'idle', label: 'Idle', p: 4, num: true, sort: (m, c) => c.idle, cell: (m, c) => h('td', { class: 'num' }, `${c.idle} s`) },
];

const sparks = [];

/** The client by its name, its MAC beneath; by its MAC when it has none. */
function clientCell(m, c) {
  const link = h('a', { class: c.name ? null : 'mono', href: `#/client/${m}` }, c.name || m);
  return h('td', {}, h('div', { class: 'who', 'data-band': c.band },
    h('div', { class: 'id' }, link, c.name ? h('small', { class: 'mono' }, m) : null)));
}

function signalCell(m, c) {
  const canvas = h('canvas', { 'aria-hidden': 'true' });
  sparks.push([canvas, m, c.band]);
  return h('td', { class: 'num' }, h('div', { class: 'sig' }, canvas, h('b', { class: `q-${quality(c.signal)}` }, String(c.signal))));
}

function matches(f, m, c) {
  if (f.band && c.band !== f.band) return false;
  if (f.ap && c.ap !== f.ap) return false;
  const q = f.q.trim().toLowerCase();
  return !q || [m, c.name || '', c.ap, c.bss, c.ssid, String(c.vlan)].some((v) => v.toLowerCase().includes(q));
}

export default {
  mount(root, store) {
    const f = (store.ui.clientFilter ||= { q: '', band: '', ap: '' });
    const sort = (store.ui.clientSort ||= { key: 'mac', dir: 1 });
    const sub = h('p');
    const search = h('input', { type: 'search', placeholder: 'Filter by name, MAC, AP, SSID or VLAN', 'aria-label': 'Filter clients', value: f.q });
    search.addEventListener('input', () => {
      f.q = search.value;
      view.update();
    });
    const bandButtons = ['', ...BANDS].map((b) => {
      const btn = h('button', { type: 'button' }, b ? `${b} GHz` : 'All bands');
      btn.addEventListener('click', () => {
        f.band = b;
        view.update();
      });
      return [b, btn];
    });
    const apSelect = h('select', { 'aria-label': 'Access point' });
    apSelect.addEventListener('change', () => {
      f.ap = apSelect.value;
      view.update();
    });
    const heads = COLUMNS.map((col) => {
      const btn = h('button', { type: 'button' }, col.label);
      btn.addEventListener('click', () => {
        sort.dir = sort.key === col.key ? -sort.dir : col.desc ? -1 : 1;
        sort.key = col.key;
        view.update();
      });
      return h('th', { class: [col.num ? 'num' : '', col.p ? `p${col.p}` : ''].join(' ').trim() || null }, btn);
    });
    const body = h('tbody');
    const table = h('div', { class: 'panel table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, heads)), body));
    const empty = h('div', { class: 'panel empty' });
    const tools = h('div', { class: 'tools' },
      h('div', { class: 'grow' }, search),
      h('div', { class: 'seg', role: 'group', 'aria-label': 'Band' }, bandButtons.map(([, b]) => b)),
      apSelect);
    const offList = h('ul', { class: 'panel off-list' });
    const off = h('section', {}, h('h2', { class: 'section-title' }, 'Blocked'), offList);
    root.append(h('div', { class: 'head' }, h('h1', {}, 'Clients'), sub), tools, table, empty, off);
    let offDrawn = '';

    const view = {
      update() {
        const all = Object.entries(store.state.clients);
        const aps = Object.keys(store.state.aps).sort();
        if (apSelect.options.length !== aps.length + 1) {
          apSelect.replaceChildren(h('option', { value: '' }, 'All APs'), ...aps.map((a) => h('option', { value: a }, a)));
          apSelect.value = f.ap;
        }
        for (const [b, btn] of bandButtons) btn.setAttribute('aria-pressed', String(f.band === b));
        COLUMNS.forEach((col, i) => {
          if (col.key === sort.key) heads[i].setAttribute('aria-sort', sort.dir > 0 ? 'ascending' : 'descending');
          else heads[i].removeAttribute('aria-sort');
        });

        const col = COLUMNS.find((c) => c.key === sort.key);
        const rows = all.filter(([m, c]) => matches(f, m, c)).sort(([ma, a], [mb, b]) => {
          const x = col.sort(ma, a);
          const y = col.sort(mb, b);
          return (x < y ? -1 : x > y ? 1 : ma < mb ? -1 : 1) * sort.dir;
        });
        sub.textContent = !store.keyed ? '' : rows.length === all.length ? `${all.length} associated` : `${rows.length} of ${all.length} shown`;

        const kept = (store.state.blocked || []).filter((m) => !(m in store.state.clients));
        off.hidden = !kept.length;
        if (kept.join() !== offDrawn) {
          offDrawn = kept.join();
          offList.replaceChildren(...kept.map((m) => h('li', {},
            h('a', { class: 'mono', href: `#/client/${m}` }, m),
            h('span', { class: 'muted' }, 'kept off every access point'))));
        }

        const anyUp = Object.values(store.state.aps).some((a) => a.up);
        table.hidden = !rows.length;
        empty.hidden = !!rows.length;
        if (!rows.length) {
          const filtered = all.length > 0;
          const [title, text] = filtered ? ['No client matches these filters', 'Change the filters, or clear them to see every client.']
            : !store.keyed ? store.waiting()
              : anyUp ? ['No clients are associated', 'Clients appear here as they join any SSID.']
                : ['No access point is connected', 'Clients are listed once an AP’s agent reports them.'];
          empty.replaceChildren(h('strong', {}, title), h('p', {}, text));
          if (filtered) {
            empty.append(h('button', { class: 'more', type: 'button', onclick: () => {
              Object.assign(f, { q: '', band: '', ap: '' });
              search.value = '';
              apSelect.value = '';
              view.update();
            } }, 'Clear filters'));
          }
          return;
        }
        sparks.length = 0;
        body.replaceChildren(...rows.map(([m, c]) => {
          const tr = h('tr', { onclick: (e) => e.target.closest('a') || (location.hash = `#/client/${m}`) },
            COLUMNS.map((col) => {
              const td = col.cell(m, c);
              if (col.p) td.classList.add(`p${col.p}`);
              return td;
            }));
          return tr;
        }));
        const p = palette();
        for (const [canvas, m, band] of sparks) {
          sparkline(canvas, store.samples.get(m)?.signal.slice(-60) || [], { color: p.band[band] || p.ink3, min: -85, max: -35 });
        }
      },
    };
    return view;
  },
};
