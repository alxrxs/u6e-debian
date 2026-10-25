// Flows: the connections each AP forwards for its clients, as the NSS
// connection manager tracks them: per client how many, how many the hardware
// offloads past the CPU, the bytes each way and their rate; a client's largest
// connections on demand, and an AP's whole table when asked for. A client's
// page shows its own with the table built here.

import { h, icon, bits, bytes, duration, time } from '../util.js';

const PROTOS = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP' };
/** Protocols whose connections have ports. */
const PORTS = new Set([6, 17, 132]);
/** Rows of a whole table shown at a time. */
const PAGE = 200;
const CHEVRON = 'M9 6l6 6-6 6';

function protoName(n) {
  return PROTOS[n] || `IP ${n}`;
}

/** An address with its port as a URL writes it, an IPv6 one in brackets. */
function endpoint(ip, port, proto) {
  if (!PORTS.has(proto)) return ip;
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** The offloaded share of `conns` as a figure and a bar. */
export function offload(conns, offloaded) {
  const p = conns ? (offloaded / conns) * 100 : 0;
  const bar = h('span', { class: 'off-bar', 'aria-hidden': 'true' }, h('i'));
  bar.firstChild.style.width = `${p}%`;
  return h('span', { class: 'off' }, bar, h('b', {}, conns ? `${Math.floor(p)} %` : '–'));
}

/** A table of connections `{ flow, mac }`; `of` names each one's client,
 * for a whole table. */
export function flowTable(rows, { of } = {}) {
  const head = [of ? 'Client' : null, 'Protocol', 'Remote end', 'Local port', 'Down', 'Up', 'Path', 'Age'];
  const num = new Set(['Down', 'Up', 'Age']);
  return h('table', { class: 'conns' },
    h('thead', {}, h('tr', {}, head.filter(Boolean).map((t) => h('th', { scope: 'col', class: num.has(t) ? 'num' : null }, t)))),
    h('tbody', {}, rows.map(({ flow: f, mac }) => {
      // The remote end is the one that is not the client's.
      const inbound = !f.client_is_src;
      const [rip, rport, lport] = inbound ? [f.src, f.sport, f.dport] : [f.dst, f.dport, f.sport];
      return h('tr', {},
        of ? h('td', { class: 'c-client' }, of(mac)) : null,
        h('td', { class: 'c-proto' }, protoName(f.proto)),
        h('td', { class: 'c-remote' }, h('span', { class: 'mono' }, endpoint(rip, rport, f.proto)), inbound ? h('small', {}, 'opened by the remote end') : null),
        h('td', { class: 'c-port mono', 'data-label': 'port' }, PORTS.has(f.proto) ? String(lport) : '–'),
        h('td', { class: 'c-down num', 'data-label': '↓' }, bytes(f.rx_bytes)),
        h('td', { class: 'c-up num', 'data-label': '↑' }, bytes(f.tx_bytes)),
        h('td', { class: 'c-path' }, f.offloaded
          ? h('span', { class: 'chip path', title: 'Forwarded by the NSS hardware, past the CPU' }, 'Offloaded')
          : h('span', { class: 'chip path cpu', title: 'Forwarded by the CPU' }, 'CPU')),
        h('td', { class: 'c-age num', 'data-label': 'for' }, duration(f.age)));
    })));
}

/** One client's top connections, as `flowTable` takes them. */
export function topRows(cf) {
  return cf.top.map((flow) => ({ flow, mac: cf.mac }));
}

/** A client's latest flows and the AP they came from, if any AP has them. */
export function clientFlows(store, mac) {
  for (const [ap, f] of Object.entries(store.flows)) {
    if (f.clients[mac]) return { ap, at: f.at, complete: f.complete, cf: f.clients[mac] };
  }
  return null;
}

/** A rate and the bytes it adds to, for a table cell. */
function rateCell(bps, total, cls) {
  return h('td', { class: `num ${cls}` }, bps === undefined ? h('span', { class: 'muted' }, '–') : bits(bps), h('small', {}, `${bytes(total)} in all`));
}

/** How long ago flows sampled at `at` were, in an element that `tick`
 * keeps current between redraws. */
export function sampled(at) {
  return h('span', { class: 'muted', 'data-at': String(at) }, ago(at));
}

function ago(at) {
  const s = Math.round((Date.now() - at) / 1000);
  return s < 2 ? 'sampled just now' : `sampled ${duration(s)} ago`;
}

/** Brings the `sampled` texts under `root` up to date. */
export function tick(root) {
  for (const el of root.querySelectorAll('[data-at]')) el.textContent = ago(Number(el.dataset.at));
}

/** Rebuilds `root` with `build`, the focus staying on the control (by its
 * `data-focus`) that had it, so the keyboard is not sent back to the top. */
export function redraw(root, build) {
  const active = document.activeElement;
  const id = root.contains(active) ? active.dataset.focus : undefined;
  const caret = id && active.matches('input') ? active.selectionStart : null;
  root.replaceChildren(...build());
  const again = id && root.querySelector(`[data-focus="${CSS.escape(id)}"]`);
  if (!again) return;
  again.focus();
  if (caret !== null) again.setSelectionRange(caret, caret);
}

/** The whole-table panel of one AP: its state kept across updates. */
function fullPanel(store, ap, view) {
  const full = (store.ui.fullFlows ||= {});
  const st = full[ap];
  if (!st) return null;
  const close = h('button', { type: 'button', class: 'btn quiet', 'data-focus': `close/${ap}`, onclick: () => {
    delete full[ap];
    view.update();
  } }, 'Close');
  const top = (title, ...rest) => h('div', { class: 'full-head' }, h('h3', {}, title), ...rest, close);
  if (st.loading) {
    return h('section', { class: 'full', 'aria-busy': 'true' }, top(`Asking ${ap} for every connection…`));
  }
  if (st.error) return h('section', { class: 'full' }, top('Whole table'), h('p', { class: 'note' }, st.error));
  const q = (st.q || '').trim().toLowerCase();
  const rows = [];
  for (const cf of st.clients) {
    const name = cf.name || '';
    for (const flow of cf.top) {
      if (q && ![cf.mac, name, flow.src, flow.dst, String(flow.sport), String(flow.dport), protoName(flow.proto)]
        .some((v) => v.toLowerCase().includes(q))) continue;
      rows.push({ flow, mac: cf.mac });
    }
  }
  rows.sort((a, b) => b.flow.rx_bytes + b.flow.tx_bytes - (a.flow.rx_bytes + a.flow.tx_bytes));
  const total = st.clients.reduce((n, c) => n + c.top.length, 0);
  const search = h('input', { type: 'search', placeholder: 'Filter by client, address, port or protocol', 'aria-label': `Filter ${ap}’s connections`, value: st.q || '', 'data-focus': `q/${ap}` });
  search.addEventListener('input', () => {
    st.q = search.value;
    st.limit = PAGE;
    view.update();
  });
  const limit = st.limit || PAGE;
  const names = Object.fromEntries(st.clients.map((c) => [c.mac, c.name]));
  const of = (mac) => h('a', { href: `#/client/${mac}` }, names[mac] || h('span', { class: 'mono' }, mac));
  return h('section', { class: 'full' },
    top(`Every connection, ${total}`, h('span', { class: 'muted' }, `as of ${time(st.at)}${st.complete ? '' : ', capped by the AP'}`)),
    h('div', { class: 'tools' }, h('div', { class: 'grow' }, search),
      q ? h('span', { class: 'muted' }, `${rows.length} match`) : null),
    rows.length ? h('div', { class: 'table-wrap' }, flowTable(rows.slice(0, limit), { of })) : h('p', { class: 'muted' }, 'No connection matches.'),
    rows.length > limit ? h('button', { type: 'button', class: 'more', 'data-focus': `more/${ap}`, onclick: () => {
      st.limit = limit + PAGE;
      view.update();
    } }, `Show ${Math.min(PAGE, rows.length - limit)} more`) : null);
}

async function askFull(store, ap, view) {
  const full = (store.ui.fullFlows ||= {});
  full[ap] = { loading: true };
  view.update();
  const r = await store.fullFlows(ap);
  if (!full[ap]) return;
  full[ap] = r.status === 200 && r.clients
    ? { at: r.at ?? Date.now(), complete: r.complete ?? true, clients: r.clients }
    : { error: r.status === 504 ? `${ap} did not send its table in time. Try again; a busy AP can take a few seconds.`
      : r.status === 429 ? `${ap} was asked for its table moments ago; it is asked at most every 10 seconds. Try again shortly.`
        : r.status === 0 ? 'The controller could not be reached.'
          : `${ap} could not send its table${r.error ? `: ${r.error}` : ''}.` };
  view.update();
}

export default {
  flows: true,
  mount(root, store) {
    const f = (store.ui.flowFilter ||= { q: '', ap: '' });
    const open = (store.ui.flowOpen ||= new Set());
    const sub = h('p');
    const search = h('input', { type: 'search', placeholder: 'Filter by name, MAC or address', 'aria-label': 'Filter flows', value: f.q });
    search.addEventListener('input', () => {
      f.q = search.value;
      view.update();
    });
    const apSelect = h('select', { 'aria-label': 'Access point' });
    apSelect.addEventListener('change', () => {
      f.ap = apSelect.value;
      view.update();
    });
    const list = h('div');
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Flows'), sub),
      h('div', { class: 'tools' }, h('div', { class: 'grow' }, search), apSelect),
      list);

    function matches(mac, cf) {
      const q = f.q.trim().toLowerCase();
      const name = cf.name || '';
      return !q || [mac, name].some((v) => v.toLowerCase().includes(q))
        || cf.top.some((x) => x.src.includes(q) || x.dst.includes(q));
    }

    function clientRows(ap, cfs) {
      return cfs.flatMap((cf) => {
        // Its band while it is associated; its name even after it left.
        const c = store.state.clients[cf.mac];
        const name = cf.name || c?.name;
        const key = `${ap}/${cf.mac}`;
        const isOpen = open.has(key);
        const toggle = h('button', { type: 'button', class: 'expand', 'data-focus': `open/${key}`, 'aria-expanded': String(isOpen), 'aria-label': `The largest connections of ${name || cf.mac}` }, icon(CHEVRON));
        const flip = () => {
          if (open.has(key)) open.delete(key);
          else open.add(key);
          view.update();
        };
        toggle.addEventListener('click', (e) => {
          e.stopPropagation();
          flip();
        });
        const row = h('tr', { onclick: (e) => e.target.closest('a') || flip() },
          h('td', { class: 'c-who' }, h('div', { class: 'who', 'data-band': c?.band },
            toggle,
            h('div', { class: 'id' },
              h('a', { href: `#/client/${cf.mac}`, class: name ? null : 'mono' }, name || cf.mac),
              name ? h('small', { class: 'mono' }, cf.mac) : null))),
          h('td', { class: 'num p2' }, String(cf.conns)),
          h('td', { class: 'num' }, offload(cf.conns, cf.offloaded), h('small', {}, `${cf.offloaded} of ${cf.conns}`)),
          rateCell(cf.down, cf.rx_bytes, 'c-rate'),
          rateCell(cf.up, cf.tx_bytes, 'c-rate'));
        if (!isOpen) return [row];
        const detail = cf.top.length
          ? h('div', { class: 'table-wrap' }, flowTable(topRows(cf)),
            cf.top.length < cf.conns ? h('p', { class: 'muted foot' }, `The largest ${cf.top.length} of ${cf.conns}; the AP’s whole table has every one.`) : null)
          : h('p', { class: 'muted foot' }, 'No connection is open.');
        return [row, h('tr', { class: 'sub' }, h('td', { colspan: '5' }, detail))];
      });
    }

    function apPanel(ap, fl) {
      const all = Object.values(fl.clients);
      const cfs = all.filter((cf) => matches(cf.mac, cf))
        .sort((a, b) => b.rx_bytes + b.tx_bytes - (a.rx_bytes + a.tx_bytes) || (a.mac < b.mac ? -1 : 1));
      const conns = all.reduce((n, c) => n + c.conns, 0);
      const off = all.reduce((n, c) => n + c.offloaded, 0);
      const pending = store.ui.fullFlows?.[ap]?.loading;
      const fullBtn = h('button', { type: 'button', class: 'btn', 'data-focus': `full/${ap}`, 'aria-busy': pending ? 'true' : null, disabled: pending, onclick: () => askFull(store, ap, view) },
        icon('M4 6h16M4 12h16M4 18h16'), 'Whole table');
      const thead = h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Client'),
        h('th', { scope: 'col', class: 'num p2' }, 'Conns'),
        h('th', { scope: 'col', class: 'num' }, 'Offloaded'),
        h('th', { scope: 'col', class: 'num' }, 'Down'),
        h('th', { scope: 'col', class: 'num' }, 'Up')));
      return h('section', { class: 'panel flows-ap' },
        h('div', { class: 'flows-top' },
          h('h2', {}, ap),
          h('span', { class: 'muted' }, `${conns} connection${conns === 1 ? '' : 's'}, ${all.length} client${all.length === 1 ? '' : 's'}`),
          conns ? h('span', { class: 'muted off-sum' }, offload(conns, off), 'offloaded') : null,
          sampled(fl.at),
          fullBtn),
        fl.complete ? null : h('p', { class: 'note warn' }, `${ap} counted more connections than it reports at once; these figures cover those it read.`),
        cfs.length
          ? h('div', { class: 'table-wrap' }, h('table', { class: 'flow-clients' }, thead, h('tbody', {}, clientRows(ap, cfs))))
          : h('p', { class: 'offline' }, all.length ? 'No client of this AP matches the filter.' : `No client of ${ap} has a connection open.`),
        fullPanel(store, ap, view));
    }

    let drawn = '';
    const view = {
      update() {
        const aps = Object.keys(store.state.aps).sort();
        if (apSelect.options.length !== aps.length + 1) {
          apSelect.replaceChildren(h('option', { value: '' }, 'All APs'), ...aps.map((a) => h('option', { value: a }, a)));
          apSelect.value = f.ap;
        }
        const shown = Object.entries(store.flows).filter(([ap]) => !f.ap || ap === f.ap).sort(([a], [b]) => a.localeCompare(b));
        const all = Object.values(store.flows).flatMap((x) => Object.values(x.clients));
        const conns = all.reduce((n, c) => n + c.conns, 0);
        const off = all.reduce((n, c) => n + c.offloaded, 0);
        sub.textContent = all.length ? `${conns} connections of ${all.length} clients, ${Math.floor((off / conns) * 100 || 0)} % offloaded` : '';
        // The flows change every 10 s at most, the samples every 2 s: most
        // updates only move the "sampled" clocks.
        const full = Object.entries(store.ui.fullFlows || {}).map(([a, x]) => [a, x.loading, x.error, x.at, x.q, x.limit]);
        const bands = all.map((c) => [c.mac, store.state.clients[c.mac]?.band]);
        const stamp = JSON.stringify([shown.map(([a, x]) => [a, x.stamp]), f, [...open], full, bands, store.flowsKeyed, store.keyed]);
        if (stamp === drawn) {
          tick(list);
          return;
        }
        drawn = stamp;
        if (!shown.length) {
          const [title, text] = !store.keyed ? store.waiting()
            : !store.flowsKeyed ? ['Loading the flows', 'Each AP sends its clients’ connections every 10 seconds while this page shows them.']
              : Object.values(store.state.aps).some((a) => a.up) ? ['No flows yet', 'Each connected AP sends its clients’ connections within 10 seconds.']
                : ['No access point is connected', 'Flows are listed once an AP’s agent reports them.'];
          list.replaceChildren(h('div', { class: 'panel empty' }, h('strong', {}, title), h('p', {}, text)));
          return;
        }
        redraw(list, () => shown.map(([ap, fl]) => apPanel(ap, fl)));
      },
    };
    return view;
  },
};
