// A client's traffic over the last week, as the controller keeps it: its
// volumes by hour (from the radio's byte counters) as bars, and, for an
// admin, where they went (from the connections its access point reports,
// by far end) for today or the whole week, each named by its reverse DNS,
// or by the client it is when it is one. Fetched when shown, again a few seconds later (the
// names it asked for have come by then) and every minute after.

import { h, bytes, dayOf, dnsTag, palette } from '../util.js';
import { barChart } from '../charts.js';

const REFRESH_MS = 60000;
const NAMES_MS = 3000;
const HOUR = 3600e3;
const PROTOS = { 6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6' };

function reading(label, value, detail) {
  return h('div', {}, h('dt', {}, label), h('dd', {}, value, detail ? h('small', {}, detail) : null));
}

/** The far end as a person reads it: its name, else its address. */
function endCell(d) {
  const where = `${d.ip.includes(':') ? `[${d.ip}]` : d.ip}:${d.port} ${PROTOS[d.proto] || d.proto}`;
  const client = d.client
    ? h('a', { href: `#/client/${d.client}` }, d.client_name || d.client)
    : null;
  return h('td', { class: 'wrap' },
    client || h('span', { class: d.name ? null : 'mono' }, d.name || d.ip, d.name ? [' ', dnsTag(d.name_confirmed)] : null),
    h('small', { class: 'mono' }, client ? `${where} · a client here` : where));
}

function destTable(list, total) {
  const rows = list.map((d) => {
    const share = total ? ((d.down + d.up) / total) * 100 : 0;
    // Set through the CSSOM: the page's policy refuses style attributes.
    const fill = h('i');
    fill.style.width = `${Math.max(2, Math.round(share))}%`;
    return h('tr', {},
      endCell(d),
      h('td', { class: 'num' }, bytes(d.down)),
      h('td', { class: 'num' }, bytes(d.up)),
      h('td', { class: 'num p3' }, h('div', { class: 'share' },
        h('b', {}, fill),
        h('span', {}, `${share < 1 ? '<1' : Math.round(share)} %`))));
  });
  return h('table', { class: 'sessions dests' },
    h('thead', {}, h('tr', {}, ['Destination', 'Down', 'Up', 'Share'].map((t, i) => h('th', { class: [i ? 'num' : '', i === 3 ? 'p3' : ''].join(' ').trim() || null }, h('span', {}, t))))),
    h('tbody', {}, rows));
}

/** The panel of `mac`'s traffic: `{ el, update }`. */
export function trafficPanel(store, mac) {
  const pick = (store.ui.trafficSpan ||= { span: 'week' });
  let data = null;
  let fetched = 0;
  let loading = false;
  let loads = 0;
  let drawn = '';
  const buttons = [['day', 'Today'], ['week', '7 days']].map(([k, label]) => {
    const b = h('button', { type: 'button' }, label);
    b.addEventListener('click', () => {
      pick.span = k;
      drawn = '';
      panel.update();
    });
    return [k, b];
  });
  const sums = h('dl', { class: 'readings flow-sum' });
  const canvas = h('canvas', { role: 'img', 'aria-label': 'Traffic by hour' });
  const legend = h('div', { class: 'legend' });
  const table = h('div', { class: 'table-wrap' });
  const note = h('p', { class: 'muted foot' });
  const empty = h('div', { class: 'panel empty' });
  const box = h('div', { class: 'panel traffic' },
    h('div', { class: 'chart-head' }, h('div', { class: 'seg', role: 'group', 'aria-label': 'Span' }, buttons.map(([, b]) => b)), legend),
    sums, h('div', { class: 'chart' }, canvas), table, note);
  const el = h('section', { class: 'client-traffic' }, h('h2', { class: 'section-title' }, 'Traffic'), box, empty);

  async function load() {
    loading = true;
    const r = await store.getJson(`/api/clients/${encodeURIComponent(mac)}/traffic`);
    loading = false;
    loads += 1;
    fetched = Date.now();
    data = r.status === 200 ? r : data || { error: r.status, days: [], top: [] };
    drawn = '';
    panel.update();
  }

  const panel = {
    el,
    update() {
      if (!loading && Date.now() - fetched > (loads === 1 ? NAMES_MS : REFRESH_MS)) load();
      for (const [k, b] of buttons) b.setAttribute('aria-pressed', String(pick.span === k));
      const p = palette();
      const stamp = `${fetched}|${pick.span}|${p.accent}|${canvas.clientWidth}`;
      if (stamp === drawn) return;
      drawn = stamp;
      const days = data?.days || [];
      box.hidden = !days.length;
      empty.hidden = !!days.length;
      empty.replaceChildren(h('p', {}, !data ? 'Loading traffic…'
        : data.error !== undefined ? 'Controller unreachable. Retrying.'
          : 'No traffic in the last 7 days.'));
      if (!days.length) return;
      const today = days[days.length - 1];
      const shown = pick.span === 'day' ? [today] : days;
      const down = shown.reduce((s, d) => s + d.down, 0);
      const up = shown.reduce((s, d) => s + d.up, 0);
      const otherDown = shown.reduce((s, d) => s + d.other_down, 0);
      const otherUp = shown.reduce((s, d) => s + d.other_up, 0);
      const dests = pick.span === 'day' ? today.dests : data.top;
      const hidden = data.destinations === false;
      sums.replaceChildren(
        reading('Down', bytes(down), pick.span === 'day' ? dayOf(today.day)
          : `${days.length} day${days.length === 1 ? '' : 's'}`),
        reading('Up', bytes(up)),
        hidden ? reading('Destinations', '–', 'wifi-admins only')
          : reading('Destinations', String(dests.length), dests.length >= 20 ? 'top 20' : ''),
        reading('Other', bytes(otherDown + otherUp), 'unlisted connections'));
      // One bar an hour over the span, from midnight of its first day.
      const start = shown[0].day;
      const count = pick.span === 'day' ? 24 : Math.round((today.day - start) / 86400e3 + 1) * 24;
      const downs = [];
      const ups = [];
      for (const d of shown) {
        for (const [at, u, dn] of d.hours) {
          const i = Math.round((at - start) / HOUR);
          downs[i] = dn;
          ups[i] = u;
        }
      }
      const color = p.accent;
      legend.replaceChildren(...[['Download', color], ['Upload', p.ink3]].map(([l, c]) => {
        const sw = h('i');
        sw.style.background = c;
        return h('span', {}, sw, l);
      }));
      requestAnimationFrame(() => barChart(canvas, {
        start, step: HOUR, count, format: (v) => bytes(v),
        series: [{ label: 'Download', color, values: downs }, { label: 'Upload', color: p.ink3, values: ups }],
      }));
      table.replaceChildren(hidden ? h('p', { class: 'muted' }, 'Destinations: wifi-admins only.')
        : dests.length ? destTable(dests, down + up) : h('p', { class: 'muted' }, 'No connections listed.'));
      note.textContent = 'Sources: radio counters · AP’s top connections · rDNS';
      note.title = 'Volumes from the radio’s byte counters. Destinations from the AP’s largest connections; smaller ones count as Other. Names from reverse DNS.';
    },
  };
  return panel;
}
