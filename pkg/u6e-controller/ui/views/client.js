// One client: where it is, its readings now, its signal, rates and traffic
// over the session as this page has seen it, and its event history.

import { h, icon, bandName, bits, bytes, duration, hm, mbps, palette, pct, phy, quality } from '../util.js';
import { lineChart } from '../charts.js';
import { feed } from './events.js';

function reading(label, value, detail, cls) {
  return h('div', {}, h('dt', {}, label), h('dd', { class: cls }, value, detail ? h('small', {}, detail) : null));
}

/** A chart panel: its canvas is kept across updates, so a pointer on it stays. */
function chartPanel(title) {
  const canvas = h('canvas', { role: 'img', 'aria-label': title });
  const wait = h('div', { class: 'wait' }, 'Collecting samples: one every 2 seconds.');
  const legend = h('div', { class: 'legend' });
  const since = h('span', { class: 'muted' });
  const el = h('section', { class: 'panel chart' },
    h('div', { class: 'chart-head' }, h('h3', {}, title, ' ', since), legend), canvas, wait);
  return { el, canvas, wait, legend, since };
}

/** A legend key: a square, or a dashed line for a dashed series. */
function swatch(color, dashed) {
  const i = h('i', { class: dashed && 'dash' });
  if (dashed) i.style.borderColor = color;
  else i.style.background = color;
  return i;
}

// A chart's second series is drawn thin and dashed over a wide first, so equal
// rates (or no traffic either way) still show both.
const FIRST = 2.6;
const SECOND = { width: 1.4, dash: [5, 4] };

export default {
  mount(root, store, mac) {
    store.loadHistory();
    const head = h('div');
    const charts = [chartPanel('Signal'), chartPanel('Rates'), chartPanel('Throughput')];
    const chartsEl = h('div', { class: 'charts' }, charts.map((c) => c.el));
    const events = h('ol', { class: 'feed panel', reversed: true });
    const noEvents = h('div', { class: 'panel empty' });
    root.append(
      h('a', { class: 'crumb', href: '#/clients' }, icon('M15 18l-6-6 6-6'), 'Clients'),
      head, chartsEl,
      h('h2', { class: 'section-title' }, 'Events'), events, noEvents);
    let drawn = '';

    return {
      update() {
        const c = store.state.clients[mac];
        const p = palette();
        if (c) {
          head.replaceChildren(h('div', { class: 'panel clip' },
            h('div', { class: 'client-head' },
              h('h1', {}, mac),
              h('div', { class: 'where' },
                h('span', { class: 'chip', 'data-band': c.band }, bandName(c.band)),
                h('span', {}, c.ssid),
                c.vlan ? h('span', { class: 'chip' }, `VLAN ${c.vlan}`) : null,
                h('span', {}, `on ${c.ap}, ${c.bss}`),
                h('span', { class: 'muted' }, `connected ${duration(c.connected)}`))),
            h('dl', { class: 'readings' },
              reading('Signal', `${c.signal} dBm`, `average ${c.signal_avg} dBm`, `q-${quality(c.signal)}`),
              reading('Transmit rate', mbps(c.tx), phy(c.tx)),
              reading('Receive rate', mbps(c.rx), phy(c.rx)),
              reading('Download', c.down === undefined ? '–' : bits(c.down), c.up === undefined ? '' : `upload ${bits(c.up)}`),
              reading('Retries', c.retries === undefined ? '–' : pct(c.retries), 'of frames sent to it'),
              reading('Airtime', c.airtime === undefined ? '–' : pct(c.airtime), 'of the channel’s time'),
              reading('Transferred', bytes(c.tx_bytes), `${bytes(c.rx_bytes)} sent by it`),
              reading('Idle', `${c.idle} s`, 'since it was last heard'))));
        } else {
          head.replaceChildren(h('div', { class: 'panel empty' },
            h('strong', { class: 'mono' }, mac),
            h('p', {}, !store.keyed ? store.waiting()[0] : 'This client is not associated with any AP right now. Its past events are below.')));
        }
        chartsEl.hidden = !c;

        const s = store.samples.get(mac);
        const enough = c && s && s.times.length >= 2;
        for (const ch of charts) {
          ch.canvas.hidden = !enough;
          ch.wait.hidden = !!enough;
          ch.since.textContent = s?.times.length ? `since ${hm(s.times[0])}` : '';
        }
        if (c) {
          const color = p.band[c.band] || p.accent;
          const legends = [
            [['Signal', color]],
            [['Transmit', color], ['Receive', p.ink3, true]],
            [['Download', color], ['Upload', p.ink3, true]],
          ];
          charts.forEach((ch, i) => ch.legend.replaceChildren(...legends[i].map(([l, col, dashed]) => h('span', {}, swatch(col, dashed), l))));
          if (enough) {
            const zones = [
              { from: -62, to: 0, color: p.ok },
              { from: -72, to: -62, color: p.warn },
              { from: -120, to: -72, color: p.bad },
            ];
            lineChart(charts[0].canvas, {
              times: s.times, zones, format: (v) => `${Math.round(v)} dBm`,
              min: Math.min(-90, ...s.signal), max: Math.max(-40, ...s.signal),
              series: [{ label: 'Signal', color, values: s.signal }],
            });
            lineChart(charts[1].canvas, {
              times: s.times, min: 0, format: (v) => `${Math.round(v)} Mbps`,
              series: [{ label: 'Transmit', color, values: s.tx, width: FIRST }, { label: 'Receive', color: p.ink3, values: s.rx, ...SECOND }],
            });
            lineChart(charts[2].canvas, {
              times: s.times, min: 0, format: (v) => bits(v).replace(' ', ' '),
              series: [{ label: 'Download', color, values: s.down, width: FIRST }, { label: 'Upload', color: p.ink3, values: s.up, ...SECOND }],
            });
          }
        }

        const mine = store.events.filter((e) => e.mac === mac);
        const stamp = `${mine.length}|${mine.at(-1)?.at}`;
        if (stamp !== drawn) {
          drawn = stamp;
          events.replaceChildren(...feed(store, mine.slice(-200).reverse(), { showMac: false }));
        }
        events.hidden = !mine.length;
        noEvents.hidden = !!mine.length;
        noEvents.replaceChildren(h('p', {}, store.historyLoaded ? 'The controller holds no events of this client.' : 'Loading the event history.'));
      },
    };
  },
};
