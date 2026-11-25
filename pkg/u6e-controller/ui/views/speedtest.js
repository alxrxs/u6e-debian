// Speed tests. The Test page measures the viewer's own device to the
// controller: the browser downloads filler for up to 10 s and times it, then
// uploads 8 MiB bodies, two at a time, for up to 10 s, which the controller
// times; the controller names the device by the address the sign-in proxy
// gives and says where it was. Each AP's panel on Devices shows its tests to
// the controller (`state.speedtests`), and an admin runs one there.

import { h, icon, ago, bandName, hm, time } from '../util.js';

const ADMIN_GROUP = 'wifi-admins';
const GAUGE = 'M12 21a9 9 0 1 1 9-9M12 12l4-4';
const OK = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M8 12l3 3 5-6';
const BAD = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16.5v.01';
/** The upload's body, made once: random, so nothing on the way shrinks it. */
const BODY_BYTES = 8 << 20;
/** Upload bodies in flight at once. */
const IN_FLIGHT = 2;

/** A rate in bit/s in Mbit/s, to a sensible precision, without its unit. */
function mbitNumber(bps) {
  if (bps === undefined || bps === null) return '–';
  const m = bps / 1e6;
  return m >= 100 ? String(Math.round(m)) : m.toFixed(m >= 10 ? 1 : 2);
}

/** A rate in bit/s as Mbit/s. */
export function mbit(bps) {
  return bps === undefined || bps === null ? '–' : `${mbitNumber(bps)} Mbit/s`;
}

function resultLine(el, tone, text) {
  el.dataset.tone = tone;
  el.replaceChildren(icon(tone === 'ok' ? OK : BAD), h('span', {}, text, h('time', { class: 'muted' }, ` ${hm(Date.now())}`)));
  el.hidden = false;
}

/** The two figures of a test, side by side. */
function figures(down, up, notes = {}) {
  const fig = (label, v, note) => h('div', { class: 'st-fig' },
    h('span', { class: 'st-label' }, label),
    h('span', { class: 'st-value' }, h('b', {}, mbitNumber(v)), ' ', h('span', { class: 'st-unit' }, 'Mbit/s')),
    note ? h('small', { class: 'muted' }, note) : null);
  return h('div', { class: 'st-figs' }, fig('Download', down, notes.down), fig('Upload', up, notes.up));
}

/** An AP test's CPU, both directions. */
function cpuText(cpu) {
  if (!cpu) return '';
  const pc = (c) => `${Math.round(c.busy)} %`;
  return `AP CPU ${pc(cpu.down)} down, ${pc(cpu.up)} up (all cores); the test’s own ${Math.round(cpu.down.thread)} % and ${Math.round(cpu.up.thread)} % of a core`;
}

/** The speed test box of AP `name` on its Devices panel. */
export function apSpeedBox(store, name, ap) {
  const all = store.state.speedtests?.aps || [];
  const mine = all.filter((t) => t.ap === name);
  const running = all.find((t) => t.status === 'running');
  const ui = (store.ui.speedtest ||= {});
  const result = h('p', { class: 'result', role: 'status', hidden: true });
  if (ui.result?.ap === name) resultLine(result, ui.result.tone, ui.result.text);
  const admin = !!store.me?.admin;
  const why = !ap.up ? `${name} is not connected`
    : running ? (running.ap === name ? 'Its test runs' : `A test of ${running.ap} runs`)
      : '';
  const run = h('button', { type: 'button', class: 'btn', 'aria-disabled': String(!!why), title: why },
    icon(GAUGE), h('span', {}, running?.ap === name ? 'Testing…' : 'Run speed test'));
  if (running?.ap === name) run.setAttribute('aria-busy', '');
  run.addEventListener('click', async () => {
    if (why) return;
    run.setAttribute('aria-busy', '');
    const res = await store.apSpeedTest(name);
    const text = res.status === 202 ? `Started: about 20 seconds, ${res.detail}.`
      : res.status === 0 ? 'Not started: the controller could not be reached.'
        : res.status === 403 && res.error === 'not an admin' ? `Not started: your account is not in ${ADMIN_GROUP}.`
          : `Not started: ${res.error || `status ${res.status}`}.`;
    ui.result = { ap: name, tone: res.status === 202 ? 'ok' : 'bad', text };
    resultLine(result, ui.result.tone, text);
  });
  const last = mine.find((t) => t.status !== 'running');
  const now = running?.ap === name
    ? h('p', { class: 'note' }, `Running since ${time(running.at)}${running.user ? `, asked by ${running.user}` : ''}: 10 s down, then 10 s up.`)
    : null;
  const lastEl = !last ? h('p', { class: 'muted' }, 'No test of this AP since the controller started.')
    : last.status === 'failed'
      ? h('p', { class: 'note warn' }, `The last test, ${ago(last.at)}, failed: ${last.detail}.`)
      : h('div', {},
        figures(last.down.bits_per_second, last.up.bits_per_second, { down: 'as the AP received it', up: 'as the controller received it' }),
        h('p', { class: 'muted st-foot' }, `${ago(last.at)}${last.user ? ` by ${last.user}` : ''}. ${cpuText(last.cpu)}.`));
  const earlier = mine.filter((t) => t.status === 'done' && t !== last).slice(0, 4);
  return h('div', { class: 'ap-st-box' },
    h('div', { class: 'st-head' }, h('h3', {}, 'Speed test to the controller'), admin ? run : null),
    now, lastEl,
    earlier.length ? h('p', { class: 'muted st-foot' }, 'Before: ', earlier.map((t) => `${hm(t.at)} ${mbit(t.down.bits_per_second)} down, ${mbit(t.up.bits_per_second)} up`).join(' · ')) : null,
    h('p', { class: 'muted st-foot' }, 'Wired, AP to controller. Test thread near 100 % means the AP’s CPU is the limit.'),
    admin ? null : h('p', { class: 'lock' }, `Running one needs membership of ${ADMIN_GROUP}.`),
    result);
}

/** A random body of `n` bytes, as a Blob the upload sends again and again. */
function randomBody(n) {
  const part = new Uint8Array(1 << 16);
  const parts = [];
  for (let i = 0; i < n; i += part.length) {
    crypto.getRandomValues(part);
    parts.push(part.slice());
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}

/** Where the controller found the device. */
function whereText(c) {
  if (!c) return null;
  return [
    h('b', {}, c.name || c.mac), ` on ${c.ap}, ${bandName(c.band)}, `, h('span', { class: 'mono' }, c.ssid),
    `; signal ${c.signal} dBm, rates ${Math.round(c.tx_mbps)} and ${Math.round(c.rx_mbps)} Mbit/s`,
  ];
}

export default {
  mount(root, store) {
    const start = h('button', { type: 'button', class: 'btn primary' }, icon(GAUGE), h('span', {}, 'Start the test'));
    const phase = h('p', { class: 'st-phase muted', role: 'status' });
    const live = h('div');
    const who = h('p', { class: 'st-who' });
    const result = h('p', { class: 'result', role: 'status', hidden: true });
    const history = h('div', { class: 'panel table-wrap' });
    root.append(
      h('div', { class: 'head' }, h('h1', {}, 'Test my connection'),
        h('p', {}, 'How fast this device reaches the Wi-Fi controller, both ways.')),
      h('section', { class: 'panel tool st-run' },
        h('div', { class: 'st-head' }, start, phase), who, live, result,
        h('p', { class: 'muted st-foot' }, 'The path is this device’s Wi-Fi to its access point, the access point’s network processor, the access router, the sign-in proxy (TLS, on whichever server answers) and the controller: a slow figure may be any of them. Each direction runs 10 seconds at most; you have one test at a time and six an hour.')),
      h('h2', { class: 'section-title' }, 'Your recent tests'), history);
    let running = false;
    let figs = { down: undefined, up: undefined };
    let drawnHist = '';
    let tests = null;

    function draw(notes) {
      live.replaceChildren(figures(figs.down, figs.up, notes));
    }

    async function loadHistory() {
      const r = await store.getJson('/api/speedtest');
      tests = r.status === 200 ? r.tests : tests;
      drawHistory();
    }

    function drawHistory() {
      const stamp = JSON.stringify(tests);
      if (stamp === drawnHist) return;
      drawnHist = stamp;
      if (!tests?.length) {
        history.replaceChildren(h('p', { class: 'muted st-none' }, tests ? 'None yet.' : 'Loading.'));
        return;
      }
      history.replaceChildren(h('table', { class: 'st-table' },
        h('thead', {}, h('tr', {}, [['When'], ['Download', 'num'], ['Upload', 'num'], ['Where']]
          .map(([t, cls]) => h('th', { class: cls }, h('span', {}, t))))),
        h('tbody', {}, tests.map((t) => h('tr', {},
          h('td', {}, `${hm(t.at)} `, h('small', { class: 'muted' }, ago(t.at))),
          h('td', { class: 'num' }, t.down ? mbit(t.down.bits_per_second) : '–'),
          h('td', { class: 'num' }, t.up ? mbit(t.up.bits_per_second) : '–'),
          h('td', {}, t.status === 'done'
            ? (t.client ? `${t.client.ap}, ${bandName(t.client.band)}, ${t.client.signal} dBm` : `not on this Wi-Fi (${t.address})`)
            : h('span', { class: 'chip bad' }, t.detail || t.status)))))));
    }

    // Timed from its answer's arrival: the filler follows the headers at
    // once, and an engine may hand the body over in large chunks.
    async function download(id) {
      const r = await fetch(`/api/speedtest/${encodeURIComponent(id)}/down`, { cache: 'no-store' });
      if (!r.ok || !r.body) throw new Error(`the download was refused (${r.status})`);
      const first = performance.now();
      const reader = r.body.getReader();
      let bytes = 0;
      let drawn = first;
      for (;;) {
        const { done, value } = await reader.read();
        const now = performance.now();
        if (done) break;
        bytes += value.length;
        if (now - drawn > 250) {
          drawn = now;
          figs.down = (bytes * 8 * 1000) / (now - first);
          draw();
        }
      }
      const ms = Math.max(1, Math.round(performance.now() - first));
      figs.down = (bytes * 8 * 1000) / ms;
      draw();
      return { down_bytes: bytes, down_ms: ms };
    }

    async function upload(id, secs) {
      const body = randomBody(BODY_BYTES);
      const url = `/api/speedtest/${encodeURIComponent(id)}/up`;
      const t0 = performance.now();
      let sent = 0;
      let open = true;
      // A body refused (the upload's time is up at the controller) ends it;
      // an engine may report that refusal as a failed request.
      const one = async () => {
        while (open && performance.now() - t0 < secs * 1000) {
          const r = await fetch(url, { method: 'POST', body, headers: { 'Content-Type': 'application/octet-stream' }, cache: 'no-store' })
            .catch(() => null);
          if (!r?.ok) {
            open = false;
            break;
          }
          sent += BODY_BYTES;
          figs.up = (sent * 8 * 1000) / (performance.now() - t0);
          draw();
        }
      };
      await Promise.all(Array.from({ length: IN_FLIGHT }, one));
    }

    async function test() {
      running = true;
      result.hidden = true;
      figs = { down: undefined, up: undefined };
      draw();
      who.replaceChildren();
      update();
      try {
        phase.textContent = 'Starting…';
        const s = await store.startSpeedTest();
        if (s.status !== 200) {
          const why = s.status === 0 ? 'the controller could not be reached' : s.error || `status ${s.status}`;
          throw new Error(why);
        }
        who.replaceChildren(...(s.client ? ['The controller sees this device as ', ...whereText(s.client), '.']
          : ['The controller does not see this device on its Wi-Fi: the test measures its path all the same.']));
        phase.textContent = 'Downloading…';
        const down = await download(s.id);
        phase.textContent = 'Uploading…';
        await upload(s.id, s.secs);
        phase.textContent = 'Finishing…';
        const { http, test: d } = await store.finishSpeedTest(s.id, down);
        if (http !== 200) throw new Error(http ? d.error || `status ${http}` : 'the controller could not be reached');
        figs = { down: d.down?.bits_per_second, up: d.up?.bits_per_second };
        draw({ down: 'as this browser received it', up: 'as the controller received it' });
        const moved = d.moved ? ` It moved to ${d.moved.ap}, ${bandName(d.moved.band)}, during the test.` : '';
        resultLine(result, d.status === 'done' ? 'ok' : 'bad', d.status === 'done' ? `Done.${moved}` : `Failed: ${d.detail}.`);
        phase.textContent = '';
      } catch (e) {
        phase.textContent = '';
        resultLine(result, 'bad', `The test did not run: ${e.message}.`);
      }
      running = false;
      loadHistory();
      update();
    }

    start.addEventListener('click', () => {
      if (!running) test();
    });
    loadHistory();

    function update() {
      start.setAttribute('aria-disabled', String(running));
      start.toggleAttribute('aria-busy', running);
      start.lastChild.textContent = running ? 'Testing…' : 'Start the test';
      drawHistory();
    }
    draw();
    return { update };
  },
};
