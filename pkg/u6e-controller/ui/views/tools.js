// The SSIDs' rate limits (the Config page), and a client's tools beside its
// readings: its rate limit (what an admin set,
// what its SSID's is, and how it stands on each AP: enforced by the NSS
// with the bytes its classes passed, waiting for the client, refused or not
// enforced, with why) and its captures (one at a time on its AP, bounded in
// time, size and snaplen, filtered by protocol, port and host; running,
// stopped, and downloaded by admins). Both read the live view
// (`state.limits`, `state.captures`); only admins change anything.

import { h, ago, ask, bytes, duration, hm, icon } from '../util.js';

const ADMIN_GROUP = 'wifi-admins';
const LOCK = 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4';
const GAUGE = 'M12 21a9 9 0 1 1 9-9M12 12l4-4';
const REC = 'M12 7a5 5 0 1 0 0 10a5 5 0 0 0 0-10z';
const STOP = 'M7 7h10v10H7z';
const DOWN = 'M12 4v12M6 10l6 6 6-6M5 20h14';
const OK = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M8 12l3 3 5-6';
const BAD = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16.5v.01';

/** A rate in kbit/s, as people read it. */
export function rateText(kbit) {
  if (kbit === null || kbit === undefined) return 'none';
  return kbit % 1000 === 0 ? `${kbit / 1000} Mbit/s` : `${(kbit / 1000).toFixed(kbit < 10000 ? 2 : 1)} Mbit/s`;
}

/** A limit's two directions: "download 20 Mbit/s, upload none". */
export function limitText(r) {
  if (!r) return 'No limit';
  return `Download ${rateText(r.down_kbit)}, upload ${rateText(r.up_kbit)}`;
}

const STATUS = {
  enforced: ['ok', 'Enforced'],
  waiting: ['', 'Waiting'],
  refused: ['bad', 'Refused'],
  'not enforced': ['warn', 'Not enforced'],
};

/** How the limit of `key` stands on each connected AP. */
export function limitStates(limits, key) {
  const rows = [];
  for (const [ap, per] of Object.entries(limits?.states || {}).sort(([a], [b]) => a.localeCompare(b))) {
    const s = per[key];
    if (!s) continue;
    const [tone, word] = STATUS[s.status] || ['', s.status];
    const counted = s.status === 'enforced' && (s.down_bytes || s.up_bytes)
      ? ` · ${bytes(s.down_bytes)} down, ${bytes(s.up_bytes)} up through its classes` : '';
    rows.push(h('li', {}, h('b', {}, ap), ' ', h('span', { class: `chip ${tone}` }, word),
      h('small', {}, ` ${s.detail}${counted}`)));
  }
  return rows.length ? h('ul', { class: 'limit-states' }, rows) : null;
}

/** A rate field in Mbit/s; empty is no limit in that direction. */
function rateField(label, kbit) {
  const input = h('input', {
    type: 'number', inputmode: 'decimal', min: '0.064', max: '2000', step: '0.001',
    placeholder: 'none', value: kbit ? String(kbit / 1000) : undefined, 'aria-label': `${label} in Mbit/s`,
  });
  return { input, el: h('label', { class: 'field' }, h('span', {}, label), h('span', { class: 'unit' }, input, 'Mbit/s')) };
}

/** The kbit/s of a field, null when empty; undefined when it is no rate. */
function kbitOf(input) {
  const v = input.value.trim();
  if (!v) return null;
  const n = Math.round(Number(v) * 1000);
  return Number.isFinite(n) && n >= 64 && n <= 2000000 ? n : undefined;
}

/** What an answer to a limit's change says: [tone, text]. */
export function limitOutcome(res, what) {
  if (res.status === 0) return ['bad', `${what} not set: the controller could not be reached.`];
  if (res.status === 403) return ['bad', res.error === 'not an admin' ? `${what} not set: your account is not in ${ADMIN_GROUP}.` : `${what} not set: reload the page and try again.`];
  if (res.status !== 200) return ['bad', `${what} not set: ${res.error || `status ${res.status}`}.`];
  const results = res.results || [];
  const failed = results.filter((r) => !r.ok);
  if (!results.some((r) => r.ap)) return ['ok', `${what} saved. No access point is connected; each is given it as it connects.`];
  const told = results.filter((r) => r.ok && r.ap).map((r) => `${r.ap} (${r.detail})`);
  const fails = failed.map((r) => `${r.ap || 'the controller'}: ${r.detail}`);
  return [failed.length ? 'bad' : 'ok', `${what} saved and given to ${told.join(', ') || 'no AP'}.${fails.length ? ` ${fails.join('; ')}.` : ''}`];
}

function resultLine(el, [tone, text]) {
  el.dataset.tone = tone;
  el.replaceChildren(icon(tone === 'ok' ? OK : BAD), h('span', {}, text, h('time', { class: 'muted' }, ` ${hm(Date.now())}`)));
  el.hidden = false;
}

function lockNote(store, what) {
  return h('p', { class: 'lock' }, icon(LOCK), h('span', {}, store.me ? `Viewing only: ${what} needs membership of ` : `${what} needs membership of `, h('b', {}, ADMIN_GROUP), '.'));
}

/** The rate limit panel of client `mac`. */
export function limitPanel(store, mac) {
  const now = h('dl', { class: 'facts' });
  const states = h('div');
  const down = rateField('Download', null);
  const up = rateField('Upload', null);
  const apply = h('button', { type: 'button', class: 'btn primary' }, icon(GAUGE), h('span', {}, 'Set limit'));
  const clear = h('button', { type: 'button', class: 'btn' }, h('span', {}, 'Remove limit'));
  const form = h('div', { class: 'tool-form' }, down.el, up.el, h('div', { class: 'tool-buttons' }, apply, clear));
  const lock = h('div');
  const result = h('p', { class: 'result', role: 'status', hidden: true });
  const el = h('section', { class: 'panel tool' },
    h('div', { class: 'tool-head' }, h('h2', {}, 'Rate limit'),
      h('small', { class: 'muted' }, 'Enforced by the access point’s NSS shaper, per direction')),
    now, states, form, lock, result);
  let busy = false;
  let shown = '';

  async function send(body, what) {
    busy = true;
    update();
    const res = await store.limit(mac, body);
    busy = false;
    resultLine(result, limitOutcome(res, what));
    update();
  }

  apply.addEventListener('click', () => {
    const d = kbitOf(down.input);
    const u = kbitOf(up.input);
    if (d === undefined || u === undefined) {
      resultLine(result, ['bad', 'A rate is 0.064 to 2000 Mbit/s; leave a direction empty for none.']);
      return;
    }
    if (d === null && u === null) {
      resultLine(result, ['bad', 'Give a download or an upload rate, or remove the limit.']);
      return;
    }
    send({ down_kbit: d, up_kbit: u }, 'Limit');
  });
  clear.addEventListener('click', async () => {
    const yes = await ask(document.body, { title: 'Remove the limit?', text: 'The client is shaped no more, but for its SSID’s limit, if it has one.', confirm: 'Remove' });
    if (yes) send({ down_kbit: null, up_kbit: null }, 'Removal');
  });

  function update() {
    const limits = store.state.limits || {};
    const mine = limits.clients?.[mac];
    const c = store.state.clients[mac];
    const ssid = c?.ssid;
    const ssidRate = ssid ? (limits.ssids?.[ssid] || limits.site?.[ssid]) : null;
    now.replaceChildren(...[
      h('div', {}, h('dt', {}, 'This client'), h('dd', {}, limitText(mine))),
      ssidRate ? h('div', {}, h('dt', {}, `Its SSID, ${ssid}`), h('dd', {}, limitText(ssidRate),
        h('small', {}, mine ? ' replaced by its own, direction by direction' : ' shared with its SSID’s other unlimited clients, on each radio'))) : null,
    ].filter(Boolean));
    states.replaceChildren(mine ? limitStates(limits, mac) || h('p', { class: 'muted tool-note' }, 'No access point has said how it stands yet.') : '');
    const admin = !!store.me?.admin;
    form.hidden = !admin;
    lock.replaceChildren(admin ? '' : lockNote(store, 'Limiting'));
    const stamp = JSON.stringify(mine || null);
    if (stamp !== shown) {
      shown = stamp;
      down.input.value = mine?.down_kbit ? String(mine.down_kbit / 1000) : '';
      up.input.value = mine?.up_kbit ? String(mine.up_kbit / 1000) : '';
    }
    for (const b of [apply, clear]) b.disabled = busy;
    clear.hidden = !mine;
    apply.toggleAttribute('aria-busy', busy);
  }
  return { el, update };
}

/** The SSIDs the access points carry and those a limit names, sorted. */
function ssidsOf(store) {
  const limits = store.state.limits || {};
  const names = new Set([...Object.keys(limits.site || {}), ...Object.keys(limits.ssids || {})]);
  for (const ap of Object.values(store.state.aps || {})) {
    for (const b of Object.values(ap.bsss || {})) names.add(b.ssid);
  }
  return [...names].filter(Boolean).sort((a, b) => a.localeCompare(b));
}

/** One SSID's row of the SSID limits: its limits, how they stand, and an
 * admin's form, kept across updates so a value being typed stays. */
function ssidRow(store, ssid) {
  const now = h('dl', { class: 'facts' });
  const states = h('div');
  const down = rateField('Download', null);
  const up = rateField('Upload', null);
  const apply = h('button', { type: 'button', class: 'btn primary' }, icon(GAUGE), h('span', {}, 'Set'));
  const clear = h('button', { type: 'button', class: 'btn' }, h('span', {}, 'Remove'));
  const form = h('div', { class: 'tool-form' }, down.el, up.el, h('div', { class: 'tool-buttons' }, apply, clear));
  const result = h('p', { class: 'result', role: 'status', hidden: true });
  const el = h('div', { class: 'ssid-limit' }, h('h3', {}, ssid), now, states, form, result);
  let busy = false;
  let shown = '';

  async function send(rates, what) {
    busy = true;
    update();
    const res = await store.ssidLimit(ssid, rates);
    busy = false;
    resultLine(result, limitOutcome(res, what));
    update();
  }
  apply.addEventListener('click', () => {
    const d = kbitOf(down.input);
    const u = kbitOf(up.input);
    if (d === undefined || u === undefined || (d === null && u === null)) {
      resultLine(result, ['bad', 'A rate is 0.064 to 2000 Mbit/s, in at least one direction.']);
      return;
    }
    send({ down_kbit: d, up_kbit: u }, `${ssid}’s limit`);
  });
  clear.addEventListener('click', () => send({ down_kbit: null, up_kbit: null }, `Removal of ${ssid}’s limit`));

  function update() {
    const limits = store.state.limits || {};
    const site = limits.site?.[ssid];
    const admin = limits.ssids?.[ssid];
    now.replaceChildren(...[
      h('div', {}, h('dt', {}, 'In force'), h('dd', {}, limitText(admin || site),
        h('small', {}, admin ? (site ? ' set here, over the site file’s' : ' set here') : site ? ' from the site file' : ''))),
      site && admin ? h('div', {}, h('dt', {}, 'The site file’s'), h('dd', {}, limitText(site))) : null,
    ].filter(Boolean));
    states.replaceChildren((admin || site) ? limitStates(limits, `ssid:${ssid}`) || '' : '');
    form.hidden = !store.me?.admin;
    const stamp = JSON.stringify(admin || null);
    if (stamp !== shown) {
      shown = stamp;
      down.input.value = admin?.down_kbit ? String(admin.down_kbit / 1000) : '';
      up.input.value = admin?.up_kbit ? String(admin.up_kbit / 1000) : '';
    }
    clear.hidden = !admin;
    clear.lastChild.textContent = site ? 'Back to the site file’s' : 'Remove';
    for (const b of [apply, clear]) b.disabled = busy;
    apply.toggleAttribute('aria-busy', busy);
  }
  return { el, update };
}

/** The SSIDs' rate limits: each SSID's, set in the site file or here. */
export function ssidLimitsPanel(store) {
  const rows = new Map();
  const list = h('div', { class: 'ssid-limits' });
  const lock = h('div');
  const el = h('section', { class: 'panel tool' },
    h('div', { class: 'tool-head' }, h('h2', {}, 'Rate limits per SSID'),
      h('small', { class: 'muted' }, 'Shared by the SSID’s clients without a limit of their own: download on each of its radios apart, upload together')),
    list, lock);
  function update() {
    const names = ssidsOf(store);
    for (const n of names) if (!rows.has(n)) rows.set(n, ssidRow(store, n));
    for (const n of [...rows.keys()]) if (!names.includes(n)) rows.delete(n);
    const els = names.map((n) => rows.get(n).el);
    if (els.length !== list.children.length || els.some((e, i) => list.children[i] !== e)) list.replaceChildren(...els);
    for (const r of rows.values()) r.update();
    if (!names.length) list.replaceChildren(h('p', { class: 'muted tool-note' }, 'No access point has told its SSIDs yet.'));
    lock.replaceChildren(store.me?.admin ? '' : lockNote(store, 'Limiting'));
  }
  return { el, update };
}

const SNAPLENS = [[64, '64 B'], [128, '128 B (headers)'], [256, '256 B'], [1514, '1514 B'], [65535, 'Whole packets']];
const DURATIONS = [10, 30, 60, 120, 300, 600];
const SIZES = [1, 5, 10, 25, 50];

function select(label, options, value) {
  const s = h('select', { 'aria-label': label },
    options.map(([v, text]) => h('option', { value: String(v), selected: v === value }, text)));
  return { input: s, el: h('label', { class: 'field' }, h('span', {}, label), s) };
}

function textField(label, attrs) {
  const input = h('input', { type: 'text', 'aria-label': label, ...attrs });
  return { input, el: h('label', { class: 'field' }, h('span', {}, label), input) };
}

/** How a capture took the flows, in words. */
export function mechanismText(m) {
  if (m === 'mirror') return 'Its connections stay offloaded; the NSS copies their packets.';
  if (m === 'off offload') return 'Taken off the offload for the capture: its traffic, and every new connection of its access point, go through the access point’s CPU until it ends.';
  return '';
}

/** What an answer to a capture's start or stop says. */
function captureOutcome(res, what) {
  if (res.status === 0) return ['bad', `${what}: the controller could not be reached.`];
  if (res.status === 403) return ['bad', res.error === 'not an admin' ? `${what}: your account is not in ${ADMIN_GROUP}.` : `${what}: reload the page and try again.`];
  if (res.status === 404) return ['bad', `${what}: the client is not associated with any access point.`];
  if (res.status >= 400) return ['bad', `${what}: ${res.error || `status ${res.status}`}.`];
  return ['ok', what === 'Not started' ? '' : `${what}.`];
}

/** The capture panel of client `mac`. */
export function capturePanel(store, mac) {
  const secs = select('Duration', DURATIONS.map((s) => [s, duration(s)]), 60);
  const size = select('At most', SIZES.map((m) => [m, `${m} MB`]), 10);
  const snap = select('Each packet', SNAPLENS, 128);
  const proto = select('Protocol', [['', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP'], ['arp', 'ARP']], '');
  const port = textField('Port', { inputmode: 'numeric', placeholder: 'any', size: 6 });
  const host = textField('Host', { placeholder: 'any address', spellcheck: 'false', autocapitalize: 'off' });
  const start = h('button', { type: 'button', class: 'btn primary' }, icon(REC), h('span', {}, 'Start capture'));
  const form = h('div', { class: 'tool-form' }, secs.el, size.el, snap.el, proto.el, port.el, host.el,
    h('div', { class: 'tool-buttons' }, start));
  const running = h('div');
  const lock = h('div');
  const list = h('div');
  const result = h('p', { class: 'result', role: 'status', hidden: true });
  const el = h('section', { class: 'panel tool' },
    h('div', { class: 'tool-head' }, h('h2', {}, 'Capture'),
      h('small', { class: 'muted' }, 'On the access point the client is on, downloaded as pcapng')),
    running, form, lock, result, list,
    h('p', { class: 'muted tool-note' }, 'Traffic between two clients of one BSS never reaches the access point’s host (its radio forwards it), so no capture holds it. The radios’ air is not captured: a monitor interface cut an associated client’s traffic for as long as it existed. Files are kept a day.'));
  let busy = false;

  /** The filter the fields make, or why they make none. */
  function filter() {
    const p = port.input.value.trim();
    const n = p ? Number(p) : null;
    if (p && !(Number.isInteger(n) && n >= 1 && n <= 65535)) return 'A port is 1 to 65535.';
    const pr = proto.input.value || null;
    if (n && (pr === 'icmp' || pr === 'arp')) return 'A port goes with TCP or UDP.';
    const a = host.input.value.trim();
    if (a && !/^[0-9a-fA-F.:]+$/.test(a)) return 'A host is an IPv4 or IPv6 address.';
    if (a && pr === 'arp' && a.includes(':')) return 'ARP carries IPv4 addresses only.';
    return { proto: pr, port: n, host: a || null };
  }

  start.addEventListener('click', async () => {
    const f = filter();
    if (typeof f === 'string') {
      resultLine(result, ['bad', f]);
      return;
    }
    busy = true;
    update();
    const res = await store.capture(mac, {
      secs: Number(secs.input.value), max_mb: Number(size.input.value), snaplen: Number(snap.input.value), filter: f,
    });
    busy = false;
    const [tone, text] = captureOutcome(res, 'Not started');
    if (tone === 'bad') resultLine(result, [tone, text]);
    else result.hidden = true;
    update();
  });

  function update() {
    const mine = (store.state.captures || []).filter((c) => c.mac === mac);
    const live = mine.find((c) => c.running);
    const admin = !!store.me?.admin;
    const onAp = !!store.state.clients[mac];
    if (live) {
      const stop = h('button', { type: 'button', class: 'btn danger-quiet' }, icon(STOP), h('span', {}, 'Stop'));
      stop.addEventListener('click', async () => {
        stop.disabled = true;
        const res = await store.stopCapture(live.id);
        const [tone, text] = captureOutcome(res, 'Not stopped');
        if (tone === 'bad') resultLine(result, [tone, text]);
      });
      const pctDone = Math.min(100, Math.round((100 * live.bytes) / live.max_bytes));
      const left = Math.max(0, live.secs - Math.floor((Date.now() - live.at) / 1000));
      running.replaceChildren(h('div', { class: 'capture-live' },
        h('p', { class: 'result', 'data-tone': 'wait', role: 'status' }, icon(REC),
          h('span', {}, h('b', {}, `Capturing on ${live.ap}`), ` · ${bytes(live.bytes)} of ${bytes(live.max_bytes)} (${pctDone} %) · ${duration(left)} left at most · filter ${live.filter}`,
            live.mechanism ? h('small', { class: 'block' }, mechanismText(live.mechanism)) : null)),
        admin ? h('div', { class: 'tool-buttons' }, stop) : null));
    } else {
      running.replaceChildren();
    }
    form.hidden = !admin || !!live;
    start.disabled = busy || !onAp;
    start.title = onAp ? '' : 'Not associated with any access point';
    start.toggleAttribute('aria-busy', busy);
    lock.replaceChildren(admin ? '' : lockNote(store, 'Capturing'));
    const done = mine.filter((c) => !c.running);
    list.replaceChildren(done.length ? h('ul', { class: 'captures' }, done.map((c) => {
      const ok = /^(stopped|its time is up|its size limit is reached)$/.test(c.reason);
      const file = c.file && admin
        ? h('a', { class: 'btn quiet', href: `/api/captures/${c.id}/file`, download: '' }, icon(DOWN), h('span', {}, 'Download'))
        : null;
      return h('li', {},
        h('div', { class: 'cap-main' },
          h('b', {}, `${hm(c.at)}`), h('span', { class: 'muted' }, ` ${ago(c.at)} on ${c.ap}${c.user ? `, by ${c.user}` : ''}`),
          h('small', { class: 'block' }, `${bytes(c.bytes)}, ${c.packets} packets${c.dropped ? `, ${c.dropped} dropped` : ''} · filter ${c.filter} · `,
            h('span', { class: ok ? '' : 'q-poor' }, c.reason),
            c.mechanism ? ` · ${c.mechanism === 'mirror' ? 'mirrored by the NSS' : 'taken off the offload'}` : '',
            c.file ? '' : ' · its file is no longer kept')),
        file);
    })) : '');
  }
  return { el, update };
}
