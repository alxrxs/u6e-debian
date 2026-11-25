// A client's history as the controller keeps it: its timeline (associations
// and roams, EAP's steps and RADIUS's verdicts, its leases, its first
// traffic, the operators' actions, the client guards' reports, a sleep
// proxy answering for it or it for another, the changes of the services it
// offers over mDNS, disconnects)
// in the feed's shape, and its sessions as a table. The client page and the
// Auth problems page share the words.

import { h, actor, bandName, bytes, dayOf, DID, duration, GUARDS, hm, serviceWords, time } from '../util.js';

/** Why a session ended, in words. */
export function ended(e) {
  switch (e.why) {
    case 'left': return 'it left or went out of range';
    case 'roamed': return `it roamed to ${e.to}`;
    case 'kicked': return `kicked by ${e.by || 'an operator'}`;
    case 'blocked': return `blocked by ${e.by || 'an operator'}`;
    case 'eap-failed': return 'its sign-in failed';
    case 'eap-timeout': return 'its sign-in timed out';
    case 'inactive': return 'it had gone silent';
    case 'unobserved': return 'unseen (AP or controller offline)';
    default: return e.why || '';
  }
}

/** A time to the minute, with its day unless it is today. */
export function when(ms) {
  return dayOf(ms) === 'Today' ? hm(ms) : `${dayOf(ms)}, ${hm(ms)}`;
}

/** How a sign-in went: its method and, over EAP, as whom, or whom it only
 * claims to be until its AP authorizes it. */
function signIn(e) {
  if (!e.method) return '';
  if (!e.identity) return e.method;
  return e.authorized === false ? `${e.method}, claiming ${e.identity}` : `${e.method} as ${e.identity}`;
}

/** What an EAP timeout means. */
export function timedOut(server) {
  return server ? 'RADIUS did not answer' : 'the client stopped answering';
}

/** A client certificate's expiry, in words and in tone. */
export function certificate(ms) {
  const left = (ms - Date.now()) / 1000;
  if (left <= 0) return { text: `expired ${duration(-left)} ago`, tone: 'bad' };
  return { text: `expires in ${duration(left)}`, tone: left < 30 * 86400 ? 'warn' : '' };
}

/** One timeline entry: its words and its tone. */
function words(e) {
  const where = [e.ssid, e.band ? bandName(e.band) : null].filter(Boolean).join(', ');
  switch (e.kind) {
    case 'joined': {
      const how = signIn(e);
      return { tone: 'ok', text: [`Joined ${where}`, how ? h('span', { class: 'muted' }, ` · ${how}`) : null, e.vlan ? h('span', { class: 'muted' }, ` · VLAN ${e.vlan}`) : null] };
    }
    case 'roamed': {
      const from = `${e.from}${e.from_band ? ` (${bandName(e.from_band)})` : ''}`;
      const how = e.ft ? 'by fast transition (802.11r)' : e.method ? 'signing in again' : '';
      const gap = e.gap === undefined ? 'without a gap'
        : `${e.gap < 1000 ? `${e.gap} ms` : duration(e.gap / 1000)} without a connection`;
      const by = e.steered_by ? `, steered by ${e.steered_by}` : '';
      return { tone: 'ok', text: [`Roamed from ${from} to ${where}`, h('span', { class: 'muted' }, ` · ${[how, gap].filter(Boolean).join(', ')}${by}`)] };
    }
    case 'ended':
      return { tone: e.why === 'kicked' || e.why === 'blocked' || e.why.startsWith('eap') ? 'bad' : '', text: [`Disconnected after ${duration(e.secs)}`, h('span', { class: 'muted' }, ` · ${ended(e)}`)] };
    case 'eap':
      switch (e.step) {
        case 'started': return { tone: '', text: ['Started signing in (EAP)'] };
        case 'succeeded': return { tone: 'ok', text: ['Signed in', e.ms === undefined ? null : h('span', { class: 'muted' }, ` · in ${(e.ms / 1000).toFixed(1)} s`)] };
        case 'failed': return { tone: 'bad', text: ['Sign-in rejected'] };
        default: return { tone: e.server ? 'bad' : 'warn', text: [`Sign-in timed out: ${timedOut(e.server)}`] };
      }
    case 'psk-mismatch':
      return { tone: 'bad', text: ['Wrong passphrase'] };
    case 'radius': {
      const node = e.node ? ` (${e.node})` : '';
      if (!e.accept) return { tone: 'bad', text: [`RADIUS${node} rejected a sign-in claiming ${e.user}: ${e.detail}`] };
      const cert = e.cert_expires ? certificate(e.cert_expires) : null;
      const its = cert ? `, certificate ${e.cert_cn} ${cert.text}` : '';
      return { tone: 'ok', text: [`RADIUS${node} accepted ${e.user}`, h('span', { class: 'muted' }, ` · ${e.detail}${its}`)] };
    }
    case 'lease':
      return { tone: '', text: [`DHCP ${e.renewed ? 'renewed' : 'leased'} `, h('span', { class: 'mono' }, e.ip), h('span', { class: 'muted' }, ` · until ${when(e.expires)}`)] };
    case 'first-traffic':
      return { tone: 'ok', text: [`First traffic: ${e.conns} connection${e.conns === 1 ? '' : 's'}`] };
    case 'action': {
      // These say what came of them: the VLANs or the kick, what Home
      // Assistant was told, the speeds.
      if (['vlan', 'presence', 'speedtest'].includes(e.action)) {
        return { tone: e.ok ? '' : 'bad', text: [`${actor(e)} ${DID[e.action]} it`, h('span', { class: 'muted' }, ` · ${e.detail}`)] };
      }
      const result = e.ok ? '' : `: failed, ${e.detail || 'no reason given'}`;
      return { tone: e.ok ? '' : 'bad', text: [`${actor(e)} ${DID[e.action] || e.action} it${result}`] };
    }
    case 'guard': {
      const more = e.repeats ? ` (+${e.repeats} since last report)` : '';
      return { tone: 'bad', text: [`Broke the ${GUARDS[e.guard] || e.guard}: ${e.detail}${more}.${e.dropped ? ' Dropped.' : ''}`] };
    }
    case 'service': {
      const w = serviceWords(e);
      return { tone: w.tone, text: [`${w.text[0].toUpperCase()}${w.text.slice(1)}`] };
    }
    case 'sleep-proxy': {
      const proxy = e.proxy_name || e.proxy;
      const owner = e.owner_name || e.owner;
      return e.answering
        ? { tone: '', text: [`${proxy} is sleep proxy for ${owner}`, h('span', { class: 'muted' }, ` · ${e.ip}, allowed`)] }
        : { tone: 'warn', text: [`${proxy} stopped being sleep proxy for ${owner}`, h('span', { class: 'muted' }, ` · ${e.ip} flagged again`)] };
    }
    default:
      return { tone: '', text: [e.kind] };
  }
}

/** The timeline `list` (newest first) as the feed's list items, a day
 * heading where the date changes. */
export function timelineItems(list) {
  const out = [];
  let lastDay = '';
  for (const e of list) {
    const d = dayOf(e.at);
    if (d !== lastDay) {
      out.push(h('li', { class: 'day' }, d));
      lastDay = d;
    }
    const w = words(e);
    out.push(h('li', { class: w.tone || null },
      h('time', { datetime: new Date(e.at).toISOString(), title: new Date(e.at).toLocaleString() }, time(e.at)),
      h('span', { class: 'ap-name' }, e.ap || (e.kind === 'radius' ? 'RADIUS' : e.kind === 'lease' ? 'DHCP' : '–')),
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      h('span', { class: 'what' }, w.text)));
  }
  return out;
}

/** The sessions (newest first) as a table, the columns that matter least
 * left out on narrower screens. */
export function sessionsTable(list) {
  const columns = [
    ['Start', '', (s) => [when(s.start), s.from ? h('small', {}, `roamed in from ${s.from}`) : null]],
    ['Duration', 'num', (s) => duration(((s.end ?? Date.now()) - s.start) / 1000)],
    ['AP', 'p2', (s) => [s.ap, h('small', {}, s.bss)]],
    ['SSID', 'p3', (s) => [s.ssid, s.band ? h('small', {}, bandName(s.band)) : null]],
    ['VLAN', 'num p3', (s) => String(s.vlan || '–')],
    ['Signed in', 'p2', (s) => [s.auth?.method || '–', s.auth?.identity
      ? h('small', {}, s.auth.authenticated ? s.auth.identity : `${s.auth.identity}, claimed only`) : null]],
    ['Down / up', 'num p3', (s) => [bytes(s.tx_bytes), h('small', {}, bytes(s.rx_bytes))]],
    ['Ended', 'wrap', (s) => (s.end === undefined ? h('span', { class: 'chip ok' }, 'Connected') : ended(s))],
  ];
  const cls = (c) => c.replace('wrap', '').trim() || null;
  return h('table', { class: 'sessions' },
    h('thead', {}, h('tr', {}, columns.map(([t, c]) => h('th', { class: cls(c) }, h('span', {}, t))))),
    h('tbody', {}, list.map((s) => h('tr', {}, columns.map(([, c, cell]) => h('td', { class: c || null }, cell(s)))))));
}
