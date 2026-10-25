// One client: where it is, its readings now, the actions an admin can take on
// it, its largest connections, its signal, rates and traffic over the session
// as this page has seen it, and its event history.

import { h, icon, bandName, bits, bytes, DID, duration, hm, mbps, palette, pct, phy, quality, time } from '../util.js';
import { lineChart } from '../charts.js';
import { feed } from './events.js';
import { clientFlows, flowTable, offload, redraw, sampled, tick, topRows } from './flows.js';

const ADMIN_GROUP = 'wifi-admins';

const ICONS = {
  kick: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  block: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M5.6 5.6l12.8 12.8',
  unblock: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M8 12l3 3 5-6',
  steer: 'M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4',
};
const LABELS = { kick: 'Kick', block: 'Block', unblock: 'Unblock', steer: 'Steer' };
const DOING = { kick: 'Kicking', block: 'Blocking', unblock: 'Unblocking', steer: 'Steering' };

/** Replaces the children of `el` with those of `kids` that are there. */
function fill(el, ...kids) {
  el.replaceChildren(...kids.filter((k) => k !== null && k !== undefined));
}

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

/** The other BSSs of the client's SSID it could be steered to, on every
 * connected AP. */
function targets(store, c) {
  const out = [];
  for (const [name, ap] of Object.entries(store.state.aps)) {
    if (!ap.up) continue;
    for (const [ifname, b] of Object.entries(ap.bsss || {})) {
      if (b.ssid !== c.ssid || (name === c.ap && ifname === c.bss)) continue;
      const r = ap.radios?.[b.phy];
      out.push({ ap: name, ifname, bssid: b.bssid, band: r?.band, channel: r?.channel, width: r?.width, up: r?.up !== false, clients: b.clients });
    }
  }
  return out.sort((a, b) => a.ap.localeCompare(b.ap) || Number(a.band) - Number(b.band));
}

/** A modal question: resolves to what `pick` makes of the dialog (true
 * without one), or null when cancelled. `choices`, given the confirm button,
 * builds what there is to pick from. */
function ask(root, { title, text, choices, confirm, danger, pick }) {
  return new Promise((resolve) => {
    const ok = h('button', { type: 'button', class: `btn ${danger ? 'danger' : 'primary'}` }, confirm);
    const cancel = h('button', { type: 'button', class: 'btn', autofocus: !choices }, 'Cancel');
    const dlg = h('dialog', { class: 'ask', 'aria-labelledby': 'ask-title' },
      h('h2', { id: 'ask-title' }, title), h('p', {}, text), choices?.(ok),
      h('div', { class: 'ask-buttons' }, cancel, ok));
    let answer = null;
    ok.addEventListener('click', () => {
      answer = pick ? pick(dlg) : true;
      dlg.close();
    });
    cancel.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => {
      dlg.remove();
      resolve(answer);
    });
    root.append(dlg);
    dlg.showModal();
  });
}

/** The steer picker: one choice per BSS, with its band, channel and AP;
 * picking one names it on the confirm button `ok`, disabled until then. */
function steerChoices(list, c, ok) {
  ok.disabled = true;
  return h('fieldset', { class: 'choices' },
    h('legend', {}, `BSSs of ${c.ssid}`),
    list.map((t, i) => {
      const input = h('input', { type: 'radio', name: 'steer-target', value: t.bssid, disabled: !t.up, autofocus: i === list.findIndex((x) => x.up) });
      input.addEventListener('change', () => {
        ok.disabled = false;
        ok.textContent = `Steer to ${t.ap}, ${bandName(t.band)}`;
      });
      return h('label', { class: 'choice' },
        input,
        h('span', { class: 'chip', 'data-band': t.band }, bandName(t.band)),
        h('span', { class: 'choice-main' },
          h('b', {}, t.ap), t.ap === c.ap ? h('span', { class: 'muted' }, ' (this AP)') : null,
          h('small', {}, `channel ${t.channel}, ${t.width} MHz · `, h('span', { class: 'mono' }, t.bssid), ` · ${t.ifname}`)),
        h('span', { class: 'choice-side' }, t.up ? `${t.clients} client${t.clients === 1 ? '' : 's'}` : h('span', { class: 'q-poor' }, 'radio down')));
    }));
}

/** What came of an action, in words: [tone, text]. */
function outcome(action, res, who, target) {
  const no = `Not ${DID[action]}`;
  const ap = res.ap || 'the AP';
  const why = (detail) => {
    if (/not associated/i.test(detail)) return `${who} was no longer on ${ap} when the command arrived.`;
    if (action === 'steer' && /unknown|neighbo|not in/i.test(detail)) return `${ap} does not know that BSS (its AP or radio may have gone down). Pick another.`;
    return detail;
  };
  switch (res.status) {
    case 0: return ['bad', `${no}: the controller could not be reached.`];
    case 403: return ['bad', res.error === 'not an admin'
      ? `${no}: your account is not in ${ADMIN_GROUP}.`
      : `${no}: the controller took the request for a cross-site one. Reload the page and try again.`];
    case 404: return ['bad', `${no}: ${who} is not associated with any access point.`];
    case 504: return ['bad', `${no}: ${ap} did not answer within 5 s. It may still have acted; its events will show.`];
    case 502: return ['bad', `${no}: ${ap} is not connected.`];
    default: break;
  }
  if (Array.isArray(res.results)) {
    const failed = res.results.filter((r) => !r.ok);
    const done = res.results.filter((r) => r.ok && r.ap).map((r) => r.ap);
    if (!res.results.some((r) => r.ap)) return ['ok', `${DID[action][0].toUpperCase()}${DID[action].slice(1)} ${who}. No access point is connected; each is told as it connects.`];
    const lead = done.length ? `${DID[action][0].toUpperCase()}${DID[action].slice(1)} ${who} on ${done.join(' and ')}.` : `${no}.`;
    const fails = failed.map((r) => (/no answer/i.test(r.detail) ? `${r.ap} did not answer in time` : `${r.ap || 'the controller'}: ${r.detail}`));
    return [failed.length ? 'bad' : 'ok', fails.length ? `${lead} ${fails.join('; ')}.` : lead];
  }
  if (res.status !== 200 && res.error) return ['bad', `${no}: ${res.error}.`];
  if (!res.ok) return ['bad', `${no}: ${why(res.detail || 'no reason given')}`];
  switch (action) {
    case 'kick': return ['ok', `Kicked ${who} off ${ap}. It may rejoin at once; block it to keep it off.`];
    case 'steer': return ['ok', `Asked ${who} to move to ${target}. The client makes the move; this page shows it when it does.`];
    default: return ['ok', `${DID[action][0].toUpperCase()}${DID[action].slice(1)} ${who}.`];
  }
}

export default {
  flows: true,
  mount(root, store, mac) {
    store.loadHistory();
    const title = h('h1');
    const sub = h('div', { class: 'id-sub' });
    const where = h('div', { class: 'where' });
    const buttons = {};
    for (const a of ['steer', 'kick', 'block', 'unblock']) {
      buttons[a] = h('button', { type: 'button', class: `btn${a === 'block' ? ' danger-quiet' : ''}` }, icon(ICONS[a]), h('span', {}, LABELS[a]));
      buttons[a].addEventListener('click', () => run(a));
    }
    const lock = h('p', { class: 'lock', hidden: true }, icon(ICONS.lock), h('span'));
    const actions = h('div', { class: 'actions', role: 'group', 'aria-label': 'Actions' }, Object.values(buttons));
    const result = h('p', { class: 'result', role: 'status', hidden: true });
    const readings = h('dl', { class: 'readings' });
    const absent = h('p', { class: 'absent' });
    const head = h('div', { class: 'panel clip' },
      h('div', { class: 'client-head' },
        h('div', { class: 'ident' }, title, sub), where,
        h('div', { class: 'act' }, actions, lock)),
      result, readings, absent);
    const charts = [chartPanel('Signal'), chartPanel('Rates'), chartPanel('Throughput')];
    const chartsEl = h('div', { class: 'charts' }, charts.map((c) => c.el));
    const flowSub = h('p');
    const flowBox = h('div');
    const flowsEl = h('section', { class: 'client-flows' },
      h('div', { class: 'head section-title' }, h('h2', {}, 'Flows'), flowSub), flowBox);
    const events = h('ol', { class: 'feed panel', reversed: true });
    const noEvents = h('div', { class: 'panel empty' });
    root.append(
      h('a', { class: 'crumb', href: '#/clients' }, icon('M15 18l-6-6 6-6'), 'Clients'),
      head, chartsEl, flowsEl,
      h('h2', { class: 'section-title' }, 'Events'), events, noEvents);
    let drawn = '';
    let flowsDrawn = '';
    /** The action on its way, if any. */
    let busy = '';
    /** The client's name as last seen: one that left keeps it here. */
    let name = '';

    /** Why `action` cannot be taken now, or '' when it can. */
    function barred(action) {
      if (!store.me?.admin) return `Needs membership of ${ADMIN_GROUP}`;
      if (busy) return `${DOING[busy]}…`;
      const c = store.state.clients[mac];
      if ((action === 'kick' || action === 'steer') && !c) return 'Not associated with any access point';
      if (action === 'steer' && !targets(store, c).length) return `No other BSS of ${c.ssid} to move to`;
      return '';
    }

    async function run(action) {
      if (barred(action)) return;
      const c = store.state.clients[mac];
      const who = name || mac;
      let body = {};
      let target = '';
      if (action === 'steer') {
        const list = targets(store, c);
        const bssid = await ask(root, {
          title: `Steer ${who}`,
          text: `Asks it to move off ${c.ap}’s ${bandName(c.band)} BSS to the one picked here (802.11v). The client decides; one that does not support it stays.`,
          choices: (ok) => steerChoices(list, c, ok), confirm: 'Steer',
          pick: (dlg) => dlg.querySelector('input:checked')?.value ?? null,
        });
        if (!bssid) return;
        const t = list.find((x) => x.bssid === bssid);
        target = `${t.ap}, ${bandName(t.band)} channel ${t.channel}`;
        body = { target_bssid: bssid };
      } else {
        const text = {
          kick: c ? `It is disconnected from ${c.ssid} on ${c.ap}. Most devices rejoin at once; to keep it off, block it.` : '',
          block: 'It is disconnected and every access point refuses it until it is unblocked. The block outlasts restarts of the controller and of the APs.',
          unblock: 'Every access point lets it join again.',
        }[action];
        const yes = await ask(root, { title: `${LABELS[action]} ${who}?`, text, confirm: LABELS[action], danger: action === 'block' });
        if (!yes) return;
      }
      busy = action;
      result.hidden = true;
      view.update();
      const res = await store.act(mac, action, body);
      busy = '';
      const [tone, text] = outcome(action, res, who, target);
      result.dataset.tone = tone;
      result.replaceChildren(icon(tone === 'ok' ? ICONS.unblock : 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16.5v.01'),
        h('span', {}, text, h('time', { class: 'muted' }, ` ${time(Date.now())}`)));
      result.hidden = false;
      view.update();
      // The button pressed keeps the focus, even when it changed (block to unblock).
      const next = action === 'block' && tone === 'ok' ? 'unblock' : action === 'unblock' && tone === 'ok' ? 'block' : action;
      if (document.activeElement === document.body) buttons[next].focus();
    }

    function updateHead(c) {
      // The policy's list holds the clients no AP lets on, too.
      const blocked = (store.state.blocked || []).includes(mac);
      name = c?.name || clientFlows(store, mac)?.cf.name || name;
      title.textContent = name || mac;
      title.className = name ? '' : 'mono';
      fill(sub, name ? h('span', { class: 'mono' }, mac) : null,
        blocked ? h('span', { class: 'chip bad' }, 'Blocked') : null);
      sub.hidden = !sub.childNodes.length;
      buttons.block.hidden = blocked;
      buttons.unblock.hidden = !blocked;
      for (const [a, b] of Object.entries(buttons)) {
        const why = barred(a);
        b.setAttribute('aria-disabled', String(!!why));
        b.title = why;
        b.toggleAttribute('aria-busy', busy === a);
        b.lastChild.textContent = busy === a ? `${DOING[a]}…` : LABELS[a];
      }
      lock.hidden = !!store.me?.admin;
      lock.lastChild.replaceChildren(store.me ? 'Viewing only: actions need membership of ' : 'Actions need membership of ',
        h('b', {}, ADMIN_GROUP), '.');
      if (c) {
        fill(where,
          h('span', { class: 'chip', 'data-band': c.band }, bandName(c.band)),
          h('span', {}, c.ssid),
          c.vlan ? h('span', { class: 'chip' }, `VLAN ${c.vlan}`) : null,
          h('span', {}, `on ${c.ap}, ${c.bss}`),
          h('span', { class: 'muted' }, `connected ${duration(c.connected)}`));
        readings.replaceChildren(
          reading('Signal', `${c.signal} dBm`, `average ${c.signal_avg} dBm`, `q-${quality(c.signal)}`),
          reading('Transmit rate', mbps(c.tx), phy(c.tx)),
          reading('Receive rate', mbps(c.rx), phy(c.rx)),
          reading('Download', c.down === undefined ? '–' : bits(c.down), c.up === undefined ? '' : `upload ${bits(c.up)}`),
          reading('Retries', c.retries === undefined ? '–' : pct(c.retries), 'of frames sent to it'),
          reading('Airtime', c.airtime === undefined ? '–' : pct(c.airtime), 'of the channel’s time'),
          reading('Transferred', bytes(c.tx_bytes), `${bytes(c.rx_bytes)} sent by it`),
          reading('Idle', `${c.idle} s`, 'since it was last heard'));
      } else {
        where.replaceChildren();
        absent.textContent = !store.keyed ? store.waiting()[0]
          : blocked ? 'Blocked: no access point lets it join. Its past events are below.'
            : 'This client is not associated with any AP right now. Its past events are below.';
      }
      readings.hidden = !c;
      absent.hidden = !!c;
    }

    function updateFlows(c) {
      const x = clientFlows(store, mac);
      const stamp = JSON.stringify([x && store.flows[x.ap].stamp, x?.ap, store.flowsKeyed, !!c]);
      flowsEl.hidden = !c && !x;
      if (stamp === flowsDrawn) {
        tick(flowsEl);
        return;
      }
      flowsDrawn = stamp;
      if (!x) {
        flowSub.replaceChildren();
        flowBox.replaceChildren(h('div', { class: 'panel empty' }, h('p', {},
          !store.flowsKeyed ? 'Loading its connections.'
            : 'It has no connection open, or its AP has not reported its connections yet: every AP does every 10 seconds while this page is open.')));
        return;
      }
      const { cf } = x;
      flowSub.replaceChildren(`through ${x.ap}, `, sampled(x.at));
      redraw(flowBox, () => [h('div', { class: 'panel' },
        h('dl', { class: 'readings flow-sum' },
          reading('Connections', String(cf.conns), `${cf.offloaded} offloaded, ${cf.conns - cf.offloaded} through the CPU`),
          reading('Offloaded', offload(cf.conns, cf.offloaded), 'forwarded by the NSS hardware'),
          reading('Down', cf.down === undefined ? '–' : bits(cf.down), `${bytes(cf.rx_bytes)} over these connections`),
          reading('Up', cf.up === undefined ? '–' : bits(cf.up), `${bytes(cf.tx_bytes)} over these connections`)),
        cf.top.length ? h('div', { class: 'table-wrap' }, flowTable(topRows(cf))) : null,
        h('p', { class: 'muted foot' }, cf.top.length < cf.conns
          ? [`The largest ${cf.top.length} of its ${cf.conns} connections. `, h('a', { href: '#/flows' }, `Every connection of ${x.ap}`), ' is on the Flows page.']
          : cf.conns ? `All its ${cf.conns} connections.` : 'No connection is open.'))]);
    }

    const view = {
      update() {
        const c = store.state.clients[mac];
        const p = palette();
        updateHead(c);
        updateFlows(c);
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
              times: s.times, min: 0, format: (v) => bits(v).replace(' ', ' '),
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
    return view;
  },
};
