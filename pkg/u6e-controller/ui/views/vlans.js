// RADIUS's MAC authentication mapping (`state.mac_auth`): which VLAN each
// device is put in when it joins one of the MAC-authenticated SSIDs with the
// shared passphrase. The VLANs page lists every entry by VLAN with the device
// as the controller knows it, whether it is on now and where, and the kick
// pending for one just moved; a client's page shows its own entry (the panel
// `vlanPanel`). An admin sets, changes or removes an entry, or adds a device
// by its MAC, from one dialog that says what the change will do before it is
// confirmed; the controller writes it to OpenBao, every RADIUS server takes
// it within a minute, and a device moved while it is on one of those SSIDs
// is disconnected once to join again on its new VLAN.

import { h, ago, ask, hm, icon } from '../util.js';

const ADMIN_GROUP = 'wifi-admins';
const LOCK = 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4';
const OK = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M8 12l3 3 5-6';
const BAD = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16.5v.01';
const TAG = 'M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8zM7.5 7.5h.01';

/** A VLAN with its group's name: "VLAN 43 (iot)". */
export function vlanName(ma, id) {
  const g = ma?.vlans?.find((v) => v.id === id)?.group;
  return g ? `VLAN ${id} (${g})` : `VLAN ${id}`;
}

/** The MAC-authenticated SSIDs, in words. */
function ssidWords(ma) {
  const s = ma?.ssids || [];
  return s.length > 1 ? `${s.slice(0, -1).join(', ')} and ${s.at(-1)}` : s[0] || 'the MAC-authenticated SSIDs';
}

/** They refuse a device with no entry: "ssid-b refuses it". */
function refuse(ma) {
  return `${ssidWords(ma)} ${ma?.ssids?.length === 1 ? 'refuses' : 'refuse'} it`;
}

/** A MAC as the controller's API spells it, from any of RADIUS's; null
 * for anything else. */
export function macOf(s) {
  const t = s.trim().toLowerCase();
  const digits = /^[0-9a-f]{12}$/.test(t) ? t
    : /^([0-9a-f]{2})([:-])([0-9a-f]{2}\2){4}[0-9a-f]{2}$/.test(t) ? t.replace(/[:-]/g, '') : null;
  if (!digits || parseInt(digits.slice(0, 2), 16) & 1 || digits === '000000000000') return null;
  return digits.match(/../g).join(':');
}

/** What setting `mac`'s entry to `to` (a VLAN, or null for none) does, in
 * words; `entry` is its entry now and `client` the client if it is on. */
export function effect(ma, who, entry, client, to) {
  const from = entry?.vlan;
  const ssids = ssidWords(ma);
  const onMab = client && ma.ssids.includes(client.ssid);
  if (to === null) {
    return `${who} loses its entry, and ${refuse(ma)} from its next join on.${onMab ? ` It stays on ${client.ssid} until it leaves.` : ''}`;
  }
  if (from === undefined) {
    return `${who} gets an entry on ${vlanName(ma, to)}: it can then join ${ssids} with the shared passphrase, and is put on VLAN ${to}. Every RADIUS server has it within a minute.`;
  }
  if (from === to) return `${who} stays on ${vlanName(ma, to)}; only its description changes.`;
  const kick = onMab
    ? ` ${who} is then disconnected once from ${client.ssid} on ${client.ap}, in about ${ma.settle_secs} s, to join again on VLAN ${to}.`
    : ` It is not on ${ma.ssids.length === 1 ? ssids : `any of ${ssids}`} now, so nothing disconnects it: it is put on VLAN ${to} when it next joins.`;
  return `${who} moves from ${vlanName(ma, from)} to ${vlanName(ma, to)}. Every RADIUS server has the change within a minute.${kick}`;
}

/** What the controller answered, in words: [tone, text]. */
export function vlanOutcome(res, who) {
  const no = `${who}'s entry not changed`;
  switch (res.status) {
    case 0: return ['bad', `${no}: the controller could not be reached.`];
    case 400: return ['bad', `${no}: ${res.error}.`];
    case 403: return ['bad', res.error === 'not an admin'
      ? `${no}: your account is not in ${ADMIN_GROUP}.`
      : `${no}: the controller took the request for a cross-site one. Reload the page and try again.`];
    case 404: return ['bad', `${no}: the controller does not edit the mapping.`];
    case 409: return ['bad', `${no}: ${res.detail}. It shows here as it is now; look again before changing it.`];
    case 502: return ['bad', `${no}: ${res.detail}. RADIUS goes on with the mapping as it was.`];
    default: break;
  }
  if (res.result === 'unchanged') return ['ok', `Nothing to change: ${who}'s entry is already so.`];
  if (!res.ok) return ['bad', `${no}: ${res.detail || 'no reason given'}.`];
  const kick = res.kick?.startsWith('once') ? ` It is disconnected ${res.kick}.` : '';
  return ['ok', `Written: ${res.detail}.${kick}`];
}

/** The choices of the dialog: each VLAN the site allows, none when there is
 * an entry, and the description; picking one says what it does in `say`
 * and names it on the confirm button `ok`. */
function choices(ma, who, entry, client, name, ok) {
  const say = h('p', { class: 'vlan-effect', role: 'status' });
  const desc = h('input', {
    type: 'text', name: 'vlan-description', maxlength: '64', 'aria-label': 'Description',
    placeholder: name || 'what the device is', value: entry?.description ?? (name || undefined),
  });
  const pickable = [...ma.vlans.map((v) => v.id), ...(entry ? [null] : [])];
  const list = pickable.map((id) => {
    const input = h('input', { type: 'radio', name: 'vlan-to', value: id === null ? '' : String(id), checked: id === (entry?.vlan ?? null) });
    const show = () => {
      ok.disabled = id === (entry?.vlan ?? null) && desc.value.trim() === (entry?.description ?? '');
      ok.textContent = id === null ? 'Remove entry' : entry ? `Set VLAN ${id}` : `Add on VLAN ${id}`;
      ok.className = `btn ${id === null ? 'danger' : 'primary'}`;
      say.textContent = effect(ma, who, entry, client, id);
    };
    input.addEventListener('change', show);
    desc.addEventListener('input', () => input.checked && show());
    if (input.checked) queueMicrotask(show);
    const group = id === null ? null : ma.vlans.find((v) => v.id === id)?.group;
    return h('label', { class: 'choice' }, input,
      h('span', { class: 'choice-main' },
        h('b', {}, id === null ? 'No entry' : `VLAN ${id}`),
        h('small', {}, id === null ? refuse(ma) : group ? `group ${group}` : 'a group of its own is made')),
      id === (entry?.vlan ?? null) && entry ? h('span', { class: 'choice-side' }, 'now') : null);
  });
  if (!entry) {
    ok.disabled = true;
    ok.textContent = 'Pick a VLAN';
  }
  return h('div', {},
    h('fieldset', { class: 'choices' }, h('legend', {}, 'VLAN'), list),
    h('label', { class: 'field vlan-desc' }, h('span', {}, 'Description'), desc),
    say);
}

/** Asks the admin what `mac`'s entry is to be, then writes it: the answer
 * in words, or null when the admin cancelled. */
export async function editEntry(store, root, mac, name) {
  const ma = store.state.mac_auth;
  const entry = ma.entries[mac];
  const client = store.state.clients[mac];
  const who = name || entry?.description || mac;
  const picked = await ask(root, {
    title: entry ? `The VLAN of ${who}` : `Add ${who}`,
    text: `RADIUS's MAC authentication puts it on this VLAN when it joins ${ssidWords(ma)}.`,
    choices: (ok) => choices(ma, who, entry, client, name, ok),
    confirm: 'Set',
    pick: (dlg) => {
      const to = dlg.querySelector('input[name=vlan-to]:checked');
      if (!to) return null;
      const description = dlg.querySelector('input[name=vlan-description]').value.trim();
      return { vlan: to.value === '' ? null : Number(to.value), description };
    },
  });
  if (!picked) return null;
  const res = await store.setVlan(mac, { ...picked, expect: entry?.vlan ?? null });
  return vlanOutcome(res, who);
}

function resultLine(el, [tone, text]) {
  el.dataset.tone = tone;
  el.replaceChildren(icon(tone === 'ok' ? OK : BAD), h('span', {}, text, h('time', { class: 'muted' }, ` ${hm(Date.now())}`)));
  el.hidden = false;
}

function lockNote(store) {
  return h('p', { class: 'lock' }, icon(LOCK), h('span', {}, store.me ? 'Viewing only: changing it needs membership of ' : 'Changing it needs membership of ', h('b', {}, ADMIN_GROUP), '.'));
}

/** The kick pending for a device just moved, in words. */
function followWords(f) {
  if (!f) return null;
  if (f.kicked) return h('span', { class: 'chip wait' }, `Kicked at ${hm(f.kick_at)}, rejoining on VLAN ${f.to}`);
  const s = Math.max(0, Math.round((f.kick_at - Date.now()) / 1000));
  return h('span', { class: 'chip wait' }, `Kicked in ${s} s, to rejoin on VLAN ${f.to}`);
}

/** Where the client is now, against its entry. */
function nowWords(ma, entry, c) {
  if (!c) return h('span', { class: 'muted' }, 'not on the Wi-Fi');
  const onMab = ma.ssids.includes(c.ssid);
  const off = onMab && entry && c.vlan !== entry.vlan;
  return [h('span', { class: `chip${off ? ' warn' : ''}` }, `VLAN ${c.vlan}`), ` ${c.ssid} on ${c.ap}`,
    off ? h('small', {}, ` · on VLAN ${entry.vlan} from its next join`) : null];
}

/** How reading the mapping goes, when not well: a note, else null. */
function readNote(ma) {
  if (ma.error) {
    const last = ma.read_at ? ` It was last read ${ago(ma.read_at)}; what shows is that.` : ' It has not been read since the controller started.';
    return h('p', { class: 'note warn' }, `The mapping cannot be read from OpenBao: ${ma.error}.${last} RADIUS goes on with the mapping it has.`);
  }
  if (ma.unread?.length) {
    return h('p', { class: 'note warn' }, `Not entries, kept as they are: ${ma.unread.join('; ')}.`);
  }
  return null;
}

/** The VLAN panel of client `mac`, on its page: its entry, where it is
 * against it, the kick pending, and an admin's change. */
export function vlanPanel(store, mac, root) {
  const facts = h('dl', { class: 'facts' });
  const note = h('div');
  const change = h('button', { type: 'button', class: 'btn' }, icon(TAG), h('span', {}, 'Change…'));
  const lock = h('div');
  const result = h('p', { class: 'result', role: 'status', hidden: true });
  const el = h('section', { class: 'panel tool' },
    h('div', { class: 'tool-head' }, h('h2', {}, 'VLAN'), h('small', { class: 'muted' }, 'RADIUS’s MAC authentication')),
    note, facts, h('div', { class: 'tool-buttons' }, change), lock, result);
  let busy = false;
  let name = '';
  change.addEventListener('click', async () => {
    if (busy || !store.me?.admin) return;
    busy = true;
    update();
    const out = await editEntry(store, root, mac, name);
    busy = false;
    if (out) resultLine(result, out);
    update();
  });

  function update() {
    const ma = store.state.mac_auth;
    el.hidden = !ma;
    if (!ma) return;
    const c = store.state.clients[mac];
    name = c?.name || name;
    const entry = ma.entries[mac];
    const fact = (label, ...value) => h('div', {}, h('dt', {}, label), h('dd', {}, ...value));
    facts.replaceChildren(...[
      fact('Entry', entry ? h('span', { class: 'chip' }, vlanName(ma, entry.vlan))
        : h('span', { class: 'chip warn' }, 'None'), entry ? null : h('small', {}, ` ${refuse(ma)}`)),
      entry?.description ? fact('Description', entry.description) : null,
      fact('Now', nowWords(ma, entry, c)),
      ma.follows?.[mac] ? fact('Kick', followWords(ma.follows[mac])) : null,
    ].filter(Boolean));
    note.replaceChildren(readNote(ma) || '');
    const admin = !!store.me?.admin;
    change.hidden = !admin;
    change.lastChild.textContent = busy ? 'Writing…' : entry ? 'Change…' : 'Add…';
    change.toggleAttribute('aria-busy', busy);
    change.disabled = busy || ma.version === null;
    lock.replaceChildren(admin ? '' : lockNote(store));
  }
  return { el, update };
}

export default {
  mount(root, store) {
    const sub = h('p');
    const note = h('div');
    const add = h('input', { type: 'text', placeholder: '02:00:00:00:00:01', 'aria-label': 'MAC of the device to add', spellcheck: 'false' });
    const addBtn = h('button', { type: 'button', class: 'btn primary' }, icon(TAG), h('span', {}, 'Add…'));
    const addForm = h('div', { class: 'panel tool vlan-add' },
      h('div', { class: 'tool-head' }, h('h2', {}, 'Add a device'), h('small', { class: 'muted' }, 'by its MAC, as it sends it (its private Wi-Fi address, if it uses one)')),
      h('div', { class: 'tool-form' }, h('label', { class: 'field' }, h('span', {}, 'MAC'), add), h('div', { class: 'tool-buttons' }, addBtn)));
    const lock = h('div');
    const result = h('p', { class: 'result', role: 'status', hidden: true });
    const groups = h('div', { class: 'vlan-groups' });
    const empty = h('div', { class: 'panel empty' });
    root.append(h('div', { class: 'head' }, h('h1', {}, 'VLANs'), sub), note, result, groups, empty, addForm, lock);
    let busy = false;
    let drawn = '';

    async function edit(mac, name) {
      if (busy || !store.me?.admin) return;
      busy = true;
      const out = await editEntry(store, root, mac, name);
      busy = false;
      if (out) resultLine(result, out);
      drawn = '';
      view.update();
    }

    addBtn.addEventListener('click', () => {
      const mac = macOf(add.value);
      if (!mac) {
        resultLine(result, ['bad', 'That is no device’s MAC: six pairs of hex digits, with colons, hyphens or nothing between them.']);
        return;
      }
      const ma = store.state.mac_auth;
      if (ma.entries[mac]) {
        resultLine(result, ['bad', `${mac} has an entry already, on ${vlanName(ma, ma.entries[mac].vlan)}: change it below.`]);
        return;
      }
      edit(mac, store.state.clients[mac]?.name || '');
    });

    function row(ma, mac, e) {
      const c = store.state.clients[mac];
      const who = c?.name || '';
      const admin = !!store.me?.admin;
      return h('tr', {},
        h('td', { class: 'v-who' }, h('a', { class: who ? null : 'mono', href: `#/client/${mac}` }, who || mac), who ? h('small', { class: 'mono' }, mac) : null),
        h('td', { class: 'v-desc' }, e.description || h('span', { class: 'muted' }, '–')),
        h('td', { class: 'v-now' }, nowWords(ma, e, c), ma.follows?.[mac] ? [' ', followWords(ma.follows[mac])] : null),
        admin ? h('td', { class: 'v-act' }, h('button', { type: 'button', class: 'btn quiet', onclick: () => edit(mac, who) }, 'Change…')) : null);
    }

    const view = {
      update() {
        const ma = store.state.mac_auth;
        const admin = !!store.me?.admin;
        addForm.hidden = !ma || !admin;
        lock.replaceChildren(ma && !admin ? lockNote(store) : '');
        if (!ma) {
          sub.textContent = '';
          note.replaceChildren();
          groups.replaceChildren();
          empty.hidden = false;
          const [title, text] = !store.keyed ? store.waiting()
            : ['The controller does not edit the mapping', 'It has no [mac_auth] section: which VLAN a MAC-authenticated device is put in is set where RADIUS reads it.'];
          empty.replaceChildren(h('strong', {}, title), h('p', {}, text));
          return;
        }
        const entries = Object.entries(ma.entries || {});
        sub.textContent = `RADIUS puts each device below on its VLAN when it joins ${ssidWords(ma)} with the shared passphrase; a device that is not listed cannot join them.${ma.version ? ` Mapping version ${ma.version}${ma.read_at ? `, read ${ago(ma.read_at)}` : ''}.` : ''}`;
        note.replaceChildren(readNote(ma) || '');
        // Drawn again when the mapping, the clients' places or the pending
        // kicks change, and every second while a kick counts down.
        const stamp = JSON.stringify([ma.version, ma.entries, ma.follows, admin,
          entries.map(([m]) => { const c = store.state.clients[m]; return c && [c.name, c.ssid, c.ap, c.vlan]; }),
          Object.keys(ma.follows || {}).length ? Math.floor(Date.now() / 1000) : 0]);
        // Never read: no VLAN can be said to be empty.
        const unread = ma.version === null;
        empty.hidden = !!entries.length;
        if (!entries.length) {
          empty.replaceChildren(h('strong', {}, unread ? (ma.error ? 'The mapping is not read yet' : 'Reading the mapping') : 'No device has an entry'),
            h('p', {}, unread ? 'The controller reads it from OpenBao every minute.' : `No device can join ${ssidWords(ma)} until it has one.`));
        }
        if (stamp === drawn) return;
        drawn = stamp;
        if (unread) {
          groups.replaceChildren();
          return;
        }
        const vlans = [...new Set([...ma.vlans.map((v) => v.id), ...entries.map(([, e]) => e.vlan)])].sort((a, b) => a - b);
        groups.replaceChildren(...vlans.map((id) => {
          const mine = entries.filter(([, e]) => e.vlan === id)
            .sort(([a, x], [b, y]) => (store.state.clients[a]?.name || x.description || a).localeCompare(store.state.clients[b]?.name || y.description || b));
          const allowed = ma.vlans.some((v) => v.id === id);
          const head = ['Device', 'Description', 'Now', ...(admin ? [''] : [])];
          return h('section', { class: 'vlan-group' },
            h('h2', { class: 'section-title' }, vlanName(ma, id), h('span', { class: 'muted' }, ` · ${mine.length} device${mine.length === 1 ? '' : 's'}`),
              allowed ? null : h('span', { class: 'chip warn' }, 'not one the site lets admins choose')),
            mine.length
              ? h('div', { class: 'panel table-wrap' }, h('table', { class: 'vlans' },
                h('thead', {}, h('tr', {}, head.map((t) => h('th', {}, h('span', {}, t))))),
                h('tbody', {}, mine.map(([m, e]) => row(ma, m, e)))))
              : h('p', { class: 'muted' }, 'No device on it.'));
        }));
      },
    };
    return view;
  },
};
