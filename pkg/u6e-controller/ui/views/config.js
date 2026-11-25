// Config: the SSIDs' rate limits (`tools`), and per AP, the Wi-Fi
// configuration it runs against the latest one
// signed for it and the one sent last (by hash: the controller never holds
// their text for the UI), how the last one went, and its image: what it
// runs, the images kept for it, the Upgrade to its newest, and the rollout
// under way or the last one, step by step until it is done or rolled back.

import { h, ago, ask, bandName, hm, icon } from '../util.js';
import { ssidLimitsPanel } from './tools.js';

const ADMIN_GROUP = 'wifi-admins';
const UP = 'M12 19V5M5 12l7-7 7 7';
const LOCK = 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4';

/** A configuration's hash, short, with the whole one to hover. */
function hash(h64) {
  return h('code', { title: h64 }, h64.slice(0, 12));
}

function fact(label, ...value) {
  return h('div', {}, h('dt', {}, label), h('dd', {}, ...value));
}

/** A signed configuration: its hash and when it was signed. */
function signed(c) {
  return [hash(c.sha256), ' ', h('small', {}, `signed ${ago(c.seq)}`)];
}

const MECHANISM = {
  unchanged: 'unchanged', 'in place': 'set in place', 'channel switch': 'channel switch',
  power: 'power set', restart: 'Wi-Fi restarted',
};

function configPanel(c) {
  const title = h('h3', {}, 'Wi-Fi configuration');
  if (!c.installed && !c.latest && !c.last) {
    return h('div', {}, h('div', { class: 'cfg-head' }, title),
      h('p', { class: 'muted' }, 'None sent or installed yet'));
  }
  const drift = c.drift === undefined || !c.installed ? null
    : c.drift
      ? h('span', { class: 'chip bad', title: 'Re-signed when it is back, its clock is synced or its rollout ends' }, 'Not on the latest')
      : h('span', { class: 'chip ok' }, 'On the latest');
  const facts = h('dl', { class: 'facts' },
    fact('Installed', c.installed ? hash(c.installed) : h('span', { class: 'muted' }, 'not reported')),
    c.latest ? fact('Latest signed', ...signed(c.latest)) : null,
    c.wanted ? fact('Sent last', ...signed(c.wanted)) : null,
    c.acked ? fact('Acknowledged', ...signed(c.acked)) : null);
  let last = null;
  if (c.last) {
    const how = (c.last.radios || []).map((r) => `${bandName(r.band)} ${MECHANISM[r.mechanism] || r.mechanism}`).join(', ');
    last = h('p', { class: 'result', role: 'status', 'data-tone': c.last.ok ? 'ok' : 'bad' },
      h('span', {}, `Last sent ${ago(c.last.at)}: `, hash(c.last.sha256), ` ${c.last.ok ? 'applied' : 'not applied'}${how ? ` (${how})` : ''}. ${c.last.detail || ''}`));
  }
  return h('div', {}, h('div', { class: 'cfg-head' }, title, drift), facts, last);
}

/** What a rollout's step says. */
function step(r) {
  const p = r.phase || {};
  switch (p.step) {
    case 'checking': return 'Checking images against manifests';
    case 'staging': return `Staging ${r.image} (reboots twice)`;
    case 'gate': return `Health gate until ${hm(p.deadline)}: image, radios, clients back`;
    case 'rolling_back': return `Rolling back to ${r.previous}: ${p.why}`;
    default: return p.step || '';
  }
}

const OUTCOME = {
  done: ['ok', 'Done'],
  rolled_back: ['bad', 'Rolled back'],
  failed: ['bad', 'Failed'],
  refused: ['bad', 'Refused'],
};

function rolloutPanel(r) {
  const open = !r.result;
  const [tone, word] = open ? ['wait', 'Under way'] : OUTCOME[r.result.outcome] || ['bad', r.result.outcome];
  const text = open ? step(r) : r.result.detail;
  const log = r.log?.length ? h('details', { class: 'manifest' }, h('summary', {}, `Log (${r.log.length} lines)`), h('pre', {}, r.log.join('\n'))) : null;
  return h('div', { class: 'rollout' },
    h('p', { class: 'result', role: 'status', 'data-tone': tone },
      h('span', {}, h('b', {}, `${word}: `), `${r.image}, asked by ${r.user} ${ago(r.at)}. ${text}`)),
    log);
}

function imagePanel(store, name, all, rollouts) {
  const imgs = all[name] || {};
  const kept = imgs.kept || [];
  // A hold on any AP holds every rollout: one AP down at a time.
  const held = Object.entries(all).find(([, i]) => i.held);
  const newest = kept[kept.length - 1];
  const mine = rollouts.filter((r) => r.ap === name).sort((a, b) => b.id - a.id);
  const busy = rollouts.find((r) => !r.result);
  const admin = !!store.me?.admin;
  let action;
  if (!store.me) action = null;
  else if (!admin) {
    action = h('p', { class: 'lock' }, icon(LOCK), h('span', {}, 'Upgrading needs ', h('b', {}, ADMIN_GROUP), '.'));
  } else {
    const why = !newest ? 'No image is kept for it.'
      : newest === imgs.running ? 'It runs its newest kept image.'
        : busy ? `Rollout of ${busy.image} to ${busy.ap} in progress`
          : held ? `${held[0]} is held until ${hm(held[1].held.until)}: ${held[1].held.reason}.`
          : !imgs.running ? 'Running image unknown, so no rollback possible'
            : null;
    const btn = h('button', { type: 'button', class: 'btn primary', disabled: !!why }, icon(UP), h('span', {}, newest ? `Upgrade to ${newest}` : 'Upgrade'));
    btn.addEventListener('click', async () => {
      const yes = await ask(document.body, {
        title: `Upgrade ${name}?`,
        text: `${name} reboots twice, Wi-Fi down a few minutes. Clients roam to another AP. If unhealthy, it rolls back to ${imgs.running}.`,
        confirm: 'Upgrade',
      });
      if (!yes) return;
      btn.disabled = true;
      const res = await store.upgrade(name, newest);
      if (res.status !== 202) await ask(document.body, { title: 'Not upgraded', text: res.error || 'Controller unreachable.', confirm: 'OK' });
    });
    action = h('div', { class: 'cfg-action' }, btn, why ? h('small', { class: 'muted' }, why) : null);
  }
  const facts = h('dl', { class: 'facts' },
    fact('Runs', imgs.running || h('span', { class: 'muted' }, 'not known')),
    imgs.either ? fact('Or', imgs.either, ' ', h('small', {}, 'rollout failed part way')) : null,
    fact('Kept', kept.length ? h('span', { class: 'kept' }, kept.map((id) => h('code', { class: id === newest ? 'newest' : '' }, id))) : h('span', { class: 'muted' }, 'none')));
  return h('div', {}, h('div', { class: 'cfg-head' }, h('h3', {}, 'Image')), facts, action, mine[0] ? rolloutPanel(mine[0]) : null);
}

function apPanel(store, name, ap) {
  const s = store.state;
  const manage = s.manage || {};
  const parts = [h('div', { class: 'ap-top' }, h('h2', {}, name),
    h('span', { class: `state ${ap.up ? 'ok' : 'bad'}` }, ap.up ? 'Connected' : 'Offline'))];
  if (manage.configs) parts.push(configPanel(s.config?.[name] || {}));
  if (manage.images) parts.push(imagePanel(store, name, manage.images, Object.values(s.rollouts || {})));
  return h('section', { class: 'panel ap cfg' }, ...parts);
}

export default {
  mount(root, store) {
    const sub = h('p');
    const limits = ssidLimitsPanel(store);
    const list = h('div');
    root.append(h('div', { class: 'head' }, h('h1', {}, 'Config'), sub), limits.el, list);
    return {
      update() {
        limits.el.hidden = !store.keyed;
        if (!store.keyed) {
          const [title, text] = store.waiting();
          list.replaceChildren(h('div', { class: 'panel empty' }, h('strong', {}, title), text ? h('p', {}, text) : null));
          return;
        }
        limits.update();
        const manage = store.state.manage || {};
        sub.textContent = [manage.configs ? 'live configurations signed here' : 'live configurations off',
          manage.images ? 'images rolled out here' : 'rollouts off'].join(', ');
        if (!manage.configs && !manage.images) {
          list.replaceChildren(h('div', { class: 'panel empty' }, h('strong', {}, 'Nothing is managed here'),
            h('p', {}, 'Needs [configs] and [rollouts] in the controller config.')));
          return;
        }
        const aps = Object.entries(store.state.aps).sort(([a], [b]) => a.localeCompare(b));
        list.replaceChildren(...aps.map(([name, ap]) => apPanel(store, name, ap)));
      },
    };
  },
};
