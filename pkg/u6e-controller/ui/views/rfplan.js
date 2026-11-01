// The RF plan, below the spectrum: for each radio of the site file, the
// channel, width and power the controller proposes from what the last hours
// measured, what it predicts the change does and why. Nothing changes until
// an admin applies chosen proposals, exactly as shown (the controller refuses
// them once the plan changed), which commits them to the site file; the
// next configuration rendered from it takes them to the access points.
// Proposals that free each other's spectrum are chosen together.

import { h, icon, ask, ago, bandName } from '../util.js';

const ADMIN_GROUP = 'wifi-admins';
const LOCK = 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4';
const OK = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M8 12l3 3 5-6';
const BAD = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16.5v.01';
const INFO = 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 11v5M12 7.5v.01';
const REFRESH = 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7';
const COMMIT = 'M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8M3 12h5M16 12h5';
/** How often the plan is asked for again while it is shown. */
const EVERY_MS = 60_000;

/** The planner's reason as a sentence. */
function sentence(text) {
  return text ? `${text[0].toUpperCase()}${text.slice(1)}.` : '';
}

/** A setting's parts, each marked when it differs from `other`'s; `channel`
 * is how the first is spelled. */
function parts(s, other, channel = 'Channel') {
  const part = (text, same) => (same ? h('span', {}, text) : h('mark', {}, text));
  const out = [
    part(`${channel} ${s.channel}`, !other || other.channel === s.channel),
    ' · ',
    part(`${s.width} MHz`, !other || other.width === s.width),
  ];
  if (s.power !== undefined) out.push(' · ', part(`${s.power} dBm`, !other || other.power === s.power));
  return out;
}

function signed(db) {
  return `${db > 0 ? '+' : db < 0 ? '−' : '±'}${Math.abs(db).toFixed(0)} dB`;
}

function effect(label, value, detail) {
  return h('div', {}, h('dt', {}, label), h('dd', {}, value, detail ? h('small', {}, detail) : null));
}

/** From one setting to another: the first quiet, the changes marked. */
function move(from, to) {
  return h('p', { class: 'plan-set' }, h('span', { class: 'was' }, ...parts(from)),
    h('span', { class: 'to', 'aria-label': 'to' }, '→'), h('span', {}, ...parts(to, from)));
}

/** One radio's proposal; `pick` is its checkbox, when it may be chosen, and
 * `others` the keys of its group's others. */
function row(r, pick, others) {
  const chips = [];
  if (r.pending) chips.push(h('span', { class: 'chip wait' }, 'Pending deploy'));
  else if (r.kept) chips.push(h('span', { class: 'chip' }, 'Kept'));
  else if (r.change && !r.measured) chips.push(h('span', { class: 'chip warn' }, 'Unmeasured'));
  if (r.restart) chips.push(h('span', { class: 'chip warn', title: r.restart }, 'Restarts Wi-Fi'));
  if (others.length) chips.push(h('span', { class: 'chip', title: 'Applied together or not at all' }, `With ${others.join(', ')}`));
  let setting;
  if (r.pending && r.runs) setting = move(r.runs, r.current);
  else if (r.change) setting = move(r.current, r.proposed);
  else setting = h('p', { class: 'plan-set same' }, 'Stays on ', ...parts(r.current, null, 'channel'));
  const shift = r.predicted_busy !== undefined && Math.round(r.predicted_busy) !== Math.round(r.busy);
  const busy = r.busy === undefined
    ? effect('Busy', '–', 'not measured')
    : r.change && shift
      ? effect('Busy', `${r.busy.toFixed(0)} % → ${r.predicted_busy.toFixed(0)} %`, 'predicted')
      : effect('Busy', `${r.busy.toFixed(0)} %`, `${r.foreign.toFixed(0)} % other networks`);
  const snr = r.snr === undefined
    ? effect('Client SNR', '–', 'no clients heard')
    : effect('Client SNR', `${r.snr.toFixed(0)} dB`, r.change ? `weakest tenth, ${signed(r.snr_change)}` : 'weakest tenth');
  const clients = effect('Clients', r.clients === undefined ? '–' : r.clients.toFixed(1), r.hours ? `over ${r.hours} h` : null);
  const why = [h('p', { class: 'plan-why' }, sentence(r.reason))];
  if (r.restart) why.push(h('p', { class: 'plan-why warn' }, sentence(r.restart)));
  return h('li', { class: 'plan-radio', 'data-band': r.band, 'data-change': String(!!r.change) },
    h('div', { class: 'plan-pick' }, pick),
    h('div', { class: 'plan-main' },
      h('div', { class: 'plan-head' }, h('b', {}, r.ap), h('span', { class: 'chip', 'data-band': r.band }, bandName(r.band)), h('span', { class: 'muted' }, r.radio), ...chips),
      setting,
      ...why),
    h('dl', { class: 'plan-effect' }, busy, snr, clients));
}

/** The plan's panel: `root` to place, `update` when the state changed,
 * `unmount` when it goes. */
export function rfPlan(store) {
  const refresh = h('button', { type: 'button', class: 'btn quiet' }, icon(REFRESH), h('span', {}, 'Refresh'));
  const sub = h('p', { class: 'plan-sub' });
  const body = h('div', { class: 'plan-body' });
  const root = h('section', { class: 'panel plan', 'aria-labelledby': 'plan-title' },
    h('div', { class: 'plan-top' }, h('div', {}, h('h2', { id: 'plan-title' }, 'RF plan'), sub), refresh),
    body);
  /** The last answer, whether one is on its way, and an apply's. */
  let plan = null;
  let loading = false;
  let applying = false;
  let result = null;
  /** The proposals chosen, and every one offered so far: a new one is
   * chosen until it is unchosen. */
  const chosen = new Set();
  const offered = new Set();
  let timer = null;

  /** Asks for the plan again in a while. */
  function again() {
    clearTimeout(timer);
    timer = setTimeout(load, EVERY_MS);
  }

  async function load() {
    if (loading) return;
    loading = true;
    render();
    plan = await store.rfPlan();
    loading = false;
    const changes = new Set((plan.radios || []).filter((r) => r.change).map((r) => r.key));
    for (const k of changes) if (!offered.has(k)) chosen.add(k);
    for (const k of [...chosen]) if (!changes.has(k)) chosen.delete(k);
    offered.clear();
    for (const k of changes) offered.add(k);
    render();
    again();
  }

  /** The keys of the proposals applied with `r`: its group's others. */
  function others(r) {
    if (r.group === undefined) return [];
    return (plan.radios || []).filter((o) => o.group === r.group && o.key !== r.key).map((o) => o.key);
  }

  async function apply() {
    const picked = (plan.radios || []).filter((r) => r.change && chosen.has(r.key));
    const n = picked.length;
    const restarts = picked.filter((r) => r.restart).length;
    const restart = restarts
      ? ` ${restarts === 1 ? 'One of them restarts' : `${restarts} of them restart`} the AP’s Wi-Fi for a radar check of about a minute.`
      : '';
    const yes = await ask(document.body, {
      title: `Apply ${n} ${n === 1 ? 'change' : 'changes'}?`,
      text: `The controller commits ${n === 1 ? 'it' : 'them'} to ${plan.site?.file || 'the site file'} as wifi-controller, naming you, ` +
        'and the next configuration rendered from it takes the change to the access points: a channel switch announcement moves their clients along, without a reboot.' + restart,
      confirm: 'Commit',
    });
    if (!yes) return;
    applying = true;
    result = null;
    render();
    const radios = picked.map((r) => ({ key: r.key, ...r.proposed }));
    const res = await store.rfApply({ plan: plan.hash, radios });
    applying = false;
    result = res.ok
      ? ['ok', `Committed ${res.commit.slice(0, 12)} to ${plan.site?.file || 'the site file'}.`]
      : ['bad', `Not applied: ${res.error || 'the controller could not be reached'}.`];
    await load();
  }

  refresh.addEventListener('click', load);

  function resultLine() {
    const last = plan?.last;
    const [tone, text] = result
      || (last ? [last.ok ? 'ok' : 'bad', `Last applied ${ago(last.at)}${last.user ? ` by ${last.user}` : ''}: ${last.ok ? last.detail : `failed, ${last.detail}`}.`] : []);
    if (!tone) return null;
    return h('p', { class: 'result', role: 'status', 'data-tone': tone }, icon(tone === 'ok' ? OK : BAD), h('span', {}, text));
  }

  function foot(changes) {
    const admin = !!store.me?.admin;
    if (!admin) {
      if (!store.me) return null;
      return h('p', { class: 'lock plan-lock' }, icon(LOCK), h('span', {},
        'Viewing only: applying a plan commits to the site file and moves radios, which needs membership of ', h('b', {}, ADMIN_GROUP), '.'));
    }
    const n = changes.filter((r) => chosen.has(r.key)).length;
    const button = h('button', { type: 'button', class: 'btn primary', disabled: !n || applying, 'aria-busy': applying || null }, icon(COMMIT),
      h('span', {}, applying ? 'Committing…' : n ? `Apply ${n} ${n === 1 ? 'change' : 'changes'}` : 'Apply'));
    button.addEventListener('click', apply);
    const what = changes.length
      ? `${n} of ${changes.length} ${changes.length === 1 ? 'proposal' : 'proposals'} chosen`
      : 'Nothing to apply: every radio stays as it is.';
    return h('div', { class: 'plan-foot' }, h('span', { class: 'muted' }, what), button);
  }

  /** Whether the user was shown the admin's controls. */
  let shownAdmin = null;

  function render() {
    shownAdmin = store.me?.admin ?? null;
    refresh.disabled = loading;
    refresh.toggleAttribute('aria-busy', loading);
    if (!plan) {
      sub.textContent = 'From what each radio measured over the last hours';
      body.replaceChildren(h('div', { class: 'empty' }, h('strong', {}, 'Working out the plan'), h('p', {}, 'The proposals appear as soon as the controller has scored the radios.')));
      return;
    }
    if (plan.status === 0) {
      body.replaceChildren(h('div', { class: 'empty' }, h('strong', {}, 'The controller cannot be reached'), h('p', {}, 'The plan appears once it answers again.')));
      return;
    }
    if (plan.configured === false) {
      sub.textContent = 'Proposes each radio’s channel, width and power from what it measured';
      body.replaceChildren(h('div', { class: 'empty' }, h('strong', {}, 'The RF planner is off'),
        h('p', {}, 'The controller’s configuration has no [rf] section: no site file to read the radios from or to commit a plan to.')));
      return;
    }
    if (plan.error) {
      body.replaceChildren(h('p', { class: 'result', 'data-tone': 'bad' }, icon(BAD), h('span', {}, `No plan: ${plan.error}.`)));
      return;
    }
    const site = plan.site || {};
    sub.replaceChildren(`From each radio’s last ${plan.window_hours} h · ${site.file} at `, h('span', { class: 'mono' }, (site.rev || '').slice(0, 12)),
      site.fetched ? `, fetched ${ago(site.fetched)}` : '');
    const admin = !!store.me?.admin;
    const radios = plan.radios || [];
    const changes = radios.filter((r) => r.change);
    const list = h('ul', { class: 'plan-list' }, ...radios.map((r) => {
      const group = others(r);
      let pick = null;
      if (r.change && admin) {
        pick = h('input', { type: 'checkbox', 'aria-label': `Apply ${r.ap}’s ${bandName(r.band)} proposal`, checked: chosen.has(r.key), disabled: applying });
        // A group is chosen, and left out, whole.
        pick.addEventListener('change', () => {
          for (const k of [r.key, ...group]) {
            if (pick.checked) chosen.add(k);
            else chosen.delete(k);
          }
          render();
        });
      }
      return row(r, pick, group);
    }));
    const notes = (plan.notes || []).map((n) => h('p', { class: 'plan-note' }, icon(INFO), h('span', {}, n)));
    if (site.error) notes.push(h('p', { class: 'plan-note warn' }, icon(BAD), h('span', {}, `The site file could not be fetched (${site.error}); this plan reads it as last fetched.`)));
    body.replaceChildren(...[...notes, list, resultLine(), foot(changes)].filter(Boolean));
  }

  load();
  return {
    root,
    // The plan is its own fetch: of the live state, only who the user is
    // changes what it shows.
    update() {
      if ((store.me?.admin ?? null) !== shownAdmin) render();
    },
    unmount() {
      clearTimeout(timer);
    },
  };
}
