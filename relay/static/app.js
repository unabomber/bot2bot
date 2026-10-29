'use strict';
// Metadata-only admin UI. All dynamic text is inserted as text nodes, never as markup.
// The CSRF value lives in memory only; the session cookie is HttpOnly and invisible to this script.
(() => {
  const app = document.getElementById('app');
  const state = { csrf: null, name: null, timers: [], view: 0 };  // view: id of the current page; stale async work checks it

  function el(tag, props, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const kid of kids) node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    return node;
  }

  function notice(text, bad) {
    const n = document.getElementById('notice');
    n.textContent = text;
    n.className = bad ? 'error' : '';
    n.hidden = false;
    clearTimeout(notice.t);
    notice.t = setTimeout(() => { n.hidden = true; }, 5000);
  }

  function stopTimers() { state.view += 1; state.timers.forEach(clearInterval); state.timers = []; }

  // Wrap a table so narrow screens scroll sideways instead of hiding columns.
  function scroller(table) { return el('div', { class: 'scroll' }, table); }

  async function api(method, path, body) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (method === 'POST') {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-CSRF'] = state.csrf || '';
      opts.body = JSON.stringify(body || {});
    }
    const res = await fetch('/ui/api/' + path, opts);
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (res.status === 401) { signedOut(); throw new Error('signed out'); }
    if (!res.ok) {
      const retry = res.headers.get('Retry-After');
      throw new Error((data.error || 'request failed') + (res.status === 429 && retry ? ` (retry in ${retry}s)` : ''));
    }
    return data;
  }

  function when(ts) { return ts ? new Date(ts * 1000).toLocaleString() : '-'; }

  function signedOut() {
    stopTimers();
    state.csrf = null;
    document.getElementById('nav').hidden = true;
    loginView();
  }

  // ---- views ----
  function loginView(message) {
    const input = el('input', { type: 'password', autocomplete: 'off', placeholder: 'Admin token', required: '' });
    const form = el('form', { onsubmit: async (e) => {
      e.preventDefault();
      try {
        const res = await fetch('/ui/login', { method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: input.value }) });
        input.value = '';
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const retry = res.headers.get('Retry-After');
          return loginView((res.status === 429 ? 'Too many attempts' : 'Sign-in failed') + (retry ? ` (retry in ${retry}s)` : ''));
        }
        state.csrf = data.csrf;
        await start();
      } catch (err) { loginView('Sign-in failed'); }
    } }, el('div', { class: 'row' }, input, el('button', { class: 'primary', type: 'submit' }, 'Sign in')));
    app.replaceChildren(el('section', {}, el('h2', {}, 'Sign in'),
      el('p', { class: 'muted' }, 'Paste the admin token. It is exchanged for a session and not kept in this page.'),
      message ? el('p', { class: 'muted' }, message) : '', form));
  }

  // navigator.clipboard only exists in secure contexts (https/localhost), not on a plain-HTTP LAN page, so fall back
  // to selecting the text and offering manual copy; none of this may throw.
  function copyToken(node) {
    const text = node.textContent;
    const manual = () => {
      try {
        const range = document.createRange();
        range.selectNodeContents(node);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        if (document.execCommand && document.execCommand('copy')) return notice('Copied');
      } catch (e) { /* fall through */ }
      notice('Selected: press Ctrl+C (or Cmd+C) to copy', true);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => notice('Copied'), manual);
    } else {
      manual();
    }
  }

  function secretPanel(title, items) {
    const box = el('section', {}, el('h2', {}, title),
      el('p', { class: 'muted' }, 'Shown once. Copy now; it cannot be displayed again.'));
    for (const [label, token] of items) {
      const code = el('code', {}, token);
      box.append(el('div', { class: 'secret' }, el('div', {}, label), code,
        el('div', { class: 'row' }, el('button', { type: 'button', onclick: () => copyToken(code) }, 'Copy'))));
    }
    box.append(el('button', { type: 'button', onclick: () => box.remove() }, 'Dismiss'));
    return box;
  }

  async function roomsView() {
    stopTimers();
    const view = state.view;
    let busy = false;
    // Forms are built once; polling only swaps table rows, so text being typed is never discarded.
    const secrets = el('div');
    const rows = el('tbody');
    const nameInput = el('input', { placeholder: 'room name', pattern: '[A-Za-z0-9_-]{1,64}', required: '' });
    const membersInput = el('input', { placeholder: 'members, comma separated' });
    const create = el('form', { onsubmit: async (e) => {
      e.preventDefault();
      try {
        const names = membersInput.value.split(',').map((s) => s.trim()).filter(Boolean);
        const made = await api('POST', 'rooms', { name: nameInput.value, members: names });
        nameInput.value = ''; membersInput.value = '';
        secrets.prepend(secretPanel('Room ' + made.room + ' created',
          made.members.map((m) => [m.name + ' (' + m.role + ')', m.token])));
        notice('Room created');
        refreshList();
      } catch (err) { notice(err.message, true); }
    } }, el('div', { class: 'row' }, nameInput, membersInput, el('button', { class: 'primary', type: 'submit' }, 'Create room')));
    app.replaceChildren(secrets, el('section', {}, el('h2', {}, 'Rooms'),
      scroller(el('table', {}, el('thead', {}, el('tr', {}, ...['Room', 'Status', 'Members', 'Active', 'Last activity'].map((h) => el('th', {}, h)))), rows)),
      el('h2', {}, 'New room'), create));

    async function render() {
      const { rooms } = await api('GET', 'rooms');
      if (view !== state.view) return;  // user navigated away while this request was in flight
      rows.replaceChildren(...rooms.map((r) => el('tr', {},
        el('td', {}, el('a', { href: '#/room/' + encodeURIComponent(r.name) }, r.name)),
        el('td', {}, el('span', { class: 'tag' + (r.status === 'closed' ? ' closed' : '') }, r.status)),
        el('td', {}, r.members), el('td', {}, r.active), el('td', {}, when(r.last_activity)))));
    }
    const refreshList = async () => {
      if (busy) return;  // never overlap list polls
      busy = true;
      try { await render(); } catch (e) { if (e.message !== 'signed out') notice(e.message, true); } finally { busy = false; }
    };
    refreshList();
    state.timers.push(setInterval(refreshList, 10000));
  }

  async function roomView(room) {
    stopTimers();
    const view = state.view;
    let after = 0;                       // feed cursor is local to this view
    let closed = false;
    const busy = { members: false, feed: false, sync: false };
    const q = encodeURIComponent(room);
    // Static controls are built once; polls update only table rows and labels, never the forms.
    const title = el('h2', {}, room + ' ');
    const status = el('span', { class: 'tag' }, 'open');
    title.append(status);
    const toggle = el('button', { type: 'button', onclick: () => act(closed ? 'reopen' : 'close', {}) }, 'Close room');
    const threadNo = el('input', { type: 'number', min: '1', step: '1', placeholder: 'thread #' });
    const head = el('section', {}, title, el('div', { class: 'row' }, toggle,
      threadNo, el('button', { type: 'button', onclick: () => {
        const n = Number(threadNo.value);
        if (!Number.isInteger(n) || n < 1) return notice('Enter the thread number shown in the traffic table', true);
        act('reset-thread', { thread_no: n });
      } }, 'Reset thread budget')));
    const membersBody = el('tbody');
    const addName = el('input', { placeholder: 'new member', pattern: '[A-Za-z0-9_-]{1,64}' });
    const addRole = el('select', {}, el('option', { value: 'agent' }, 'agent'), el('option', { value: 'monitor' }, 'monitor'));
    const secrets = el('div');
    const membersBox = el('section', {}, el('h2', {}, 'Members'),
      scroller(el('table', {}, el('thead', {}, el('tr', {}, ...['Name', 'Role', 'State', 'Last seen', '', ''].map((h) => el('th', {}, h)))), membersBody)),
      el('div', { class: 'row' }, addName, addRole, el('button', { type: 'button', onclick: async () => {
        if (!addName.value) return;
        try {
          const made = await api('POST', `rooms/${q}/members`, { name: addName.value, role: addRole.value });
          addName.value = '';
          secrets.prepend(secretPanel('Member added', [[made.name, made.token]]));
          pollMembers();
        } catch (err) { notice(err.message, true); }
      } }, 'Add member')));
    const feedBody = el('tbody');
    const stats = el('p', { class: 'muted' });
    const feed = el('section', {}, el('h2', {}, 'Traffic (metadata only)'), stats,
      el('div', { class: 'feed scroll' }, el('table', {}, el('thead', {}, el('tr', {},
        ...['#', 'Time', 'From', 'To', 'Bytes', 'Source', 'Thread'].map((h) => el('th', {}, h)))), feedBody)));
    // ---- agreement / stall panel: versions, names and numbers only (never state text or reasons) ----
    const syncLine = el('p', { class: 'muted' });
    const roundLine = el('p', { class: 'muted' });
    const syncBody = el('tbody');
    const strictBox = el('input', { type: 'checkbox', 'aria-label': 'Strict mode' });
    const autoBox = el('input', { type: 'checkbox', 'aria-label': 'Auto-pass turn when stalled' });
    const stallInput = el('input', { type: 'number', min: '5', max: '86400', step: '1', placeholder: 'stall seconds', 'aria-label': 'Stall seconds' });
    const turnSelect = el('select', { 'aria-label': 'Turn holder' }, el('option', { value: '' }, '(no turn holder)'));
    const removeSelect = el('select', { 'aria-label': 'Participant to remove' });
    const resetInput = el('input', { type: 'number', min: '0', step: '1', placeholder: 'version', 'aria-label': 'Version to reset to' });
    // only fields the admin actually edited are sent, so a stale form can never overwrite newer settings
    const dirty = new Set();
    const fields = { strict: strictBox, auto_pass: autoBox, stall_seconds: stallInput, turn: turnSelect };
    for (const [key, input] of Object.entries(fields)) input.addEventListener('change', () => dirty.add(key));
    const postSync = async (action, body, done) => {
      try { await api('POST', `rooms/${q}/sync/${action}`, body); notice(done); if (action === 'settings') dirty.clear(); pollSync(); }
      catch (err) { notice(err.message, true); }
    };
    const syncBox = el('section', {}, el('h2', {}, 'Agreement and stalls'), syncLine, roundLine,
      scroller(el('table', {}, el('thead', {}, el('tr', {}, ...['Member', 'Agreed version', 'In sync', 'Waiting on'].map((h) => el('th', {}, h)))), syncBody)),
      el('div', { class: 'row' }, el('button', { type: 'button', onclick: () => postSync('abort', {}, 'Round aborted') }, 'Abort open round'),
        removeSelect, el('button', { class: 'danger', type: 'button', onclick: () => {
          if (removeSelect.value && confirm('Remove ' + removeSelect.value + ' from the round? Everyone remaining must acknowledge again.'))
            postSync('remove', { name: removeSelect.value }, 'Participant removed');
        } }, 'Remove participant'),
        resetInput, el('button', { type: 'button', onclick: () => {
          const v = Number(resetInput.value);
          if (resetInput.value === '' || !Number.isInteger(v) || v < 0) return notice('Enter a version number (0 for the empty initial state)', true);
          postSync('reset', { version: v }, 'Reset proposed; members must acknowledge');
        } }, 'Propose reset to version')),
      el('div', { class: 'row' }, el('label', {}, strictBox, ' Strict: messages must carry the current version'),
        el('label', {}, autoBox, ' Auto-pass turn when stalled'), stallInput, turnSelect,
        el('button', { class: 'primary', type: 'button', onclick: () => {
          const body = {};
          if (dirty.has('strict')) body.strict = strictBox.checked;
          if (dirty.has('auto_pass')) body.auto_pass = autoBox.checked;
          if (dirty.has('turn')) body.turn = turnSelect.value || null;
          if (dirty.has('stall_seconds')) {
            const secs = Number(stallInput.value);
            if (!Number.isInteger(secs) || secs < 5 || secs > 86400) return notice('Stall seconds must be 5 to 86400', true);
            body.stall_seconds = secs;
          }
          if (!Object.keys(body).length) return notice('No settings changed');
          postSync('settings', body, 'Settings saved');
        } }, 'Save settings')));
    app.replaceChildren(el('p', {}, el('a', { href: '#/rooms' }, '\u2190 Rooms')), head, secrets, membersBox, syncBox, feed, injectForm(room));

    async function refreshMembers() {
      const [{ members }, { rooms }] = await Promise.all([api('GET', `rooms/${q}/members`), api('GET', 'rooms')]);
      if (view !== state.view) return;
      const info = rooms.find((r) => r.name === room);
      closed = !!info && info.status === 'closed';
      status.textContent = closed ? 'closed' : 'open';
      status.className = 'tag' + (closed ? ' closed' : '');
      toggle.textContent = closed ? 'Reopen room' : 'Close room';
      membersBody.replaceChildren(...members.map((m) => el('tr', {},
        el('td', {}, el('span', { class: 'dot' + (m.active ? ' on' : '') }), m.name),
        el('td', {}, m.role), el('td', {}, m.active ? 'active' : 'idle'), el('td', {}, when(m.last_seen)),
        el('td', {}, m.waiting ? 'waiting' : ''),
        el('td', {}, el('button', { type: 'button', onclick: () => rotate(m.name) }, 'Rotate'), ' ',
          el('button', { class: 'danger', type: 'button', onclick: () => revoke(m.name) }, 'Revoke')))));
    }

    async function act(action, body) {
      try { await api('POST', `rooms/${q}/${action}`, body); notice('Done'); pollMembers(); }
      catch (err) { notice(err.message, true); }
    }
    async function revoke(name) {
      if (!confirm('Revoke ' + name + '? Their open connections end immediately.')) return;
      try { await api('POST', `rooms/${encodeURIComponent(room)}/members/${encodeURIComponent(name)}/revoke`, {}); pollMembers(); }
      catch (err) { notice(err.message, true); }
    }
    async function rotate(name) {
      if (!confirm('Rotate the token for ' + name + '? The old token stops working immediately.')) return;
      try {
        const res = await api('POST', `rooms/${encodeURIComponent(room)}/members/${encodeURIComponent(name)}/rotate`, {});
        secrets.prepend(secretPanel('New token for ' + res.name, [[res.name, res.token]]));
        pollMembers();
      } catch (err) { notice(err.message, true); }
    }
    async function refreshSync() {
      const s = await api('GET', `rooms/${q}/sync`);
      if (view !== state.view) return;
      const names = Object.keys(s.acks || {}).sort();
      const removable = (s.round_open && s.round ? s.round.enrolled : names).slice().sort();
      syncLine.textContent = `Committed version ${s.version}. ` + (s.stalled ? `STALLED (${s.kind}) since ${when(s.since)}: ${(s.members || []).join(', ')}.` : 'Not stalled.')
        + (s.turn ? ` Turn: ${s.turn}.` : '');
      roundLine.textContent = s.round_open && s.round
        ? `Round v${s.round.version} open: acknowledged ${s.round.acked.length} of ${s.round.enrolled.length}`
          + (s.unacked.length ? `, waiting for ${s.unacked.join(', ')}` : '') + `, deadline ${when(s.round.deadline)}.`
        : 'No round open.';
      syncBody.replaceChildren(...names.map((n) => el('tr', {}, el('td', {}, n), el('td', {}, s.acks[n] === null ? '-' : s.acks[n]),
        el('td', {}, (s.drift || []).includes(n) ? 'DRIFT' : 'yes'), el('td', {}, (s.waiting_on && s.waiting_on[n]) || ''))));
      const keep = removeSelect.value;
      removeSelect.replaceChildren(el('option', { value: '' }, 'Remove participant...'), ...removable.map((n) => el('option', { value: n }, n)));
      removeSelect.value = removable.includes(keep) ? keep : '';
      const turn = turnSelect.value;
      turnSelect.replaceChildren(el('option', { value: '' }, '(no turn holder)'), ...names.map((n) => el('option', { value: n }, n)));
      // untouched fields follow the server (another admin tab or an auto-pass may have changed them); edited ones are left alone
      if (!dirty.has('strict')) strictBox.checked = !!s.strict;
      if (!dirty.has('auto_pass')) autoBox.checked = !!s.auto_pass;
      if (!dirty.has('stall_seconds') && document.activeElement !== stallInput) stallInput.value = s.stall_seconds;
      turnSelect.value = dirty.has('turn') ? (names.includes(turn) ? turn : '') : (s.turn || '');
    }
    async function refreshFeed() {
      const res = await api('GET', `rooms/${encodeURIComponent(room)}/monitor?after=${after}&limit=200`);
      if (view !== state.view) return;  // stale response from a room we already left: ignore it, keep our cursor
      for (const e of res.events) {
        feedBody.append(el('tr', {}, el('td', {}, e.id), el('td', {}, when(e.ts)), el('td', {}, e.from),
          el('td', {}, e.to_count + ' recipient(s)'), el('td', {}, e.bytes), el('td', {}, e.source), el('td', {}, e.thread_no)));
      }
      after = res.cursor;
      while (feedBody.rows.length > 500) feedBody.deleteRow(0);
      const s = await api('GET', `rooms/${encodeURIComponent(room)}/stats`);
      if (view !== state.view) return;
      stats.textContent = `${s.messages} messages, ${s.bytes} bytes total`;
    }
    // One poll of each kind at a time: a slow response must not start a second overlapping poll (duplicate rows).
    const safe = (key, fn) => async () => {
      if (busy[key]) return;
      busy[key] = true;
      try { await fn(); } catch (e) { if (e.message !== 'signed out') notice(e.message, true); } finally { busy[key] = false; }
    };
    const pollFeed = safe('feed', refreshFeed), pollMembers = safe('members', refreshMembers), pollSync = safe('sync', refreshSync);
    pollMembers(); pollFeed(); pollSync();
    state.timers.push(setInterval(pollFeed, 2000), setInterval(pollMembers, 5000), setInterval(pollSync, 5000));
  }

  function injectForm(room) {
    const text = el('textarea', { placeholder: 'Message from the human (not shown back here)', maxlength: '8192' });
    const to = el('input', { placeholder: "* for everyone, or names separated by commas", value: '*' });
    return el('section', {}, el('h2', {}, 'Send a message as human'), text,
      el('div', { class: 'row' }, to, el('button', { class: 'primary', type: 'button', onclick: async () => {
        const raw = to.value.trim();
        const target = raw === '*' ? '*' : raw.split(',').map((s) => s.trim()).filter(Boolean);
        try {
          await api('POST', `rooms/${encodeURIComponent(room)}/inject`, { to: target, text: text.value });
          text.value = '';
          notice('Sent');
        } catch (err) { notice(err.message, true); }
      } }, 'Send')));
  }

  // ---- routing and boot ----
  function route() {
    if (!state.csrf) return;
    const hash = location.hash || '#/rooms';
    const m = hash.match(/^#\/room\/([^/]+)$/);
    (m ? roomView(decodeURIComponent(m[1])) : roomsView()).catch((e) => notice(e.message, true));
  }

  async function start() {
    try {
      const s = await api('GET', 'session');
      state.csrf = s.csrf;
      state.name = s.name;
      document.getElementById('who').textContent = s.name;
      document.getElementById('nav').hidden = false;
      route();
    } catch (e) { loginView(); }
  }

  document.getElementById('logout').addEventListener('click', async () => {
    try { await api('POST', 'logout', {}); } catch (e) { /* already signed out */ }
    signedOut();
  });
  document.getElementById('logout-all').addEventListener('click', async () => {
    try { await api('POST', 'logout-all', {}); } catch (e) { /* already signed out */ }
    signedOut();
  });
  window.addEventListener('hashchange', route);
  start();
})();
