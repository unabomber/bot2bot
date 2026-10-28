'use strict';
// Metadata-only admin UI. All dynamic text is inserted with textContent (never innerHTML).
// The CSRF value lives in memory only; the session cookie is HttpOnly and invisible to this script.
(() => {
  const app = document.getElementById('app');
  const state = { csrf: null, name: null, timers: [], after: 0 };

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

  function stopTimers() { state.timers.forEach(clearInterval); state.timers = []; }

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

  function secretPanel(title, items) {
    const box = el('section', {}, el('h2', {}, title),
      el('p', { class: 'muted' }, 'Shown once. Copy now; it cannot be displayed again.'));
    for (const [label, token] of items) {
      box.append(el('div', { class: 'secret' }, el('div', {}, label),
        el('code', {}, token),
        el('div', { class: 'row' }, el('button', { type: 'button', onclick: () => {
          navigator.clipboard.writeText(token).then(() => notice('Copied'), () => notice('Copy failed', true));
        } }, 'Copy'))));
    }
    box.append(el('button', { type: 'button', onclick: () => box.remove() }, 'Dismiss'));
    return box;
  }

  async function roomsView() {
    stopTimers();
    const holder = el('div');
    app.replaceChildren(holder);
    async function render() {
      const { rooms } = await api('GET', 'rooms');
      const body = el('tbody');
      for (const r of rooms) {
        body.append(el('tr', {},
          el('td', {}, el('a', { href: '#/room/' + encodeURIComponent(r.name) }, r.name)),
          el('td', {}, el('span', { class: 'tag' + (r.status === 'closed' ? ' closed' : '') }, r.status)),
          el('td', {}, r.members), el('td', {}, r.active), el('td', {}, when(r.last_activity))));
      }
      const nameInput = el('input', { placeholder: 'room name', pattern: '[A-Za-z0-9_-]{1,64}', required: '' });
      const membersInput = el('input', { placeholder: 'members, comma separated' });
      const create = el('form', { onsubmit: async (e) => {
        e.preventDefault();
        try {
          const names = membersInput.value.split(',').map((s) => s.trim()).filter(Boolean);
          const made = await api('POST', 'rooms', { name: nameInput.value, members: names });
          nameInput.value = ''; membersInput.value = '';
          holder.prepend(secretPanel('Room ' + made.room + ' created',
            made.members.map((m) => [m.name + ' (' + m.role + ')', m.token])));
          notice('Room created');
          refreshList();
        } catch (err) { notice(err.message, true); }
      } }, el('div', { class: 'row' }, nameInput, membersInput, el('button', { class: 'primary', type: 'submit' }, 'Create room')));
      const list = el('section', {}, el('h2', {}, 'Rooms'),
        el('table', {}, el('thead', {}, el('tr', {}, ...['Room', 'Status', 'Members', 'Active', 'Last activity'].map((h) => el('th', {}, h)))), body),
        el('h2', {}, 'New room'), create);
      holder.querySelector('#roomlist')?.remove();
      list.id = 'roomlist';
      holder.append(list);
    }
    const refreshList = () => render().catch((e) => notice(e.message, true));
    refreshList();
    state.timers.push(setInterval(refreshList, 10000));
  }

  async function roomView(room) {
    stopTimers();
    state.after = 0;
    const head = el('section');
    const membersBox = el('section');
    const feedBody = el('tbody');
    const stats = el('p', { class: 'muted' });
    const feed = el('section', {}, el('h2', {}, 'Traffic (metadata only)'), stats,
      el('div', { class: 'feed' }, el('table', {}, el('thead', {}, el('tr', {},
        ...['#', 'Time', 'From', 'To', 'Bytes', 'Source'].map((h) => el('th', {}, h)))), feedBody)));
    const secrets = el('div');
    const inject = injectForm(room);
    app.replaceChildren(el('p', {}, el('a', { href: '#/rooms' }, '← Rooms')), head, secrets, membersBox, feed, inject);

    async function refreshMembers() {
      const [{ members }, { rooms }] = await Promise.all([api('GET', `rooms/${encodeURIComponent(room)}/members`), api('GET', 'rooms')]);
      const info = rooms.find((r) => r.name === room);
      const closed = info && info.status === 'closed';
      head.replaceChildren(el('h2', {}, room + ' ', el('span', { class: 'tag' + (closed ? ' closed' : '') }, closed ? 'closed' : 'open')),
        el('div', { class: 'row' },
          el('button', { type: 'button', onclick: () => act(closed ? 'reopen' : 'close', {}) }, closed ? 'Reopen room' : 'Close room'),
          el('button', { type: 'button', onclick: () => {
            const t = prompt('Thread name to reset'); if (t) act('reset-thread', { thread: t });
          } }, 'Reset thread budget')));
      const body = el('tbody');
      for (const m of members) {
        body.append(el('tr', {},
          el('td', {}, el('span', { class: 'dot' + (m.active ? ' on' : '') }), m.name),
          el('td', {}, m.role), el('td', {}, m.active ? 'active' : 'idle'), el('td', {}, when(m.last_seen)),
          el('td', {}, m.waiting ? 'waiting' : ''),
          el('td', {}, el('button', { type: 'button', onclick: () => rotate(m.name) }, 'Rotate'), ' ',
            el('button', { class: 'danger', type: 'button', onclick: () => revoke(m.name) }, 'Revoke'))));
      }
      const addName = el('input', { placeholder: 'new member', pattern: '[A-Za-z0-9_-]{1,64}' });
      const addRole = el('select', {}, el('option', { value: 'agent' }, 'agent'), el('option', { value: 'monitor' }, 'monitor'));
      membersBox.replaceChildren(el('h2', {}, 'Members'),
        el('table', {}, el('thead', {}, el('tr', {}, ...['Name', 'Role', 'State', 'Last seen', '', ''].map((h) => el('th', {}, h)))), body),
        el('div', { class: 'row' }, addName, addRole, el('button', { type: 'button', onclick: async () => {
          if (!addName.value) return;
          try {
            const made = await api('POST', `rooms/${encodeURIComponent(room)}/members`, { name: addName.value, role: addRole.value });
            secrets.prepend(secretPanel('Member added', [[made.name, made.token]]));
            refreshMembers();
          } catch (err) { notice(err.message, true); }
        } }, 'Add member')));
    }

    async function act(action, body) {
      try { await api('POST', `rooms/${encodeURIComponent(room)}/${action}`, body); notice('Done'); refreshMembers(); }
      catch (err) { notice(err.message, true); }
    }
    async function revoke(name) {
      if (!confirm('Revoke ' + name + '? Their open connections end immediately.')) return;
      try { await api('POST', `rooms/${encodeURIComponent(room)}/members/${encodeURIComponent(name)}/revoke`, {}); refreshMembers(); }
      catch (err) { notice(err.message, true); }
    }
    async function rotate(name) {
      if (!confirm('Rotate the token for ' + name + '? The old token stops working immediately.')) return;
      try {
        const res = await api('POST', `rooms/${encodeURIComponent(room)}/members/${encodeURIComponent(name)}/rotate`, {});
        secrets.prepend(secretPanel('New token for ' + res.name, [[res.name, res.token]]));
        refreshMembers();
      } catch (err) { notice(err.message, true); }
    }
    async function refreshFeed() {
      const res = await api('GET', `rooms/${encodeURIComponent(room)}/monitor?after=${state.after}&limit=200`);
      for (const e of res.events) {
        feedBody.append(el('tr', {}, el('td', {}, e.id), el('td', {}, when(e.ts)), el('td', {}, e.from),
          el('td', {}, e.to_count + ' recipient(s)'), el('td', {}, e.bytes), el('td', {}, e.source)));
      }
      state.after = res.cursor;
      while (feedBody.rows.length > 500) feedBody.deleteRow(0);
      const s = await api('GET', `rooms/${encodeURIComponent(room)}/stats`);
      stats.textContent = `${s.messages} messages, ${s.bytes} bytes total`;
    }
    const safe = (fn) => () => fn().catch((e) => { if (e.message !== 'signed out') notice(e.message, true); });
    safe(refreshMembers)(); safe(refreshFeed)();
    state.timers.push(setInterval(safe(refreshFeed), 2000), setInterval(safe(refreshMembers), 5000));
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
