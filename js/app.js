/*
 * UI wiring for the hidden relay test client.
 *
 * Connect with an nsec and an nrv address, publish a kind 1 note through the
 * bridge, and read your own kind 1 notes back from the relay on the far side.
 */
(function () {
  'use strict';

  const N = window.HRNostr;
  const STORAGE_KEY = 'hidden-relay-test-client';

  const el = (id) => document.getElementById(id);
  const ui = {
    nsec: el('nsec'), nrv: el('nrv'), relayOverride: el('relay-override'),
    toggleNsec: el('toggle-nsec'), remember: el('remember'),
    connect: el('connect'), disconnect: el('disconnect'), status: el('status'),
    identity: el('identity'), myNpub: el('my-npub'), bridgeNpub: el('bridge-npub'),
    relayUrl: el('relay-url'),
    composeCard: el('compose-card'), content: el('content'), publish: el('publish'),
    publishStatus: el('publish-status'),
    notesCard: el('notes-card'), refresh: el('refresh'), notes: el('notes'),
    notesEmpty: el('notes-empty'),
    log: el('log'), clearLog: el('clear-log'),
  };

  let client = null;

  // ------------------------------------------------------------------ log --

  function log(text, kind = '') {
    const time = new Date().toTimeString().slice(0, 8);
    const line = document.createElement('div');
    const stamp = document.createElement('span');
    stamp.className = 't';
    stamp.textContent = time + '  ';
    const body = document.createElement('span');
    if (kind) body.className = kind;
    body.textContent = text;
    line.append(stamp, body);
    ui.log.append(line);
    ui.log.scrollTop = ui.log.scrollHeight;
  }

  function setStatus(node, text, kind = '') {
    node.textContent = text;
    node.className = 'status' + (kind ? ' status-' + kind : '');
  }

  function truncate(text, max = 220) {
    const flat = String(text).replace(/\s+/g, ' ');
    return flat.length > max ? flat.slice(0, max) + '…' : flat;
  }

  // --------------------------------------------------------- connect flow --

  function setConnected(isConnected) {
    ui.connect.disabled = isConnected;
    ui.disconnect.disabled = !isConnected;
    ui.nsec.disabled = isConnected;
    ui.nrv.disabled = isConnected;
    ui.relayOverride.disabled = isConnected;
    ui.publish.disabled = !isConnected;
    ui.refresh.disabled = !isConnected;
    ui.composeCard.setAttribute('aria-disabled', String(!isConnected));
    ui.notesCard.setAttribute('aria-disabled', String(!isConnected));
    ui.identity.hidden = !isConnected;
  }

  async function connect() {
    disconnect({ quiet: true });
    setStatus(ui.status, 'connecting…', 'busy');
    try {
      client = N.HiddenRelayClient.fromNrv({
        nsec: ui.nsec.value,
        nrv: ui.nrv.value,
        relayUrl: ui.relayOverride.value.trim() || null,
        onRelayMessage: (message) => {
          log('< ' + truncate(JSON.stringify(message)), 'in');
        },
        onStatus: (kind, detail) => {
          if (kind === 'closed') {
            log('rendez-vous relay closed the connection', 'warn');
            setStatus(ui.status, 'disconnected', 'warn');
            setConnected(false);
          } else if (kind === 'warn') {
            log(detail, 'warn');
          } else if (kind === 'auth') {
            log(detail, 'out');
          }
        },
      });
    } catch (err) {
      setStatus(ui.status, err.message, 'error');
      log('cannot start: ' + err.message, 'error');
      return;
    }

    ui.myNpub.textContent = N.encodeNpub(client.pubkey);
    ui.bridgeNpub.textContent = N.encodeNpub(client.bridgePubkey);
    ui.relayUrl.textContent = client.relayUrl;

    try {
      await client.connect();
    } catch (err) {
      setStatus(ui.status, err.message, 'error');
      log('connection failed: ' + err.message, 'error');
      client = null;
      return;
    }

    setConnected(true);
    setStatus(ui.status, 'connected', 'ok');
    log('connected to ' + client.relayUrl, 'out');
    log('your pubkey ' + client.pubkey);
    log('bridge pubkey ' + client.bridgePubkey);
    saveInputs();
    fetchNotes();
  }

  function disconnect({ quiet = false } = {}) {
    if (client) {
      client.close();
      client = null;
      if (!quiet) log('disconnected', 'warn');
    }
    setConnected(false);
    if (!quiet) setStatus(ui.status, 'not connected', '');
  }

  // ------------------------------------------------------------- publish --

  async function publishNote() {
    const content = ui.content.value.trim();
    if (!content) {
      setStatus(ui.publishStatus, 'write something first', 'warn');
      return;
    }
    ui.publish.disabled = true;
    setStatus(ui.publishStatus, 'signing and publishing…', 'busy');
    try {
      const event = N.buildEvent(client.secretKey, { kind: 1, content });
      log('> EVENT ' + event.id.slice(0, 12) + ' (kind 1, ' + content.length + ' chars)', 'out');
      const ok = await client.publish(event);
      setStatus(ui.publishStatus, 'accepted as ' + event.id.slice(0, 12), 'ok');
      log('note accepted: ' + truncate(JSON.stringify(ok)), 'in');
      ui.content.value = '';
      await fetchNotes();
    } catch (err) {
      setStatus(ui.publishStatus, err.message, 'error');
      log('publish failed: ' + err.message, 'error');
    } finally {
      ui.publish.disabled = !client;
    }
  }

  // --------------------------------------------------------------- notes --

  async function fetchNotes() {
    if (!client) return;
    ui.refresh.disabled = true;
    ui.notesEmpty.textContent = 'fetching…';
    ui.notesEmpty.hidden = false;
    try {
      const filter = { kinds: [1], authors: [client.pubkey] };
      log('> REQ ' + JSON.stringify(filter), 'out');
      const events = await client.request([filter]);
      renderNotes(events);
      log('fetched ' + events.length + ' note(s)', 'in');
    } catch (err) {
      ui.notesEmpty.textContent = err.message;
      log('fetch failed: ' + err.message, 'error');
    } finally {
      ui.refresh.disabled = !client;
    }
  }

  function renderNotes(events) {
    const byId = new Map();
    for (const event of events) {
      if (event && event.id && !byId.has(event.id)) byId.set(event.id, event);
    }
    const notes = [...byId.values()].sort((a, b) => b.created_at - a.created_at);

    ui.notes.replaceChildren();
    ui.notesEmpty.hidden = notes.length > 0;
    ui.notesEmpty.textContent = 'No kind 1 notes from your pubkey on the far side yet.';

    for (const note of notes) {
      const item = document.createElement('li');
      item.className = 'note';

      const content = document.createElement('p');
      content.className = 'note-content';
      content.textContent = note.content;

      const meta = document.createElement('div');
      meta.className = 'note-meta';
      const when = document.createElement('span');
      when.textContent = new Date(note.created_at * 1000).toLocaleString();
      const id = document.createElement('span');
      id.textContent = 'id ' + String(note.id).slice(0, 16) + '…';
      const valid = document.createElement('span');
      const isValid = N.verifyEvent(note);
      valid.textContent = isValid ? 'signature ok' : 'BAD SIGNATURE';
      valid.className = isValid ? 'status-ok' : 'status-error';
      meta.append(when, id, valid);

      item.append(content, meta);
      ui.notes.append(item);
    }
  }

  // ------------------------------------------------------------- storage --

  function saveInputs() {
    if (!ui.remember.checked) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      nsec: ui.nsec.value,
      nrv: ui.nrv.value,
      relayOverride: ui.relayOverride.value,
    }));
  }

  function loadInputs() {
    let saved;
    try {
      saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    } catch (err) {
      return;
    }
    if (!saved) return;
    ui.nsec.value = saved.nsec || '';
    ui.nrv.value = saved.nrv || '';
    ui.relayOverride.value = saved.relayOverride || '';
    ui.remember.checked = true;
    log('loaded saved inputs from this browser');
  }

  // --------------------------------------------------------------- wiring --

  ui.connect.addEventListener('click', connect);
  ui.disconnect.addEventListener('click', () => disconnect());
  ui.publish.addEventListener('click', publishNote);
  ui.refresh.addEventListener('click', fetchNotes);
  ui.remember.addEventListener('change', saveInputs);
  ui.clearLog.addEventListener('click', () => ui.log.replaceChildren());

  ui.toggleNsec.addEventListener('click', () => {
    const hidden = ui.nsec.type === 'password';
    ui.nsec.type = hidden ? 'text' : 'password';
    ui.toggleNsec.textContent = hidden ? 'hide' : 'show';
  });

  ui.content.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !ui.publish.disabled) {
      publishNote();
    }
  });

  window.addEventListener('beforeunload', () => disconnect({ quiet: true }));

  setConnected(false);
  log('ready. Enter your nsec and the nrv address of the bridge, then connect.');
  loadInputs();
})();
