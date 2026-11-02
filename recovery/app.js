import { RecoveryCall } from './call.js';
import { RemotePlayback } from '/playback.js';

const $ = id => document.getElementById(id);
const state = { view: 'home', generation: 0, joinGeneration: 0, user: null, meeting: null, pending: false, tiles: new Map(), playbacks: new Map() };
const make = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};
function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const use = document.createElementNS(svg.namespaceURI, 'use');
  svg.classList.add('icon'); svg.setAttribute('aria-hidden', 'true');
  use.setAttribute('href', `/icons.svg#${name}`); svg.append(use); return svg;
}
function action(label, fn, className = '') {
  const button = make('button', label, className); button.type = 'button';
  button.onclick = () => run(button, fn); return button;
}
async function run(button, fn) {
  if (button.disabled) return;
  button.disabled = true;
  try { await fn(); } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; if (call.room) renderCall(); }
}
async function api(path, { body, method = body === undefined ? 'GET' : 'POST' } = {}) {
  const response = await fetch('/recovery/api' + path, { method, credentials: 'same-origin', signal: AbortSignal.timeout(20000), headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = Error(result.error || 'The meeting service is unavailable. Please try again.');
    error.status = response.status; throw error;
  }
  return result;
}
async function identity() {
  try { return await api('/me'); } catch (error) { if (error.status === 401) return null; throw error; }
}
let toastTimer;
function toast(message, error = false) {
  $('toast').textContent = message; $('toast').classList.toggle('error', error); $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 5500);
}
function errorMessage(error) {
  if (error.name === 'NotAllowedError') return 'Microphone access wasn’t allowed. You can join to listen, or allow access in your browser settings.';
  if (error.name === 'NotFoundError') return 'No microphone was found. You can still join to listen.';
  if (error.name === 'NotReadableError') return 'Your microphone is unavailable. Close other apps using it, or join to listen.';
  return error.message || 'Something interrupted joining. Please try again.';
}
function entryError(message = '') { $('entry-error').textContent = message; }
function showView(view) {
  state.view = view;
  for (const id of ['home', 'entry', 'call', 'left']) $(id + '-view').hidden = id !== view;
  document.body.classList.toggle('in-call', view === 'call');
}
function showEntry(panel) {
  showView('entry');
  for (const id of ['create-form', 'join-link-form', 'join-form', 'created-panel', 'entry-loading']) $(id).hidden = id !== panel;
  entryError(); $('entry-status').textContent = ''; $('cancel-join').hidden = true;
}
function invitation(id) { return new URL(`/recovery/#meeting=${id}`, location.origin).href; }
function meetingId(value) {
  if (/^[a-f0-9]{64}$/.test(value)) return value;
  try {
    const url = new URL(value, location.origin);
    if (url.origin !== location.origin) return null;
    return url.hash.match(/^#meeting=([a-f0-9]{64})$/)?.[1] || null;
  } catch { return null; }
}
function go(hash = '') { if (location.hash === hash || (!hash && !location.hash)) route(); else location.hash = hash; }
function setJoinPending(pending) {
  state.pending = pending;
  for (const id of ['join-listen', 'join-microphone', 'join-name', 'join-consent']) $(id).disabled = pending;
  $('cancel-join').hidden = !pending;
}
const call = new RecoveryCall({
  api, changed: () => { if (state.view === 'call') renderCall(); },
  admitted: () => { setJoinPending(false); showView('call'); $('call-title').textContent = call.room.name; renderCall(); $('leave-button').focus(); },
  ended: message => { setJoinPending(false); clearTiles(); $('left-description').textContent = message; showView('left'); $('rejoin-button').focus(); },
  error: message => {
    if (state.view === 'call') toast(message, true);
    else { setJoinPending(false); $('entry-status').textContent = ''; entryError(message); }
  },
  approved: () => toast('The chair has invited your share. Unmute whenever you’re ready.'),
});

async function route() {
  const generation = ++state.generation;
  ++state.joinGeneration;
  if (call.busy) call.leave();
  clearTiles(); setJoinPending(false);
  const hash = location.hash;
  if (hash === '#create') {
    showEntry('create-form');
    $('entry-title').replaceChildren('A space', document.createElement('br'), 'for your group.');
    $('entry-description').textContent = 'Create a familiar place to return to. A first name or a chosen name is all you need.';
    try {
      const user = await identity();
      if (generation !== state.generation) return;
      state.user = user;
      const host = user && !user.scoped_guest;
      $('create-name').readOnly = !!host;
      if (host) $('create-name').value = user.display_name;
      (host ? $('create-title') : $('create-name')).focus({ preventScroll: true });
    } catch (error) { if (generation === state.generation) entryError(errorMessage(error)); }
  } else if (hash === '#join') {
    showEntry('join-link-form');
    $('entry-title').textContent = 'A familiar place. A friendly face.';
    $('entry-description').textContent = 'Your group’s invitation is all you need. No sign-in, no public profile.';
    $('join-link').focus({ preventScroll: true });
  } else if (hash.startsWith('#meeting=')) {
    $('join-consent').checked = false;
    showEntry('entry-loading');
    const id = meetingId(hash);
    if (!id) { showEntry('join-link-form'); entryError('That invitation doesn’t look complete. Ask your group for the full link.'); return; }
    try {
      const [meeting, user] = await Promise.all([api(`/meetings/${id}/preview`), identity()]);
      if (generation !== state.generation) return;
      state.meeting = meeting; state.user = user;
      showEntry('join-form');
      $('entry-title').textContent = meeting.name;
      $('entry-description').textContent = 'Take a breath. You’re welcome to listen, share, or simply be here with your group.';
      $('join-title').textContent = 'Welcome to the room.';
      const current = user && (!user.scoped_guest || user.meeting_id === id);
      $('join-name').value = current ? user.display_name : '';
      $('join-name').readOnly = !!current;
      (current ? $('join-consent') : $('join-name')).focus({ preventScroll: true });
    } catch (error) {
      if (generation !== state.generation) return;
      showEntry('join-link-form');
      entryError(error.status === 404 || error.status === 403 ? 'This invitation is unavailable. Ask your group for a current meeting link.' : errorMessage(error));
    }
  } else showView('home');
  if (!hash || !['#how-it-works'].includes(hash)) window.scrollTo({ top: 0, behavior: 'instant' });
}

$('create-form').onsubmit = async event => {
  event.preventDefault();
  const button = event.submitter, generation = state.generation;
  if (button.disabled) return;
  const name = $('create-name').value.trim(), title = $('create-title').value.trim();
  if (!name || !title) { entryError('Please enter a name for yourself and your meeting.'); return; }
  button.disabled = true; entryError();
  try {
    state.user = await api('/start', { body: { display_name: name } });
    if (generation !== state.generation) return;
    const meeting = await api('/meetings', { body: { name: title, open_invite: true } });
    if (generation !== state.generation) return;
    // Store the real link in the UI before configuring optional speaking turns,
    // so a temporary moderation error cannot make a created meeting disappear.
    state.meeting = meeting;
    $('created-link').value = invitation(meeting.meeting_id);
    showEntry('created-panel');
    if ($('create-turns').checked) {
      try { await api(`/meetings/${meeting.meeting_id}/speaking`, { body: { enabled: true } }); }
      catch { toast('Your link is ready. Enable chair-guided sharing from inside the meeting.', true); }
    }
    if (generation === state.generation) $('created-continue').focus();
  } catch (error) { if (generation === state.generation) entryError(errorMessage(error)); }
  finally { button.disabled = false; }
};
$('join-link-form').onsubmit = event => {
  event.preventDefault();
  const id = meetingId($('join-link').value.trim());
  if (!id) { entryError('Paste a complete invitation from this Fellowship service.'); return; }
  go(`#meeting=${id}`);
};
$('created-continue').onclick = () => go(`#meeting=${state.meeting.meeting_id}`);
async function join(microphone) {
  if (!$('join-form').reportValidity() || state.pending || !state.meeting) return;
  const name = $('join-name').value.trim();
  if (!name) { entryError('Enter a first name or chosen name.'); return; }
  const generation = ++state.joinGeneration;
  setJoinPending(true); entryError();
  $('entry-status').textContent = microphone ? 'Preparing your microphone. It will start muted…' : 'Opening your meeting. Your devices will stay off…';
  try {
    let user = await identity();
    if (generation !== state.joinGeneration) return;
    if (!user || (user.scoped_guest && user.meeting_id !== state.meeting.meeting_id))
      user = await api(`/meetings/${state.meeting.meeting_id}/guest`, { body: { display_name: name } });
    if (generation !== state.joinGeneration) return;
    state.user = user;
    await call.start({ id: state.meeting.meeting_id, user, microphone });
  } catch (error) {
    if (generation !== state.joinGeneration) return;
    setJoinPending(false); $('entry-status').textContent = ''; entryError(errorMessage(error));
  }
}
$('join-form').onsubmit = event => { event.preventDefault(); join(false); };
$('join-microphone').onclick = () => join(true);
$('cancel-join').onclick = () => { ++state.joinGeneration; call.leave(); setJoinPending(false); $('entry-status').textContent = 'Joining canceled. Your devices are off.'; };

function clearTiles() {
  for (const playback of state.playbacks.values()) playback.dispose();
  state.playbacks.clear(); state.tiles.clear(); state.peopleKey = null; $('participant-grid').replaceChildren(); $('enable-sound').hidden = true;
}
function createTile(member) {
  const tile = make('article', undefined, 'participant-tile');
  tile.id = `participant-${member.id}`;
  tile.dataset.memberId = member.id;
  const avatar = make('span', undefined, 'tile-avatar'), video = make('video');
  avatar.setAttribute('aria-hidden', 'true');
  video.id = `video-${member.id}`; video.autoplay = true; video.playsInline = true; video.muted = true;
  const caption = make('div', undefined, 'tile-caption'), info = make('span'), name = make('span', undefined, 'tile-name'), status = make('small', undefined, 'tile-status'), mic = make('span');
  info.append(name, status); caption.append(info, mic);
  const hand = make('span', undefined, 'hand-tag'); hand.append(icon('hand'), 'Hand raised'); hand.hidden = true;
  tile.append(avatar, video, caption, hand);
  if (!member.self) {
    const playback = new RemotePlayback(video, () => { $('enable-sound').hidden = ![...state.playbacks.values()].some(p => p.blocked); });
    state.playbacks.set(member.id, playback);
  }
  const result = { tile, avatar, video, name, status, mic, hand };
  state.tiles.set(member.id, result); $('participant-grid').append(tile); return result;
}
function updateTile(member, index) {
  const nodes = state.tiles.get(member.id) || createTile(member);
  nodes.tile.dataset.color = index % 5;
  nodes.tile.classList.toggle('self', member.self);
  nodes.tile.classList.toggle('speaking', !!member.speaking && !member.muted);
  nodes.avatar.textContent = [...member.display_name.trim()][0]?.toUpperCase() || '•';
  nodes.name.textContent = `${member.display_name}${member.self ? ' · You' : ''}`;
  const status = member.is_admin ? 'Chair' : member.hand_raised ? 'Hand raised' : member.speaking_allowed ? 'Invited to share' : member.muted ? 'Listening' : 'Microphone on';
  nodes.status.textContent = member.failed ? 'Connection interrupted' : member.connected ? status : 'Connecting…';
  nodes.mic.replaceChildren(icon(member.muted ? 'mic-off' : 'mic'));
  nodes.hand.hidden = !member.hand_raised;
  if (member.stream && nodes.video.srcObject !== member.stream) {
    nodes.video.srcObject = member.stream;
    if (!member.self) state.playbacks.get(member.id).attach(member.stream);
    nodes.video.play().catch(() => {});
  }
  const showVideo = () => nodes.tile.classList.toggle('video-on', member.camera && nodes.video.videoWidth > 0);
  nodes.video.onresize = showVideo; nodes.video.onloadeddata = showVideo; showVideo();
  if (!member.self && member.stream) {
    const playback = state.playbacks.get(member.id);
    const audioKey = member.stream.getAudioTracks().map(t => t.id).join(',');
    playback.attach(member.stream);
    if (playback._audioKey !== audioKey) { playback._audioKey = audioKey; playback.play(); }
  }
}
function renderPeople(members) {
  const root = $('participant-list'), focus = root.contains(document.activeElement) ? document.activeElement.dataset.actionKey : null;
  root.replaceChildren();
  for (const member of members) {
    const row = make('div', undefined, 'person-row'); row.dataset.memberId = member.id;
    const info = make('div', undefined, 'person-info'), name = make('span');
    name.append(make('strong', `${member.display_name}${member.self ? ' · You' : ''}`, 'person-name'), make('small', member.is_admin ? 'Chair' : member.hand_raised ? 'Hand raised' : member.speaking_allowed ? 'Invited to share' : member.muted ? 'Listening' : 'Microphone on', 'person-status'));
    info.append(make('span', [...member.display_name][0]?.toUpperCase() || '•', 'person-avatar'), name);
    if (member.hand_raised) { const hand = icon('hand'); hand.classList.add('person-hand'); info.append(hand); }
    row.append(info);
    if (call.isChair && !member.self && !member.is_admin) {
      const controls = make('div', undefined, 'person-actions');
      const add = (label, type, className) => {
        const button = action(label, async () => {
          if (type === 'remove' && !confirm(`Remove ${member.display_name} from this meeting?`)) return;
          await call.moderate(member, type);
        }, className);
        button.dataset.actionKey = `${member.id}-${type}`; controls.append(button);
      };
      if (member.hand_raised) add('Invite to share', 'approve');
      if (member.speaking_allowed) add('End share', 'end-turn');
      if (!call.room.raise_hand_enabled) add(member.moderator_muted ? 'Allow microphone' : 'Mute', member.moderator_muted ? 'allow' : 'mute');
      add('Remove', 'remove', 'remove'); row.append(controls);
    }
    if (!member.self && member.code) {
      const details = make('details', undefined, 'verify-code');
      details.dataset.peerId = member.id;
      details.append(make('summary', 'Verify connection'), make('code', member.code), make('p', 'Compare this code through a separate trusted channel. Matching codes verify this pair of peer certificates.'));
      details.open = state.openCodes?.has(member.id) || false;
      details.ontoggle = () => { state.openCodes ||= new Set(); if (details.open) state.openCodes.add(member.id); else state.openCodes.delete(member.id); };
      row.append(details);
    }
    root.append(row);
  }
  if (focus) [...root.querySelectorAll('[data-action-key]')].find(n => n.dataset.actionKey === focus)?.focus({ preventScroll: true });
}
function labelControl(id, glyph, text, pressed) {
  const button = $(id);
  if (button.dataset.label !== text) {
    button.replaceChildren(icon(glyph), make('span', text)); button.dataset.label = text;
  }
  button.setAttribute('aria-label', text);
  if (pressed !== undefined) button.setAttribute('aria-pressed', String(pressed));
}
function renderCall() {
  if (!call.room || state.view !== 'call') return;
  const members = call.view().sort((a, b) => Number(b.self) - Number(a.self) || a.display_name.localeCompare(b.display_name));
  const ids = new Set(members.map(m => m.id));
  for (const [id, nodes] of state.tiles) if (!ids.has(id)) {
    state.playbacks.get(id)?.dispose(); state.playbacks.delete(id); nodes.tile.remove(); state.tiles.delete(id);
  }
  members.forEach(updateTile);
  $('participant-grid').classList.toggle('solo', members.length === 1);
  $('participant-grid').classList.toggle('many', members.length > 4);
  $('participant-count').textContent = members.length;
  $('solo-note').hidden = members.length > 1;
  $('chair-controls').hidden = !call.isChair;
  $('chair-turns').checked = call.room.raise_hand_enabled;
  labelControl('microphone-button', call.muted ? 'mic-off' : 'mic', call.muted ? 'Unmute' : 'Mute', !call.muted);
  $('microphone-button').disabled = call.blocked || !!state.microphoneBusy;
  $('microphone-button').title = call.waitingForTurn ? 'Raise your hand to be invited to share' : call.blocked ? 'Muted by the chair' : '';
  labelControl('camera-button', call.camera ? 'video' : 'video-off', call.camera ? 'Camera on' : 'Camera off', call.camera);
  $('camera-button').disabled = !!state.cameraBusy;
  $('hand-button').hidden = call.isChair || !call.room.raise_hand_enabled;
  labelControl('hand-button', 'hand', call.self?.speaking_allowed ? 'End my share' : call.self?.hand_raised ? 'Lower hand' : 'Raise hand', !!(call.self?.hand_raised || call.self?.speaking_allowed));
  $('call-status').textContent = call.waitingForTurn ? (call.self.hand_raised ? 'Your hand is raised. The chair will invite you when it’s your turn.' : 'You’re welcome to listen. Raise your hand when you’d like to share.') : call.blocked ? 'The chair has muted your microphone.' : call.self?.speaking_allowed ? 'You’re invited to share. Unmute when you’re ready.' : 'Your microphone starts muted. You can unmute whenever you’re ready.';
  const peers = members.filter(m => !m.self), verified = peers.length > 0 && peers.every(m => m.connected && m.verified);
  $('encryption-status').textContent = !peers.length ? 'Encrypted calls · No built-in recording' : verified ? 'Peer encryption verified · No built-in recording' : peers.some(p => p.failed) ? 'A peer connection needs attention' : 'Checking encrypted peer connections…';
  // Keep participant controls stable during periodic encryption/statistics updates.
  const peopleKey = JSON.stringify(members.map(m => [m.id,m.display_name,m.muted,m.hand_raised,m.speaking_allowed,m.is_admin,m.moderator_muted,m.code]));
  if (peopleKey !== state.peopleKey) { state.peopleKey = peopleKey; renderPeople(members); }
}

for (const button of document.querySelectorAll('[data-create]')) button.onclick = () => go('#create');
for (const button of document.querySelectorAll('[data-join]')) button.onclick = () => go('#join');
for (const button of document.querySelectorAll('[data-privacy]')) button.onclick = () => { $('privacy-dialog')._returnFocus = button; $('privacy-dialog').showModal(); };
for (const button of document.querySelectorAll('[data-close-dialog]')) button.onclick = () => button.closest('dialog').close();
for (const dialog of document.querySelectorAll('dialog')) {
  dialog.addEventListener('close', () => dialog._returnFocus?.focus({ preventScroll: true }));
  dialog.addEventListener('click', event => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close(); } });
}
$('entry-back').onclick = $('left-home').onclick = () => go();
$('rejoin-button').onclick = () => go(`#meeting=${state.meeting.meeting_id}`);
$('leave-button').onclick = () => { call.leave(); clearTiles(); setJoinPending(false); $('left-description').textContent = 'You’ve left the meeting. Your microphone and camera are off.'; showView('left'); $('rejoin-button').focus(); };
$('microphone-button').onclick = () => run($('microphone-button'), async () => { state.microphoneBusy = true; try { await call.toggleMicrophone(); } finally { state.microphoneBusy = false; } });
$('camera-button').onclick = () => run($('camera-button'), async () => { state.cameraBusy = true; try { await call.toggleCamera(); } finally { state.cameraBusy = false; } });
$('hand-button').onclick = () => run($('hand-button'), () => call.hand());
$('chair-turns').onchange = () => run($('chair-turns'), async () => { try { await call.turns($('chair-turns').checked); } finally { $('chair-turns').checked = !!call.room?.raise_hand_enabled; } });
$('people-button').onclick = () => { const open = $('meeting-sidebar').classList.toggle('open'); $('people-button').setAttribute('aria-expanded', String(open)); if (open) $('close-people').focus(); };
$('close-people').onclick = () => { $('meeting-sidebar').classList.remove('open'); $('people-button').setAttribute('aria-expanded', 'false'); $('people-button').focus(); };
document.addEventListener('keydown', event => { if (event.key === 'Escape' && $('meeting-sidebar').classList.contains('open')) $('close-people').click(); });
async function copyLink(button, input) {
  try { await navigator.clipboard.writeText(input.value); toast('Invitation copied. Share it privately with your group.'); }
  catch { input.focus(); input.select(); toast('Your invitation is selected. Copy it to share with your group.'); }
}
function invite(from) { $('invite-link').value = invitation(state.meeting.meeting_id); $('invite-dialog')._returnFocus = from; $('invite-dialog').showModal(); }
$('invite-button').onclick = () => invite($('invite-button'));
$('solo-invite').onclick = () => invite($('solo-invite'));
$('copy-created-link').onclick = () => copyLink($('copy-created-link'), $('created-link'));
$('copy-invite').onclick = () => copyLink($('copy-invite'), $('invite-link'));
$('enable-sound').onclick = () => Promise.allSettled([...state.playbacks.values()].map(p => p.play()));
setInterval(() => {
  if (!call.room || state.view !== 'call') return;
  const seconds = Math.floor((Date.now() - call.startedAt) / 1000);
  $('call-duration').textContent = `${String(Math.floor(seconds / 60)).padStart(2,'0')}:${String(seconds % 60).padStart(2,'0')}`;
}, 1000);
window.addEventListener('hashchange', route);
window.addEventListener('pagehide', () => call.leave());
window.addEventListener('beforeunload', event => { if (call.busy) { event.preventDefault(); event.returnValue = ''; } });
route();
