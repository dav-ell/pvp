import { createPeerConnection } from '../packages/pvp-call/src/mesh.js';
import { captureList, moveNavigation, reveal } from '/motion.js';
import { BandwidthMeter, bandwidthLabel, bandwidthControls, validCaps, videoCap, saverCaps, connectionIsMetered, saverLimit } from './bandwidth.js';
import { MeetingLinks, meetingId } from '/meetings.js';
import { GroupCalls } from '/group-calls.js';
import { inspectReport, endpointLabel, mediaCaptureCommand } from '/inspector.js';
import { isRelay, requireCandidate, requireEncryptedSdp, safetyCode, inspectEncryptionReport } from '/security.js';
import { bindSelfPreview, resetStage, bindViewport } from './call-stage.js';
import { mountTrustPanel } from './trust.js';
import { RemotePlayback } from './playback.js';
import { monitorLocalMicrophone, replaceMicrophone, OutboundVideoStats, selectedQuality, sentVideoLabel } from './media-health.js';
import { MeetingJoin } from './meeting-join.js';
import { icon as uiIcon, callAction, rowAction, labeledAction, bindLabels, bindSheet, openSheet, closeSheet, videoState } from './ui.js';
const $ = (id) => document.getElementById(id);
bindViewport();
// iPads can report MacIntel; keep the native download specific to Macs.
const isMac = /Mac/i.test(navigator.userAgentData?.platform || navigator.platform || navigator.userAgent) && !(navigator.maxTouchPoints > 1);
document.querySelectorAll('[data-mac-download]').forEach(node => { node.hidden = !isMac; });
const PRESETS = {
  saver: { resolution: 360, fps: 15, video: 400, audio: 24 },
  balanced: { resolution: 720, fps: 30, video: 1800, audio: 64 },
  studio: { resolution: 1080, fps: 30, video: 4000, audio: 96 },
};
const state = { me: null, friends: [], history: [], view: 'meetings', tab: 'friends', ws: null, stream: null, pc: null, call: null, candidates: [], retry: null, stats: null, lastStats: null, callTimeout: null, preferences: null, register: false, replaced: false, mediaPromise: null, mediaGeneration: 0, authGeneration: 0, restoreRetry: null, retryAttempt: 0, signalCount: 0, ring: null, audio: null };
let toastTimer, qualityTimer, messageChain = Promise.resolve();
let trustScope = null, trustPanel;
let guestPreviewGeneration = 0;
const DEFAULTS = { dataSend:'auto', dataReceive:'auto', preset: 'balanced', ...PRESETS.balanced, camera: '', mic: '', echoCancellation: true };
let echoCancellationChanging = false;
let microphoneMonitor, microphoneChange, microphoneChangeId = 0, mutedSpeechActive = false;
const groupMediaStats = new Map();
const groups = new GroupCalls({mediaStats:sampleGroupMedia,mediaState:()=>queueMicrotask(refreshMediaHealth),cameraBusy:()=>!!state.cameraPromise,devices:()=>enumerateDevices(),device:setGroupDevice,browse:()=>changeView('meetings'),enableMicrophone:()=>meetingJoin.upgrade(),admitted:id=>meetingJoin.admitted(id),rejected:message=>meetingJoin.rejected(message),ended:reason=>meetingJoin.ended(reason),motion:{captureList},user:()=>state.me, friends:()=>state.friends, preferences:()=>state.preferences, stream:()=>state.stream, capture:(voice=true)=>prepareMedia(false,voice), camera:toggleVideo, stopMedia, send, busy:()=>!!state.call, toast, level:()=>Number($('mic-level').value)/4, ring:()=>{primeSound();ring('Group call');}, stopRing:stopRinging, manageMeeting:id=>meetingLinks.open(id),moderate:(id,member,action)=>meetingLinks.moderate(id,member,action),api,primeSound,approved:speakingTone, quality:async preset=>{Object.assign(state.preferences,PRESETS[preset],{preset});renderPreferences();await savePreferences();}});

const meetingLinks=new MeetingLinks({arrive:reveal,navigate:changeView,user:()=>state.me,friends:()=>state.friends,api,toast,busy:()=>groups.busy||!!state.call,follow:id=>meetingJoin.open(id),start:id=>openMeetingEntry(id)});

const meetingJoin = new MeetingJoin({
  user:()=>state.me, api, busy:()=>groups.busy||!!state.call, joined:()=>groups.joined,
  audioConstraints:()=>mediaConstraints().audio,
  authenticate:async(id,name)=>{
    if(state.me && (!state.me.scoped_guest || state.me.meeting_id===id)) return state.me;
    cancelSessionRenewal(); clearTimeout(state.restoreRetry); const generation=++state.authGeneration;
    const user=await api(`/meetings/${id}/guest`,{method:'POST',body:{display_name:name}});
    if(generation!==state.authGeneration)throw new DOMException('Sign-in changed','AbortError');
    await enterApp(user); return user;
  },
  takeOver:()=>{state.replaced=false;connect();},
  ready:async()=>{
    if(!state.ws&&!state.replaced)connect();
    for(let i=0;i<150;i++){
      if(state.replaced)throw Error('This meeting is open in another tab. Close it there before rejoining.');
      if(state.ws?.readyState===WebSocket.OPEN && groups.meetingsAvailable)return;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    throw Error('Unable to reach the meeting. Check your connection and try again.');
  },
  adopt:stream=>{stopMedia();state.stream=stream;if(stream.getAudioTracks().length)startMicrophoneMonitor(stream);},
  enter:id=>groups.startMeeting(id,true), cancelAdmission:()=>groups.leave('canceled'),
  upgrade:async stream=>{
    const wasMuted=groups.muted&&state.stream.getAudioTracks().some(t=>t.readyState==='live');
    await groups.attachMicrophone(stream.getAudioTracks()[0]);groups.muted=wasMuted||groups.moderatorMuted;stream.getAudioTracks().forEach(t=>t.enabled=!groups.muted);
    state.stream.getAudioTracks().forEach(track=>{state.stream.removeTrack(track);track.stop();});
    stream.getAudioTracks().forEach(track=>state.stream.addTrack(track));startMicrophoneMonitor(state.stream);
    groups.render();groups.broadcastState();enumerateDevices().catch(()=>{});
  },
  signIn:()=>{$('auth-view').hidden=false;$('app-view').hidden=true;showAccount();},
  manage:async id=>{await meetingJoin.o.ready();await meetingLinks.open(id);}
});
async function openMeetingEntry(id){
  if(location.hash!==`#meeting=${id}`)history.replaceState(null,'',`#meeting=${id}`);
  await meetingJoin.open(id);
}


function mediaHealth(detail) { document.dispatchEvent(new CustomEvent('pvp-media-health', { detail })); }
function mutedSpeech(active, moderated = false) {
  if (mutedSpeechActive === active) return;
  mutedSpeechActive = active; mediaHealth({type:'muted-speech', active, moderated});
}
function microphoneStatus(status, message, deviceLabel = '') {
  state.microphoneHealth = {type:'microphone', status, message, deviceLabel};
  mediaHealth(state.microphoneHealth);
}
function stopMicrophoneMonitor() {
  microphoneMonitor?.stop(); microphoneMonitor = null; mutedSpeech(false);
  for (const id of ['mic-level', 'call-mic-level']) $(id).value = 0;
  $('mic-feedback').textContent = 'Start a device check to test your microphone.';
}
function startMicrophoneMonitor(stream) {
  stopMicrophoneMonitor(); primeSound();
  const track = stream.getAudioTracks()[0];
  if (!track || track.readyState !== 'live') return;
  try {
    microphoneMonitor = monitorLocalMicrophone(track, state.audio, () => ({
      muted: !track.enabled,
      active: !document.hidden && (groups.joined || state.call?.status === 'connected'),
      moderated: groups.joined && groups.moderatorMuted
    }), ({level, mutedSpeech: nudge, moderated}) => {
      const message = track.readyState !== 'live' ? 'Microphone disconnected — switching input…' : !track.enabled ? 'Microphone muted' : state.audio.state !== 'running' ? 'Click to check microphone sound' : level > .005 ? 'Microphone is picking up sound' : 'No sound detected — speak or choose another microphone';
      for (const id of ['mic-level', 'call-mic-level']) $(id).value = track.enabled ? Math.min(1, level * 4) : 0;
      $('mic-feedback').textContent = message; $('call-mic-feedback').textContent = message;
      mutedSpeech(nudge, moderated);
      const speaking = !document.hidden && track.enabled && track.readyState === 'live' && level > .025;
      document.querySelector('#group-grid .self')?.classList.toggle('speaking', !!speaking);
      $('local-video').closest('.self-video').classList.toggle('speaking', !!speaking);
    }, {ended:()=>{if(state.stream===stream)recoverMicrophone('ended').catch(()=>{});}});
  } catch { /* Meter support must not prevent joining a call. */ }
}
function sampleGroupMedia(report, id) {
  let meter = groupMediaStats.get(id);
  if (!meter) { meter = new OutboundVideoStats(); groupMediaStats.set(id, meter); }
  meter.sample(report); refreshMediaHealth();
}
function refreshMediaHealth() {
  // Constructor renders can run before GroupCalls is assigned; the option queues this helper.
  microphoneMonitor?.update();
  const scope = groups.joined ? 'group' : 'direct';
  const peers = groups.joined
    ? [...groups.links.values()].map(link=>({id:link.id,path:link.useOverlay?'encoded-forwarding':'rtp',rows:link.useOverlay?(groups.overlay?.observedOutput()||[]):(groupMediaStats.get(link.id)?.fresh()||[])}))
    : state.call ? [{id:state.call.peer?.id||'peer',rows:state.call.videoStats?.fresh()||[]}] : [];
  for (const id of groupMediaStats.keys()) if (!groups.links.has(id)) groupMediaStats.delete(id);
  const camera = !!state.stream?.getVideoTracks().some(track=>track.enabled&&track.readyState==='live');
  const sharing = !!(groups.joined ? groups.display : state.call?.displayStream);
  mediaHealth({type:'quality',scope,selected:selectedQuality(state.preferences),sent:{peers,camera,sharing,label:sentVideoLabel(peers,{camera,sharing})},previewNotice:'Your preview shows the local camera. Sent quality can be lower.'});
}
function microphoneSenders() {
  return [state.pc,...[...groups.links.values()].map(link=>link.pc)]
    .filter(pc=>pc&&pc.signalingState!=='closed').flatMap(pc=>pc.getSenders());
}
async function switchMicrophone(deviceId, automatic = false) {
  const stream = state.stream, track = stream?.getAudioTracks()[0];
  // Saving an input preference must never capture for a listen-only participant.
  if (!track) return;
  if (echoCancellationChanging) throw Error('Wait for microphone processing to finish changing.');
  const generation = state.mediaGeneration, account = state.me, changeId = ++microphoneChangeId;
  const valid = () => generation===state.mediaGeneration && account===state.me && stream===state.stream && changeId===microphoneChangeId;
  const previous = state.preferences.mic;
  const enabled = () => track.enabled && !(groups.joined && (groups.muted || groups.moderatorMuted));
  const constraints = {...mediaConstraints().audio}; delete constraints.deviceId;
  if (deviceId) constraints.deviceId={exact:deviceId};
  if (automatic) microphoneStatus('recovering', 'Microphone disconnected. Switching to an available input…');
  const pending = (async()=>{
    try {
      const next = await replaceMicrophone({stream,track,valid,enabled,senders:microphoneSenders,
        capture:()=>navigator.mediaDevices.getUserMedia({audio:constraints,video:false})});
      if (!valid()) { next.stop(); return; }
      state.preferences.mic=deviceId; startMicrophoneMonitor(stream);
      if (groups.joined) {groups.muted=!next.enabled;groups.render();groups.broadcastState();}
      else if(state.call) syncDirectControls();
      const deviceLabel=next.label||'System default microphone';
      microphoneStatus(automatic?'switched':'ready',automatic?`Microphone switched to ${deviceLabel}.`:`Using ${deviceLabel}.`,deviceLabel);
      await savePreferences(); await enumerateDevices();
    } catch(error) {
      if(valid()) {
        state.preferences.mic=previous;
        if(automatic) {microphoneStatus('unavailable','No microphone is available. Listening continues. Choose an input in Audio & video.');mutedSpeech(false);}
      }
      throw error;
    }
  })();
  microphoneChange=pending;
  try{return await pending;}finally{if(microphoneChange===pending)microphoneChange=null;}
}
async function recoverMicrophone(reason, devices) {
  if (microphoneChange || state.mediaPromise || echoCancellationChanging || !state.preferences) return;
  const track=state.stream?.getAudioTracks()[0]; if(!track)return;
  const current=track.getSettings().deviceId||state.preferences.mic;
  const inputs=devices?.filter(device=>device.kind==='audioinput');
  const missing=inputs && current && !inputs.some(device=>device.deviceId===current);
  if(reason!=='ended'&&track.readyState==='live'&&!missing)return;
  stopMicrophoneMonitor();
  try { await switchMicrophone('',true); }
  catch(error) { if(error.name!=='AbortError' && state.stream?.getAudioTracks().includes(track)) enumerateDevices().catch(()=>{}); }
}
async function playRemoteAudio() {
  const call = state.call;
  if (!call || !$('remote-video').srcObject?.getAudioTracks().length) return;
  call.playback ||= new RemotePlayback($('remote-video'), blocked => {
    if (state.call === call) $('enable-playback').hidden = !blocked;
  });
  call.playback.attach($('remote-video').srcObject);
  await call.playback.play();
}

function networkEvent(detail, source = 'Application event') {
  if (!state.call) return;
  const events = state.call.networkEvents ||= [];
  events.push({ at: new Date().toISOString(), source, detail: String(detail).slice(0, 256) });
  if (events.length > 120) events.shift();
}
function connectionReport() {
  return { schemaVersion: 1, exportedAt: new Date().toISOString(), client: 'PVP browser',
    notice: 'App-reported observations, not an independent packet capture. Contains network addresses. No credentials or media.',
    signaling: { source: 'Browser WebSocket URL and state', service: state.ws?.url || null, connected: state.ws?.readyState === WebSocket.OPEN, socket: null },
    media: state.call?.evidence || null, events: state.call?.networkEvents || [] };
}
function inspectorTable(id, headers, rows) {
  const table = element('table'), head = element('tr');
  for (const label of headers) head.append(element('th', '', label));
  const thead = element('thead'); thead.append(head); table.append(thead);
  const body = element('tbody');
  for (const values of rows) { const row = element('tr'); for (const value of values) row.append(element('td', '', value == null ? 'unavailable' : String(value))); body.append(row); }
  table.append(body); $(id).replaceChildren(table);
}
function renderInspector() {
  if (!$('inspector-dialog').open) return;
  $('connection-bandwidth').textContent=bandwidthLabel([state.call?.meter?.rate]);
  $('connection-bandwidth-status').textContent=state.call?.bandwidthSupported?'Receive limits supported by your friend.':'Waiting for receive-limit support. Older clients may not honor receive limits.';
  const d = state.call?.evidence, age = d ? Math.max(0, (Date.now() - Date.parse(d.sampledAt)) / 1000) : null;
  const fresh = age != null && age < 4;
  $('inspector-sampled').textContent = d ? `${d.source} · sampled ${d.sampledAt} · ${age.toFixed(1)}s ago${fresh ? '' : ' · STALE'}` : 'No WebRTC statistics available yet. No packet capture is running.';
  $('inspector-route').textContent = fresh && d?.direct ? 'Direct media path · WebRTC reported' : 'Media path not yet verified';
  document.querySelector('.connection-arrow').textContent = fresh && d?.selectedPairId ? '↔' : '…';
  $('inspector-local').textContent = endpointLabel(d?.local); $('inspector-remote').textContent = endpointLabel(d?.remote);
  $('inspector-local-type').textContent = d?.local?.candidateType || 'Type unavailable'; $('inspector-remote-type').textContent = d?.remote?.candidateType || 'Type unavailable';
  $('inspector-transport').textContent = `${d?.connectionState || 'unavailable'} · ${d?.local?.protocol || 'protocol unavailable'} · selected pair ${d?.selectedPairId || 'unavailable'} · ${d?.selectionSource || 'selection unavailable'}`;
  $('inspector-counters').textContent = `Sent ${d?.bytesSent ?? 'unavailable'} bytes · received ${d?.bytesReceived ?? 'unavailable'} bytes · RTT ${d?.rttSeconds == null ? 'unavailable' : Math.round(d.rttSeconds * 1000) + ' ms'}`;
  $('inspector-encryption').textContent = `DTLS ${d?.dtlsState || 'unavailable'} · ${d?.dtlsCipher || 'cipher unavailable'} · SRTP ${d?.srtpCipher || 'cipher unavailable'}. Relay policy: disabled. Observed relay: ${fresh && d?.direct ? 'none in selected pair' : 'path not verified'}.`;
  $('inspector-signaling').textContent = `${state.ws?.url || 'URL unavailable'} · ${state.ws?.readyState === WebSocket.OPEN ? 'connected' : 'disconnected'}`;
  $('inspector-servers').textContent = `Configured STUN URLs (configuration): ${d?.configuredServers?.join(', ') || 'unavailable'}`;
  inspectorTable('inspector-candidates', ['Side', 'Type', 'Reported endpoint', 'Protocol', 'Reported STUN URL'], (d?.candidates || []).map(c => [c.side, c.candidateType, endpointLabel(c), c.protocol, c.url]));
  inspectorTable('inspector-pairs', ['Path', 'State', 'Local ↔ remote', 'STUN requests sent / received', 'Responses sent / received'], (d?.pairs || []).map(p => [p.selected ? 'SELECTED' : 'TESTED', p.state, `${endpointLabel(p.local)} ↔ ${endpointLabel(p.remote)}`, `${p.requestsSent ?? 'unavailable'} / ${p.requestsReceived ?? 'unavailable'}`, `${p.responsesSent ?? 'unavailable'} / ${p.responsesReceived ?? 'unavailable'}`]));
  inspectorTable('inspector-media', ['Direction', 'Kind', 'RTP packets', 'Bytes', 'Packets lost'], (d?.media || []).map(r => [r.direction, r.kind, r.packets, r.bytes, r.packetsLost]));
  const command = fresh ? mediaCaptureCommand(d, $('inspector-platform').value) : null;
  $('inspector-command').textContent = command || 'Filter unavailable: waiting for a current literal peer IP, port and protocol.';
  $('copy-inspector-command').disabled = !command;
  $('inspector-events').replaceChildren(...(state.call?.networkEvents || []).slice().reverse().map(e => element('p', '', `${e.at} · ${e.source} · ${e.detail}`)));
}

function toast(message, error = false) {
  clearTimeout(toastTimer); $('toast').classList.remove('pvp-toast-leaving'); $('toast').textContent = message; $('toast').classList.toggle('error', error); $('toast').hidden = false;
  toastTimer = setTimeout(() => {
    $('toast').classList.add('pvp-toast-leaving');
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 180);
  }, 6000);
}
async function api(path, { method = 'GET', body, signal } = {}) {
  const response = await fetch(`/api${path}`, { method, credentials: 'same-origin', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, signal: signal || AbortSignal.timeout(20000) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(result.error || 'The service is unavailable. Please try again.'); error.status = response.status; throw error; }
  return result;
}
function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.classList.add('icon'); svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(svg.namespaceURI, 'use'); use.setAttribute('href', `#i-${name}`); svg.append(use); return svg;
}
function element(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }
function button(text, className, action, symbol) { const node = element('button', className, text); node.type = 'button'; if (symbol) node.prepend(icon(symbol)); node.addEventListener('click', () => Promise.resolve(action()).catch((e) => toast(e.message, true))); return node; }
function avatar(name, size = '', online) {
  const node = element('span', `avatar ${size}`, name.trim().split(/\s+/).slice(0, 2).map((s) => [...s][0] || '').join('').toUpperCase());
  const colors = [['#e5ebd8', '#687d55'], ['#f1e1ce', '#9a7957'], ['#dee9e8', '#5f8181'], ['#e8e0ec', '#8b7396'], ['#e8e4d6', '#8c8462']];
  const color = colors[[...name].reduce((sum, s) => sum + s.codePointAt(0), 0) % colors.length];
  node.style.setProperty('--avatar-bg', color[0]); node.style.setProperty('--avatar-ink', color[1]);
  if (online !== undefined) node.append(element('span', `status-dot ${online ? 'online' : ''}`));
  return node;
}
function fillAvatar(id, name, size) { const node = avatar(name, size); node.id = id; $(id).replaceWith(node); }
function bitrate(value) { return value >= 1000 ? `${(value / 1000).toFixed(1).replace(/\.0$/, '')} Mbps` : `${value} Kbps`; }
function validPreferences(raw) {
  return { echoCancellation: raw.echoCancellation !== false, dataSend: ['off','auto','low','verylow','minimal','none'].includes(raw.dataSend)?raw.dataSend:'auto', dataReceive: ['off','auto','low','verylow','minimal','none'].includes(raw.dataReceive)?raw.dataReceive:'auto', preset: Object.hasOwn(PRESETS, raw.preset) ? raw.preset : 'custom', resolution: [360, 480, 720, 1080].includes(raw.resolution) ? raw.resolution : 720, fps: [15, 24, 30, 60].includes(raw.fps) ? raw.fps : 30, video: Number.isFinite(raw.video) ? Math.max(128, Math.min(8000, raw.video)) : 1800, audio: [24, 48, 64, 96].includes(raw.audio) ? raw.audio : 64, camera: typeof raw.camera === 'string' ? raw.camera : '', mic: typeof raw.mic === 'string' ? raw.mic : '' };
}
function loadPreferences() {
  try { state.preferences = validPreferences(JSON.parse(localStorage.getItem(`pvp.settings.${state.me.id}`)) || DEFAULTS); } catch { state.preferences = { ...DEFAULTS }; }
  renderPreferences();
}
function renderPreferences() {
  const p = state.preferences;
  for (const id of ['echo-cancellation', 'in-call-echo-cancellation', 'group-echo-cancellation']) {
    $(id).checked = p.echoCancellation;
    $(id).disabled = echoCancellationChanging;
  }
  for(const direction of ['Send','Receive']) for(const prefix of ['','call-']) $(prefix+'data-'+direction.toLowerCase()).value=p['data'+direction]||'auto';
  $('data-connection').textContent=connectionIsMetered()?'Cellular, metered, data-saving or slow connection detected. Automatic limits video to 128 Kbps per participant.':navigator.connection?'No metered connection hint detected. You can choose a limit manually.':'Connection detection is unavailable in this browser. Choose a limit manually for cellular or LTE.';
  $('quality-preset').value = p.preset; $('in-call-preset').value = p.preset; $('resolution').value = p.resolution; $('frame-rate').value = p.fps;
  $('bandwidth').value = p.video; $('bandwidth-value').textContent = bitrate(p.video); $('audio-bitrate').value = p.audio;
  const name = { saver: 'Data saver', balanced: 'Balanced', studio: 'High quality', custom: 'Custom' }[p.preset];
  $('quality-summary').textContent = `${name} · ${p.resolution}p`; $('bandwidth-summary').textContent = `Up to ${bitrate(p.video)} video`;
  $('in-call-quality').textContent = `${name} selected · up to ${p.resolution}p · ${p.fps} fps · ${bitrate(p.video)} video + ${p.audio} Kbps audio. Preview is local; sent quality adapts.`;
  queueMicrotask(refreshMediaHealth);
}
async function savePreferences() {
  if (!state.me || !state.preferences) return;
  try { localStorage.setItem(`pvp.settings.${state.me.id}`, JSON.stringify(state.preferences)); $('settings-saved').textContent = 'Saved'; } catch { $('settings-saved').textContent = 'Available for this session'; }
  renderPreferences();
  sendBandwidth(state.call);
  reveal($('settings-saved'), { direction: 0 });
  try { await applyQuality(); } catch (error) { toast(`Your device could not apply these settings: ${error.message}`, true); }
}
function mediaConstraints() {
  const p = state.preferences || DEFAULTS;
  return { video: { width: { ideal: Math.round(p.resolution * 16 / 9) }, height: { ideal: p.resolution }, frameRate: { ideal: p.fps, max: p.fps }, ...(p.camera ? { deviceId: { exact: p.camera } } : {}) }, audio: { echoCancellation: p.echoCancellation, noiseSuppression: true, autoGainControl: true, ...(p.mic ? { deviceId: { exact: p.mic } } : {}) } };
}
async function applyEchoCancellation(stream, track, enabled, previous) {
  const generation = state.mediaGeneration, replaced = [];
  const valid = () => stream === state.stream && generation === state.mediaGeneration;
  try {
    await track.applyConstraints({ ...track.getConstraints(), echoCancellation: enabled });
    if (track.getSettings().echoCancellation === enabled) return;
  } catch { /* Some browsers can only change processing when opening a source. */ }

  if (!valid() || track.readyState !== 'live') throw new DOMException('Capture canceled', 'AbortError');
  const audio = { ...mediaConstraints().audio, echoCancellation: enabled };
  const deviceId = track.getSettings().deviceId;
  if (deviceId) audio.deviceId = { exact: deviceId };
  const sendersFor = tracks => [state.pc, ...[...groups.links.values()].map(link => link.pc)]
    .filter(pc => pc && pc.signalingState !== 'closed')
    .flatMap(pc => pc.getSenders()).filter(sender => tracks.includes(sender.track));
  let captured, next, installed = false, released = false;
  try {
    captured = await navigator.mediaDevices.getUserMedia({ audio, video: false });
    next = captured.getAudioTracks()[0];
    if (!next || next.readyState !== 'live') throw new Error('No microphone was opened.');
    if (!valid()) throw new DOMException('Capture canceled', 'AbortError');
    if (next.getSettings().echoCancellation !== undefined && next.getSettings().echoCancellation !== enabled) {
      // Chromium may reuse the unprocessed source when enabling cancellation.
      // Release both references before opening the processed source again.
      captured.getTracks().forEach(t => t.stop());
      captured = null;
      stopMicrophoneMonitor(); track.stop();
      released = true;
      captured = await navigator.mediaDevices.getUserMedia({ audio, video: false });
      next = captured.getAudioTracks()[0];
      if (!next || next.readyState !== 'live') throw new Error('No microphone was opened.');
    }
    const actual = next.getSettings().echoCancellation;
    if (typeof actual === 'boolean' && actual !== enabled) throw new Error('Your browser could not apply echo cancellation.');
    if (!valid()) throw new DOMException('Capture canceled', 'AbortError');
    next.enabled = track.enabled;
    // Rescan after awaits to include group peers that joined during capture.
    for (;;) {
      const senders = sendersFor([track]);
      if (!senders.length) break;
      for (const sender of senders) {
        next.enabled = track.enabled;
        await sender.replaceTrack(next);
        replaced.push(sender);
        if (!valid()) throw new DOMException('Capture canceled', 'AbortError');
      }
    }
    next.enabled = track.enabled;
    stream.removeTrack(track);
    stream.addTrack(next);
    installed = true;
    startMicrophoneMonitor(stream);
    track.stop();
    captured.getTracks().filter(t => t !== next).forEach(t => t.stop());
  } catch (error) {
    captured?.getTracks().forEach(t => t.stop());
    if (released && valid()) {
      // If reopening fails, restore the previous processing choice and route
      // its replacement to every sender, including ones already updated.
      let restored;
      try {
        restored = await navigator.mediaDevices.getUserMedia({ audio: { ...audio, echoCancellation: previous }, video: false });
        const original = restored.getAudioTracks()[0];
        if (!original || original.readyState !== 'live' || !valid()) throw error;
        original.enabled = track.enabled;
        for (;;) {
          const senders = sendersFor([track, next]);
          if (!senders.length) break;
          for (const sender of senders) {
            await sender.replaceTrack(original);
            if (!valid()) throw error;
          }
        }
        original.enabled = track.enabled;
        for (const old of stream.getAudioTracks()) stream.removeTrack(old);
        stream.addTrack(original);
        startMicrophoneMonitor(stream);
        restored.getTracks().filter(t => t !== original).forEach(t => t.stop());
      } catch {
        restored?.getTracks().forEach(t => t.stop());
      }
      throw error;
    }
    if (installed && valid()) {
      stream.removeTrack(next);
      stream.addTrack(track);
      try { startMicrophoneMonitor(stream); } catch { /* Restore senders below. */ }
    }
    for (const sender of replaced.reverse()) {
      try { if (track.readyState === 'live') await sender.replaceTrack(track); } catch { /* A peer may have left. */ }
    }
    throw error;
  }
}
async function setEchoCancellation(enabled) {
  if (echoCancellationChanging) return;
  if (microphoneChange) { toast('Wait for the microphone to finish switching.'); return; }
  const preferences = state.preferences, previous = preferences.echoCancellation;
  echoCancellationChanging = true;
  preferences.echoCancellation = enabled;
  renderPreferences();
  let tracks = [];
  try {
    // Capture may still be waiting on permission using the previous choice.
    if (state.mediaPromise) await state.mediaPromise;
    if (state.preferences !== preferences) return;
    const stream = state.stream;
    tracks = stream?.getAudioTracks() || [];
    for (const track of tracks) await applyEchoCancellation(stream, track, enabled, previous);
    if (state.preferences === preferences) await savePreferences();
  } catch (error) {
    preferences.echoCancellation = previous;
    await Promise.allSettled(tracks.filter(track => track.readyState === 'live').map(track => track.applyConstraints({ echoCancellation: previous })));
    if (state.preferences === preferences) toast(`Could not change echo cancellation: ${error.message}`, true);
  } finally {
    echoCancellationChanging = false;
    if (state.preferences) renderPreferences();
  }
}
async function prepareMedia(force = false, voice = true) {
  if (force && echoCancellationChanging) throw new Error('Wait for echo cancellation to finish changing.');
  if (groups.joined && force) throw new Error('Finish the group call before changing capture devices.');
  if (state.call?.shareBusy) throw new Error('Wait for screen sharing to finish changing.');
  if (state.mediaPromise) return state.mediaPromise;
  if (state.stream?.getAudioTracks().length && state.stream.getTracks().every((t) => t.readyState === 'live') && !force && (voice || state.stream.getVideoTracks().length)) return state.stream;
  if (!navigator.mediaDevices?.getUserMedia) throw new Error('Microphone access requires HTTPS and a browser that supports WebRTC.');
  const generation = state.mediaGeneration, account = state.me;
  const valid = () => generation === state.mediaGeneration && account === state.me && !!account;
  const promise = (async () => {
    let stream, usedDefaultMic = false;
    const capture = async () => {
      const constraints={...mediaConstraints(), ...(voice ? {video:false} : {})};
      try { return await navigator.mediaDevices.getUserMedia(constraints); }
      catch(error) {
        if(!constraints.audio.deviceId || !['NotFoundError','OverconstrainedError'].includes(error.name) || !valid())throw error;
        delete constraints.audio.deviceId; usedDefaultMic=true;
        return navigator.mediaDevices.getUserMedia(constraints);
      }
    };
    try { stream = await capture(); }
    catch (error) {
      if (error.name === 'NotAllowedError') throw new Error(voice?'Allow microphone access in your browser to join a call.':'Allow camera and microphone access for the device preview.');
      if (error.name === 'NotFoundError' || error.name === 'OverconstrainedError') throw new Error('Camera or microphone not found. Choose System default in Call settings.');
      throw new Error('Your camera or microphone is unavailable. Close other apps using it and try again.');
    }
    if (!valid()) { stream.getTracks().forEach((t) => t.stop()); throw new DOMException("Capture canceled", "AbortError"); }
    if (!stream.getAudioTracks().some(t => t.readyState === 'live')) { stream.getTracks().forEach(t => t.stop()); throw new Error('No microphone was opened. Choose another microphone in Call settings.'); }
    const previous = state.stream, pc = state.pc;
    for (const track of stream.getTracks()) {
      const old = previous?.getTracks().find(t => t.kind === track.kind);
      if (old) track.enabled = old.enabled;
    }
    const replaced = [];
    const rollback = async () => {
      if (state.pc !== pc || !pc || pc.signalingState === 'closed') return;
      for (const { sender, track } of replaced) {
        try { await sender.replaceTrack(track); } catch { /* A closing peer may disappear. */ }
      }
    };
    if (state.pc) {
      try {
        for (const sender of pc.getSenders()) {
          if (sender.track?.kind === 'video' && state.call?.displayStream) continue;
          const replacement = stream.getTracks().find((t) => t.kind === sender.track?.kind);
          if (replacement) { const old = sender.track; replacement.enabled = old.enabled; await sender.replaceTrack(replacement); replaced.push({ sender, track: old }); }
        }
      } catch (error) { await rollback(); stream.getTracks().forEach((t) => t.stop()); throw error; }
    }
    if (!valid() || pc !== state.pc) { await rollback(); stream.getTracks().forEach((t) => t.stop()); throw new DOMException("Capture canceled", "AbortError"); }
    state.stream = stream; previous?.getTracks().forEach((t) => t.stop());
    if(usedDefaultMic){state.preferences.mic='';microphoneStatus('switched',`Microphone switched to ${stream.getAudioTracks()[0].label||'System default'}.`,stream.getAudioTracks()[0].label||'System default');}
    startMicrophoneMonitor(stream);
    $('preview-video').srcObject = stream; $('local-video').srcObject = state.call?.displayStream || stream;
    $('preview-video').hidden = !stream.getVideoTracks().length; $('preview-placeholder').hidden = true; $('stop-preview').hidden = !!state.call;
    $('preview-caption').textContent = 'Looking good. You’re ready.';
    enumerateDevices().catch(() => {}); return stream;
  })();
  state.mediaPromise = promise;
  try { return await promise; } finally { if (state.mediaPromise === promise) state.mediaPromise = null; }
}
function stopMedia() {
  state.mediaGeneration++; microphoneChangeId++; microphoneChange = null; state.microphoneHealth = null; state.mediaPromise = null; state.cameraPromise = null; state.cameraFacing = null;
  for (const id of ['preview-video', 'local-video', 'group-self-video']) $(id).classList.remove('rear-camera');
  stopMicrophoneMonitor();
  state.stream?.getTracks().forEach((t) => t.stop()); state.stream = null;
  $('preview-video').srcObject = null; $('local-video').srcObject = null;
  $('preview-video').hidden = true; $('preview-placeholder').hidden = false; $('stop-preview').hidden = true; $('preview-caption').textContent = 'Camera is off';
}
async function enumerateDevices() {
  if (!navigator.mediaDevices?.enumerateDevices) return;
  const account = state.me;
  const devices = await navigator.mediaDevices.enumerateDevices();
  if (!account || account !== state.me) return;
  for (const [id, kind, key] of [['camera-device','videoinput','camera'],['group-camera-device','videoinput','camera'],['mic-device','audioinput','mic'],['group-mic-device','audioinput','mic'],['in-call-mic','audioinput','mic']]) {
    const select = $(id); select.replaceChildren(new Option('System default', ''));
    devices.filter((d) => d.kind === kind).forEach((d, i) => select.add(new Option(d.label || `${kind === 'videoinput' ? 'Camera' : 'Microphone'} ${i + 1}`, d.deviceId)));
    if (state.preferences[key] && ![...select.options].some((option) => option.value === state.preferences[key])) select.add(new Option('Previously selected device (unavailable)', state.preferences[key]));
    select.value = state.preferences[key];
  }
  return devices;
}
navigator.mediaDevices?.addEventListener?.('devicechange', async () => {
  try { const devices=await enumerateDevices(); if(devices)await recoverMicrophone('devicechange',devices); } catch { /* Device discovery can be unavailable after permission changes. */ }
});
async function applyQuality() {
  if(groups.joined){groups.broadcastState();await groups.overlay?.refresh();await groups.limits();}
  const p = state.preferences, track = state.stream?.getVideoTracks()[0];
  if (track) await track.applyConstraints({ width: { ideal: Math.round(p.resolution * 16 / 9) }, height: { ideal: p.resolution }, frameRate: { ideal: p.fps, max: p.fps } });
  const screen = state.call?.displayStream?.getVideoTracks()[0];
  if (screen) await screen.applyConstraints({ frameRate: { ideal: p.fps, max: p.fps } });
  if (!state.pc || state.pc.signalingState === 'closed') return;
  for (const sender of state.pc.getSenders()) {
    if (!sender.track) continue;
    const parameters = sender.getParameters();
    if (!parameters.encodings?.length) continue; // Apply again after SDP negotiation.
    for (const encoding of parameters.encodings) {
      encoding.maxBitrate = (sender.track.kind === 'video' ? videoCap(p.video,saverCaps(state.call?.caps?.send||{camera:null,screen:null},p.dataSend),state.call?.requested,!!state.call?.displayStream) : p.audio) * 1000;
      if (sender.track.kind === 'video') {
        const cap = encoding.maxBitrate / 1000;
        encoding.active = cap !== 0;
        if (!encoding.active) delete encoding.maxBitrate;
        encoding.maxFramerate = Math.min(p.fps, cap <= 128 ? 10 : cap <= 400 ? 15 : 60);
        const height = cap <= 128 ? 180 : cap <= 400 ? 360 : p.resolution;
        encoding.scaleResolutionDownBy = state.call?.displayStream ? 1 : Math.max(1, (sender.track.getSettings().height || p.resolution) / height);
      }
    }
    if (sender.track.kind === 'video') parameters.degradationPreference = 'maintain-framerate';
    await sender.setParameters(parameters);
  }
}
function changeView(view) {
  if(meetingJoin.phase!=='capturing'&&meetingJoin.phase!=='connecting')meetingJoin.hide();
  state.view = view;
  document.querySelector('.workspace').classList.add('browsing');
  $('meetings-dialog').hidden = view !== 'meetings';
  $('voice-link-view').hidden = view !== 'voice-link';
  $('meeting-links-nav').classList.toggle('active', view === 'meetings');
  for (const name of ['people', 'recent', 'settings']) $(`${name}-view`).hidden = name !== view;
  document.querySelectorAll('[data-view]').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
  moveNavigation();
  $('breadcrumb').textContent = { people: 'People', recent: 'Recent calls', settings: 'Settings', meetings: 'Rooms', 'voice-link': 'Voice room' }[view];
  if (view === 'recent') refreshHistory().catch((e) => toast(e.message, true));
  if (view === 'settings') { enumerateDevices().catch(() => {}); $('discovery-enabled').disabled = true; if(!state.me?.guest)api('/discovery').then(p => { $('discovery-enabled').checked = p.enabled; $('discovery-enabled').disabled = false; }).catch(e => { $('discovery-status').textContent = e.message; }); }
}
async function refreshFriends() { const account = state.me;if(account?.guest)return; const friends = await api('/friends'); if (!account || account !== state.me) return; state.friends = friends; renderFriends(); }
function renderFriends() {
  const accepted = state.friends.filter((f) => f.status === 'accepted');
  $('friends-count').textContent = accepted.length; $('people-count').textContent = accepted.length;
  $('requests-count').textContent = state.friends.filter((f) => f.status !== 'accepted').length;
  $('friends-tab').classList.toggle('selected', state.tab === 'friends'); $('online-tab').classList.toggle('selected', state.tab === 'online'); $('requests-tab').classList.toggle('selected', state.tab === 'requests');
  const query = $('friend-search').value.trim().toLowerCase();
  const settleFriends = captureList($('friend-list'), `${state.tab}:${query}`);
  const list = state.friends.filter((f) => (state.tab === 'requests' ? f.status !== 'accepted' : f.status === 'accepted' && (state.tab !== 'online' || f.online)) && `${f.display_name} ${f.username}`.toLowerCase().includes(query));
  list.sort((a, b) => Number(b.online) - Number(a.online) || a.display_name.localeCompare(b.display_name));
  $('voice-rooms').replaceChildren();
  const seenRooms = new Set();
  for (const friend of accepted.filter(f=>f.voice_room)) {
    if(seenRooms.has(friend.voice_room.room_id))continue;
    seenRooms.add(friend.voice_room.room_id);
    const room = button(`${friend.display_name} · ${friend.voice_room.participants} online`, 'nav-item voice-room', ()=>groups.enterVoice(friend.voice_room.room_id), 'mic');
    room.disabled=groups.busy||!!state.call; $('voice-rooms').append(room);
  }
  $('voice-empty').hidden=seenRooms.size>0;
  $('friend-list').replaceChildren(); $('friends-empty').hidden = list.length > 0;
  if (!list.length) {
    const empty = $('friends-empty');
    empty.querySelector('h2').textContent = query ? 'No familiar faces by that name.' : state.tab === 'requests' ? 'All caught up.' : state.tab === 'online' ? 'Your friends are offline.' : 'Make space for your people.';
    empty.querySelector('p').textContent = query ? 'Try a different name or username.' : state.tab === 'requests' ? 'New friend requests will appear here.' : state.tab === 'online' ? 'Your room is ready whenever you want to hang out.' : 'Add a friend by username. Once they accept, a good conversation is always one click away.';
    $('empty-add').hidden = state.tab !== 'friends' || !!query;
  }
  for (const friend of list) {
    const card = element('article', 'friend-card'); card.dataset.peerId = friend.id;
    const top = element('div', 'friend-card-top'); top.append(avatar(friend.display_name, '', friend.status === 'accepted' ? friend.online : undefined));
    const remove = button('', 'icon-button', async () => {
      const question = friend.status === 'accepted' ? `Remove ${friend.display_name} from your friends? You will need a new accepted request to call again.` : `Remove this friend request with ${friend.display_name}?`;
      if (!confirm(question)) return;
      await api(`/friends/${friend.id}`, { method: 'DELETE' }); await refreshFriends();
    }, 'close'); remove.title = friend.status === 'accepted' ? 'Remove friend' : 'Remove request'; remove.setAttribute('aria-label', `${remove.title}: ${friend.display_name}`); top.append(remove);
    card.append(top, element('h3', '', friend.display_name), element('p', 'friend-handle', `@${friend.username}`));
    const status = element('p', `friend-status ${friend.online ? 'online' : ''}`);
    status.append(element('span', `status-dot ${friend.online ? 'online' : ''}`), document.createTextNode(friend.status === 'sent' ? 'Request sent' : friend.status === 'received' ? 'Wants to be your friend' : friend.voice_room ? 'In a voice room' : friend.online ? 'Online' : 'Offline'));
    card.append(status);
    if (friend.status === 'accepted') {
      if(friend.voice_room)card.append(button('Join room', 'button primary', ()=>groups.enterVoice(friend.voice_room.room_id), 'mic'));
      const call = button('Call', `button ${friend.online ? 'primary' : 'secondary'}`, () => startCall(friend), 'mic'); call.disabled = !state.ws || state.ws.readyState !== WebSocket.OPEN || !!state.call; card.append(call);
    } else if (friend.status === 'received') {
      card.append(button('Accept request', 'button primary', async () => { await api(`/friends/${friend.id}/accept`, { method: 'POST' }); await refreshFriends(); toast(`${friend.display_name} is now in your people.`); }, 'check'));
    } else { const pending = button('Awaiting acceptance', 'button secondary', () => {}); pending.disabled = true; card.append(pending); }
    $('friend-list').append(card);
  }
  settleFriends();
}
async function refreshHistory() {
  const account = state.me, history = await api('/history'); if (!account || account !== state.me) return;
  state.history = history; $('history-list').replaceChildren();
  if (!state.history.length) { $('history-list').append(element('p', 'history-empty', 'Your first hello is waiting. Calls will appear here.')); return; }
  for (const item of state.history) {
    const row = element('article', 'history-row'), info = element('div');
    info.append(element('strong', '', item.display_name));
    const outcome = { missed: 'Missed call', declined: 'Declined', disconnected: 'Connection ended', removed: 'Friend removed', ended: 'Call ended' }[item.outcome] || 'Call ended';
    info.append(element('p', '', `${item.outgoing ? 'Outgoing' : 'Incoming'} · ${outcome}`));
    const date = new Date(item.started * 1000), time = element('time', '', date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })); time.dateTime = date.toISOString();
    row.append(avatar(item.display_name, 'small'), info, time);
    const friend = state.friends.find((f) => f.id === item.peer_id && f.status === 'accepted');
    if (friend) row.append(button('Call again', 'button secondary', () => startCall(friend), 'mic'));
    $('history-list').append(row);
  }
}
function send(message) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) throw new Error('Reconnecting to PVP. Try again in a moment.');
  state.ws.send(JSON.stringify(message));
  if (message.type !== 'pong') networkEvent(`Signaling sent: ${message.type === 'signal' ? message.payload.type : message.type}`);
}
function connect() {
  clearTimeout(state.retry);
  if (!state.me || state.replaced) return;
  const old = state.ws; state.ws = null; old?.close(); messageChain = Promise.resolve(); state.signalCount = 0;
  groups.meetingsAvailable=false;
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/ws`); state.ws = ws;
  ws.onopen = () => { if (state.ws !== ws) { ws.close(); return; } state.retryAttempt = 0; $('connection-label').textContent = meetingJoin.id ? 'Meeting service connected' : 'Ready for a hello'; $('connection-dot').classList.add('online'); refreshFriends().catch((e) => toast(e.message, true)); };
  ws.onmessage = (event) => {
    if (state.ws !== ws || !state.me || typeof event.data !== 'string' || event.data.length > 65536) return;
    let message; try { message = JSON.parse(event.data); } catch { ws.close(); return; }
    const call = state.call;
    const run = async () => { if (state.ws === ws && state.me && (!['signal', 'call-accepted'].includes(message.type) || state.call === call)) await onMessage(message); };
    const fail = (error) => { if (state.ws !== ws || state.call !== call || error.name === 'AbortError') return; toast(error.message, true); if (state.call) hangup(); };
    // Cancellation and session events must never wait behind a permission dialog.
    if (['signal', 'call-accepted'].includes(message.type)) {
      if (++state.signalCount > 260) { hangup(); return; }
      messageChain = messageChain.then(run).catch(fail);
    } else run().catch(fail);
  };
  ws.onclose = () => {
    if (state.ws !== ws) return;
    $('connection-label').textContent = state.replaced ? 'Open in another window' : 'Reconnecting…'; $('connection-dot').classList.remove('online');
    if (groups.busy) groups.cleanup('interrupted');
    if (state.call) cleanupCall('Your connection to PVP was interrupted.'); renderFriends();
    state.ws = null;
    scheduleReconnect();
  };
}
function scheduleReconnect() {
  clearTimeout(state.retry);
  if (!state.me || state.replaced) return;
  const account = state.me;
  state.retry = setTimeout(async () => {
    if (account !== state.me || state.replaced) return;
    try { await api('/me'); if (account === state.me) connect(); }
    catch (error) { if (account !== state.me) return; if (error.status === 401) showAuth(); else scheduleReconnect(); }
  }, Math.min(30000, 1000 * 2 ** Math.min(state.retryAttempt++, 5)) + Math.random() * 500);
}
function primeSound() {
  try { state.audio ??= new AudioContext(); state.audio.resume().catch(() => {}); } catch {}
}
function speakingTone() {
  primeSound();
  const audio=state.audio;if(!audio)return;
  // A quiet ascending chime, played only for the approved participant.
  for(const [offset,frequency] of [[0,523.25],[0.13,783.99]]){
    const oscillator=audio.createOscillator(),gain=audio.createGain(),at=audio.currentTime+offset;
    oscillator.type='sine';oscillator.frequency.value=frequency;
    gain.gain.setValueAtTime(0,at);gain.gain.linearRampToValueAtTime(0.075,at+0.015);gain.gain.exponentialRampToValueAtTime(0.001,at+0.25);
    oscillator.connect(gain);gain.connect(audio.destination);oscillator.start(at);oscillator.stop(at+0.27);
    oscillator.onended=()=>{oscillator.disconnect();gain.disconnect();};
  }
}
function ring(name = state.call?.peer.display_name || 'Your friend') {
  stopRinging(); document.title = `${name} is calling · PVP`;
  const tone = () => {
    const audio = state.audio; if (!audio || audio.state !== 'running') return;
    for (const offset of [0, 0.45]) {
      const oscillator = audio.createOscillator(), gain = audio.createGain(), at = audio.currentTime + offset;
      oscillator.frequency.value = 660; gain.gain.setValueAtTime(0, at); gain.gain.linearRampToValueAtTime(0.12, at + 0.03); gain.gain.setValueAtTime(0.12, at + 0.15); gain.gain.linearRampToValueAtTime(0, at + 0.22);
      oscillator.connect(gain); gain.connect(audio.destination); oscillator.start(at); oscillator.stop(at + 0.23); oscillator.onended = () => { oscillator.disconnect(); gain.disconnect(); };
    }
  };
  tone(); state.ring = setInterval(tone, 3000);
}
function stopRinging() { clearInterval(state.ring); state.ring = null; document.title = 'PVP · Your people, closer'; }

async function onMessage(message) {
  if(message.type==='server-capabilities'){groups.available=message.groupCalls===true;groups.voiceAvailable=message.voiceRooms===true&&!state.me?.guest;followVoiceLink();$('open-voice').disabled=!groups.voiceAvailable;groups.meetingsAvailable=message.permanentMeetings===true;if(groups.available)groups.capabilities();if(groups.meetingsAvailable)try{await meetingLinks.activate();await meetingJoin.resume();}catch(e){toast(e.message,true);}return;}
  if(message.type==='meetings-changed'){await meetingLinks.refresh();return;}
  if (message.type.startsWith('room-')) { await groups.message(message); return; }
  if (message.type === 'error') await groups.message(message);
  if (message.type !== 'ping') networkEvent(`Signaling received: ${message.type === 'signal' ? message.payload?.type : message.type}`);
  if (message.type === 'ping') { send({ type: 'pong' }); return; }
  if (message.type === 'friends-changed') { await refreshFriends(); return; }
  if (message.type === 'replaced') { state.replaced = true; if(groups.busy)groups.cleanup('replaced'); meetingJoin.rejected('This meeting is open in another tab. Close it there before rejoining.'); cleanupCall(); toast('PVP is active in another window. Refresh to use this one.'); return; }
  if (message.type === 'signed-out') { showAuth(); return; }
  if (message.type === 'error') { toast(message.message, true); if (state.call?.status === 'requesting') cleanupCall(); return; }
  if (message.type === 'calling') {
    if (!state.call) { send({ type: 'hangup', call_id: message.call_id }); return; }
    state.call.id = message.call_id; state.call.status = 'ringing'; clearTimeout(state.callTimeout); return;
  }
  if (message.type === 'incoming') {
    if (groups.busy) { send({type:'decline',call_id:message.call_id}); return; }
    if (state.call) { if (state.call.id !== message.call_id) send({ type: 'decline', call_id: message.call_id }); return; }
    state.signalCount = 0;
    state.call = { id: message.call_id, peer: message.peer, status: 'incoming' }; networkEvent('Signaling received: incoming'); ring();
    $('incoming-name').textContent = message.peer.display_name; fillAvatar('incoming-avatar', message.peer.display_name, 'large'); $('incoming-error').textContent = ''; $('accept-call').disabled = false;
    if (!$('incoming-dialog').open) $('incoming-dialog').showModal();
    renderFriends();
    if ('Notification' in window && Notification.permission === 'granted' && document.hidden) {
      const note = new Notification(`${message.peer.display_name} is calling`, { body: 'Open PVP to answer your voice call.', icon: '/icon.svg', tag: 'pvp-call' }); note.onclick = () => { window.focus(); note.close(); }; state.call.notification = note;
    }
    return;
  }
  if (!state.call || state.call.id !== message.call_id) return;
  if (message.type === 'call-ended') {
    const reason = { missed: 'No answer this time. Your friend can find the call in Recent calls.', declined: 'Your friend couldn’t pick up this time.', disconnected: 'Your friend disconnected.', removed: 'The friendship was removed.', ended: 'Call ended.' }[message.reason] || 'Call ended.';
    cleanupCall(reason); if (state.view === 'recent') await refreshHistory(); return;
  }
  if (message.type === 'call-accepted') {
    const call = state.call; call.initiator = message.initiator === true; stopRinging();
    state.call.status = 'connecting'; $('incoming-dialog').close(); state.call.notification?.close(); showCall();
    $('call-status').textContent = 'Making a direct connection…'; $('call-detail').textContent = 'Just a moment. Your conversation is almost here.';
    const pc = await createPeer(call); if (!pc || state.call !== call) return;
    if (message.initiator) {
      const offer = await pc.createOffer(); if (state.call !== call) return; requireEncryptedSdp(offer.sdp);
      await pc.setLocalDescription(offer); await applyQuality(); if (state.call !== call) return;
      send({ type: 'signal', call_id: state.call.id, payload: { type: 'offer', sdp: state.pc.localDescription.sdp } });
    }
    clearTimeout(state.callTimeout); const callId = state.call.id;
    state.callTimeout = setTimeout(() => { if (state.call?.id === callId && state.call.status !== 'connected') { toast('A direct connection could not be established. Try a different network.', true); hangup(); } }, 30000);
    return;
  }
  if (message.type === 'signal') await receiveSignal(message.payload);
}
async function startCall(friend) {
  if (state.call || groups.busy) throw new Error('Finish your current call first.');
  if (state.ws?.readyState !== WebSocket.OPEN) throw new Error('PVP is reconnecting. Try again in a moment.');
  primeSound(); state.signalCount = 0;
  const call = { peer: friend, status: 'requesting', id: null }; state.call = call; renderFriends();
  stopMedia(); showCall(); $('call-status').textContent = 'Getting your microphone ready…'; $('call-detail').textContent = 'Allow microphone access if your browser asks. Video is optional.';
  try {
    await prepareMedia();
    if (state.call !== call) return;
    showCall(); send({ type: 'call', peer_id: friend.id });
    state.callTimeout = setTimeout(() => { if (state.call?.status === 'requesting') cleanupCall('Your call could not be started. Please try again.'); }, 10000);
  } catch (error) { if (state.call === call) cleanupCall(); if (error.name !== 'AbortError') throw error; }
}
function showCall() {
  $('call-view').toggleAttribute('data-connecting', state.call.status !== 'connected');
  document.querySelector('.workspace').classList.remove('browsing'); $('call-view').hidden = false; $('call-name').textContent = state.call.peer.display_name; fillAvatar('call-avatar', state.call.peer.display_name, 'extra-large');
  $('call-placeholder').hidden = false; $('call-status').textContent = `Calling ${state.call.peer.display_name}…`; $('call-detail').textContent = state.call.peer.online === false ? 'They’re away. We’ll ring if they return within a minute.' : 'Waiting for your friend to answer.';
  $('call-security').textContent = 'Encryption verification available after connecting';
  $('call-bandwidth').textContent = 'Your bandwidth · measuring…'; $('call-network').textContent = 'Connecting…'; $('call-stats').textContent = 'Encrypted · direct peer-to-peer'; $('call-timer').textContent = '00:00'; $('local-video').srcObject = state.stream;
  updateCameraControl();syncDirectControls(); $('stop-preview').hidden = true;
}
async function createPeer(call) {
  await prepareMedia(); if (state.call !== call) return null;
  // Intentionally STUN only. There is no TURN fallback and no media server.
  const pc = createPeerConnection(); state.pc = pc; state.candidates = [];
  networkEvent('Peer connection created; STUN configured, no TURN');
  clearInterval(state.stats); state.stats = setInterval(() => updateStats().catch(() => { if (state.pc === pc && state.call === call) { call.evidence = null;call.proof=null;$('call-trust').textContent='Connection evidence'; $('call-network').textContent = 'Route unavailable'; renderInspector(); } }), 1000);
  pc.oniceconnectionstatechange = () => { if (state.pc === pc && state.call === call) networkEvent(`ICE: ${pc.iceConnectionState}`, 'WebRTC event'); };
  pc.onicegatheringstatechange = () => { if (state.pc === pc && state.call === call) networkEvent(`ICE gathering: ${pc.iceGatheringState}`, 'WebRTC event'); };
  state.stream.getAudioTracks().forEach((track) => pc.addTrack(track, state.stream));
  if(call.initiator){call.videoSender=pc.addTransceiver('video',{direction:'sendrecv',streams:[state.stream]}).sender;const camera=state.stream.getVideoTracks()[0];if(camera)await call.videoSender.replaceTrack(camera);}
  call.meter=new BandwidthMeter();call.caps={receive:{camera:null,screen:null},send:{camera:null,screen:null}};call.requested={camera:null,screen:null};
  const attach=dc=>{if(dc.label!=='pvp-bandwidth'||call.bandwidthChannel){dc.close();return;}call.bandwidthChannel=dc;
    dc.onopen=()=>sendBandwidth(call);dc.onmessage=e=>{if(state.call!==call||typeof e.data!=='string'||e.data.length>1024)return;let msg;try{msg=JSON.parse(e.data);}catch{return;}
      if(msg.type==='bandwidth'){const caps=validCaps(msg.caps);if(caps){call.requested=caps;call.bandwidthSupported=true;dc.send(JSON.stringify({type:'bandwidth-ack'}));applyQuality().catch(e=>toast(e.message,true));}}else if(msg.type==='bandwidth-ack')call.bandwidthSupported=true;};};
  pc.ondatachannel=e=>attach(e.channel);if(call.initiator)attach(pc.createDataChannel('pvp-bandwidth'));
  const callId = state.call.id;
  pc.onicecandidate = ({ candidate }) => {
    if (!candidate || candidate.type === 'relay' || isRelay(candidate.candidate) || state.call?.id !== callId) return;
    try { send({ type: 'signal', call_id: callId, payload: { type: 'candidate', candidate: candidate.toJSON() } }); } catch (error) { toast(error.message, true); }
  };
  pc.ontrack = ({ track, streams }) => {
    if (state.pc !== pc || state.call !== call) { track.stop(); return; }
    const remote = $('remote-video').srcObject || new MediaStream();
    if (!remote.getTracks().some(t => t.id === track.id)) remote.addTrack(track);
    $('remote-video').srcObject = remote;playRemoteAudio();syncDirectControls();
    if(track.kind==='video'){track.onunmute=()=>{if(state.call===call){call.remoteCamera=true;syncDirectControls();}};track.onmute=()=>{if(state.call===call){call.remoteCamera=false;syncDirectControls();}};call.remoteCamera=!track.muted;syncDirectControls();}
  };
  pc.onconnectionstatechange = () => {
    if (state.pc !== pc || state.call !== call) return;
    networkEvent(`Peer connection: ${pc.connectionState}`, 'WebRTC event');
    call.evidence = null; renderInspector();
    if (pc.connectionState === 'connected') {
      $('call-view').removeAttribute('data-connecting');
      state.call.status = 'connected'; state.call.connectedAt = Date.now(); clearTimeout(state.callTimeout); $('call-network').textContent = 'Checking media route';
      $('call-status').textContent=state.call.peer.display_name;$('call-detail').textContent='';syncDirectControls();
      updateStats().catch(() => {});
    } else if (pc.connectionState === 'failed') { toast('This network could not establish a direct peer connection. Try another network.', true); hangup(); }
    else if (pc.connectionState === 'disconnected') { $('call-network').textContent = 'Connection interrupted'; clearTimeout(state.callTimeout); state.callTimeout = setTimeout(() => { if (state.pc?.connectionState === 'disconnected') hangup(); }, 15000); }
  };
  return pc;
}
async function receiveSignal(payload) {
  const pc = state.pc, call = state.call; if (!pc || !call) return;
  if (payload.type === 'candidate') {
    const candidate = payload.candidate;
    requireCandidate(candidate);
    if (pc.remoteDescription) await pc.addIceCandidate(candidate); else { if (state.candidates.length >= 128) throw new Error('Too many peer candidates.'); state.candidates.push(candidate); }
  } else if (payload.type === 'offer' || payload.type === 'answer') {
    requireEncryptedSdp(payload.sdp);
    if (pc.remoteDescription || (payload.type === 'offer' ? call.initiator : !call.initiator)) throw new Error('Unexpected peer negotiation.');
    await pc.setRemoteDescription({ type: payload.type, sdp: payload.sdp });
    if (state.pc !== pc || state.call !== call) return;
    for (const candidate of state.candidates.splice(0)) await pc.addIceCandidate(candidate);
    if (payload.type === 'offer') {
      const slot=pc.getTransceivers().find(t=>t.receiver.track.kind==='video');
      if(slot){slot.direction='sendrecv';call.videoSender=slot.sender;slot.sender.setStreams(state.stream);const camera=state.stream.getVideoTracks()[0];if(camera)await slot.sender.replaceTrack(camera);}
      const answer = await pc.createAnswer(); requireEncryptedSdp(answer.sdp); if (state.call !== call) return;
      await pc.setLocalDescription(answer); await applyQuality(); if (state.call !== call) return;
      send({ type: 'signal', call_id: state.call.id, payload: { type: 'answer', sdp: pc.localDescription.sdp } });
    } else await applyQuality();
    if (state.pc !== pc || state.call !== call) return;
    const code = await safetyCode(pc.localDescription.sdp, pc.remoteDescription.sdp).catch(()=>null);
    if (state.pc === pc && state.call === call) { call.securityCode = code; $('call-security').textContent = code?`Verify with your friend: ${code}`:'Certificate comparison unavailable'; }
  }
}
function sendBandwidth(call) {if(call?.bandwidthChannel?.readyState==='open')call.bandwidthChannel.send(JSON.stringify({type:'bandwidth',caps:saverCaps(call.caps.receive,state.preferences.dataReceive)}));}
async function updateStats() {
  const pc = state.pc, call = state.call; if (!pc || !call) return;
  let timer;const report = await Promise.race([pc.getStats(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Connection evidence unavailable')),3000);})]).finally(()=>clearTimeout(timer)); if (state.pc !== pc || state.call !== call) return;
  const proof = await inspectEncryptionReport(report, {localSdp:pc.localDescription?.sdp,remoteSdp:pc.remoteDescription?.sdp,connectionState:pc.connectionState});
  if(state.pc!==pc||state.call!==call)return;call.proof=proof;
  if(proof.failure){toast('Connection security check failed. The call has been stopped.',true);hangup();return;}
  $('call-trust').textContent=proof.encryptionState==='confirmed'?'Encryption observed':'Connection evidence';
  const evidence = inspectReport(report, { connectionState: pc.connectionState, iceState: pc.iceConnectionState, configuredServers: pc.getConfiguration().iceServers.flatMap(s => Array.isArray(s.urls) ? s.urls : [s.urls]) });
  if (evidence.selectedPairId !== call.evidence?.selectedPairId) networkEvent(`Selected path: ${endpointLabel(evidence.local)} ↔ ${endpointLabel(evidence.remote)}`, 'WebRTC statistics');
  call.meter.sample(report);$('call-bandwidth').textContent=bandwidthLabel([call.meter.rate]);
  call.videoStats ||= new OutboundVideoStats(); call.videoStats.sample(report); refreshMediaHealth();
  call.evidence = evidence; renderInspector();
  $('call-network').textContent = proof.routeState === 'direct'
    ? `Direct · WebRTC reported${proof.encryptionState === 'confirmed' ? ' · encrypted' : ''}`
    : 'Route unavailable';
  $('call-stats').textContent = sentVideoLabel([{id:call.peer?.id,rows:call.videoStats.fresh()}],{camera:!!state.stream?.getVideoTracks().some(t=>t.enabled&&t.readyState==='live'),sharing:!!call.displayStream});
  const seconds = Math.floor((Date.now() - (call.connectedAt || Date.now())) / 1000); $('call-timer').textContent = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}
function cleanupCall(message) {
  resetStage($('call-view'));
  if(trustScope==='direct'&&$('trust-dialog').open)$('trust-dialog').close();
  $('inspector-dialog').close();
  for (const id of ['inspector-local', 'inspector-remote', 'inspector-command', 'inspector-events', 'inspector-candidates', 'inspector-pairs', 'inspector-media', 'inspector-signaling', 'inspector-transport', 'inspector-counters', 'inspector-encryption', 'inspector-servers', 'inspector-sampled']) $(id).replaceChildren();
  stopRinging(); messageChain = Promise.resolve(); state.signalCount = 0;
  clearTimeout(state.callTimeout); clearInterval(state.stats); state.stats = null; state.lastStats = null; state.candidates = [];
  releaseDisplay(state.call); state.call?.notification?.close(); state.call?.playback?.dispose(); state.call = null; state.pc?.close(); state.pc = null;
  $('incoming-dialog').close();closeSheet($('call-more-dialog'));closeSheet($('call-audio-dialog')); $('call-view').hidden = true; $('call-settings').hidden = true; $('remote-video').srcObject = null;
  $('enable-playback').hidden = true;
  stopMedia(); if (state.me) renderFriends(); if (message) toast(message);
}
function hangup() { if (state.call?.id) { try { send({ type: 'hangup', call_id: state.call.id }); } catch {} } cleanupCall(); }
function toggleTrack(kind) {
  const track = kind === 'audio' ? state.stream?.getAudioTracks()[0] : (state.call?.displayStream || state.stream)?.getVideoTracks()[0]; if (!track) return;
  track.enabled = !track.enabled; microphoneMonitor?.update(); const control = $(kind === 'audio' ? 'toggle-mic' : 'toggle-camera'); control.setAttribute('aria-pressed', String(!track.enabled));
  const text = kind === 'audio' ? (track.enabled ? 'Mute microphone' : 'Unmute microphone') : state.call?.displayStream ? (track.enabled ? 'Pause sharing' : 'Resume sharing') : (track.enabled ? 'Turn camera off' : 'Turn camera on'); control.title = text; control.setAttribute('aria-label', text);syncDirectControls();
}
async function enterApp(user) {
  guestPreviewGeneration++;
  clearTimeout(state.restoreRetry); $('auth-error').textContent=''; state.me = user; state.replaced = false; loadPreferences();$('guest-sign-in').hidden=!user.guest;$('guest-manage').hidden=!!user.scoped_guest;$('guest-name').readOnly=true;$('guest-name').value=user.display_name;
  $('auth-view').hidden = true; $('app-view').hidden = false; $('app-view').classList.toggle('guest-session',!!user.guest); $('my-name').textContent = user.display_name; $('copy-username').textContent = user.guest?'Guest':`@${user.username}`;$('copy-username').disabled=!!user.guest; fillAvatar('my-avatar', user.display_name, 'small');
  $('guest-account-nav').hidden=!user.guest;
  changeView('meetings'); if(meetingId(location.href))meetingJoin.open().catch(e=>toast(e.message,true)); renewSessionCookie(); if(!meetingId(location.href)||['capturing','connecting'].includes(meetingJoin.phase))connect(); await refreshFriends();
}
function showAuth() {
  meetingJoin.cancel();
  meetingLinks.reset();
  cancelSessionRenewal();
  if (groups.busy) groups.cleanup();
  state.authGeneration++;
  clearTimeout(state.restoreRetry); clearTimeout(state.retry); clearTimeout(qualityTimer); state.me = null; state.friends = []; state.history = []; state.ws?.close(); state.ws = null; cleanupCall();
  $('app-view').hidden = true; $('auth-view').hidden = false; $('password').value = '';
  meetingJoin.id=null;$('guest-form').hidden=true;
  previewGuestMeeting().catch(e=>{$('guest-error').textContent=e.message;});
}
async function previewGuestMeeting(){
  if(meetingId(location.href))await meetingJoin.open();
  else {meetingJoin.hide();$('auth-view').hidden=false;}
}
window.addEventListener('hashchange',()=>{if(state.me?.scoped_guest&&meetingId(location.href)!==state.me.meeting_id)showAuth();else if(!state.me)previewGuestMeeting().catch(e=>{$('guest-error').textContent=e.message;});});
function authMode(register) {
  state.register = register; $('name-label').hidden = !register; $('display-name').required = register;
  $('login-tab').classList.toggle('selected', !register); $('register-tab').classList.toggle('selected', register);
  $('auth-title').textContent = register ? 'Find your people.' : 'Welcome back.';
  $('auth-description').textContent = register ? 'A name, a username, and you’re on your way.' : 'Your next conversation is just a click away.';
  $('auth-submit').replaceChildren(document.createTextNode(register ? 'Create your account ' : 'Sign in '), icon('arrow'));
  $('password').autocomplete = register ? 'new-password' : 'current-password'; $('password').minLength = register ? 10 : 1; $('auth-error').textContent = '';
}
async function copyUsername() {
  try { await navigator.clipboard.writeText(`@${state.me.username}`); toast('Username copied. Send it to someone you’d like to see.'); } catch { toast(`Your username is @${state.me.username}`); }
}
function openFriendDialog() { $('friend-suggestions').replaceChildren(); $('friend-discovery-status').textContent = ''; $('friend-error').textContent = ''; $('friend-username').value = ''; $('friend-dialog').showModal(); }

$('login-tab').onclick = () => authMode(false); $('register-tab').onclick = () => authMode(true);
$('auth-form').onsubmit = async (event) => {
  event.preventDefault(); cancelSessionRenewal(); clearTimeout(state.restoreRetry); const generation = ++state.authGeneration; $('auth-submit').disabled = true; $('auth-error').textContent = '';
  try { const user = await api(state.register ? '/register' : '/login', { method: 'POST', body: { username: $('username').value, password: $('password').value, display_name: $('display-name').value } }); if (generation !== state.authGeneration) return; $('password').value = ''; await enterApp(user); }
  catch (error) { $('auth-error').textContent = error.message; } finally { $('auth-submit').disabled = false; }
};
document.querySelectorAll('[data-view]').forEach((button) => { button.onclick = () => changeView(button.dataset.view); });
$('logout').onclick = async () => { cancelSessionRenewal(); try { await api(state.me?.scoped_guest?'/guest/logout':'/logout', { method: 'POST' }); showAuth(); } catch (e) { toast(e.message, true); } };
// Link creation and sharing never request microphone or camera access.
$('guest-create-form').onsubmit = async event => {
  event.preventDefault(); const button=$('home-create-link'); if(button.disabled)return;
  button.disabled=true; $('home-error').textContent='';
  try {
    cancelSessionRenewal(); clearTimeout(state.restoreRetry); const generation=++state.authGeneration;
    const user=await api('/guest/start',{method:'POST',body:{display_name:$('home-guest-name').value.trim()}});
    if(generation!==state.authGeneration)return;
    await enterApp(user);
    const meeting=await api('/meetings',{method:'POST',body:{name:$('home-meeting-name').value.trim()||'My room',open_invite:true}});
    meetingLinks.available=true; await meetingLinks.open(meeting.meeting_id);
  } catch(error) { $('home-error').textContent=error.message;toast(error.message,true); }
  finally {button.disabled=false;}
};
$('guest-account-nav').onclick=()=>{meetingJoin.cancel();meetingJoin.hide();$('app-view').hidden=true;$('auth-view').hidden=false;showAccount();};
async function followMeeting(id){
  if(groups.busy||state.call)throw Error('Finish your current call first.');
  history.replaceState(null,'',`#meeting=${id}`);
  if(state.me?.scoped_guest&&state.me.meeting_id!==id)showAuth();
  else await meetingJoin.open(id);
}
$('home-join-form').onsubmit=async event=>{
  event.preventDefault();const id=meetingId($('home-meeting-link').value.trim());
  if(!id){$('home-error').textContent='Paste a PVP meeting link for this service.';return;}
  try{await followMeeting(id);}catch(error){$('home-error').textContent=error.message;}
};
let zoomResult=null,zoomGeneration=0;
for(const id of ['home-zoom','zoom-nav'])$(id).onclick=()=>{$('zoom-dialog').showModal();$('zoom-input').focus();};
$('zoom-close').onclick=()=>$('zoom-dialog').close();
$('zoom-input').oninput=()=>{zoomGeneration++;zoomResult=null;$('zoom-result').hidden=true;$('zoom-pvp-link').value='';$('zoom-error').textContent='';$('zoom-copy-status').textContent='';};
$('zoom-form').onsubmit=async event=>{
  event.preventDefault();const generation=++zoomGeneration;$('zoom-open').disabled=true;$('zoom-error').textContent='';
  try{const result=await api('/zoom',{method:'POST',body:{link:$('zoom-input').value.trim()}});if(generation!==zoomGeneration)return;zoomResult=result;$('zoom-pvp-link').value=result.url;$('zoom-result').hidden=false;}
  catch(error){if(generation===zoomGeneration)$('zoom-error').textContent=error.message;}
  finally{$('zoom-open').disabled=false;}
};
async function copyZoom(message=false){
  if(!zoomResult)return;
  const value=message?`We’re meeting on PVP from now on. The Zoom invitation is the same: paste it into ${location.origin} and choose “Use a Zoom invitation”, or use our permanent PVP link: ${zoomResult.url}\nNo account needed. Everyone joins in PVP; Zoom passcodes and host roles don’t carry over.`:zoomResult.url;
  try{await navigator.clipboard.writeText(value);$('zoom-copy-status').textContent=message?'Message copied. Send it by text or email.':'PVP link copied.';}
  catch{$('zoom-pvp-link').focus();$('zoom-pvp-link').select();$('zoom-copy-status').textContent='Select and copy the PVP link above.';}
}
$('zoom-copy').onclick=()=>copyZoom();$('zoom-copy-message').onclick=()=>copyZoom(true);
$('zoom-join').onclick=async()=>{if(!zoomResult)return;try{await followMeeting(zoomResult.meeting_id);$('zoom-dialog').close();}catch(error){$('zoom-error').textContent=error.message;}};
for (const id of ['copy-username', 'share-username']) $(id).onclick = copyUsername;
for (const id of ['add-friend', 'empty-add']) $(id).onclick = openFriendDialog;
$('close-friend').onclick = () => $('friend-dialog').close();
$('friend-form').onsubmit = async (event) => {
  event.preventDefault(); const submit = event.target.querySelector('[type=submit]'); submit.disabled = true;
  try { await api('/friends/request', { method: 'POST', body: { username: $('friend-username').value } }); $('friend-dialog').close(); state.tab = 'requests'; await refreshFriends(); toast('Friend request sent. A hello is on its way.'); }
  catch (error) { $('friend-error').textContent = error.message; } finally { submit.disabled = false; }
};
$('friend-search').oninput = renderFriends;
for (const [id, tab] of [['friends-tab', 'friends'], ['online-tab', 'online'], ['requests-tab', 'requests']]) $(id).onclick = () => { state.tab = tab; renderFriends(); };
$('open-settings').onclick = () => changeView('settings');
$('start-preview').onclick = () => prepareMedia(false,false).catch((e) => toast(e.message, true));
$('stop-preview').onclick = () => { if (!state.call && !groups.busy) stopMedia(); };
$('settings-preview').onclick = async () => { try { await prepareMedia(false,false); $('device-feedback').textContent = 'Camera and microphone are ready. Preview is in Call settings.'; } catch (e) { toast(e.message, true); } };
for (const id of ['echo-cancellation', 'in-call-echo-cancellation', 'group-echo-cancellation']) $(id).onchange = () => setEchoCancellation($(id).checked);
$('quality-preset').onchange = () => { const preset = $('quality-preset').value; if (PRESETS[preset]) Object.assign(state.preferences, PRESETS[preset]); state.preferences.preset = preset; savePreferences(); };
$('in-call-preset').onchange = () => { const preset = $('in-call-preset').value; if (PRESETS[preset]) Object.assign(state.preferences, PRESETS[preset]); state.preferences.preset = preset; savePreferences(); };
for (const [id, key] of [['resolution', 'resolution'], ['frame-rate', 'fps'], ['audio-bitrate', 'audio']]) $(id).onchange = () => { state.preferences[key] = Number($(id).value); state.preferences.preset = 'custom'; savePreferences(); };
$('bandwidth').oninput = () => { state.preferences.video = Number($('bandwidth').value); state.preferences.preset = 'custom'; renderPreferences(); clearTimeout(qualityTimer); qualityTimer = setTimeout(savePreferences, 200); };
for (const [id, key] of [['camera-device', 'camera'], ['mic-device', 'mic'], ['in-call-mic', 'mic']]) $(id).onchange = async () => {
  const previous = state.preferences[key]; state.preferences[key] = $(id).value;
  try { if (key==='mic') await switchMicrophone($(id).value); else if (state.stream) await prepareMedia(true,!state.stream.getVideoTracks().length); await savePreferences(); } catch (e) { state.preferences[key] = previous; $(id).value = previous; toast(e.message, true); }
};
$('notifications').onclick = async () => {
  if (!('Notification' in window)) { toast('This browser does not support background notifications.'); return; }
  const result = await Notification.requestPermission(); $('notifications').textContent = result === 'granted' ? 'Notifications enabled' : 'Notifications unavailable';
  if (result === 'granted') toast('We’ll let you know when a friend calls while PVP is open.');
};
$('incoming-dialog').addEventListener('cancel', (event) => event.preventDefault());
$('accept-call').onclick = async () => {
  const call = state.call, callId = call?.id; if (!callId) return; stopRinging(); $('accept-call').disabled = true; $('incoming-error').textContent = '';
  try { stopMedia(); await prepareMedia(); if (state.call !== call) return; send({ type: 'accept', call_id: callId }); }
  catch (error) { if (state.call === call && error.name !== 'AbortError') $('incoming-error').textContent = error.message; } finally { $('accept-call').disabled = false; }
};
$('decline-call').onclick = () => { if (state.call?.id) { try { send({ type: 'decline', call_id: state.call.id }); } catch {} } cleanupCall(); };
$('end-call').onclick = hangup; $('toggle-mic').onclick = () => toggleTrack('audio'); $('toggle-camera').onclick = () => toggleVideo().catch(e=>toast(e.message,true));
$('call-quality').onclick = () => {closeSheet($('call-more-dialog'));$('call-settings').hidden=false;openSheet($('call-audio-dialog'),$('call-more'));}; $('close-call-settings').onclick = () => closeSheet($('call-audio-dialog'));
$('connection-inspector').onclick = () => {closeSheet($('call-more-dialog')); if(state.call?.caps)bandwidthControls($('connection-bandwidth-controls'),state.call.caps,(direction,source,value)=>{state.call.caps[direction][source]=value;sendBandwidth(state.call);applyQuality().catch(e=>toast(e.message,true));});$('inspector-dialog').showModal(); renderInspector(); };
$('close-inspector').onclick = () => $('inspector-dialog').close();
$('inspector-platform').onchange = renderInspector;
$('copy-inspector-command').onclick = async () => {
  renderInspector(); if ($('copy-inspector-command').disabled) return;
  try { await navigator.clipboard.writeText($('inspector-command').textContent); toast('tcpdump command copied.'); }
  catch { toast('Select and copy the command above.'); }
};
$('export-inspector').onclick = () => {
  renderInspector();
  const url = URL.createObjectURL(new Blob([JSON.stringify(connectionReport(), null, 2)], { type: 'application/json' }));
  const link = element('a'); link.href = url; link.download = 'PVP-connection.json'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
setInterval(() => { if(state.call){$('call-bandwidth').textContent=bandwidthLabel([state.call.meter?.rate]);syncDirectControls();} if ($('inspector-dialog').open) renderInspector(); }, 1000);
$('call-view').addEventListener('click', playRemoteAudio);
$('enable-playback').onclick = playRemoteAudio;
document.addEventListener('pointerdown', primeSound, { passive: true });
$('enable-sound').onclick = () => { primeSound(); toast('Call sound enabled while this page is open.'); };
window.addEventListener('pagehide', () => { if(groups.busy)groups.leave('reload'); meetingJoin.cancelCapture(); hangup(); clearTimeout(state.retry); const ws = state.ws; state.ws = null; ws?.close(); });
window.addEventListener('pageshow', (event) => { if (event.persisted && state.me) connect(); });
async function boot() {
  const generation = state.authGeneration;
  try { const user = await api('/me'); if (generation === state.authGeneration && !state.me){if(user.scoped_guest&&meetingId(location.href)!==user.meeting_id)await previewGuestMeeting();else await enterApp(user);} }
  catch (error) {
    if (generation !== state.authGeneration || state.me) return;
    if(error.status===401){if($('auth-error').textContent==='Reconnecting to your saved sign-in…')$('auth-error').textContent='';await previewGuestMeeting();return;}
    $('auth-error').textContent = 'Reconnecting to your saved sign-in…';if(meetingId(location.href))meetingJoin.status('Reconnecting to PVP. Your invitation will load when the connection returns.');
    clearTimeout(state.restoreRetry);
    state.restoreRetry = setTimeout(() => { if(generation===state.authGeneration&&!state.me)boot(); },5000);
  }
}
// Only deliberate renewals issue cookies; cancel them before account changes.
// A delayed bootstrap /me response must never overwrite a newer login cookie.
let sessionRenewal = null;
function cancelSessionRenewal(){sessionRenewal?.abort();sessionRenewal=null;}
async function renewSessionCookie(){
  const account=state.me;if(!account||account.scoped_guest||state.replaced||sessionRenewal)return;
  const controller=new AbortController();sessionRenewal=controller;
  const timeout=setTimeout(()=>controller.abort(),20000);
  try{await api('/me?renew=1',{signal:controller.signal});}
  catch(error){if(state.me===account&&error.status===401)showAuth();}
  finally{clearTimeout(timeout);if(sessionRenewal===controller)sessionRenewal=null;}
}
setInterval(renewSessionCookie,3600000);

if(meetingId(location.href))meetingJoin.show();
boot();

function updateCameraControl() {
  const enabled = !!state.stream?.getVideoTracks().some(t=>t.enabled&&t.readyState==='live');
  const control=$('toggle-camera');control.setAttribute('aria-pressed',String(!enabled));
  control.title=enabled?'Turn camera off':'Turn camera on';control.setAttribute('aria-label',control.title);
  $('local-video').hidden=!enabled&&!state.call?.displayStream;syncDirectControls();
}
// Reopen only video: phone browsers may require releasing the current camera first.
async function cycleCamera() {
  if (state.cameraPromise || state.mediaPromise) return;
  const stream = state.stream, old = stream?.getVideoTracks()[0];
  if (!old || old.readyState !== 'live') { toast('Turn on your camera first.'); return; }
  if (state.call?.displayStream || groups.display) { toast('Stop screen sharing to switch cameras.'); return; }
  const call = state.call, roomId = groups.room?.room_id, generation = state.mediaGeneration;
  const valid = () => stream === state.stream && generation === state.mediaGeneration && call === state.call && roomId === groups.room?.room_id;
  const controls = ['preview-switch-camera', 'switch-camera', 'group-switch-camera'].map($);
  controls.forEach(control => control.disabled = true);
  const pending = (async () => {
    const devices = await navigator.mediaDevices.enumerateDevices().catch(() => []);
    if (!valid()) return;
    const cameras = devices.filter(device => device.kind === 'videoinput' && device.deviceId);
    const settings = old.getSettings(), current = settings.deviceId || state.preferences.camera;
    const index = cameras.findIndex(device => device.deviceId === current);
    const next = cameras.length > 1 ? cameras[(index + 1) % cameras.length].deviceId : '';
    const facing = settings.facingMode || state.cameraFacing || 'user';
    const constraints = {...mediaConstraints().video};
    delete constraints.deviceId;
    if (next) constraints.deviceId = {exact: next};
    else constraints.facingMode = {exact: facing === 'environment' ? 'user' : 'environment'};
    const previousConstraints = {...mediaConstraints().video};
    if (settings.deviceId) previousConstraints.deviceId = {exact: settings.deviceId};
    else if (!previousConstraints.deviceId) previousConstraints.facingMode = {ideal: facing};
    const senders = () => groups.joined ? [...groups.links.values()].map(link => link.videoSender).filter(Boolean) : [call?.videoSender].filter(Boolean);
    let captured, installed = false;
    const install = async (video, fallbackFacing = facing) => {
      if (!valid()) return;
      const track = video.getVideoTracks()[0];
      if (!track || track.readyState !== 'live') throw Error('No camera was opened.');
      track.enabled = old.enabled;
      for (const sender of senders()) { await sender.replaceTrack(track); if (!valid()) return; }
      stream.addTrack(track); video.removeTrack(track); installed = true;
      track.onended = () => { if (valid()) { stream.removeTrack(track); updateCameraControl(); } };
      state.cameraFacing = track.getSettings().facingMode || fallbackFacing;
      for (const id of ['preview-video', 'local-video', 'group-self-video']) $(id).classList.toggle('rear-camera', state.cameraFacing === 'environment');
      $('preview-video').srcObject = stream;
      $('local-video').srcObject = stream;
      updateCameraControl();
      if (groups.joined) { groups.overlay?.sourceChanged(); groups.render(); groups.broadcastState(); await groups.limits(); }
    };
    // Keep the microphone and its mute state intact throughout the switch.
    stream.removeTrack(old); old.stop();
    try {
      captured = await navigator.mediaDevices.getUserMedia({audio: false, video: constraints});
      await install(captured, constraints.facingMode?.exact || facing);
      if (valid() && installed) { state.preferences.camera = next || stream.getVideoTracks()[0].getSettings().deviceId || ''; await savePreferences(); await enumerateDevices(); }
    } catch (error) {
      if (valid() && !installed) {
        try {
          captured?.getTracks().forEach(track => track.stop());
          captured = await navigator.mediaDevices.getUserMedia({audio: false, video: previousConstraints});
          await install(captured);
        } catch {
          for (const sender of senders()) try { await sender.replaceTrack(null); } catch {}
          updateCameraControl();
          if (groups.joined) { groups.render(); groups.broadcastState(); }
        }
      }
      throw error;
    } finally { captured?.getTracks().forEach(track => track.stop()); }
  })();
  state.cameraPromise = pending;
  try { await pending; }
  finally { if (state.cameraPromise === pending) state.cameraPromise = null; controls.forEach(control => control.disabled = false); }
}
for (const id of ['preview-switch-camera', 'switch-camera', 'group-switch-camera']) $(id).onclick = () => {if(id==='switch-camera')closeSheet($('call-more-dialog'));return cycleCamera().catch(error => { if (error.name !== 'AbortError') toast(`Could not switch camera: ${error.message}`, true); });};

async function toggleVideo() {
  if(state.cameraPromise)return state.cameraPromise;
  if(state.call?.displayStream){toggleTrack('video');return;}
  if(groups.display){groups.paused=!groups.paused;groups.display.getVideoTracks().forEach(t=>t.enabled=!groups.paused);return;}
  const stream=state.stream, call=state.call, room=groups.room, generation=state.mediaGeneration;
  if(!stream||(!call&&!groups.joined))return;
  // Room revisions replace the snapshot object; membership changes do not cancel consent.
  const sameSession=()=>stream===state.stream&&generation===state.mediaGeneration&&call===state.call&&room?.room_id===groups.room?.room_id;
  const senders=()=>groups.joined?[...groups.links.values()].map(l=>l.videoSender).filter(Boolean):[call?.videoSender].filter(Boolean);
  const pending=(async()=>{
    const old=stream.getVideoTracks()[0];
    if(old){
      const replaced=[];try{for(const sender of senders()){await sender.replaceTrack(null);replaced.push(sender);}}catch(e){for(const sender of replaced)try{await sender.replaceTrack(old);}catch{}throw e;}
      stream.removeTrack(old);old.stop();updateCameraControl();return;
    }
    let captured;const replaced=[];
    try{
      captured=await navigator.mediaDevices.getUserMedia({audio:false,video:mediaConstraints().video});
      if(!sameSession())return;
      const track=captured.getVideoTracks()[0];if(!track||track.readyState!=='live')throw Error('No camera was opened.');
      for(const sender of senders()){const previous=sender.track;await sender.replaceTrack(track);replaced.push([sender,previous]);}
      if(!sameSession())return;
      if(groups.joined)await groups.limits();else await applyQuality();
      if(!sameSession())return;
      stream.addTrack(track);captured.removeTrack(track);
      track.onended=()=>{if(sameSession()){stream.removeTrack(track);updateCameraControl();if(groups.joined){groups.paused=true;groups.broadcastState();groups.render();}}};
      updateCameraControl();
    }catch(e){for(const [sender,previous] of replaced)try{await sender.replaceTrack(previous);}catch{}throw e;}
    finally{captured?.getTracks().forEach(t=>t.stop());}
  })();state.cameraPromise=pending;
  try{await pending;}finally{if(state.cameraPromise===pending)state.cameraPromise=null;}
}

function releaseDisplay(call) {
  if (!call) return;
  call.shareToken = (call.shareToken || 0) + 1;
  call.displayStream?.getTracks().forEach(t => { t.onended = null; t.stop(); });
  call.displayStream = null;
  $('local-video').classList.remove('screen-sharing');
  document.querySelector('.self-video span').textContent = 'You';
  $('share-screen').setAttribute('aria-pressed', 'false');
  $('share-screen').title = 'Share screen'; $('share-screen').setAttribute('aria-label', 'Share screen');
}
async function stopSharing(call = state.call) {
  if (!call?.displayStream) return;
  const pc = state.pc, camera = state.stream?.getVideoTracks()[0];
  releaseDisplay(call);
  if (state.call !== call) return;
  call.shareBusy = true;
  try {
    if (camera) camera.enabled = call.cameraBeforeShare;
    await call.videoSender.replaceTrack(camera || null);
    if (state.call === call) {
      $('local-video').srcObject = state.stream;
      $('toggle-camera').setAttribute('aria-pressed', String(!camera?.enabled));
      $('toggle-camera').title = camera?.enabled ? 'Turn camera off' : 'Turn camera on'; $('toggle-camera').setAttribute('aria-label', $('toggle-camera').title);
      updateCameraControl();toast('Screen sharing stopped.');
    }
  } catch { if (state.call === call) hangup(); }
  finally { call.shareBusy = false; }
}
$('share-screen').onclick = async () => {
  const call = state.call, pc = state.pc;
  if (!call || pc?.connectionState !== 'connected' || call.shareBusy || state.mediaPromise || state.cameraPromise) return;
  if (call.displayStream) { await stopSharing(call); return; }
  if (!navigator.mediaDevices?.getDisplayMedia) { toast('Screen sharing is unavailable in this browser.', true); return; }
  const token = call.shareToken = (call.shareToken || 0) + 1;
  call.shareBusy = true;
  let display, sender, previous;
  const valid = () => state.call === call && state.pc === pc && token === call.shareToken;
  try {
    // Invoke the browser picker directly from the user's click.
    display = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: state.preferences.fps, max: state.preferences.fps } }, audio: false });
    if (!valid()) return;
    const video = display.getVideoTracks();
    if (video.length !== 1 || video[0].readyState !== 'live') throw new Error('No screen video was opened.');
    display.getAudioTracks().forEach(t => { t.stop(); display.removeTrack(t); });
    sender = call.videoSender;
    if (!sender) throw new Error('Video channel is still connecting.');
    previous = sender.track;
    await sender.replaceTrack(video[0]);
    if (!valid()) return;
    call.cameraBeforeShare = state.stream.getVideoTracks()[0]?.enabled ?? false;
    call.displayStream = display;
    state.stream.getVideoTracks().forEach(t => { t.enabled = false; });
    $('local-video').srcObject = display; $('local-video').hidden=false; $('local-video').classList.add('screen-sharing');
    document.querySelector('.self-video span').textContent = 'You are sharing';
    $('toggle-camera').setAttribute('aria-pressed', 'false'); $('toggle-camera').title = 'Pause sharing'; $('toggle-camera').setAttribute('aria-label', 'Pause sharing');
    $('share-screen').setAttribute('aria-pressed', 'true'); $('share-screen').title = 'Stop sharing'; $('share-screen').setAttribute('aria-label', 'Stop sharing');
    video[0].onended = () => { if (state.call === call && call.displayStream === display) stopSharing(call); };
    toast('Sharing your selected screen or window. Microphone audio stays connected.');
  } catch (error) {
    if (valid() && sender) { try { await sender.replaceTrack(previous); } catch { hangup(); } }
    if (valid() && error.name !== 'NotAllowedError' && error.name !== 'AbortError') toast(error.message, true);
  } finally {
    if (display !== call.displayStream) display?.getTracks().forEach(t => t.stop());
    call.shareBusy = false;syncDirectControls();
  }
};

// Calls share the workspace, so navigation remains available while connected.
const workspace = document.querySelector('.workspace');
for (const id of ['call-view', 'group-view']) {
  const panel = $(id);
  workspace.append(panel);
  new MutationObserver(() => {
    $('return-call').hidden = $('call-view').hidden && $('group-view').hidden;
    if (panel.hidden) { panel.classList.remove('expanded'); labeledAction(button,'maximize','Full screen'); }
    if (panel.hidden && !!document.fullscreenElement) document.exitFullscreen().catch(() => {});
  }).observe(panel, {attributes:true, attributeFilter:['hidden']});
  const button = $(id === 'call-view' ? 'call-fullscreen' : 'group-fullscreen');
  button.onclick = async () => {
    closeSheet($('group-more-dialog'));closeSheet($('call-more-dialog'));
    try {
      if (panel.classList.contains('expanded')) { panel.classList.remove('expanded'); labeledAction(button,'maximize','Full screen'); }
      else if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch { panel.classList.add('expanded'); labeledAction(button,'minimize','Exit full screen'); }
  };
  document.addEventListener('fullscreenchange', () => {
    labeledAction(button,!!document.fullscreenElement?'minimize':'maximize',!!document.fullscreenElement?'Exit full screen':'Full screen');
  });
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') for (const id of ['call', 'group']) { $(`${id}-view`).classList.remove('expanded'); labeledAction($(`${id}-fullscreen`),'maximize','Full screen'); }
});
$('return-call').onclick=$('call-return-strip').onclick=()=>{workspace.classList.remove('browsing');syncCallShell();};
function followVoiceLink() {
  const id = new URLSearchParams(location.hash.slice(1)).get('voice');
  if (!id || !/^[a-zA-Z0-9-]{1,128}$/.test(id) || !state.me) return;
  changeView('voice-link');
  $('voice-link-join').onclick = async () => {
    try { await groups.enterVoice(id); } catch (e) { toast(e.message, true); }
  };
}
window.addEventListener('hashchange', followVoiceLink);

for(const direction of ['Send','Receive']) for(const prefix of ['','call-']) $(prefix+'data-'+direction.toLowerCase()).onchange=()=>{state.preferences['data'+direction]=$(prefix+'data-'+direction.toLowerCase()).value;savePreferences();};
navigator.connection?.addEventListener?.('change',()=>{if(state.preferences){renderPreferences();sendBandwidth(state.call);applyQuality().catch(e=>toast(e.message,true));}});

let friendSearchTimer, friendSearchGeneration = 0;
$('friend-username').oninput = () => {
  clearTimeout(friendSearchTimer);
  const generation = ++friendSearchGeneration;
  $('friend-suggestions').replaceChildren();
  $('friend-discovery-status').textContent = '';
  const q = $('friend-username').value.trim().replace(/^@/, '');
  if (q.length < 2) return;
  friendSearchTimer = setTimeout(async () => {
    try {
      const users = await api('/friends/search?q=' + encodeURIComponent(q));
      if (generation !== friendSearchGeneration || !$('friend-dialog').open) return;
      for (const user of users) {
        const option = document.createElement('option');
        option.value = user.username; option.label = user.display_name;
        $('friend-suggestions').append(option);
      }
      $('friend-discovery-status').textContent = users.length ? '' : 'No suggestions. You can still enter an exact username.';
    } catch (e) { if (generation === friendSearchGeneration) $('friend-discovery-status').textContent = e.message; }
  }, 250);
};
$('friend-dialog').addEventListener('close', () => { clearTimeout(friendSearchTimer); ++friendSearchGeneration; });
$('discovery-enabled').onchange = async () => {
  const input = $('discovery-enabled'); input.disabled = true;
  try { await api('/discovery', {method: 'POST', body: {enabled: input.checked}}); $('discovery-status').textContent = 'Saved to your account'; }
  catch (e) { input.checked = !input.checked; $('discovery-status').textContent = e.message; }
  finally { input.disabled = false; }
};

async function setGroupDevice(kind,id){
  const previous=state.preferences[kind];state.preferences[kind]=id;
  try{if(kind==='mic'&&state.stream?.getAudioTracks().length)await switchMicrophone(id);
    if(kind==='camera'&&state.stream?.getVideoTracks().length){await toggleVideo();await toggleVideo();groups.paused=!state.stream.getVideoTracks().length;groups.render();groups.broadcastState();}
    await savePreferences();
  }catch(error){state.preferences[kind]=previous;$('group-'+kind+'-device').value=previous;throw error;}
}
function syncDirectControls(){
  const call=state.call;if(!call)return;
  const proofAge=Date.now()-Date.parse(call.proof?.sampledAt||'');$('call-trust').textContent=state.pc?.connectionState==='connected'&&proofAge>=0&&proofAge<4000&&call.proof.encryptionState==='confirmed'?'Encryption observed':'Connection evidence';
  const mic=state.stream?.getAudioTracks().some(t=>t.enabled&&t.readyState==='live'),camera=state.stream?.getVideoTracks().some(t=>t.enabled&&t.readyState==='live');
  callAction($('toggle-mic'),{glyph:mic?'mic':'mic-off',label:'Microphone',action:mic?'Mute':'Unmute',active:mic,pressed:mic});
  callAction($('toggle-camera'),{glyph:camera?'video':'video-off',label:'Camera',action:camera?'Turn camera off':'Turn camera on',active:camera,pressed:camera,busy:!!state.cameraPromise});
  callAction($('share-screen'),{glyph:call.displayStream?'screen-share-off':'screen-share',label:'Screen sharing',action:call.displayStream?'Stop sharing':'Share screen',active:!!call.displayStream,pressed:!!call.displayStream,busy:call.shareBusy});$('share-screen').hidden=!navigator.mediaDevices?.getDisplayMedia&&!call.displayStream;
  callAction($('call-more'),{glyph:'ellipsis',label:'More'});callAction($('end-call'),{glyph:'phone-off',label:'End call',action:'Leave',always:true});
  rowAction($('switch-camera'),'switch-camera','Flip camera');$('switch-camera').hidden=!camera||!!call.displayStream;
  rowAction($('connection-inspector'),'wifi','Connection');rowAction($('call-quality'),'settings-2','Audio & video');rowAction($('call-fullscreen'),'maximize','Full screen');
  labeledAction($('call-back'),'chevron-left','Back to rooms');labeledAction($('enable-playback'),'volume-2','Hear meeting');
  $('call-sharing').hidden=!call.displayStream;$('call-view').dataset.sharing=String(!!call.displayStream);
  videoState($('call-view'),$('remote-video'),call.remoteCamera===true);$('call-view').classList.toggle('voice-call',call.remoteCamera!==true);
  $('call-placeholder').hidden=$('call-view').dataset.video==='on';
  $('direct-self-preview').hidden=!camera&&!call.displayStream;
  syncCallShell();
}
function syncCallShell(){
  const ongoing=!$('call-view').hidden||!$('group-view').hidden,browsing=workspace.classList.contains('browsing');document.body.classList.toggle('call-stage',ongoing&&!browsing);document.body.classList.toggle('ongoing-call',ongoing);
  $('call-return-strip').hidden=!ongoing||!browsing;
  if(!ongoing&&$('trust-dialog').open)$('trust-dialog').close();
  const sharing=ongoing&&(!$('call-view').hidden&&$('call-view').dataset.sharing==='true'||!$('group-view').hidden&&$('group-view').dataset.sharing==='true');labeledAction($('call-return-strip'),sharing?'screen-share':'phone-off',sharing?'Sharing screen · Return to call':'Return to call');
}
const audioDialog=document.createElement('dialog');audioDialog.id='call-audio-dialog';audioDialog.className='context-sheet';audioDialog.setAttribute('aria-label','Audio & video');audioDialog.append($('call-settings'));document.body.append(audioDialog);bindSheet(audioDialog);audioDialog.addEventListener('close',()=>{$('call-settings').hidden=true;});
bindLabels();bindSheet($('call-more-dialog'));labeledAction($('call-more-close'),'x','Back to call');
$('call-more').onclick=()=>openSheet($('call-more-dialog'),$('call-more'));$('call-more-close').onclick=()=>closeSheet($('call-more-dialog'));
$('call-more-content').append($('switch-camera'),$('call-secondary-actions'),$('call-fullscreen'));
$('call-back').onclick=()=>{changeView('meetings');meetingLinks.open().catch(e=>toast(e.message,true));};$('call-stop-sharing').onclick=()=>$('share-screen').click();
for(const panel of [$('call-view'),$('group-view'),workspace])new MutationObserver(syncCallShell).observe(panel,{attributes:true,attributeFilter:['hidden','class','data-sharing']});
for(const dialog of document.querySelectorAll('dialog.context-sheet')){dialog.classList.add('polished-sheet');}
for(const [id,glyph,label]of [['meeting-chat-attach','paperclip','Attach file'],['meeting-chat-send','send','Send'],['guest-submit','mic','Join with microphone'],['guest-listen','headphones','Join to listen']]){labeledAction($(id),glyph,label);}
syncCallShell();

// One home and one invitation flow. Accounts add convenience to the same rooms.
function showAccount() {
  $('account-auth').hidden = false;
  $('show-account').setAttribute('aria-expanded', 'true');
  $('account-auth').scrollIntoView({block:'nearest',behavior:'auto'});
  $('username').focus({preventScroll:true});
}
$('landing-signin').onclick=showAccount;
$('network-create').onclick=()=>{$('guest-home').scrollIntoView({block:'start',behavior:'auto'});$('home-guest-name').focus({preventScroll:true});};
$('network-join').onclick=()=>{$('home-join-form').scrollIntoView({block:'center',behavior:'auto'});$('home-meeting-link').focus({preventScroll:true});};
$('show-account').onclick = () => {
  if ($('account-auth').hidden) showAccount();
  else { $('account-auth').hidden = true; $('show-account').setAttribute('aria-expanded','false'); }
};
$('guest-back-rooms').onclick = () => {
  meetingJoin.cancel();meetingJoin.hide();history.replaceState(null,'',location.pathname);
  meetingLinks.open().catch(error=>toast(error.message,true));
};
// Drop-in calling and migration are contextual tools, rather than competing homes.
const dropInDirectory=document.querySelector('.voice-directory');
if(dropInDirectory)document.querySelector('.people-main').append(dropInDirectory);
const accountTools=document.querySelector('.sidebar-extras');
if(accountTools)$('settings-view').append(accountTools);
const accountActions=document.createElement('div');accountActions.className='settings-account-actions';const settingsSignout=document.createElement('button');settingsSignout.className='button secondary';settingsSignout.type='button';settingsSignout.textContent='Sign out';settingsSignout.onclick=()=>$('logout').click();accountActions.append(settingsSignout);$('settings-view').append(accountActions);
bindSelfPreview($('call-view'),$('direct-self-preview'));

function showTrust(scope, from) {
  trustPanel?.destroy();trustScope=scope;
  openSheet($('trust-dialog'),from);
  trustPanel=mountTrustPanel($('trust-content'),{
    getPeers:()=>scope==='group'?[...groups.links.values()].map(link=>({id:link.id,name:groups.members.find(m=>m.id===link.id)?.display_name||'Participant',pc:link.pc}))
      :state.pc?[{id:state.call?.peer?.id||'peer',name:state.call?.peer?.display_name||'Participant',pc:state.pc}]:[],
    onSecurityFailure:()=>{if(scope==='group')groups.leave('security');else hangup();toast('Connection security check failed. Your media has been stopped.',true);}
  });
}
bindSheet($('trust-dialog'));
$('home-trust').onclick=()=>showTrust('preview',$('home-trust'));
$('call-trust').onclick=()=>showTrust('direct',$('call-trust'));
$('group-trust').onclick=()=>showTrust('group',$('group-trust'));
$('trust-close').onclick=()=>$('trust-dialog').close();
$('trust-dialog').addEventListener('close',()=>{trustPanel?.destroy();trustPanel=null;trustScope=null;});

const qualityDetails={};
for(const [scope,parent] of [['direct',$('call-settings')],['group',$('group-advanced')]]) {
  const detail=document.createElement('p');detail.className='quality-details';detail.id=scope==='direct'?'call-quality-detail':'group-quality-detail';
  parent.prepend(detail);qualityDetails[scope]=detail;
}
$('call-quality-summary').onclick=()=>$('call-quality').click();
$('group-quality-summary').onclick=()=>$('group-audio-open').click();
let nudgeDismissedUntil=0,microphoneStatusTimer;
document.addEventListener('pvp-media-health',event=>{
  const health=event.detail;
  if(health.type==='quality'&&health.selected) {
    const scope=health.scope,p=health.selected,panel=$(scope==='group'?'group-quality-summary':'call-quality-summary');
    const sendMode={auto:'Auto data saver',off:'Quality settings',low:'Low · 400 Kbps',verylow:'Very low · 128 Kbps',minimal:'Minimal · 64 Kbps',none:'Audio only'}[p.dataSend]||p.dataSend;
    const sendLimit=saverLimit(p.dataSend),policy=sendLimit===0?'Video off':sendLimit!=null?`${sendLimit} Kbps send cap`:p.dataSend==='auto'?'Auto bandwidth':'';
    const target=`${p.label} · ${p.resolution}p target${policy?' · '+policy:''}`;
    panel.textContent=`${target} · ${health.sent.label}`;
    panel.setAttribute('aria-label',`${panel.textContent}. Change audio and video quality`);
    qualityDetails[scope].textContent=`Selected: ${p.label}, up to ${p.resolution}p / ${p.fps} fps / ${p.kbps} Kbps per video connection.\nSend policy: ${sendMode}. Receive policy: ${p.dataReceive}.\n${health.sent.label}.\n${health.previewNotice} These are local encoder observations; the other person's playback can differ.`;
  }
  if(health.type==='microphone') {
    clearTimeout(microphoneStatusTimer);
    for(const id of ['call-health','group-health']){const node=$(id).querySelector('.mic-status');node.textContent=health.message;node.hidden=!health.message||health.status==='ready';}
    if(health.status==='switched')microphoneStatusTimer=setTimeout(()=>document.querySelectorAll('.mic-status').forEach(node=>node.hidden=true),6000);
  }
  if(health.type==='muted-speech') {
    const active=health.active&&!health.moderated&&Date.now()>nudgeDismissedUntil;
    $('group-health').querySelector('.muted-nudge').hidden=!active||!groups.joined;
    $('call-health').querySelector('.muted-nudge').hidden=!active||!state.call;
  }
});
for(const dismiss of document.querySelectorAll('[data-dismiss-nudge]'))dismiss.onclick=()=>{nudgeDismissedUntil=Date.now()+30000;document.querySelectorAll('.muted-nudge').forEach(node=>node.hidden=true);};
for(const action of document.querySelectorAll('[data-unmute]'))action.onclick=()=>{
  if(action.dataset.unmute==='group'){if(groups.joined&&groups.muted&&!groups.moderatorMuted)$('group-mic').click();}
  else if(state.call&&state.stream?.getAudioTracks().some(track=>!track.enabled&&track.readyState==='live'))$('toggle-mic').click();
};
