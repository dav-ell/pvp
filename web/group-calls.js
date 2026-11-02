import { syncPairStage, resetStage } from './call-stage.js';
import { createPeerConnection } from '../packages/pvp-call/src/mesh.js';
import { BandwidthMeter, bandwidthLabel, bandwidthControls, validCaps, videoCap, saverCaps } from './bandwidth.js';
import { MeetingChat } from '/meeting-chat.js';
import { cameraQuality, groupVideoKbps, screenVideoKbps } from './group-quality.js';
import { requireEncryptedSdp, requireCandidate, isRelay, safetyCode, inspectEncryptionReport } from '/security.js';
import { inspectReport, endpointLabel, mediaCaptureCommand } from '/inspector.js';
import { VideoOverlay } from '/group-video.js';
import { RemotePlayback } from './playback.js';
import { icon, callAction, rowAction, labeledAction, openSheet, closeSheet, bindSheet, copied, participantAvatar, stateBadge, videoState } from './ui.js';

const $ = id => document.getElementById(id);
const make = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
const STUN = ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'];
export class GroupCalls {
  constructor(options) {
    this.chat = new MeetingChat({self:()=>this.o.user()?.id,name:id=>id===this.o.user()?.id?'You':(()=>{const m=this.room?.members.find(m=>m.id===id);return m?`${m.display_name} · ${(m.id.startsWith('guest-')||m.username?.startsWith('~'))?'Guest':'@'+m.username}`:'Participant';})(),changed:()=>this.renderChat(),error:e=>this.o.toast(e,true)});
    this.o = options; this.room = null; this.links = new Map(); this.token = 0; this.events = []; this.pending = false;
    this.connectionCaps = new Map(); this.messageChain = Promise.resolve(); this.earlyCandidates = new Map(); this.maximized = null;
    this.display = null; this.shareBusy = false; this.shareToken = 0; this.inspectId = null; this.muted = !this.o.stream()?.getAudioTracks().some(t=>t.enabled&&t.readyState==='live'); this.paused = false;
    this.timer = setInterval(() => this.sample().catch(e => this.o.toast(e.message, true)), 1000);
    this.mobile=matchMedia('(max-width:700px)');this.seenChat=new Set();
    const extra=$('group-desktop-actions'),footer=$('group-more').parentElement;
    const layout=()=>{if(this.mobile.matches)$('group-more-content').prepend(extra);else footer.insertBefore(extra,$('group-more'));this.render();};this.mobile.addEventListener('change',layout);layout();document.addEventListener('visibilitychange',()=>{if($('meeting-chat-dialog').open&&!document.hidden)this.renderChat();if(document.hidden)document.querySelectorAll('.group-tile.speaking').forEach(n=>n.classList.remove('speaking'));});
    for(const id of ['group-more-dialog','group-audio-dialog','group-people-dialog','meeting-chat-dialog'])bindSheet($(id));
    for(const [button,dialog] of [['group-people-close','group-people-dialog'],['group-audio-close','group-audio-dialog'],['group-more-close','group-more-dialog'],['meeting-chat-close','meeting-chat-dialog']]){labeledAction($(button),'x','Back to call');$(button).onclick=()=>closeSheet($(dialog));}
    $('group-more').onclick=()=>openSheet($('group-more-dialog'),$('group-more'));
    $('group-people').onclick=()=>this.showPeople($('group-people'));
    $('group-audio-open').onclick=async()=>{closeSheet($('group-more-dialog'));const token=this.token;await this.o.devices();if(token!==this.token||!this.joined)return;for(const [kind,source] of [['mic','mic-device'],['camera','camera-device']]){$('group-'+kind+'-device').replaceChildren(...[...$(source).options].map(o=>o.cloneNode(true)));$('group-'+kind+'-device').value=this.o.preferences()[kind];}openSheet($('group-audio-dialog'),$('group-more'));};
    for(const kind of ['mic','camera'])$('group-'+kind+'-device').onchange=()=>this.o.device(kind,$('group-'+kind+'-device').value).catch(e=>this.o.toast(e.message,true));
    $('group-connection-open').onclick=()=>{closeSheet($('group-more-dialog'));this.showPeople($('group-more'));};
    $('group-chat-open').onclick=()=>{closeSheet($('group-more-dialog'));openSheet($('meeting-chat-dialog'),this.mobile.matches?$('group-more'):$('group-chat-open'));this.renderChat();};
    $('meeting-chat-dialog').addEventListener('close',()=>this.render());
    $('group-back').onclick=()=>this.o.browse();
    $('group-solo-invite').onclick=()=>$('group-copy-link').hidden?this.chooseFriends(true):$('group-copy-link').click();
    $('group-people-invite').onclick=()=>$('group-copy-link').hidden?this.chooseFriends(true):$('group-copy-link').click();
    $('group-stop-sharing').onclick=()=>this.stopSharing();
    $('meeting-chat-text').oninput=()=>this.updateChatComposer();
    $('meeting-chat-form').onsubmit=async e=>{e.preventDefault();try{await this.chat.text($('meeting-chat-text').value);$('meeting-chat-text').value='';this.updateChatComposer();}catch(e){this.o.toast(e.message,true);}};
    $('meeting-chat-attach').onclick=()=> $('meeting-chat-file').click();$('meeting-chat-file').onchange=async()=>{const file=$('meeting-chat-file').files[0];$('meeting-chat-file').value='';if(file)try{await this.chat.offer(file);}catch(e){this.o.toast(e.message,true);}};
    $('open-voice').onclick = () => this.enterVoice().catch(e=>this.o.toast(e.message,true));
    $('new-group').onclick = () => this.chooseFriends();
    $('group-join').onclick = () => this.join().catch(e => this.o.toast(e.message, true));
    $('group-decline').onclick = () => this.leave(); $('group-leave').onclick = () => this.leave();
    $('group-mic').onclick = () => { if(this.moderatorMuted)return; if(!this.o.stream()?.getAudioTracks().some(t=>t.readyState==='live')){this.o.enableMicrophone();return;} this.muted = !this.muted; this.o.stream()?.getAudioTracks().forEach(t => t.enabled = !this.muted); this.render(); this.broadcastState(); };
    $('group-hand').onclick=()=>this.changeHand();
    $('group-camera').onclick = async () => {try{await this.o.camera();this.paused=this.display?!this.display.getVideoTracks()[0]?.enabled:!this.o.stream()?.getVideoTracks().length;this.overlay?.sourceChanged();await this.limits();this.render();this.broadcastState();}catch(e){this.o.toast(e.message,true);}};
    $('group-share').onclick = () => this.share();
    $('group-play').onclick = () => this.playAll();
    $('group-quality').onchange=()=>this.o.quality($('group-quality').value).then(()=>this.limits()).catch(e=>this.o.toast(e.message,true));
    $('group-copy-link').onclick = async () => {
      if (!this.room) return;
      const url = new URL('/', location.origin);
      url.hash = this.room.meeting_id ? `meeting=${this.room.meeting_id}` : `voice=${this.room.room_id}`;
      try { await navigator.clipboard.writeText(url.href); for(const id of ['group-copy-link','group-solo-invite','group-people-invite'])copied($(id),()=>this.render()); }
      catch { window.prompt('Copy this room link', url.href); }
    };
    $('group-add').onclick = () => {closeSheet($('group-more-dialog'));this.showPeople(this.mobile.matches?$('group-more'):$('group-add'));};
    $('group-inspect-close').onclick = () => $('group-inspector').close();
    $('group-export').onclick = () => this.exportReport().catch(e=>this.o.toast(e.message,true));
  }
  get busy() { return this.pending || !!this.room; }
  get joined() { return this.room?.members.find(m => m.id === this.o.user()?.id)?.joined === true; }
  get members() { return this.room?.members.filter(m => m.joined) || []; }
  outgoing() { return this.display || this.o.stream(); }
  event(detail) { this.events.push({ at: new Date().toISOString(), source: 'Application event', detail }); if (this.events.length > 100) this.events.shift(); }
  get self() {return this.members.find(m=>m.id===this.o.user()?.id);}
  get speakingRequired() {return this.room?.raise_hand_enabled===true&&!this.isAdmin;}
  get awaitingApproval() {return this.speakingRequired&&!this.self?.speaking_allowed;}
  async changeHand() {
    if(!this.joined||!this.speakingRequired)return;
    this.o.primeSound?.();const button=$('group-hand');button.disabled=true;
    try{await this.o.api(`/meetings/${this.room.meeting_id}/hand`,{method:'POST',body:{raised:!this.self.hand_raised&&!this.self.speaking_allowed}});}
    catch(e){this.o.toast(e.message,true);}finally{button.disabled=false;}
  }
  get moderatorMuted() {return this.members.some(m=>m.id===this.o.user()?.id&&m.moderator_muted===true);}
  get isAdmin() {return this.members.some(m=>m.id===this.o.user()?.id&&m.is_admin===true);}
  isModerated(id) {return this.members.some(m=>m.id===id&&m.moderator_muted===true);}
  applyModeration() {
    if(this.moderatorMuted){this.muted=true;this.o.stream()?.getAudioTracks().forEach(t=>t.enabled=false);}
    for(const link of this.links.values()){link.remote.getAudioTracks().forEach(t=>t.enabled=!this.isModerated(link.id));if(this.isModerated(link.id))link.speaking=false;}
  }
  capabilities() { this.o.send({type: 'room-capabilities', client: 'browser', meeting_moderation: true, raise_hand: true}); }
  chooseFriends(adding = false) {
    if(!this.available){this.o.toast('Group calls require the updated PVP signaling service.',true);return;}
    if (!adding && (this.busy || this.o.busy())) return;
    const choices = this.o.friends().filter(f => f.status === 'accepted' && !this.room?.members.some(m => m.id === f.id));
    const form = $('group-picker-form'); form.replaceChildren(make('h2', adding ? 'Invite friends' : 'Start a group call'), make('p', 'Up to 16 people. Each invitation shows the participants before microphone access. Turn on your camera later if you want.'));
    for (const friend of choices) { const label = make('label', undefined, 'group-choice'), box = make('input'); box.type = 'checkbox'; box.value = friend.id; label.append(box, make('span', `${friend.display_name} · @${friend.username}`)); form.append(label); }
    const actions = make('div', undefined, 'group-actions'), cancel = make('button', 'Cancel', 'button secondary'), submit = make('button', adding ? 'Invite' : 'Start call', 'button primary'); cancel.type = 'button'; cancel.onclick = () => $('group-picker').close(); submit.type = 'submit'; actions.append(cancel, submit); form.append(actions);
    form.onsubmit = async e => { e.preventDefault(); const ids = [...form.querySelectorAll('input:checked')].map(n => n.value); if (!ids.length || ids.length > (adding ? 16 - this.room.members.length : 15)) { this.o.toast('Choose friends within the 16-person room limit.', true); return; }
      $('group-picker').close(); if (adding) ids.forEach(peer_id => this.o.send({type: 'room-invite', room_id: this.room.room_id, peer_id})); else await this.start(ids).catch(error => this.o.toast(error.message, true)); };
    $('group-picker').showModal();
  }
  async enterVoice(id) {
    if(!this.voiceAvailable)throw Error('Update the signaling service to use voice rooms.');
    if(this.busy||this.o.busy())throw Error('Finish your current call first.');
    const token=++this.token;this.pending=true;this.personalRoom=!id;
    try { this.o.stopMedia(); await this.o.capture(true); if(token!==this.token)return; this.o.send(id?{type:'voice-join',room_id:id}:{type:'voice-open'}); }
    catch(e){if(token===this.token){this.pending=false;this.o.stopMedia();}throw e;}
  }
  async start(ids) {
    this.personalRoom=false;
    if (this.busy || this.o.busy()) throw new Error('Finish your current call first.');
    const token = ++this.token; this.pending = true;
    try { this.o.stopMedia(); await this.o.capture(); if (token !== this.token) return; this.o.send({type: 'room-create', peer_ids: ids}); }
    catch(e) { if (token === this.token) { this.pending = false; this.o.stopMedia(); } throw e; }
  }
  async startMeeting(id,prepared=false){
    this.personalRoom=false;
    if(!this.meetingsAvailable)throw Error('Update PVP to join recurring meetings.');
    if(this.busy||this.o.busy())throw Error('Finish your current call first.');
    const token=++this.token;this.pending=true;
    try{if(!prepared){this.o.stopMedia();await this.o.capture();}if(token!==this.token)return;this.o.send({type:'meeting-enter',meeting_id:id});}
    catch(e){if(token===this.token){this.pending=false;this.o.stopMedia();}throw e;}
  }
  async join() {
    if (!this.room || this.joined || this.pending) return;
    const token = this.token; this.pending = true;
    try { this.o.stopMedia(); await this.o.capture(); if (token !== this.token || !this.room) return; this.o.send({type: 'room-join', room_id: this.room.room_id}); }
    catch(e) { if (token === this.token) { this.pending = false; this.o.stopMedia(); } throw e; }
  }
  message(msg) {
    const token=this.token;
    const next=this.messageChain.then(()=>{if(token===this.token)return this.receiveMessage(msg);});
    this.messageChain=next.catch(()=>{});return next;
  }
  async receiveMessage(msg) {
    if (msg.type === 'error' && this.pending) { this.pending = false; if (!this.joined) this.o.stopMedia(); this.render(); this.o.rejected?.(msg.message); return; }
    if (!msg.type.startsWith('room-')) return;
    if (msg.type === 'room-ended') { if (this.room?.room_id === msg.room_id) this.cleanup('removed'); return; }
    if (msg.type === 'room-state') {
      const self = msg.members?.find(m => m.id === this.o.user()?.id);
      if (!self) { if (this.room?.room_id === msg.room_id) this.cleanup('removed'); return; }
      if ((this.room && this.room.room_id !== msg.room_id) || this.o.busy()) { this.o.send({type: 'room-leave', room_id: msg.room_id}); return; }
      if (this.room && msg.revision <= this.room.revision) return;
      if(self.joined&&!this.room&&!this.pending){this.o.send({type:'room-leave',room_id:msg.room_id});return;}
      if(!self.joined)this.personalRoom=false;
      const settle=this.o.motion?.captureList($('group-grid'),msg.room_id);const wasJoined = this.joined,wasAllowed=this.self?.speaking_allowed===true; this.room = msg; this.pending = false;
      if (self.joined) {
        if (!wasJoined) { this.muted = !this.o.stream()?.getAudioTracks().some(t=>t.enabled&&t.readyState==='live'); this.paused = !this.o.stream()?.getVideoTracks().length; const token=this.token; this.overlay = new VideoOverlay(this); await this.overlay.initialize(); if(token!==this.token)return; }
        this.applyModeration();
        if(wasJoined&&!wasAllowed&&self.speaking_allowed===true&&this.speakingRequired){this.o.approved?.();this.o.toast('You can unmute and speak now.');}
        for (const [id, link] of this.links) if (!this.members.some(m => m.id === id)) this.closeLink(id, link);
        await this.reconcile(); this.overlay?.membershipChanged(); this.broadcastState();
      } else if (!wasJoined) this.o.ring?.();
      this.render();settle?.(); if(self.joined&&msg.meeting_id)this.o.admitted?.(msg.meeting_id); return;
    }
    if (msg.type === 'room-signal' && this.joined && msg.room_id === this.room.room_id) {
      let link = this.links.get(msg.from);
      if (!this.members.some(m => m.id === msg.from)) return;
      if (msg.payload.type === 'offer') {
        if (link && msg.generation > link.generation) this.closeLink(msg.from, link);
        link = this.links.get(msg.from) || await this.createLink(msg.from, msg.generation, false);
      }
      const key=`${msg.from}/${msg.generation}`;
      if(msg.payload.type==='candidate'&&(!link||link.generation<msg.generation)){
        requireCandidate(msg.payload.candidate);
        const pending=this.earlyCandidates.get(key)||[];
        if(pending.length<64){pending.push(msg.payload);this.earlyCandidates.set(key,pending);}return;
      }
      if (!link || link.generation !== msg.generation) return;
      for(const candidate of this.earlyCandidates.get(key)||[])link.chain=link.chain.then(()=>this.receive(link,candidate));
      this.earlyCandidates.delete(key);
      link.chain = link.chain.then(() => this.receive(link, msg.payload)).catch(e => this.linkFailure(link, e));
    }
  }
  async reconcile() {
    if (!this.joined || !this.o.stream()) return;
    for (const member of this.members) if (member.id !== this.o.user().id && !this.links.has(member.id)) {
      const initiator = this.o.user().id < member.id;
      if (initiator) await this.createLink(member.id, 1, true);
    }
  }
  async attachMicrophone(track) {
    if(!this.joined)throw Error('Rejoin the meeting before enabling your microphone.');
    const token=this.token,replaced=[];track.enabled=!this.moderatorMuted;
    try {
      for(const link of this.links.values())if(link.audioSender){await link.audioSender.replaceTrack(track);replaced.push(link);}
      if(token!==this.token||!this.joined)throw new DOMException('Call ended','AbortError');
      this.muted=this.moderatorMuted;
    } catch(error) {for(const link of replaced)try{await link.audioSender.replaceTrack(null);}catch{}throw error;}
  }
  caps(id) { if(!this.connectionCaps.has(id)) this.connectionCaps.set(id,{receive:{camera:null,screen:null},send:{camera:null,screen:null}}); return this.connectionCaps.get(id); }
  async createLink(id, generation, initiator) {
    if (this.links.has(id)) return this.links.get(id);
    const token = this.token, roomId = this.room.room_id;
    const pc = createPeerConnection();
    const link = { meter: new BandwidthMeter(), caps: this.caps(id), requested: {camera:null,screen:null}, id, pc, generation, chain: Promise.resolve(), candidates: [], remote: new MediaStream(), state: {}, evidence: null, code: '', frames: 0, forwardedBytes: 0, sentBytes: 0, receivedBytes: 0, openedAt: performance.now() };
    this.links.set(id, link);
    const valid = () => token === this.token && this.links.get(id) === link && roomId === this.room?.room_id;
    if(initiator){link.audioSender=pc.addTransceiver('audio',{direction:'sendrecv',streams:[this.o.stream()]}).sender;await link.audioSender.replaceTrack(this.o.stream().getAudioTracks()[0]||null);}
    if(initiator){link.videoSender=pc.addTransceiver('video',{direction:'sendrecv',streams:[this.o.stream()]}).sender;const video=this.outgoing()?.getVideoTracks()[0];if(video)await link.videoSender.replaceTrack(video);}
    pc.onicecandidate = e => { if (valid() && e.candidate && !isRelay(e.candidate.candidate)) this.signal(link, {type: 'candidate', candidate: e.candidate.toJSON()}); };
    pc.ontrack = e => { if (!valid()) return; if (!link.remote.getTracks().some(t => t.id === e.track.id)) link.remote.addTrack(e.track); this.applyModeration(); this.render(); this.play(link); };
    pc.onconnectionstatechange = () => { if (!valid()) return; this.event(`Peer ${id}: ${pc.connectionState}`); this.render(); if(pc.connectionState==='connected'){link.error=null;clearTimeout(link.retry);link.retry=null;link.disconnectedAt=null;}
      if(pc.connectionState==='disconnected')link.disconnectedAt ||= performance.now();
      if (pc.connectionState === 'failed') this.linkFailure(link, new Error('Direct peer connection failed')); };
    pc.ondatachannel = e => this.channel(link, e.channel);
    if (initiator) {
      this.channel(link, pc.createDataChannel('pvp-group-chat'));
      this.channel(link, pc.createDataChannel('pvp-group-control'));
      this.channel(link, pc.createDataChannel('pvp-group-video', { ordered: false, maxRetransmits: 0 }));
      const offer = await pc.createOffer(); requireEncryptedSdp(offer.sdp); if (!valid()) return link;
      await pc.setLocalDescription(offer); this.signal(link, {type: 'offer', sdp: pc.localDescription.sdp});
    }
    this.render(); return link;
  }
  signal(link, payload) { if (this.links.get(link.id) === link && this.room) this.o.send({type: 'room-signal', room_id: this.room.room_id, to: link.id, generation: link.generation, payload}); }
  async receive(link, p) {
    if (this.links.get(link.id) !== link) return;
    if (p.type === 'candidate') { requireCandidate(p.candidate); if (link.pc.remoteDescription) await link.pc.addIceCandidate(p.candidate); else link.candidates.push(p.candidate); return; }
    requireEncryptedSdp(p.sdp); await link.pc.setRemoteDescription({type: p.type, sdp: p.sdp});
    for (const c of link.candidates.splice(0)) await link.pc.addIceCandidate(c);
    if (p.type === 'offer') { const audio=link.pc.getTransceivers().find(t=>t.receiver.track.kind==='audio');if(audio){audio.direction='sendrecv';link.audioSender=audio.sender;audio.sender.setStreams(this.o.stream());await audio.sender.replaceTrack(this.o.stream().getAudioTracks()[0]||null);} const slot=link.pc.getTransceivers().find(t=>t.receiver.track.kind==='video');if(slot){slot.direction='sendrecv';link.videoSender=slot.sender;slot.sender.setStreams(this.o.stream());const video=this.outgoing()?.getVideoTracks()[0];if(video)await slot.sender.replaceTrack(video);} const answer = await link.pc.createAnswer(); requireEncryptedSdp(answer.sdp); await link.pc.setLocalDescription(answer); this.signal(link, {type: 'answer', sdp: link.pc.localDescription.sdp}); }
    link.code = await safetyCode(link.pc.localDescription.sdp, link.pc.remoteDescription.sdp).catch(()=>null); await this.limits();
  }
  channel(link, dc) {
    if(this.links.get(link.id)!==link||!this.joined){dc.close();return;}
    if(dc.label==='pvp-group-chat'){if(link.chat){dc.close();return;}link.chat=dc;this.chat.peer(link.id,dc);return;}
    if (!['pvp-group-control', 'pvp-group-video'].includes(dc.label)) { dc.close(); return; }
    const key = dc.label.endsWith('control') ? 'control' : 'video'; if (link[key]) { dc.close(); return; } link[key] = dc; dc.binaryType = 'arraybuffer';
    dc.onopen = () => { this.broadcastState(); this.overlay?.peerOpened(link); };
    let windowAt = performance.now(), messages = 0;
    dc.onmessage = e => {
      if (this.links.get(link.id) !== link) return;
      if (performance.now() - windowAt > 1000) { windowAt = performance.now(); messages = 0; }
      if (++messages > (key === 'control' ? 40 : 400)) return;
      if (key === 'video') { if (e.data instanceof ArrayBuffer && e.data.byteLength <= 10000) this.overlay?.packet(link, e.data); return; }
      if (typeof e.data !== 'string' || e.data.length > 4096) return;
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.type === 'state') { const wasSharing=link.state.sharing;link.state = { muted: msg.muted === true, paused: msg.paused === true, sharing: msg.sharing === true, speaking: msg.speaking === true, listening:msg.listening===true };if(wasSharing!==link.state.sharing)this.overlay?.remoteSourceChanged(link);this.render(); }
      else if(msg.type==='bandwidth'){const caps=validCaps(msg.caps);if(caps){const changed=caps.camera!==link.requested.camera||caps.screen!==link.requested.screen;link.requested=caps;link.bandwidthSupported=true;this.control(link,{type:'bandwidth-ack'});if(changed)this.limits().catch(e=>this.o.toast(e.message,true));}}
      else if(msg.type==='bandwidth-ack')link.bandwidthSupported=true;
      else this.overlay?.control(link, msg).catch(() => {});
    };
    dc.onclose = () => { link.overlayReady = false; this.overlay?.refresh(); };
  }
  control(link, msg) { if (link.control?.readyState === 'open' && link.control.bufferedAmount < 32768) link.control.send(JSON.stringify(msg)); }
  broadcastState() {
    if (!this.joined) return;
    const speaking = !this.muted && this.o.level() > .025;
    for (const link of this.links.values()) {this.control(link,{type:'bandwidth',caps:saverCaps(link.caps.receive,this.o.preferences().dataReceive)});this.control(link, {type: 'state', muted: this.muted, paused: this.paused, sharing: !!this.display, speaking, listening:!this.o.stream()?.getAudioTracks().some(t=>t.readyState==='live')});}
  }
  activeSpeakers() {
    const ids=[...this.links.values()].filter(l=>l.state.speaking&&!l.state.muted&&!this.isModerated(l.id)).map(l=>l.id);
    if(!this.muted&&this.o.level()>.025)ids.push(this.o.user().id);
    const active=ids.sort();const now=performance.now();
    if(now-(this.speakerSelectedAt||0)<2000&&this.selectedSpeakers?.some(id=>active.includes(id)))return this.selectedSpeakers.filter(id=>active.includes(id));
    this.speakerSelectedAt=now;this.selectedSpeakers=active.slice(0,2);return this.selectedSpeakers;
  }
  async limits() {
    const p = this.o.preferences(), count = Math.max(1, this.members.length - 1);
    await Promise.all([...this.links.values()].map(async link => {
      if(link.limiting || link.pc.signalingState==='closed')return;
      link.limiting=true;
      const update=Promise.all(link.pc.getSenders().map(async sender => {
        if(!sender.track)return;
        const params=sender.getParameters();if(!params.encodings?.length)return;
        for(const enc of params.encodings){
          enc.maxBitrate=sender.track.kind==='audio'?Math.min(p.audio,32)*1000:Math.max(16000,Math.floor(groupVideoKbps(p,this.members.length)*(this.overlay?.ready()?500:1000)/count));
          if(sender.track.kind==='video'){
            const high=!!this.display||this.activeSpeakers().includes(this.o.user().id)||link.wantHigh;
            const quality=cameraQuality(p,this.members.length,high,sender.track.getSettings().height||p.resolution);
            params.degradationPreference=this.display||quality.small?'maintain-resolution':'balanced';
            enc.maxFramerate=this.display?15:quality.fps;
            if(this.display){enc.maxBitrate=screenVideoKbps(p,link.wantHigh&&link.focusedScreen,[...this.links.values()].some(l=>l.wantHigh&&l.focusedScreen),count)*1000;enc.priority=link.wantHigh&&link.focusedScreen?'high':'medium';}
            else if(link.focusedScreen){enc.maxBitrate=Math.min(enc.maxBitrate,30000);enc.maxFramerate=3;}
            else enc.priority='low';
            enc.scaleResolutionDownBy=this.display?1:quality.scale;
            if(!high&&!quality.small)enc.maxBitrate=Math.min(30000,enc.maxBitrate);
            enc.maxBitrate=videoCap(enc.maxBitrate/1000,saverCaps(link.caps.send,p.dataSend),link.requested,!!this.display)*1000;
            if(enc.maxBitrate<=400000){enc.maxFramerate=Math.min(enc.maxFramerate,enc.maxBitrate<=128000?10:15);if(!this.display)enc.scaleResolutionDownBy=Math.max(enc.scaleResolutionDownBy,(sender.track.getSettings().height||p.resolution)/(enc.maxBitrate<=128000?180:360));}
            enc.active=!this.paused&&!link.useOverlay&&enc.maxBitrate!==0;
            if(enc.maxBitrate===0)delete enc.maxBitrate;
          }
        }
        await sender.setParameters(params);
      })).finally(()=>{link.limiting=false;});
      let timer;
      try{await Promise.race([update,new Promise(resolve=>{timer=setTimeout(resolve,2000);})]);}finally{clearTimeout(timer);}
    }));
  }
  async sample() {
    if(this.sampling)return this.sampling;
    const pending=this.sampleOnce();this.sampling=pending;
    try{return await pending;}finally{if(this.sampling===pending)this.sampling=null;}
  }
  async sampleOnce() {
    if (!this.joined) return;
    this.broadcastState(); await this.overlay?.refresh();
    await Promise.all([...this.links.values()].map(async link => {
      if (link.sampling || link.pc.connectionState === 'closed') return; link.sampling = true;
      try { const stats = await Promise.race([link.pc.getStats(), new Promise((_,reject)=>setTimeout(()=>reject(new Error('Peer stats timeout')),3000))]); if (this.links.get(link.id) !== link) return;
        link.meter.sample(stats);this.o.mediaStats?.(stats,link.id);
        link.proof=await inspectEncryptionReport(stats,{localSdp:link.pc.localDescription?.sdp,remoteSdp:link.pc.remoteDescription?.sdp,connectionState:link.pc.connectionState});
        if(this.links.get(link.id)!==link)return;
        if(link.proof.failure){this.leave('security');this.o.toast('Connection security check failed. The room connection has been stopped.',true);return;}
        link.evidence = inspectReport(stats, {connectionState: link.pc.connectionState, iceState: link.pc.iceConnectionState, configuredServers: STUN});
        if(link.pc.connectionState==='disconnected'&&performance.now()-link.disconnectedAt>8000)this.linkFailure(link,new Error('Peer disconnected'));
        if(link.pc.connectionState==='connecting'&&performance.now()-link.openedAt>15000)this.linkFailure(link,new Error('Peer connection timed out'));
        const audio = [...stats.values()].find(s => s.type === 'inbound-rtp' && s.kind === 'audio');
        const delta = audio && link.energy ? (audio.totalAudioEnergy - link.energy.value) / Math.max(.001, audio.totalSamplesDuration - link.energy.duration) : 0;
        link.energy = audio ? {value: audio.totalAudioEnergy || 0, duration: audio.totalSamplesDuration || 0} : null;
        link.speaking = link.pc.connectionState==='connected' && !this.isModerated(link.id) && !link.state.muted && (audio?.audioLevel > .025 || delta > .0006);
      } catch { link.proof=null;/* Older observations retain their original timestamp. */ } finally { link.sampling = false; }
    }));
    await this.limits(); this.render(); this.renderInspector();
  }
  linkFailure(link, error) {
    if (this.links.get(link.id) !== link) return;
    this.event(`Peer ${link.id}: ${error.message}`); link.error = 'Direct connection unavailable'; link.overlayReady = false;
    this.overlay?.refresh(); this.render();
    if (this.o.user().id < link.id && link.generation < 8 && !link.retry) link.retry = setTimeout(async () => {
      if (!this.joined || this.links.get(link.id) !== link) return;
      this.closeLink(link.id, link); try { await this.createLink(link.id, link.generation + 1, true); } catch(e) { this.o.toast(e.message, true); }
    }, 2500);
  }
  closeLink(id, link) { this.chat.remove(id);link.chat?.close();clearTimeout(link.retry); link.control?.close(); link.video?.close();link.playback?.dispose(); link.pc.close(); this.overlay?.removePeer(id); this.links.delete(id); if(this.maximized===id)this.maximized=null; $(`group-tile-${id}`)?.remove();this.updatePlaybackButton(); }
  updateChatComposer(){
    $('meeting-chat-send').disabled=!this.chat.ready().length || !$('meeting-chat-text').value.trim();
    $('meeting-chat-attach').disabled=!this.chat.ready().length;
  }
  renderChat(){
    const root=$('meeting-chat-messages');if(!root)return;if($('meeting-chat-dialog').open&&!document.hidden)this.chat.items.forEach(item=>this.seenChat.add(item.peer+':'+item.id));const nearBottom=root.scrollHeight-root.scrollTop-root.clientHeight<80;const settle=this.o.motion?.captureList(root);root.replaceChildren();
    if(!this.chat.items.length){const empty=make('div',undefined,'chat-empty');empty.append(make('strong','Start the conversation'),make('p','Messages and files appear here.'));root.append(empty);}
    for(const item of this.chat.items){const row=make('article',undefined,'chat-message');row.dataset.motionKey=item.peer+':'+item.id;row.append(make('strong',item.sender||'Participant'));if(item.text)row.append(make('p',item.text));else{row.append(make('p',`${item.name} · ${(item.size/1024).toFixed(1)} KiB`));if(item.bytes){const preview=this.chat.url(item,true);if(preview){const image=make('img');image.src=preview;image.alt=item.name;image.loading='lazy';row.append(image);}const save=make('a','Save file','button secondary');save.href=this.chat.url(item);save.download=item.name;row.append(save);}else if(item.peer!==this.o.user()?.id&&item.status==='Offered'){const accept=make('button','Accept file','button secondary');accept.onclick=()=>{try{this.chat.accept(item);}catch(e){this.o.toast(e.message,true);}};row.append(accept);}const clear=make('button',item.bytes?'Clear file':'Cancel','button subtle');clear.onclick=()=>this.chat.cancel(item);row.append(clear);}row.append(make('small',item.status));root.append(row);}
    const count=this.chat.ready().length;
    $('meeting-chat-status').textContent=(count?`${count} participant${count===1?'':'s'} connected to chat`:'Waiting for another participant to connect')+' · Messages are cleared when you leave.';
    this.updateChatComposer();settle?.();if(nearBottom)root.scrollTop=root.scrollHeight;this.renderControls();
  }
  updatePlaybackButton() { $('group-play').hidden = ![...this.links.values()].some(link => link.playback?.blocked);this.renderStatus(); }
  async play(link) {
    const video = $(`group-video-${link.id}`);
    if (!video || !link.remote.getTracks().length || this.links.get(link.id) !== link) return;
    link.playback ||= new RemotePlayback(video, () => this.updatePlaybackButton());
    link.playback.attach(link.remote);
    await link.playback.play();
  }
  playAll() { for (const l of this.links.values()) this.play(l); }
  maximize(id) {
    this.maximized=this.maximized===id?null:id;this.render();
    this.overlay?.refresh().then(()=>this.limits()).catch(()=>{});
  }
  showPeople(from){this.renderPeople();openSheet($('group-people-dialog'),from||$('group-people'));}
  renderPeople() {
    const key=JSON.stringify([this.room?.members,this.room?.raise_hand_enabled,this.isAdmin,[...this.links.keys()]]);if(key===this.peopleKey)return;this.peopleKey=key;
    const root=$('group-people-content');root.replaceChildren();
    if(this.isAdmin&&this.room?.meeting_id){
      const label=make('label','Raise hand to speak','sheet-switch'),toggle=make('input');toggle.id='group-raise-hand';toggle.type='checkbox';toggle.setAttribute('role','switch');toggle.checked=!!this.room.raise_hand_enabled;
      toggle.onchange=async()=>{toggle.disabled=true;try{await this.o.api(`/meetings/${this.room.meeting_id}/speaking`,{method:'POST',body:{enabled:toggle.checked}});}catch(e){toggle.checked=!toggle.checked;this.o.toast(e.message,true);}finally{toggle.disabled=false;}};
      label.append(toggle);root.append(label,make('p','Participants need admin approval before unmuting. Admins can speak freely.','muted'));
    }
    for(const member of [...(this.room?.members||[])].sort((a,b)=>Number(!!b.hand_raised)-Number(!!a.hand_raised))){
      const row=make('div',undefined,'meeting-person'),name=make('div',undefined,'person-info'),avatar=make('span',member.display_name.trim().split(/\s+/).slice(0,2).map(n=>n[0]||'').join(''),'person-avatar');avatar.setAttribute('aria-hidden','true');name.append(make('strong',member.display_name),make('p',`${member.joined?'In the call':'Invited'}${member.id.startsWith('guest-')?' · Guest':''}${member.is_admin?' · Admin':''}${member.hand_raised?' · Hand raised':member.speaking_allowed?' · Can speak':member.moderator_muted?(this.room.raise_hand_enabled&&!member.is_admin?' · Waiting for approval':' · Muted by admin'):''}`));row.dataset.memberId=member.id;row.append(avatar,name);
      const menu=make('details',undefined,'person-menu'),summary=make('summary');summary.setAttribute('aria-label',`Options for ${member.display_name}`);summary.append(icon('ellipsis'));menu.append(summary);
      const item=(glyph,label,fn)=>{const b=make('button',undefined,'button secondary');rowAction(b,glyph,label);b.dataset.action=label==='Mute'?'mute':label==='Allow unmute'?'allow':label==='Remove'?'kick':glyph;b.onclick=async()=>{menu.open=false;b.disabled=true;try{await fn();}catch(e){this.o.toast(e.message,true);}finally{b.disabled=false;}};menu.append(b);};
      if(this.isAdmin&&member.id!==this.room.owner_id&&member.id!==this.o.user()?.id){
        if(this.room.raise_hand_enabled&&!member.is_admin){
          if(member.hand_raised)item('hand','Allow to speak',()=>this.o.moderate(this.room.meeting_id,member,'speak'));
          if(member.speaking_allowed)item('mic-off','End speaking turn',()=>this.o.moderate(this.room.meeting_id,member,'stop-speaking'));
        }else item('mic-off',member.moderator_muted?'Allow unmute':'Mute',()=>this.o.moderate(this.room.meeting_id,member,member.moderator_muted?'allow':'mute'));
        item('log-out','Remove',()=>this.o.moderate(this.room.meeting_id,member,'kick'));
      }
      if(member.joined&&member.id!==this.o.user()?.id&&this.links.has(member.id)){item('pin',this.pinned===member.id?'Unpin':'Pin',()=>{this.pinned=this.pinned===member.id?null:member.id;this.render();});item('maximize','Expand',()=>{closeSheet($('group-people-dialog'));this.maximize(member.id);});item('wifi','Connection details',()=>{closeSheet($('group-people-dialog'));this.inspectId=member.id;bandwidthControls($('group-bandwidth-controls'),this.caps(member.id),(direction,source,value)=>{this.caps(member.id)[direction][source]=value;this.broadcastState();this.overlay?.refresh().then(()=>this.limits()).catch(e=>this.o.toast(e.message,true));});openSheet($('group-inspector'),$('group-people'));this.renderInspector();});}
      if(menu.children.length>1)row.append(menu);root.append(row);
    }
  }
  renderControls(){
    const raised=this.members.filter(m=>m.hand_raised).length;
    const hasMic=this.o.stream()?.getAudioTracks().some(t=>t.readyState==='live'),busy=$('group-mic').dataset.capturePending==='true',unread=this.chat.items.filter(i=>i.peer!==this.o.user()?.id&&!this.seenChat.has(i.peer+':'+i.id)).length;
    callAction($('group-mic'),{glyph:!hasMic?'mic':this.muted?'mic-off':'mic',label:hasMic?'Microphone':'Use mic',action:this.awaitingApproval?'Waiting for approval':this.moderatorMuted?'Muted by admin':!hasMic?'Use mic':this.muted?'Unmute':'Mute',pressed:hasMic?!this.muted:undefined,active:hasMic&&!this.muted,always:!hasMic||(this.moderatorMuted&&!this.awaitingApproval),add:!hasMic,busy});
    $('group-hand').hidden=!this.joined||!this.speakingRequired;
    callAction($('group-hand'),{glyph:'hand',label:this.self?.speaking_allowed?'Finish speaking':this.self?.hand_raised?'Lower hand':'Raise hand',action:this.self?.speaking_allowed?'Finish speaking':this.self?.hand_raised?'Lower hand':'Raise hand',pressed:!!this.self?.hand_raised,active:!!this.self?.hand_raised,always:true});
    callAction($('group-camera'),{glyph:this.paused?'video-off':'video',label:'Camera',action:this.paused?'Turn camera on':'Turn camera off',pressed:!this.paused,active:!this.paused,busy:this.o.cameraBusy()});
    if(this.mobile.matches){rowAction($('group-share'),this.display?'screen-share-off':'screen-share',this.display?'Stop sharing':'Share screen');rowAction($('group-chat-open'),'message-circle',unread?`Chat · ${unread} new`:'Chat');rowAction($('group-add'),'users-round',`People · ${this.members.length}${raised?` · ${raised} raised`:''}`);}else{
      callAction($('group-share'),{glyph:this.display?'screen-share-off':'screen-share',label:'Screen sharing',action:this.display?'Stop sharing':'Share screen',active:!!this.display,pressed:!!this.display});callAction($('group-chat-open'),{glyph:'message-circle',label:'Chat',action:'Chat',badge:unread});callAction($('group-add'),{glyph:'users-round',label:`People, ${this.members.length} in call${raised?`, ${raised} hands raised`:''}`,action:'People'});
    }
    callAction($('group-more'),{glyph:'ellipsis',label:'More',badge:this.mobile.matches?unread+raised:0});callAction($('group-leave'),{glyph:'phone-off',label:'Leave room',action:'Leave',always:true});
    labeledAction($('group-people'),raised?'hand':'users-round',raised?`${raised} raised`:String(this.members.length));$('group-people').setAttribute('aria-label',`People, ${this.members.length} in call${raised?`, ${raised} hands raised`:''}`);
    if(!$('group-copy-link').dataset.copied)labeledAction($('group-copy-link'),'link','Invite');
    for(const [id,glyph,label] of [['group-back','chevron-left','Back to rooms'],['group-solo-invite','link','Invite'],['group-people-invite','link','Invite'],['group-play','volume-2','Hear meeting']]){if(!$(id).dataset.copied)labeledAction($(id),glyph,label);}
    for(const [id,glyph,label] of [['group-audio-open','settings-2','Audio & video'],['group-connection-open','wifi','Connection details'],['group-fullscreen','maximize','Full screen'],['group-switch-camera','switch-camera','Flip camera']])rowAction($(id),glyph,label);
    $('group-share').hidden=!navigator.mediaDevices?.getDisplayMedia&&!this.display;$('group-switch-camera').hidden=!this.o.stream()?.getVideoTracks().length||!!this.display;
    $('group-sharing').hidden=!this.display;$('group-view').dataset.sharing=String(!!this.display);
  }
  renderStatus() {
    if(!this.joined)return;
    const blocked=[...this.links.values()].some(l=>l.playback?.blocked), connected=[...this.links.values()].filter(l=>l.pc.connectionState==='connected').length;
    $('group-call-status').textContent=blocked?'Tap to hear the meeting':this.members.length===1?'Waiting for others':[...this.links.values()].some(l=>l.error)?'Connection interrupted':connected<this.members.length-1?'Connecting…':this.awaitingApproval?(this.self?.hand_raised?'Hand raised · Waiting for an admin':'Raise your hand to speak'):this.speakingRequired&&this.self?.speaking_allowed&&this.muted?'You can unmute and speak now':!this.o.stream()?.getAudioTracks().some(t=>t.readyState==='live')?'Listening':this.moderatorMuted?'Muted by admin':'';
  }
  render() {
    document.body.classList.toggle('meeting-in-call',this.joined);
    this.renderStatus();this.renderControls();if($('group-people-dialog').open)this.renderPeople();
    if (this.joined && $('group-view').hidden) document.querySelector('.workspace').classList.remove('browsing');
    $('group-copy-link').hidden = !this.room?.voice && !this.room?.meeting_id;
    $('group-incoming').hidden = !this.room || this.joined; $('group-view').hidden = !this.joined;
    this.o.mediaState?.();
    if (!this.room) {resetStage($('group-view'));return;}
    const names = this.room.members.map(m => `${m.display_name}${m.joined ? '' : ' (invited)'}`).join(', ');
    $('group-roster').textContent = names; $('group-invite-roster').textContent = names;
    $('group-join').disabled = this.pending; $('group-invite-detail').textContent = 'Joining authorizes encrypted connections to these participants, including people outside your friends list. Peers can see your network address.';
    if (!this.joined) return;
    $('group-grid').classList.toggle('maximized',!!this.maximized);
    $('group-grid').querySelector('.self').classList.toggle('maximized',this.maximized==='self');
    let selfMax=$('group-self-maximize');if(!selfMax){selfMax=make('button','Maximize','group-small-button');selfMax.id='group-self-maximize';selfMax.onclick=()=>this.maximize('self');$('group-self-label').parentElement.append(selfMax);}labeledAction(selfMax,this.maximized==='self'?'minimize':'maximize',this.maximized==='self'?'Restore':'Maximize');selfMax.setAttribute('aria-label',this.maximized==='self'?'Restore self view':'Expand self view');
    $('group-quality').value=this.o.preferences().preset;
    for(const preset of ['saver','balanced','studio']){const defaults={saver:{preset,resolution:360,video:400},balanced:{preset,resolution:720,video:1800},studio:{preset,resolution:1080,video:4000}};const p=defaults[preset],kbps=groupVideoKbps(p,this.members.length);$('group-quality').querySelector(`[value=${preset}]`).textContent=`${preset==='saver'?'Data saver':preset==='studio'?'High quality':'Balanced'} · ${preset==='balanced'&&this.members.length<=8?'480p target · ':''}${(kbps/1000).toFixed(1)} Mbps cap`; }
    $('group-bandwidth').textContent=bandwidthLabel([...this.links.values()].map(l=>l.meter.rate));
    $('group-camera').hidden=false;
    $('group-share').hidden=!navigator.mediaDevices?.getDisplayMedia&&!this.display;
    $('group-add').hidden=false;
    $('group-quality').closest('label').hidden=this.paused&&!this.display;
    $('group-view').classList.toggle('voice-only',this.paused&&!this.display&&![...this.links.values()].some(l=>l.state.paused===false));
    $('group-heading').textContent=this.personalRoom?'Your drop-in room':this.room.name||(this.room.voice?'Drop-in room':'Conversation');$('group-view').dataset.count=String(this.members.length);$('group-solo-invite').hidden=this.members.length!==1;$('group-grid').classList.toggle('solo',this.members.length===1);$('group-grid').classList.toggle('duo',this.members.length===2);
    $('group-mic').disabled=this.moderatorMuted;this.renderControls();
    const local = $('group-self-video'), outgoing=this.outgoing(), videoTrack=outgoing?.getVideoTracks()[0]?.id||'';
    // An initially empty listen-only stream can gain its first camera track.
    // Retry playback on that transition; Safari may reject the empty source.
    if (local.srcObject !== outgoing || local._sourceVideoTrack !== videoTrack) { local._sourceVideoTrack=videoTrack;local.srcObject = outgoing; local.play().catch(() => {}); } local.classList.toggle('screen-sharing', !!this.display);
    $('group-self-video').closest('.group-tile').dataset.initials=(this.o.user()?.display_name||'You').trim().split(/\s+/).slice(0,2).map(n=>n[0]).join('').toUpperCase();
    const selfTile=$('group-self-video').closest('.group-tile');selfTile.dataset.localCapture=String(!this.paused);participantAvatar(selfTile,this.o.user()?.display_name||'You');stateBadge(selfTile,{muted:this.muted,listening:!this.o.stream()?.getAudioTracks().length,adminMuted:this.moderatorMuted,sharing:!!this.display});videoState(selfTile,local,!this.paused);selfTile.classList.toggle('speaking',!this.muted&&this.o.level()>.025&&!document.hidden);
    syncPairStage($('group-view'),this.members.length);
    const proofs=[...this.links.values()].map(l=>l.proof);$('group-trust').textContent=proofs.length&&proofs.every(p=>p?.encryptionState==='confirmed'&&Date.now()-Date.parse(p.sampledAt)>=0&&Date.now()-Date.parse(p.sampledAt)<4000)&&[...this.links.values()].every(l=>l.pc.connectionState==='connected')?'Encryption observed':'Connection evidence';
    $('group-self-label').textContent = `${this.o.user()?.display_name||'You'}${this.members.length===1?'':' · You'}${this.self?.hand_raised?' · Hand raised':''}`;
    for (const member of this.members) {
      if (member.id === this.o.user().id) continue;
      let tile = $(`group-tile-${member.id}`);
      if (!tile) {
        tile = make('article', undefined, 'group-tile'); tile.id = `group-tile-${member.id}`;tile.dataset.motionKey=member.id; tile.dataset.initials=member.display_name.trim().split(/\s+/).slice(0,2).map(n=>n[0]).join('').toUpperCase();
        const video = make('video'); video.id = `group-video-${member.id}`; video.autoplay = true; video.playsInline = true;
        const canvas = make('canvas'); canvas.id = `group-canvas-${member.id}`; canvas.hidden = true;
        const caption = make('div', undefined, 'group-tile-caption'), label = make('span'), inspect = make('button', 'Connection', 'group-small-button'); inspect.onclick = async () => { this.inspectId = member.id; bandwidthControls($('group-bandwidth-controls'),this.caps(member.id),(direction,source,value)=>{this.caps(member.id)[direction][source]=value;this.broadcastState();this.overlay?.refresh().then(()=>this.limits()).catch(e=>this.o.toast(e.message,true));}); $('group-inspector').showModal(); await this.sample(); this.renderInspector(); };
        const pin = make('button', 'Pin', 'group-small-button'); pin.onclick = () => { this.pinned = this.pinned === member.id ? null : member.id; this.render(); };
        const maximize=make('button','Maximize','group-small-button');maximize.dataset.maximize='';maximize.onclick=()=>this.maximize(member.id);
        for(const [button,glyph,text]of [[pin,'pin','Pin'],[maximize,'maximize','Maximize'],[inspect,'wifi','Connection']]){labeledAction(button,glyph,text);button.setAttribute('aria-label',text+' '+member.display_name);button.title=text;}caption.append(label,pin,maximize,inspect); tile.append(video, canvas, caption); $('group-grid').append(tile);
      }
      const link = this.links.get(member.id); const video = $(`group-video-${member.id}`);
      if (link && video.srcObject !== link.remote && link.remote.getTracks().length) { video.srcObject = link.remote; this.play(link); }
      if(link?.state.paused){const canvas=tile.querySelector('canvas');if(!canvas.hidden){const ctx=canvas.getContext('2d');ctx.fillStyle='#122a21';ctx.fillRect(0,0,canvas.width,canvas.height);}}
      tile.classList.toggle('maximized',this.maximized===member.id);labeledAction(tile.querySelector('[data-maximize]'),this.maximized===member.id?'minimize':'maximize',this.maximized===member.id?'Restore':'Maximize');
      tile.classList.toggle('speaking', !!link?.speaking&&link?.pc.connectionState==='connected'&&!document.hidden); tile.classList.toggle('pinned', this.pinned === member.id);
      tile.querySelector('span').textContent=member.display_name+(member.hand_raised?' · Hand raised':'');participantAvatar(tile,member.display_name);stateBadge(tile,{muted:link?.state.muted,listening:link?.state.listening,adminMuted:member.moderator_muted,sharing:link?.state.sharing});videoState(tile,video,link?.state.paused===false);

    }
  }
  videoForwarder(link) {
    if(!link?.receivingOverlay)return null;
    const parent=this.overlay?.parent(link.id);
    return parent&&parent!==link.id?parent:null;
  }
  renderInspector() {
    if (!$('group-inspector').open) return;
    const link = this.links.get(this.inspectId), d = link?.evidence;
    const member = this.members.find(m => m.id === this.inspectId);
    $('group-connection-bandwidth').textContent=bandwidthLabel(link?[link.meter.rate]:[]);
    $('group-bandwidth-status').textContent=link?.bandwidthSupported?'Receive limits supported by this participant.':'Waiting for receive-limit support from this participant. Older clients may not honor receive limits.';
    $('group-inspector-title').textContent = `Connection to ${member?.display_name || 'participant'}`;
    $('group-inspector-detail').textContent = `WebRTC observations, not packet capture. ${d?.direct && link.pc.connectionState==='connected' && Date.now()-Date.parse(d.sampledAt)<4000 ? 'Selected direct peer route' : 'Route unverified'}\nObserved: ${d?.sampledAt || 'unavailable'}\nLocal: ${endpointLabel(d?.local)}\nRemote: ${endpointLabel(d?.remote)}\nDTLS: ${d?.dtlsState || 'unavailable'} · ${d?.dtlsCipher || 'unavailable'} · ${d?.srtpCipher || 'unavailable'}\nSent ${d?.bytesSent ?? 'unavailable'} bytes · received ${d?.bytesReceived ?? 'unavailable'} bytes\nPair certificate code: ${link?.code || 'unavailable'}\n${link?.receivingOverlay ? (this.videoForwarder(link)?`Video source ${link.id}; immediate forwarder ${this.videoForwarder(link)}. Forwarded encrypted content is authenticated separately from hop transport.`:`Video received directly from source ${link.id} as encrypted frames. Audio uses this direct link.`) : 'Video and audio use this direct link.'}\n${mediaCaptureCommand(d, 'macos') || 'Capture filter unavailable.'}`;
  }
  async exportReport() {
    await this.sample();
    const report = {schemaVersion: 2, client: 'PVP browser group call', exportedAt: new Date().toISOString(), notice: 'Observed application/engine data; not an independent packet capture. Includes peer network addresses.', roomId: this.room?.room_id, revision: this.room?.revision,
      peers: [...this.links.values()].map(l => ({peerId: l.id, media: l.evidence, certificateCode: l.code, receivingEncodedVideo: !!l.receivingOverlay, receivingForwardedVideo: !!this.videoForwarder(l), forwarder: this.videoForwarder(l), overlay: {forwardedBytes: l.forwardedBytes, sentBytes: l.sentBytes, receivedBytes: l.receivedBytes, decodedFrames: l.frames}})), events: this.events};
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type:'application/json'})), a = make('a'); a.href = url; a.download = `pvp-group-${Date.now()}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async share() {
    if (!this.joined || this.shareBusy) return;
    if (this.display) { await this.stopSharing(); return; }
    if (!navigator.mediaDevices.getDisplayMedia) { this.o.toast('Screen sharing unavailable.', true); return; }
    const token = this.token, shareToken = ++this.shareToken; this.shareBusy = true; let display; const replaced = [];
    try {
      display = await navigator.mediaDevices.getDisplayMedia({video:{width:{ideal:3840},height:{ideal:2160},frameRate:{ideal:15,max:15}},audio:false});
      if (token !== this.token || shareToken !== this.shareToken) return;
      const track = display.getVideoTracks()[0]; if (!track) throw new Error('No screen was opened.');track.contentHint='detail';
      display.getAudioTracks().forEach(t => {t.stop();display.removeTrack(t);});
      for (const link of this.links.values()) for (const s of [link.videoSender]) if (s) { const old=s.track; await s.replaceTrack(track); replaced.push([s,old]); }
      if (token !== this.token) return;
      this.cameraBeforeShare = this.paused; this.display = display; this.paused = false; this.o.stream().getVideoTracks().forEach(t=>t.enabled=false);
      track.onended=()=>this.stopSharing(); this.overlay?.sourceChanged(); this.render(); this.broadcastState();
    } catch(e) { if(token===this.token){for(const [s,t] of replaced){try{await s.replaceTrack(t);}catch{}}this.o.toast(e.message,true);} }
    finally { if(display!==this.display)display?.getTracks().forEach(t=>t.stop());this.shareBusy=false;await this.limits(); }
  }
  async stopSharing() {
    const token=this.token; ++this.shareToken; const display=this.display;if(!display)return;this.display=null;
    display.getTracks().forEach(t=>{t.onended=null;t.stop();});this.paused=this.cameraBeforeShare;const camera=this.o.stream()?.getVideoTracks()[0];if(camera)camera.enabled=!this.paused;
    try{for(const l of this.links.values())for(const s of [l.videoSender])if(s)await s.replaceTrack(camera||null);}catch{if(token===this.token)this.leave();return;}
    if(token!==this.token)return;this.overlay?.sourceChanged();this.render();this.broadcastState();await this.limits();
  }
  leave(reason='left') { if (this.room) { try { this.o.send({type:'room-leave',room_id:this.room.room_id}); } catch {} } this.cleanup(reason); }
  cleanup(reason='ended') { this.peopleKey=null;this.seenChat.clear(); const wasMeeting=!!this.room?.meeting_id; this.chat.clear();$('meeting-chat-dialog').close();
    resetStage($('group-view'));++this.token; ++this.shareToken;this.earlyCandidates.clear();this.maximized=null;this.pinned=null; this.pending=false; this.personalRoom=false; this.room=null; this.overlay?.close();this.overlay=null;
    this.display?.getTracks().forEach(t=>{t.onended=null;t.stop();});this.display=null;this.shareBusy=false;
    for(const [id,l] of this.links)this.closeLink(id,l);
    $('group-inspector').close();$('group-picker').close();$('group-self-video').srcObject=null;
    if(reason!=='interrupted'||!wasMeeting)this.o.stopMedia();this.o.stopRing?.();this.events=[];this.connectionCaps.clear();$('group-more-dialog').close();$('group-audio-dialog').close();$('group-people-dialog').close();this.render();if(wasMeeting)this.o.ended?.(reason);
  }
}
