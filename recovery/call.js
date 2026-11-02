import { PvpMesh, MediaController } from '/packages/pvp-call/src/index.js';

// Adapt the shared, tested WebRTC core to PVP's authenticated meeting protocol.
// Network evidence stays inside the core; the recovery UI receives no addresses.
class RecoveryMesh extends PvpMesh {
  channel(link, channel) {
    super.channel(link, channel);
    if (channel.label !== 'pvp-presence') return;
    const presence = channel.onmessage;
    channel.onmessage = event => {
      if (!this.valid(link) || typeof event.data !== 'string' || event.data.length > 512) return;
      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }
      if (packet.type === 'recovery-state') {
        if (typeof packet.muted !== 'boolean' || typeof packet.camera !== 'boolean') return;
        link.memberState = { muted: packet.muted, camera: packet.camera };
        this.notify();
      } else if (packet.type === 'recovery-retry') {
        if (this.self.id < link.peer.id && Date.now() - (link.lastRetryRequest || 0) > 4000) {
          link.lastRetryRequest = Date.now();
          this.retry(link.peer.id, (link.failures || 0) + 1);
        }
      } else presence?.(event);
    };
    channel.onopen = () => { this.notify(); this.publishState(); };
  }
  publishState() {
    const value = JSON.stringify({ type: 'recovery-state', muted: !this.stream.getAudioTracks().some(t => t.enabled && t.readyState === 'live'), camera: this.stream.getVideoTracks().some(t => t.enabled && t.readyState === 'live') });
    for (const link of this.links.values())
      if (link.control?.readyState === 'open' && link.control.bufferedAmount < 4096) link.control.send(value);
  }
}

export class RecoveryCall {
  constructor({ api, changed, admitted, ended, error, approved }) {
    Object.assign(this, { api, changed, admitted, ended, error, approved });
    this.media = new MediaController();
    this.room = null;
    this.mesh = null;
    this.user = null;
    this.socket = null;
    this.version = 0;
    this.chain = Promise.resolve();
    this.pending = false;
    this.statsTimer = setInterval(() => this.sample(), 1500);
  }
  get members() { return this.room?.members.filter(m => m.joined) || []; }
  get self() { return this.members.find(m => m.id === this.user?.id); }
  get isChair() { return this.self?.is_admin === true; }
  get muted() { return !this.media.get('audio')?.enabled; }
  get camera() { return !!this.media.get('video'); }
  get blocked() { return this.self?.moderator_muted === true; }
  get waitingForTurn() { return this.room?.raise_hand_enabled && !this.isChair && !this.self?.speaking_allowed; }
  get busy() { return this.pending || !!this.room; }
  view() {
    return this.members.map(member => {
      const self = member.id === this.user.id;
      const link = this.mesh?.links.get(member.id);
      return {
        ...member, self,
        stream: self ? this.media.stream : link?.remote,
        muted: member.moderator_muted || (self ? this.muted : link?.memberState?.muted !== false),
        camera: self ? this.camera : link?.memberState?.camera === true,
        speaking: !member.moderator_muted && !self && link?.speaking,
        connected: self || link?.pc.connectionState === 'connected',
        verified: !self && link?.evidence?.dtlsState === 'connected' && link.evidence.direct === true,
        code: link?.code || '',
        failed: !!link?.error,
      };
    });
  }
  async start({ id, user, microphone = false }) {
    if (this.busy) throw Error('Leave your current meeting before joining another.');
    const version = ++this.version;
    this.user = user;
    this.meetingId = id;
    this.pending = true;
    try {
      // Permission is requested only after an explicit microphone join gesture.
      if (microphone) {
        await this.media.enable('audio', { echoCancellation: true, noiseSuppression: true, autoGainControl: true });
        if (version !== this.version) return;
        this.media.mute(true);
      }
      if (version !== this.version) return;
      await this.connect(version);
      if (version !== this.version) return;
      this.send({ type: 'meeting-enter', meeting_id: id });
      this.admissionTimeout = setTimeout(() => {
        if (this.pending && version === this.version) this.fail('The meeting didn’t open. Please try again.');
      }, 20000);
    } catch (error) {
      if (version !== this.version) return;
      this.cleanup();
      throw error;
    }
  }
  connect(version) {
    return new Promise((resolve, reject) => {
      const url = new URL('/recovery/api/ws', location.origin);
      url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = this.socket = new WebSocket(url);
      let ready = false;
      const timer = setTimeout(() => { reject(Error('Unable to connect to the meeting service. Please try again.')); socket.close(); }, 15000);
      this.cancelConnect = () => { clearTimeout(timer); reject(new DOMException('Joining canceled', 'AbortError')); };
      socket.onmessage = event => {
        if (version !== this.version || this.socket !== socket) return;
        let packet;
        try { packet = JSON.parse(event.data); } catch { return; }
        if (packet.type === 'ping') { this.send({ type: 'pong' }); return; }
        if (packet.type === 'server-capabilities' && !ready) {
          if (!packet.permanentMeetings || !packet.meetingModeration || !packet.raiseHand) {
            clearTimeout(timer); reject(Error('This service needs an update to support recovery meetings.')); return;
          }
          ready = true;
          clearTimeout(timer);
          this.cancelConnect = null;
          this.send({ type: 'room-capabilities', client: 'browser', meeting_moderation: true, raise_hand: true });
          resolve();
        }
        this.chain = this.chain.then(() => {
          if (version === this.version) return this.receive(packet);
        }).catch(error => { if (version === this.version) this.error(error.message); });
      };
      socket.onclose = () => {
        clearTimeout(timer);
        if (!ready) reject(Error('The meeting service disconnected. Please try again.'));
        if (version !== this.version) return;
        const wasJoined = !!this.room;
        this.cleanup();
        if (wasJoined) this.ended('You were disconnected. Your microphone and camera are off. You can rejoin when you’re ready.');
        else this.error('The connection closed. Please try joining again.');
      };
      socket.onerror = () => { if (!ready) reject(Error('Couldn’t reach the meeting service. Check your connection.')); };
    });
  }
  send(packet) {
    if (this.socket?.readyState !== WebSocket.OPEN) throw Error('Your connection to the meeting has closed.');
    this.socket.send(JSON.stringify(packet));
  }
  async receive(packet) {
    if (packet.type === 'replaced' || packet.type === 'signed-out') {
      const joined = !!this.room;
      this.cleanup();
      const message = packet.type === 'replaced' ? 'This meeting was opened in another tab. Your devices are off here.' : 'Your meeting session ended. Your devices are off.';
      if (joined) this.ended(message); else this.error(message);
      return;
    }
    if (packet.type === 'error') {
      if (this.pending) this.fail(packet.message); else this.error(packet.message);
      return;
    }
    if (packet.type === 'room-ended' && packet.room_id === this.room?.room_id) {
      this.cleanup(); this.ended('This meeting ended or you were removed. Your devices are off.'); return;
    }
    if (packet.type === 'room-state') {
      if (packet.meeting_id !== this.meetingId || (!this.pending && !this.room)) return;
      if (this.room && (packet.room_id !== this.room.room_id || packet.revision <= this.room.revision)) return;
      const self = packet.members.find(m => m.id === this.user.id && m.joined);
      if (!self) { this.cleanup(); this.ended('You’ve left this room. Your microphone and camera are off.'); return; }
      const wasAllowed = this.self?.speaking_allowed === true;
      const justJoined = !this.room;
      this.room = packet;
      this.pending = false;
      clearTimeout(this.admissionTimeout);
      if (!this.mesh) this.createMesh();
      this.enforceModeration();
      this.mesh.setPeers(this.members.map(m => ({ id: m.id, name: m.display_name, epoch: packet.room_id })));
      this.enforceModeration();
      if (justJoined) { this.startedAt = Date.now(); this.admitted(); }
      else if (!wasAllowed && self.speaking_allowed && !this.isChair) this.approved();
      this.changed();
      return;
    }
    if (packet.type === 'room-signal' && this.mesh && packet.room_id === this.room?.room_id) {
      await this.mesh.receive(packet.from, { ...packet.payload, generation: packet.generation, fromEpoch: packet.room_id, toEpoch: packet.room_id });
      this.enforceModeration();
    }
  }
  createMesh() {
    this.mesh = new RecoveryMesh({
      self: { id: this.user.id, epoch: this.room.room_id }, stream: this.media.stream,
      send: (to, signal) => {
        if (!this.room) return;
        if (signal.type === 'retry') {
          const control = this.mesh?.links.get(to)?.control;
          if (control?.readyState === 'open' && control.bufferedAmount < 4096) control.send(JSON.stringify({ type: 'recovery-retry' }));
          return;
        }
        const { generation, fromEpoch, toEpoch, ...payload } = signal;
        this.send({ type: 'room-signal', room_id: this.room.room_id, to, generation, payload });
      },
      onChange: () => { this.enforceModeration(); this.changed(); },
      onStream: () => { this.enforceModeration(); this.changed(); },
      onError: error => this.error(error.message),
      preferences: { preset: 'balanced', resolution: 480, fps: 24, video: 1200, audio: 32 },
    });
  }
  enforceModeration() {
    if (this.blocked) this.media.mute(true);
    for (const [id, link] of this.mesh?.links || []) {
      const member = this.members.find(m => m.id === id);
      for (const track of link.remote.getAudioTracks()) track.enabled = !!member && !member.moderator_muted;
    }
  }
  async toggleMicrophone() {
    if (!this.room) return;
    if (this.blocked) throw Error(this.waitingForTurn ? 'Raise your hand and wait for the chair to invite your share.' : 'The chair has muted your microphone.');
    const version = this.version;
    if (!this.media.get('audio')) {
      await this.media.enable('audio', { echoCancellation: true, noiseSuppression: true, autoGainControl: true });
      if (version !== this.version || !this.room) return;
      this.media.mute(this.blocked);
      await this.mesh.updateStream();
    } else this.media.mute(!this.muted);
    this.enforceModeration();
    this.mesh?.publishState();
    this.changed();
  }
  async toggleCamera() {
    if (!this.room) return;
    const version = this.version;
    if (this.camera) this.media.disable('video');
    else await this.media.enable('video', { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24, max: 24 } });
    if (version !== this.version || !this.room) return;
    await this.mesh.updateStream();
    this.mesh?.publishState();
    this.changed();
  }
  async hand() {
    if (!this.room || this.isChair || !this.room.raise_hand_enabled) return;
    await this.api(`/meetings/${this.meetingId}/hand`, { body: { raised: !this.self.hand_raised && !this.self.speaking_allowed } });
  }
  async moderate(member, action) {
    if (!this.isChair || !this.room) return;
    const path = `/meetings/${this.meetingId}/members/${member.id}`;
    if (action === 'remove') await this.api(path, { method: 'DELETE' });
    else if (action === 'approve' || action === 'end-turn') await this.api(path + '/speak', { body: { allowed: action === 'approve' } });
    else await this.api(path + '/mute', { body: { muted: action === 'mute' } });
  }
  async turns(enabled) { await this.api(`/meetings/${this.meetingId}/speaking`, { body: { enabled } }); }
  async sample() {
    if (!this.mesh || this.sampling) return;
    this.sampling = true;
    try { await this.mesh.sample(); } finally { this.sampling = false; }
  }
  fail(message) { this.cleanup(); this.error(message); }
  leave() {
    try { if (this.room) this.send({ type: 'room-leave', room_id: this.room.room_id }); } catch {}
    this.cleanup();
  }
  cleanup() {
    ++this.version;
    clearTimeout(this.admissionTimeout);
    this.cancelConnect?.(); this.cancelConnect = null;
    this.mesh?.close(); this.mesh = null;
    this.media.stop();
    this.room = null;
    this.pending = false;
    const socket = this.socket; this.socket = null;
    if (socket) { socket.onclose = null; socket.onmessage = null; socket.close(); }
    this.changed();
  }
}
