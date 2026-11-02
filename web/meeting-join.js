// Meeting entry owns intent, capture and admission independently. Credentials stay in cookies.
import { meetingId } from './meetings.js';
import { labeledAction } from './ui.js';
const $ = id => document.getElementById(id);
const stop = stream => stream?.getTracks().forEach(track => track.stop());
export class MeetingJoin {
  constructor(options) {
    this.o = options; this.id = null; this.attempt = 0; this.phase = 'idle'; this.capture = null;
    $('guest-form').onsubmit = e => { e.preventDefault(); this.start('listen'); };
    $('guest-submit').onclick = () => this.start('microphone');
    $('guest-takeover').onclick=()=>{this.o.takeOver();$('guest-takeover').hidden=true;this.status('This tab is ready. Choose how to rejoin.');};
    $('guest-cancel').onclick = () => this.cancel();
    $('guest-sign-in').onclick = () => { this.cancel(); this.hide(); this.o.signIn(); };
    $('guest-manage').onclick = () => { this.hide(); this.o.manage(this.id); };
    $('meeting-mic-retry').onclick = () => this.upgrade();
    $('meeting-mic-cancel').onclick = () => { this.cancelCapture(); this.micMessage(''); };
    $('meeting-mic-help').onclick = () => $('meeting-mic-guide').hidden = !$('meeting-mic-guide').hidden;
    $('guest-name').oninput = () => this.save(false);
  }
  saved() { try { return JSON.parse(sessionStorage.getItem('pvp.meeting.intent') || 'null'); } catch { return null; } }
  save(active = this.saved()?.active === true) {
    try { sessionStorage.setItem('pvp.meeting.intent', JSON.stringify({ id:this.id, name:$('guest-name').value.trim(), active })); } catch { /* Storage may be disabled. */ }
  }
  show() {
    document.documentElement.classList.add('meeting-route'); $('meeting-entry-view').hidden = false;
    $('auth-view').hidden = true; $('app-view').hidden = true;
  }
  hide() { $('meeting-entry-view').hidden = true; document.documentElement.classList.remove('meeting-route'); if(this.o.user()) $('app-view').hidden = false; }
  async open(id = meetingId(location.href)) {
    if (!id) { if(this.id && !this.o.joined()) { this.cancel(); this.hide(); } return; }
    if (this.id === id && ['capturing','connecting','reconnecting','joined'].includes(this.phase)) return;
    if(this.id===id && !$('guest-form').hidden){this.show();return;}
    const changed = this.id !== id; if(changed) this.cancelCapture();
    this.id = id; this.phase = 'idle'; this.show();
    const saved = this.saved(), user = this.o.user();
    if(changed || !$('guest-name').value) $('guest-name').value = user?.display_name || (saved?.id === id ? saved.name : '') || '';
    $('guest-back-rooms').hidden=!user||!!user.scoped_guest;
    $('guest-name').readOnly = !!user; $('guest-sign-in').hidden = !!user && !user.guest; $('guest-manage').hidden = !user || user.scoped_guest;
    $('guest-heading').textContent = 'Join a room'; $('guest-form').hidden = true;
    this.status('Loading room…');
    const generation = this.preview = (this.preview || 0) + 1;
    try {
      const m = await this.o.api(`/meetings/${id}${user ? '' : '/preview'}`);
      if(this.id !== id || this.preview !== generation || this.phase !== 'idle') return;
      $('guest-heading').textContent = m.name; $('guest-form').hidden = false;
      const rejoin = saved?.id === id && saved.active;
      $('guest-eyebrow').textContent = rejoin ? 'WELCOME BACK' : 'YOU’RE INVITED';
      $('guest-description').textContent = rejoin ? 'The same room is here for you. Join to listen or use your microphone.' : m.open_invite ? 'Anyone with the link can join. No account needed.' : 'A private room for invited people.';
      $('guest-zoom-note').hidden = !m.zoom;$('guest-network-note').hidden=!m.network_visible;
      $('guest-listen').textContent = rejoin ? 'Rejoin to listen' : 'Join to listen';
      this.status('');
    } catch(error) {
      if(this.id !== id || this.preview !== generation) return;
      $('guest-description').textContent = 'Ask the host if you need a new invitation.';
      this.status(error.status === 403 && !user ? 'This meeting needs an invitation. Sign in with your invited account, or ask the host for an open link.' : error.message, true);
    }
  }
  status(text, error = false) {
    labeledAction($('guest-submit'),'mic','Join with microphone');labeledAction($('guest-listen'),'headphones',$('guest-listen').textContent||'Join to listen');
    $('guest-error').textContent = error ? text : ''; $('guest-status').textContent = error ? '' : text;
    $('guest-cancel').hidden = !['capturing','connecting','reconnecting'].includes(this.phase);
    $('guest-submit').disabled = this.phase === 'capturing' || this.phase === 'connecting' || !!this.capture;
    $('guest-listen').disabled = this.phase === 'connecting';
  }
  errorText(error) {
    if(error.name === 'NotFoundError' || error.name === 'OverconstrainedError') return 'No microphone is available. You can still join to listen.';
    if(error.name === 'NotReadableError') return 'The microphone is unavailable right now. Close other apps using it, or join to listen.';
    if(error.name === 'NotAllowedError' || error.name === 'SecurityError') return 'We couldn’t access your microphone. Check browser access, or join to listen.';
    return error.message || 'Your microphone could not be opened. You can still listen.';
  }
  captureMic() {
    if(this.capture) return Promise.reject(Error('A microphone request is still waiting. You can keep listening.'));
    const ticket = { canceled:false }; this.capture=ticket;$('group-mic').dataset.capturePending='true';$('guest-submit').setAttribute('aria-busy','true');
    let result;
    try { result = navigator.mediaDevices?.getUserMedia({audio:this.o.audioConstraints(), video:false}); if(!result) throw Error('Microphone access needs HTTPS and a supported browser.'); }
    catch(error) { result = Promise.reject(error); }
    ticket.promise = Promise.resolve(result).then(stream => {
      if(ticket.canceled) { stop(stream); throw new DOMException('Capture canceled','AbortError'); }
      if(!stream.getAudioTracks().some(t=>t.readyState==='live')) { stop(stream); throw Error('No microphone was opened. You can still listen.'); }
      return stream;
    }).finally(() => { if(this.capture === ticket) {$('group-mic').dataset.capturePending='false';$('guest-submit').setAttribute('aria-busy','false');this.capture=null;if(this.phase==='idle')$('guest-submit').disabled=false;$('meeting-mic-cancel').hidden=true;} });
    return ticket.promise;
  }
  cancelCapture() { if(this.capture) this.capture.canceled = true; clearTimeout(this.waiting); }
  cancel() {
    ++this.attempt; this.cancelCapture();
    if(this.phase === 'connecting'||this.phase==='reconnecting') this.o.cancelAdmission();
    this.phase = 'idle'; this.status('You can join whenever you’re ready.');
  }
  async start(mode) {
    if(this.phase === 'connecting' || this.phase === 'joined') return;
    if(mode === 'microphone' && (this.phase === 'capturing' || this.capture)) return;
    if(!$('guest-name').reportValidity())return;if(!$('guest-name').value.trim()){this.status('Enter a display name to join.',true);return;}
    if(this.o.busy()) { this.status('Finish your current call before joining this meeting.', true); return; }
    const attempt = ++this.attempt, id = this.id;
    if(mode === 'listen') this.cancelCapture();
    this.phase = mode === 'listen' ? 'connecting' : 'capturing'; this.save(false);
    this.status(mode === 'listen' ? 'Connecting to the meeting…' : 'Waiting for microphone access. Check your browser’s prompt.');
    // Invoke capture inside the tap, before starting any authentication/network work.
    const media = mode === 'listen' ? Promise.resolve(new MediaStream()) : this.captureMic();
    this.waiting = setTimeout(() => { if(attempt === this.attempt && this.phase === 'capturing') this.status('Still waiting for microphone access. You can join to listen while you decide.'); }, 8000);
    let acquired;
    media.then(stream=>{acquired=stream;if(attempt!==this.attempt)stop(stream);},()=>{});
    try {
      await Promise.all([media, this.o.authenticate(id, $('guest-name').value.trim())]);
      if(attempt !== this.attempt) return;
      clearTimeout(this.waiting); this.phase = 'connecting'; this.status('Connecting to the meeting…');
      await this.o.ready(); if(attempt !== this.attempt) return;
      this.o.adopt(acquired); acquired = null;
      await this.o.enter(id);
      this.admissionTimer = setTimeout(()=>{if(attempt===this.attempt&&this.phase==='connecting'){this.cancel();this.status('The connection is taking too long. Check your connection and try again.',true);}},20000);
    } catch(error) {
      if(attempt !== this.attempt) return;
      ++this.attempt; this.cancelCapture(); this.phase = 'idle';
      this.status(mode === 'microphone' && error.status === undefined ? this.errorText(error) : error.message, true);
    } finally { if(attempt !== this.attempt || this.phase !== 'joined') stop(acquired); }
  }
  admitted(id) {
    if(id !== this.id) return;
    clearTimeout(this.admissionTimer); this.phase = 'joined'; this.save(true); this.hide();
  }
  rejected(message) {
    if(this.phase !== 'connecting') return;
    ++this.attempt; clearTimeout(this.admissionTimer); this.cancelCapture(); this.phase = 'idle'; this.show(); this.status(message, true);
  }
  ended(reason) {
    if(!this.id || this.phase !== 'joined') return;
    ++this.attempt; this.cancelCapture(); this.micMessage(''); this.phase = 'idle';$('guest-takeover').hidden=reason!=='replaced';
    if(reason === 'reload') return;
    this.save(reason === 'interrupted'); this.show();if(reason==='interrupted')this.phase='reconnecting';
    $('guest-listen').textContent = 'Rejoin to listen';
    this.status(reason === 'left' ? 'You left the room. Your microphone and camera are off. Others can stay; come back with this link anytime.' : reason === 'replaced' ? 'This meeting is open in another tab. Close it there, then rejoin here.' : reason === 'interrupted' ? 'Your connection was interrupted. Reconnecting to the meeting…' : 'You left or were removed from the meeting. Contact the host if you need access.', reason !== 'left');
  }
  async resume() {
    if(this.phase!=='reconnecting')return;
    this.phase='connecting';this.status('Rejoining the meeting…');
    try {await this.o.enter(this.id);}
    catch(error){this.rejected(error.message);}
  }
  micMessage(text) { $('meeting-mic-status').textContent = text; $('meeting-mic-recovery').hidden = !text; $('meeting-mic-cancel').hidden = !this.capture; }
  async upgrade() {
    if(!this.o.joined())return;if(this.capture){this.micMessage('A microphone request is still pending in your browser. You can keep listening.');return;}
    const attempt = this.attempt;
    this.micMessage('Waiting for microphone access. You can keep listening.');
    const pending = this.captureMic(); this.micMessage('Waiting for microphone access. You can keep listening.');
    try {
      const stream = await pending;
      if(attempt !== this.attempt || !this.o.joined()) { stop(stream); return; }
      try { await this.o.upgrade(stream);this.micMessage('');return true; }
      catch(error) { stop(stream); throw error; }
    } catch(error) { if(attempt === this.attempt && error.name !== 'AbortError') this.micMessage(this.errorText(error));return false;}
  }
}
