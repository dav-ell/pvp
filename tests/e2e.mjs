import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { mkdir, mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:net';
import { endpointLabel } from '../web/inspector.js';

let base = process.env.PVP_TEST_URL;
const suffix = process.env.PVP_TEST_SUFFIX || `${Date.now()}`.slice(-9);
const accounts = [{ username: `alice_${suffix}`, display_name: 'Alice Morgan' }, { username: `jamie_${suffix}`, display_name: 'Jamie Chen' }];
const password = 'test-only-passphrase-123';
let browser, contexts, pages, users, server, temporary;
async function waitFor(page, fn, arg) { await page.waitForFunction(fn, arg, { timeout: 30000 }); }
async function settings(page) {
  if(await page.locator('body').evaluate(b=>b.classList.contains('call-stage')))await page.locator('#call-back').click();
  await page.locator('[data-view=settings]').first().click();
}
async function request(context, path, data, method = 'POST') {
  const response = await context.request.fetch(`${base}/api${path}`, { method, headers: { Origin: base }, ...(data ? { data } : {}) });
  return { status: response.status(), body: await response.json() };
}
before(async () => {
  if (!base) {
    await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
    const probe = createServer(); await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port; await new Promise((resolve) => probe.close(resolve)); base = `http://localhost:${port}`;
    temporary = await mkdtemp(join(tmpdir(), 'pvp-tests-'));
    server = spawn('signaling/target/debug/pvp-signaling', [], { env: { ...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: join(temporary, 'pvp.sqlite') }, stdio: 'ignore' });
    let ready = false;
    for (let i = 0; i < 100; i++) { try { if ((await fetch(`${base}/health`)).ok) { ready = true; break; } } catch {} await new Promise((resolve) => setTimeout(resolve, 100)); }
    assert.ok(ready, 'test signaling service started');
  }
  browser = await chromium.launch({ headless: true, ...(process.env.PVP_CHROME ? { executablePath: process.env.PVP_CHROME } : {}), args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', '--autoplay-policy=no-user-gesture-required'] });
  contexts = await Promise.all(accounts.map(() => browser.newContext({ permissions: ['camera', 'microphone'], viewport: { width: 1440, height: 1000 } })));
  pages = await Promise.all(contexts.map((c) => c.newPage()));
  for (const page of pages) {
    await page.addInitScript(() => {
      const Original = window.RTCPeerConnection;
      window.RTCPeerConnection = class extends Original {
        constructor(...args) { super(...args); window.__peer = this; window.__observedReports = []; }
        async getStats(...args) {
          const stats = await super.getStats(...args);
          window.__observedReports.push([...stats.values()]);
          if (window.__observedReports.length > 100) window.__observedReports.shift();
          return stats;
        }
      };
    });
    // Real browser media tracks and WebRTC, independent of the host's devices/TCC.
    await page.addInitScript(() => {
      if (!navigator.mediaDevices) return;
      window.__deviceCapture = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = async (constraints) => {
        const canvas = document.createElement('canvas'); canvas.height = constraints.video?.height?.ideal || 720; canvas.width = Math.round(canvas.height * 16 / 9);
        const context = canvas.getContext('2d'); let frame = 0;
        const timer = setInterval(() => { context.fillStyle = '#194d3b'; context.fillRect(0, 0, canvas.width, canvas.height); context.fillStyle = '#dceabf'; context.fillRect((frame++ * 7) % canvas.width, 50, 100, 100); }, 33);
        const stream = canvas.captureStream(30); const track = stream.getVideoTracks()[0], stop = track.stop.bind(track); track.stop = () => { clearInterval(timer); stop(); };
        const audio = new AudioContext(), oscillator = audio.createOscillator(), destination = audio.createMediaStreamDestination(); oscillator.connect(destination); oscillator.start(); await audio.resume();
        const sound = destination.stream.getAudioTracks()[0], stopSound = sound.stop.bind(sound); let soundStopped = false; sound.stop = () => { if (soundStopped) return; soundStopped = true; stopSound(); oscillator.stop(); if (audio.state !== 'closed') audio.close().catch(error => { if (error.name !== 'InvalidStateError') throw error; }); };
        // Web Audio output tracks cannot reconfigure microphone processing.
        // Model that setting for generated-audio call tests; a device test below
        // exercises Chromium's real capture and reported processing settings.
        const settings = sound.getSettings.bind(sound); let echo = constraints.audio?.echoCancellation;
        sound.getSettings = () => ({...settings(), echoCancellation:echo});
        sound.applyConstraints = async c => { if ('echoCancellation' in c) echo = c.echoCancellation; };
        stream.addTrack(sound);
        window.__captureCalls ||= [];window.__captureCalls.push({audio:constraints.audio,video:constraints.video});
        if(constraints.video===false){track.stop();stream.removeTrack(track);}
        if(constraints.audio===false){sound.stop();stream.removeTrack(sound);}return stream;
      };
    });
    page.on('pageerror', (error) => assert.fail(`Browser error: ${error.message}`));
    if (process.env.PVP_TEST_DEBUG) {
      page.on('console', (message) => console.log('browser:', message.text()));
      page.on('websocket', (socket) => { socket.on('framesent', (event) => console.log('sent:', JSON.parse(event.payload).type)); socket.on('framereceived', (event) => { const message = JSON.parse(event.payload); console.log('received:', message.type, message.message || ''); }); });
    }
  }
  users = [];
  for (let i = 0; i < accounts.length; i++) {
    const page = pages[i]; await page.goto(base); await page.locator('#show-account').click(); await page.locator('#register-tab').click();
    await page.locator('#display-name').fill(accounts[i].display_name); await page.locator('#username').fill(accounts[i].username); await page.locator('#password').fill(password); await page.locator('#auth-submit').click();
    await page.locator('#app-view').waitFor({ state: 'visible' }); await page.locator('#connection-dot.online').waitFor(); await page.locator('[data-view=people]').click();
    const response = await request(contexts[i], '/me', undefined, 'GET'); assert.equal(response.status, 200); users.push(response.body);
  }
}, { timeout: 60000 });
after(async () => { await browser?.close(); if (server) { server.kill(); await new Promise((resolve) => server.once('exit', resolve)); } if (temporary) await rm(temporary, { recursive: true, force: true }); });

test('authentication, origin checks, and mutual friend acceptance', async () => {
  const anonymous = await browser.newContext();
  assert.equal((await request(anonymous, '/friends', undefined, 'GET')).status, 401);
  const badOrigin = await contexts[0].request.post(`${base}/api/friends/request`, { headers: { Origin: 'https://untrusted.example' }, data: { username: accounts[1].username } }); assert.equal(badOrigin.status(), 403);
  const cookies = await contexts[0].cookies(); assert.equal(cookies.find((c) => c.name === 'pvp_session').httpOnly, true);
  const page = pages[0]; await page.locator('#add-friend').click(); await page.locator('#friend-username').fill(`@${accounts[1].username}`); await page.locator('#friend-form button[type=submit]').click();
  await pages[1].locator('#requests-tab').click(); await pages[1].getByRole('button', { name: 'Accept request' }).waitFor();
  assert.equal((await request(contexts[0], `/friends/${users[1].id}/accept`)).status, 400, 'sender cannot accept own request');
  const blocked = await contexts[0].request.get(`${base}/api/history`); assert.equal(blocked.status(), 200);
  await pages[1].getByRole('button', { name: 'Accept request' }).click();
  await page.locator('#friends-tab').click(); await pages[1].locator('#friends-tab').click();
  await page.locator('.friend-card .button.primary').waitFor(); await pages[1].locator('.friend-card .button.primary').waitFor();
  assert.equal((await request(contexts[0], '/friends', undefined, 'GET')).body[0].status, 'accepted');
  await page.reload(); await page.locator('#connection-dot.online').waitFor(); await page.locator('[data-view=people]').click(); await page.locator('.friend-card .button.primary').waitFor();
  assert.equal((await request(contexts[1], '/friends', undefined, 'GET')).body[0].status, 'accepted');
  await anonymous.close();
});

test('real WebRTC call, direct candidate pair, live bitrate controls, mute, and cleanup', async () => {
  const [a, b] = pages;
  await a.bringToFront();
  await a.locator('.friend-card .button.primary').click(); await b.locator('#incoming-dialog').waitFor({ state: 'visible' }); await b.bringToFront(); await b.locator('#accept-call').click();
  for(const page of pages){
    await waitFor(page,()=>window.__peer?.connectionState==='connected');
    assert.equal(await page.evaluate(()=>window.__captureCalls.at(-1).video),false,'calls request only the microphone');
    assert.equal(await page.evaluate(()=>window.__captureCalls.at(-1).audio.echoCancellation),true,'echo cancellation defaults on');
    assert.equal(await page.evaluate(()=>window.__peer.getSenders().some(s=>s.track?.kind==='video')),false);
    await waitFor(page,()=>{const audio=document.getElementById('remote-audio');return audio&&!audio.paused&&!audio.muted&&audio.readyState>=2&&audio.currentTime>0;});
  }
  for(const page of pages){
    await page.locator('#toggle-camera').click();
    await waitFor(page,()=>window.__peer.getSenders().some(s=>s.track?.kind==='video'));
    assert.equal(await page.evaluate(()=>window.__captureCalls.at(-1).audio),false,'opt-in requests only the camera');
  }
  await a.evaluate(() => {
    window.__echoPeer = window.__peer;
    window.__echoMic = window.__peer.getSenders().find(s => s.track?.kind === 'audio').track;
    window.__echoMic.enabled = false;
    const apply = window.__echoMic.applyConstraints.bind(window.__echoMic);
    const capture = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = async constraints => {
      if (window.__rejectEcho) throw new Error('Microphone unavailable');
      return capture(constraints);
    };
    window.__echoCalls = [];
    window.__echoMic.applyConstraints = async constraints => {
      window.__echoCalls.push(constraints);
      if (window.__rejectEcho && constraints.echoCancellation === false) throw new Error('Processing unavailable');
      return apply(constraints);
    };
  });
  if(!await a.locator('#call-more-dialog').evaluate(d=>d.open))await a.locator('#call-more').click();await a.locator('#call-quality').click();
  const echo = a.locator('#in-call-echo-cancellation');
  assert.equal(await echo.isChecked(), true);
  await echo.uncheck();
  await waitFor(a, () => !document.getElementById('in-call-echo-cancellation').disabled);
  assert.deepEqual(await a.evaluate(() => window.__echoCalls.at(-1)), {echoCancellation:false});
  assert.equal(await a.evaluate(() => window.__peer === window.__echoPeer && window.__peer.getSenders().some(s => s.track === window.__echoMic) && !window.__echoMic.enabled && window.__echoMic.readyState === 'live'), true, 'echo toggle keeps the peer, microphone and mute state');
  assert.equal(await a.locator('#echo-cancellation').isChecked(), false, 'settings stay in sync');
  await echo.check();
  await waitFor(a, () => !document.getElementById('in-call-echo-cancellation').disabled);
  await a.evaluate(() => window.__rejectEcho = true);
  await echo.click();
  await waitFor(a, () => !document.getElementById('in-call-echo-cancellation').disabled);
  assert.equal(await echo.isChecked(), true, 'failed changes restore the switch');
  assert.equal(await a.evaluate(id => JSON.parse(localStorage.getItem(`pvp.settings.${id}`)).echoCancellation, users[0].id), true, 'failed changes do not persist');
  await a.evaluate(() => { window.__rejectEcho = false; window.__echoMic.enabled = true; });
  await echo.uncheck();
  await waitFor(a, () => !document.getElementById('in-call-echo-cancellation').disabled);
  await a.locator('#close-call-settings').click();
  for (const page of pages) {
    try { await waitFor(page, () => window.__peer?.connectionState === 'connected'); }
    catch (error) { console.log('Call diagnostics:', await Promise.all(pages.map((p) => p.evaluate(() => ({ connection: window.__peer?.connectionState, ice: window.__peer?.iceConnectionState, signaling: window.__peer?.signalingState, toast: document.getElementById('toast').textContent, status: document.getElementById('call-status').textContent }))))); throw error; }
    await waitFor(page, () => document.getElementById('remote-video').videoWidth > 0);
    await waitFor(page, async () => [...(await window.__peer.getStats()).values()].some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > 0.005));
    assert.equal(await page.locator('#remote-video').evaluate(v => v.paused), false, 'remote video is playing');
    assert.equal(await page.locator('#remote-video').evaluate(v => v.muted), true, 'video does not duplicate the audio sink');
    assert.equal(await page.locator('#remote-audio').evaluate(a => a.paused || a.muted || a.currentTime <= 0), false, 'remote audio is playing');
    const config = await page.evaluate(() => window.__peer.getConfiguration()); assert.equal(config.iceServers.some((s) => JSON.stringify(s).includes('turn:')), false);
    const types = await page.evaluate(async () => [...(await window.__peer.getStats()).values()].filter((s) => s.type === 'local-candidate' || s.type === 'remote-candidate').map((s) => s.candidateType));
    assert.ok(types.length > 0); assert.ok(!types.includes('relay'));
    const encryption = await page.evaluate(async () => [...(await window.__peer.getStats()).values()].filter((s) => s.type === 'transport').map((s) => ({ dtls: s.dtlsState, cipher: s.dtlsCipher, srtp: s.srtpCipher })));
    assert.ok(encryption.some((s) => s.dtls === 'connected' && s.cipher && s.srtp), 'DTLS and SRTP ciphers negotiated');
    await waitFor(page, () => document.getElementById('call-security').textContent.includes('Verify with your friend:'));

  }
  assert.equal(await a.locator('#call-security').textContent(), await b.locator('#call-security').textContent(), 'certificate verification codes match');
  // The displayed/exported endpoints must match the actual selected transport.
  await a.setViewportSize({width:390,height:844});
  assert.equal(await a.locator('#call-bandwidth').isVisible(),false,'routine bandwidth lives in Connection');
  await a.locator('#call-more').click();
  await a.locator('#connection-inspector').click();
  const mobileInspector=await a.locator('#inspector-dialog').boundingBox();
  assert.ok(mobileInspector.x>=0&&mobileInspector.x+mobileInspector.width<=390,'connection details fit mobile');
  await a.locator('#close-inspector').click();
  await a.setViewportSize({width:1440,height:1000});
  for (const page of pages) {
    if(!await page.locator('#call-more-dialog').evaluate(d=>d.open))await page.locator('#call-more').click();await page.locator('#connection-inspector').click();
    await waitFor(page, () => document.getElementById('inspector-route').textContent === 'Direct media path · WebRTC reported');
    await waitFor(page, () => /Sent [1-9]\d* bytes · received [1-9]\d* bytes/.test(document.getElementById('inspector-counters').textContent));
    await waitFor(page, () => ['incoming', 'outgoing'].every(direction => [...document.querySelectorAll('#inspector-media tbody tr')].some(row => row.cells[0].textContent === direction && Number(row.cells[2].textContent) > 0)));
    await waitFor(page, () => /You · ↓ .* · ↑ .*MB\/min/.test(document.getElementById('call-bandwidth').textContent));
    const other = page === a ? b : a;
    const receiveCamera = page.locator('#connection-bandwidth-controls select[data-direction="receive"][data-source="camera"]');
    await receiveCamera.selectOption('64');
    await waitFor(other, () => window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0].maxBitrate === 64000);
    await page.locator('#connection-bandwidth-controls select[data-direction="receive"][data-source="screen"]').selectOption('8000');
    assert.equal(await other.evaluate(()=>window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0].maxBitrate),64000,'screen limit does not change camera');
    await receiveCamera.selectOption('');
    await page.locator('#connection-bandwidth-controls select[data-direction="receive"][data-source="screen"]').selectOption('');
    await waitFor(other, () => window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0].maxBitrate === 1800000);
    const downloading = page.waitForEvent('download');
    const diagram = await page.evaluate(() => {
      document.getElementById('export-inspector').click();
      return { local: document.getElementById('inspector-local').textContent, remote: document.getElementById('inspector-remote').textContent, command: document.getElementById('inspector-command').textContent };
    });
    const download = await downloading;
    const evidence = JSON.parse(await readFile(await download.path(), 'utf8'));
    const live = await page.evaluate(evidence => {
      // ICE can legitimately switch paths between export and a later getStats.
      // Match the export to the real engine report from that observation.
      for (const values of window.__observedReports.slice().reverse()) {
        const stats = new Map(values.map(s => [s.id, s]));
        const transport = values.find(s => s.type === 'transport' && s.selectedCandidatePairId === evidence.selectedPairId);
        const pair = stats.get(transport?.selectedCandidatePairId);
        if (pair?.bytesSent === evidence.bytesSent && pair?.bytesReceived === evidence.bytesReceived) return { pair, local: stats.get(pair.localCandidateId), remote: stats.get(pair.remoteCandidateId) };
      }
      return null;
    }, evidence.media);
    assert.ok(live, 'export matches a real engine report, including selected path and byte counters');
    assert.equal(evidence.media.selectedPairId, live.pair.id);
    for (const side of ['local', 'remote']) {
      assert.equal(evidence.media[side].address, live[side].address ?? live[side].ip ?? null);
      assert.equal(evidence.media[side].port, live[side].port);
      assert.equal(diagram[side], endpointLabel(evidence.media[side]), 'diagram renders observed endpoint, not an example');
    }
    assert.ok(evidence.media.bytesSent > 0 && evidence.media.bytesSent === live.pair.bytesSent);
    assert.ok(evidence.media.bytesReceived > 0 && evidence.media.bytesReceived === live.pair.bytesReceived);
    assert.ok(evidence.media.media.some(r => r.direction === 'incoming' && r.packets > 0));
    assert.ok(evidence.media.media.some(r => r.direction === 'outgoing' && r.packets > 0));
    assert.equal(evidence.signaling.socket, null, 'browser never guesses signaling IPs');
    assert.ok(!JSON.stringify(evidence).includes('pvp_session'));
    if (evidence.media.remote.ip) assert.ok(diagram.command.includes(`host ${evidence.media.remote.ip} and port ${evidence.media.remote.port}`));
    if (process.env.PVP_TEST_SCREENSHOTS !== '0' && page === a) {
      await mkdir('.build/inspector/screenshots', { recursive: true });
      await page.screenshot({ path: '.build/inspector/screenshots/browser-inspector.png' });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.getElementById('inspector-dialog').scrollWidth <= document.getElementById('inspector-dialog').clientWidth), true, 'inspector fits a mobile viewport');
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.locator('#close-inspector').click();
  }
  await settings(a);
  await a.locator('#data-send').selectOption('none');
  await waitFor(a,()=>window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0].active===false);
  await a.locator('#data-send').selectOption('minimal');
  await waitFor(a,()=>{const e=window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0];return e.active&&e.maxBitrate===64000;});
  await a.locator('#data-receive').selectOption('none');
  await waitFor(b,()=>window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0].active===false);
  await a.locator('#data-receive').selectOption('verylow');
  await waitFor(b,()=>{const e=window.__peer.getSenders().find(s=>s.track?.kind==='video').getParameters().encodings[0];return e.active&&e.maxBitrate===128000;});
  await a.locator('#data-send').selectOption('off');
  await a.locator('#data-receive').selectOption('off');
  await settings(a); await a.locator('#quality-preset').selectOption('saver');
  await waitFor(a, () => window.__peer.getSenders().find((s) => s.track?.kind === 'video')?.getParameters().encodings[0]?.maxBitrate === 400000);
  assert.equal(await a.evaluate(() => window.__peer.getSenders().find((s) => s.track?.kind === 'audio').getParameters().encodings[0].maxBitrate), 24000);
  await a.locator('#return-call').click(); await a.locator('#toggle-mic').click(); assert.equal(await a.evaluate(() => window.__peer.getSenders().find((s) => s.track?.kind === 'audio').track.enabled), false);
  const audioEnergy = () => b.evaluate(async () => [...(await window.__peer.getStats()).values()].find(s => s.type === 'inbound-rtp' && s.kind === 'audio').totalAudioEnergy);
  await b.waitForTimeout(700);
  const mutedEnergy = await audioEnergy(); await b.waitForTimeout(700);
  assert.ok((await audioEnergy()) - mutedEnergy < 0.0001, 'muting stops audible audio at the recipient');
  // Changing microphones while muted must keep the replacement track muted.
  await settings(a);
  await waitFor(a, () => document.getElementById('mic-device').options.length > 1);
  await a.locator('#mic-device').selectOption({ index: 1 });
  await waitFor(a, () => window.__peer.getSenders().find(s => s.track?.kind === 'audio')?.track.enabled === false);
  await a.locator('#return-call').click();
  await a.locator('#toggle-mic').click();
  await waitFor(b, async baseline => [...(await window.__peer.getStats()).values()].some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > baseline + 0.005), mutedEnergy);
  // Partial device-change failure must restore every sender before stopping
  // the rejected replacement stream, or it can leave outgoing audio silent.
  await a.evaluate(() => {
    const senders = window.__peer.getSenders().filter(s => s.track);
    window.originalTrackIds = senders.map(s => s.track.id);
    const sender = senders.find(s => s.track.kind === 'audio'), original = sender.replaceTrack.bind(sender);
    let fail = true;
    sender.replaceTrack = track => { if (fail) { fail = false; return Promise.reject(new Error('Test device disconnected')); } return original(track); };
  });
  await settings(a);
  await a.locator('#mic-device').selectOption('');
  await waitFor(a, () => document.getElementById('toast').textContent.includes('Test device disconnected'));
  assert.deepEqual(await a.evaluate(() => window.__peer.getSenders().filter(s => s.track).map(s => s.track.id)), await a.evaluate(() => window.originalTrackIds));
  assert.equal(await a.evaluate(() => window.__peer.getSenders().filter(s => s.track).every(s => s.track.readyState === 'live')), true);
  const restoredEnergy = await audioEnergy();
  await waitFor(b, async baseline => [...(await window.__peer.getStats()).values()].some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > baseline + 0.005), restoredEnergy);
  await a.locator('#return-call').click();
  // Screen frames traverse the same real encrypted transport, preserving audio.
  await a.evaluate(() => {
    window.beforeShare = { pc: window.__peer, camera: window.__peer.getSenders().find(s => s.track?.kind === 'video').track, audio: window.__peer.getSenders().find(s => s.track?.kind === 'audio').track };
    navigator.mediaDevices.getDisplayMedia = async () => {
      const canvas = document.createElement('canvas'); canvas.width = 960; canvas.height = 540;
      const ctx = canvas.getContext('2d'); ctx.fillStyle = '#ff0088'; ctx.fillRect(0, 0, 960, 540);
      const timer = setInterval(() => { ctx.fillRect(0, 0, 960, 540); }, 33);
      const stream = canvas.captureStream(30), track = stream.getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); }; window.sharedTrack = track;
      return stream;
    };
  });
  await a.locator('#share-screen').click();
  // Media can arrive before replaceTrack resolves and sender cleanup completes.
  await waitFor(a, () => document.getElementById('share-screen').getAttribute('aria-pressed') === 'true');
  await waitFor(b, () => document.getElementById('remote-video').videoWidth === 960);
  assert.equal(await a.evaluate(() => window.__peer === window.beforeShare.pc && window.__peer.getSenders().find(s => s.track?.kind === 'audio').track === window.beforeShare.audio), true);
  assert.equal(await a.evaluate(() => window.beforeShare.camera.enabled), false);
  assert.equal(await a.locator('#share-screen').getAttribute('aria-pressed'), 'true');
  const sharingEnergy = await audioEnergy();
  await waitFor(b, async baseline => [...(await window.__peer.getStats()).values()].some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > baseline + 0.005), sharingEnergy);
  const pixel = await b.evaluate(() => { const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1; const c = canvas.getContext('2d'); c.drawImage(document.getElementById('remote-video'), 0, 0, 1, 1); return [...c.getImageData(0, 0, 1, 1).data]; });
  assert.ok(pixel[0] > 200 && pixel[1] < 40 && pixel[2] > 80, 'recipient receives the actual screen image');
  await a.locator('#share-screen').click();
  await waitFor(a, () => window.__peer.getSenders().find(s => s.track?.kind === 'video').track === window.beforeShare.camera);
  assert.equal(await a.evaluate(() => window.sharedTrack.readyState), 'ended');
  assert.equal(await a.evaluate(() => window.beforeShare.camera.enabled), true);
  // Screen sharing after camera opt-out returns to microphone-only capture.
  await a.locator('#toggle-camera').click();
  await a.locator('#share-screen').click();
  await waitFor(a, () => document.getElementById('share-screen').getAttribute('aria-pressed') === 'true');
  await a.evaluate(() => { window.sharedTrack.stop(); window.sharedTrack.dispatchEvent(new Event('ended')); });
  await waitFor(a, () => !window.__peer.getSenders().some(s => s.track?.kind === 'video'));
  assert.equal(await a.evaluate(() => window.beforeShare.camera.readyState), 'ended');
  await a.locator('#toggle-camera').click();
  await waitFor(a,()=>window.__peer.getSenders().some(s=>s.track?.kind==='video'));
  await a.evaluate(()=>window.beforeShare.camera=window.__peer.getSenders().find(s=>s.track?.kind==='video').track);
  // Canceling the OS picker leaves both original tracks intact.
  await a.evaluate(() => { navigator.mediaDevices.getDisplayMedia = async () => { throw new DOMException('Canceled', 'NotAllowedError'); }; });
  await a.locator('#share-screen').click(); await a.waitForTimeout(100);
  assert.equal(await a.evaluate(() => window.__peer.getSenders().find(s => s.track?.kind === 'video').track === window.beforeShare.camera && window.__peer.getSenders().find(s => s.track?.kind === 'audio').track === window.beforeShare.audio), true);
  // A blocked browser autoplay prompt stays visible until playback succeeds.
  await b.evaluate(() => {
    const audio = document.getElementById('remote-audio'); audio.pause();
    window.originalRemotePlay = audio.play;
    audio.play = () => Promise.reject(new DOMException('Autoplay blocked', 'NotAllowedError'));
  });
  await b.locator('#call-view').click({ position: { x: 300, y: 300 } });
  await b.locator('#enable-playback').waitFor({ state: 'visible' });
  await b.evaluate(() => { document.getElementById('remote-audio').play = window.originalRemotePlay; });
  await b.locator('#enable-playback').click();
  await b.locator('#enable-playback').waitFor({ state: 'hidden' });
  assert.equal(await b.locator('#remote-audio').evaluate(audio => audio.paused), false);
  await a.locator('#toggle-camera').click(); await waitFor(a,()=>!window.__peer.getSenders().some(s=>s.track?.kind==='video'));
  await a.evaluate(() => { navigator.mediaDevices.getDisplayMedia = () => new Promise(resolve => { window.resolveScreen = resolve; }); });
  await a.locator('#share-screen').click();
  await waitFor(a, () => typeof window.resolveScreen === 'function');
  await a.locator('#end-call').click(); await b.locator('#call-view').waitFor({ state: 'hidden' });
  await a.evaluate(() => { const canvas = document.createElement('canvas'); const stream = canvas.captureStream(30); window.lateScreen = stream.getVideoTracks()[0]; window.resolveScreen(stream); });
  await waitFor(a, () => window.lateScreen.readyState === 'ended');

  for (const page of pages) {
    assert.equal(await page.locator('#inspector-dialog').evaluate(d => d.open), false);
    assert.equal(await page.locator('#inspector-local').textContent(), '', 'call teardown clears endpoint observations');
  }
  assert.equal(await a.evaluate(() => window.__peer.connectionState), 'closed');
  const history = (await request(contexts[0], '/history', undefined, 'GET')).body; assert.equal(history[0].outcome, 'ended'); assert.equal(history[0].peer_id, users[1].id);
  await settings(a); assert.equal(await a.locator('#quality-preset').inputValue(), 'saver');
  await a.reload(); await a.locator('#connection-dot.online').waitFor(); await settings(a); assert.equal(await a.locator('#quality-preset').inputValue(), 'saver');
  assert.equal(await a.locator('#echo-cancellation').isChecked(), false, 'echo preference survives reload');
  await a.locator('#start-preview').click();
  await waitFor(a, () => document.getElementById('preview-video').srcObject?.getAudioTracks().length > 0);
  assert.equal(await a.evaluate(() => window.__captureCalls.at(-1).audio.echoCancellation), false, 'new capture uses the saved setting');
  await a.locator('#stop-preview').click();
  await a.locator('#echo-cancellation').check();
  await waitFor(a, () => !document.getElementById('echo-cancellation').disabled);
  await a.locator('[data-view=people]').click();
});

test('device echo cancellation changes live and older preferences default on', async () => {
  const page = pages[0];
  await page.evaluate(id => {
    const key = `pvp.settings.${id}`, saved = JSON.parse(localStorage.getItem(key));
    delete saved.echoCancellation;
    localStorage.setItem(key, JSON.stringify(saved));
  }, users[0].id);
  await page.reload();
  await page.locator('#connection-dot.online').waitFor();
  await settings(page);
  assert.equal(await page.locator('#echo-cancellation').isChecked(), true);
  await page.evaluate(() => {
    window.__syntheticCapture = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = window.__deviceCapture;
  });
  await page.locator('#start-preview').click();
  await waitFor(page, () => document.getElementById('preview-video').srcObject?.getAudioTracks().length > 0);
  assert.equal(await page.evaluate(() => {
    window.__deviceMic = document.getElementById('preview-video').srcObject.getAudioTracks()[0];
    window.__deviceMic.enabled = false;
    return window.__deviceMic.getSettings().echoCancellation;
  }), true);
  await page.locator('#echo-cancellation').uncheck();
  await waitFor(page, () => !document.getElementById('echo-cancellation').disabled);
  assert.equal(await page.evaluate(() => document.getElementById('preview-video').srcObject.getAudioTracks()[0].getSettings().echoCancellation), false, 'actual browser capture disables echo cancellation');
  assert.equal(await page.evaluate(() => !document.getElementById('preview-video').srcObject.getAudioTracks()[0].enabled), true, 'microphone stays muted after processing changes');
  await page.locator('#echo-cancellation').check();
  await waitFor(page, () => !document.getElementById('echo-cancellation').disabled);
  assert.equal(await page.evaluate(() => document.getElementById('preview-video').srcObject.getAudioTracks()[0].getSettings().echoCancellation), true);
  await page.evaluate(() => {
    window.__lateEchoTracks = [];
    navigator.mediaDevices.getUserMedia = constraints => new Promise(resolve => {
      window.__resolveEcho = async () => {
        const stream = await window.__syntheticCapture(constraints);
        window.__lateEchoTracks = stream.getTracks();
        resolve(stream);
      };
    });
  });
  await page.locator('#echo-cancellation').uncheck();
  await waitFor(page, () => !!window.__resolveEcho);
  await page.locator('#stop-preview').click();
  await page.evaluate(() => window.__resolveEcho());
  await waitFor(page, () => !document.getElementById('echo-cancellation').disabled);
  assert.equal(await page.evaluate(() => window.__lateEchoTracks.every(t => t.readyState === 'ended')), true, 'canceling a pending processing change releases late capture');
  assert.equal(await page.locator('#echo-cancellation').isChecked(), true, 'canceled capture retains the saved preference');
  await page.evaluate(() => navigator.mediaDevices.getUserMedia = window.__syntheticCapture);
  await page.locator('[data-view=people]').click();
});

test('camera denial and hangup during opt-in keep voice capture separate',async()=>{
  const [a,b]=pages;
  await a.locator('.friend-card .button.primary').click();await b.locator('#incoming-dialog').waitFor();await b.locator('#accept-call').click();
  for(const p of pages)await waitFor(p,()=>window.__peer?.connectionState==='connected');
  await a.locator('#toggle-mic').click();
  await a.evaluate(()=>{window.__savedCapture=navigator.mediaDevices.getUserMedia;window.__voiceMic=window.__peer.getSenders().find(s=>s.track?.kind==='audio').track;navigator.mediaDevices.getUserMedia=async c=>{if(c.audio===false)throw new DOMException('Camera access denied','NotAllowedError');return window.__savedCapture(c);};});
  await a.locator('#toggle-camera').click();await waitFor(a,()=>document.querySelector('#toast').textContent.includes('Camera access denied'));
  assert.equal(await a.evaluate(()=>window.__peer.getSenders().find(s=>s.track?.kind==='audio').track===window.__voiceMic&&!window.__voiceMic.enabled&&window.__voiceMic.readyState==='live'),true);
  assert.equal(await a.evaluate(()=>window.__peer.getSenders().some(s=>s.track?.kind==='video')),false);
  await a.evaluate(()=>navigator.mediaDevices.getUserMedia=c=>c.audio===false?new Promise(resolve=>window.__resolveCamera=resolve):window.__savedCapture(c));
  await a.locator('#toggle-camera').click();await waitFor(a,()=>typeof window.__resolveCamera==='function');
  await a.locator('#end-call').click();await b.locator('#call-view').waitFor({state:'hidden'});
  await a.evaluate(()=>{const canvas=document.createElement('canvas');const stream=canvas.captureStream(5);window.__lateCamera=stream.getVideoTracks()[0];window.__resolveCamera(stream);navigator.mediaDevices.getUserMedia=window.__savedCapture;});
  await waitFor(a,()=>window.__lateCamera.readyState==='ended');
});

test('switching cameras preserves the call and restores video after capture failure', async () => {
  const [a,b] = pages;
  await request(contexts[0], '/friends/request', {username: accounts[1].username});
  await request(contexts[1], `/friends/${users[0].id}/accept`);
  await a.locator('.friend-card .button.primary').click(); await b.locator('#incoming-dialog').waitFor(); await b.locator('#accept-call').click();
  for (const page of pages) await waitFor(page, () => window.__peer?.connectionState === 'connected');
  await a.locator('#toggle-camera').click();
  await waitFor(a, () => window.__peer.getSenders().some(sender => sender.track?.kind === 'video'));
  await a.evaluate(() => {
    window.__switchAudio = window.__peer.getSenders().find(sender => sender.track?.kind === 'audio').track;
    window.__switchOld = window.__peer.getSenders().find(sender => sender.track?.kind === 'video').track;
    window.__savedDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
    navigator.mediaDevices.enumerateDevices = async () => [];
  });
  if(!await a.locator('#call-more-dialog').evaluate(d=>d.open))await a.locator('#call-more').click();await a.locator('#switch-camera').click();
  await waitFor(a, () => !document.querySelector('#switch-camera').disabled);
  assert.equal(await a.evaluate(() => window.__switchOld.readyState), 'ended');
  assert.equal(await a.evaluate(() => window.__peer.getSenders().find(sender => sender.track?.kind === 'video').track.readyState), 'live');
  assert.equal(await a.evaluate(() => window.__peer.getSenders().find(sender => sender.track?.kind === 'audio').track === window.__switchAudio), true);
  await a.evaluate(() => {
    window.__savedSwitchCapture = navigator.mediaDevices.getUserMedia;
    let fail = true;
    navigator.mediaDevices.getUserMedia = constraints => {
      if (fail) { fail = false; return Promise.reject(new DOMException('Camera unavailable', 'NotReadableError')); }
      return window.__savedSwitchCapture(constraints);
    };
  });
  if(!await a.locator('#call-more-dialog').evaluate(d=>d.open))await a.locator('#call-more').click();await a.locator('#switch-camera').click();
  await waitFor(a, () => !document.querySelector('#switch-camera').disabled);
  assert.equal(await a.evaluate(() => window.__peer.getSenders().find(sender => sender.track?.kind === 'video').track.readyState), 'live');
  assert.equal(await a.evaluate(() => window.__peer.connectionState), 'connected');
  await a.evaluate(() => { navigator.mediaDevices.getUserMedia = window.__savedSwitchCapture; navigator.mediaDevices.enumerateDevices = window.__savedDevices; });
  await a.locator('#end-call').click(); await b.locator('#call-view').waitFor({state:'hidden'});
});

test('hangup cancels pending browser microphone permission in both call directions', async () => {
  const [a, b] = pages;
  async function delayCapture(page) {
    await page.evaluate(() => {
      window.originalCapture = navigator.mediaDevices.getUserMedia;
      navigator.mediaDevices.getUserMedia = (constraints) => new Promise((resolve) => {
        window.releaseCapture = async () => { const stream = await window.originalCapture(constraints); window.lateTracks = stream.getTracks(); resolve(stream); };
      });
    });
  }
  async function release(page) {
    await page.evaluate(() => window.releaseCapture());
    await waitFor(page, () => window.lateTracks.every((t) => t.readyState === 'ended'));
    await page.evaluate(() => { navigator.mediaDevices.getUserMedia = window.originalCapture; });
  }
  await delayCapture(a); await a.locator('.friend-card .button.primary').click();
  await waitFor(a, () => typeof window.releaseCapture === 'function');
  await a.locator('#end-call').click(); await release(a);
  assert.equal(await a.locator('#local-video').evaluate((v) => v.srcObject), null);
  await delayCapture(b); await a.locator('.friend-card .button.primary').click();
  await b.locator('#incoming-dialog').waitFor({ state: 'visible' });
  assert.match(await b.title(), /is calling/);
  await b.locator('#accept-call').click(); await waitFor(b, () => typeof window.releaseCapture === 'function');
  await a.locator('#end-call').click(); await b.locator('#incoming-dialog').waitFor({ state: 'hidden' }); await release(b);
  assert.equal(await b.locator('#local-video').evaluate((v) => v.srcObject), null);
  assert.ok(!(await b.title()).includes('is calling'));
});

test('recipient can return after a call starts, decline, and remove friendship', async () => {
  const [a, b] = pages;
  await b.goto('about:blank');
  await a.bringToFront();
  await waitFor(a, () => document.querySelector('.friend-status')?.textContent.includes('Offline'));
  await a.locator('.friend-card .button.secondary').click(); await a.locator('#call-view').waitFor({ state: 'visible' });
  await b.goto(base); await b.locator('#incoming-dialog').waitFor({ state: 'visible' }); await b.locator('#decline-call').click(); await a.locator('#call-view').waitFor({ state: 'hidden' });
  assert.equal((await request(contexts[0], '/history', undefined, 'GET')).body[0].outcome, 'declined');
  assert.equal((await request(contexts[0], `/friends/${users[1].id}`, undefined, 'DELETE')).status, 200);
  await waitFor(a, () => document.getElementById('friends-count').textContent === '0');
  assert.deepEqual((await request(contexts[1], '/friends', undefined, 'GET')).body, []);
});

test('professional desktop and mobile layouts, preview permissions, and screenshots', async () => {
  const [a, b] = pages;
  await a.bringToFront();
  await request(contexts[0], '/friends/request', { username: accounts[1].username }); await request(contexts[1], `/friends/${users[0].id}/accept`);
  await a.locator('.friend-card .button.primary').waitFor(); await settings(a); await a.locator('#start-preview').click();
  await waitFor(a, () => document.getElementById('preview-video').videoWidth > 0);
  await a.setViewportSize({width:390,height:844});
  await a.evaluate(() => {
    window.__originalDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
    navigator.mediaDevices.enumerateDevices = async () => [{kind:'videoinput',deviceId:'front',label:'Front'}, {kind:'videoinput',deviceId:'back',label:'Back'}];
    const stream = document.querySelector('#preview-video').srcObject;
    window.__previewMic = stream.getAudioTracks()[0]; window.__previewOld = stream.getVideoTracks()[0];
    window.__previewOld.getSettings = () => ({deviceId:'front',facingMode:'user'});
    window.__previewMic.enabled = false;
  });
  await a.locator('#preview-switch-camera').click();
  await waitFor(a, () => !document.querySelector('#preview-switch-camera').disabled);
  assert.equal(await a.evaluate(() => window.__captureCalls.at(-1).video.deviceId.exact), 'back');
  assert.equal(await a.evaluate(() => window.__captureCalls.at(-1).audio), false);
  assert.equal(await a.evaluate(() => window.__previewOld.readyState), 'ended');
  assert.equal(await a.evaluate(() => document.querySelector('#preview-video').srcObject.getAudioTracks()[0] === window.__previewMic && !window.__previewMic.enabled && window.__previewMic.readyState === 'live'), true);
  await a.evaluate(() => { navigator.mediaDevices.enumerateDevices = async () => []; });
  await a.locator('#preview-switch-camera').click();
  await waitFor(a, () => !document.querySelector('#preview-switch-camera').disabled);
  assert.equal(await a.evaluate(() => window.__captureCalls.at(-1).video.facingMode.exact), 'environment');
  await a.locator('#preview-switch-camera').click();
  await waitFor(a, () => !document.querySelector('#preview-switch-camera').disabled);
  assert.equal(await a.evaluate(() => window.__captureCalls.at(-1).video.facingMode.exact), 'user');
  await a.evaluate(() => { navigator.mediaDevices.enumerateDevices = window.__originalDevices; });
  await a.setViewportSize({width:1440,height:1000});
  await a.locator('#stop-preview').click();
  assert.equal(await a.locator('#preview-video').isVisible(), false);
  await a.locator('[data-view=people]').click();
  const extra = [];
  for (const [index, name] of ['Sam Rivera', 'Olivia Taylor'].entries()) {
    const context = await browser.newContext(); extra.push(context);
    const username = `friend${index}_${suffix}`;
    const registered = await request(context, '/register', { username, password, display_name: name }); assert.equal(registered.status, 200);
    await request(contexts[0], '/friends/request', { username }); await request(context, `/friends/${users[0].id}/accept`);
  }
  await waitFor(a, () => document.getElementById('friends-count').textContent === '3');
  await a.locator('#toast').waitFor({ state: 'hidden' });
  if (process.env.PVP_TEST_SCREENSHOTS !== '0') { await mkdir('docs/screenshots', { recursive: true }); await a.screenshot({ path: 'docs/screenshots/people-desktop.png', fullPage: true }); }
  await a.setViewportSize({ width: 390, height: 844 });
  assert.equal(await a.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  if (process.env.PVP_TEST_SCREENSHOTS !== '0') await a.screenshot({ path: 'docs/screenshots/people-mobile.png', fullPage: true });
  await settings(a); assert.equal(await a.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await a.setViewportSize({ width: 1440, height: 1000 }); if (process.env.PVP_TEST_SCREENSHOTS !== '0') await a.screenshot({ path: 'docs/screenshots/settings-desktop.png', fullPage: true });
  await a.locator('#logout').click(); await a.locator('#auth-view').waitFor({ state: 'visible' });
  assert.equal((await request(contexts[0], '/me', undefined, 'GET')).status, 401);
  if (process.env.PVP_TEST_SCREENSHOTS !== '0') await a.screenshot({ path: 'docs/screenshots/sign-in.png', fullPage: true });
  await b.locator('#logout').click();
  for (const context of extra) await context.close();
});
