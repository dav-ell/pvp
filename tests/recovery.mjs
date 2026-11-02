import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

// Exercise real DTLS-SRTP, audio, and video using generated tracks. Never open
// the user's physical microphone or camera while testing a recovery product.
function generatedMedia() {
  window.__captures = []; window.__tracks = []; window.__peers = [];
  const Peer = RTCPeerConnection;
  window.RTCPeerConnection = class extends Peer { constructor(...args) { super(...args); window.__peers.push(this); } };
  navigator.mediaDevices.getUserMedia = async constraints => {
    window.__captures.push(constraints);
    const stream = new MediaStream();
    if (constraints.audio !== false) {
      const context = new AudioContext(), oscillator = context.createOscillator(), destination = context.createMediaStreamDestination();
      oscillator.connect(destination); oscillator.start(); await context.resume();
      const track = destination.stream.getAudioTracks()[0], stop = track.stop.bind(track);
      let stopped = false; track.stop = () => { if (stopped) return; stopped = true; stop(); oscillator.stop(); if (context.state !== 'closed') context.close().catch(error => { if (error.name !== 'InvalidStateError') throw error; }); };
      stream.addTrack(track); window.__tracks.push(track);
    }
    if (constraints.video !== false) {
      const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 480;
      const context = canvas.getContext('2d'); let frame = 0;
      const paint = () => { context.fillStyle = '#8c9c70'; context.fillRect(0, 0, 640, 480); context.fillStyle = '#f6f5ef'; context.fillRect((frame++ * 4) % 640, 100, 120, 120); };
      paint(); const timer = setInterval(paint, 60);
      const track = canvas.captureStream(15).getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { stop(); clearInterval(timer); };
      stream.addTrack(track); window.__tracks.push(track);
    }
    return stream;
  };
}

test('recovery meetings isolate identities, respect device consent, and encrypt moderated calls', { timeout: 120000 }, async () => {
  const temp = await mkdtemp(join(tmpdir(), 'fellowship-'));
  let server, browser;
  try {
    await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
    const probe = createServer(); await new Promise(r => probe.listen(0, '127.0.0.1', r));
    const port = probe.address().port; await new Promise(r => probe.close(r));
    const base = `http://localhost:${port}`;
    server = spawn('signaling/target/debug/pvp-signaling', [], { env: { ...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: join(temp, 'meetings.sqlite'), PVP_RECOVERY: '1' }, stdio: 'pipe' });
    let logs = ''; server.stderr.on('data', chunk => logs += chunk.toString());
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(base + '/health')).ok) break; } catch {}
      if (server.exitCode !== null) throw Error(logs);
      await new Promise(r => setTimeout(r, 100));
    }
    browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required'] });
    const hostContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const guestContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    const thirdContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const host = await hostContext.newPage(), guest = await guestContext.newPage(), third = await thirdContext.newPage();
    const errors = [], external = [];
    for (const page of [host, guest, third]) {
      await page.addInitScript(generatedMedia);
      page.on('pageerror', error => errors.push(error.message));
      page.on('request', request => { if (!request.url().startsWith(base) && /^https?:/.test(request.url())) external.push(request.url()); });
    }
    const request = async (context, path, data, status = 200, method = data === undefined ? 'GET' : 'POST', prefix = '/recovery/api', origin = base) => {
      const response = await context.request.fetch(base + prefix + path, { method, headers: { Origin: origin }, ...(data === undefined ? {} : { data }) });
      assert.equal(response.status(), status, `${path}: ${await response.text()}`);
      return response.json();
    };
    const pvpUser = await request(hostContext, '/register', { username: 'not_my_recovery_name', display_name: 'Real PVP Name', password: 'identity-isolation-test' }, 200, 'POST', '/api');
    await host.goto(base);
    await host.getByRole('heading', { name: /Your recovery/ }).waitFor();
    await mkdir('docs/screenshots', { recursive: true });
    await host.screenshot({ path: 'docs/screenshots/recovery-home.png', fullPage: true });
    assert.equal(await host.evaluate(() => window.__captures.length), 0);
    await host.locator('.hero [data-create]').click();
    await host.locator('#create-name').fill('Alex');
    await host.locator('#create-title').fill('One day at a time');
    await host.locator('#create-form button[type=submit]').click();
    await host.locator('#created-panel').waitFor({ state: 'visible' });
    const link = await host.locator('#created-link').inputValue(), id = new URL(link).hash.slice(9);
    assert.match(link, /\/recovery\/#meeting=[a-f0-9]{64}$/);
    assert.equal(await host.evaluate(() => window.__captures.length), 0, 'creating a link never opens a device');
    const hostUser = await request(hostContext, '/me');
    assert.equal(hostUser.display_name, 'Alex'); assert.notEqual(hostUser.id, pvpUser.id);
    assert.equal((await request(hostContext, '/me', undefined, 200, 'GET', '/api')).id, pvpUser.id, 'PVP session survives recovery session creation');
    assert.equal((await request(hostContext, `/meetings/${id}`)).raise_hand_enabled, true);
    const cookies = await hostContext.cookies();
    const hostCookie = cookies.find(c => c.name === 'fellowship_session');
    assert.ok(hostCookie.httpOnly); assert.equal(hostCookie.sameSite, 'Strict');
    await request(guestContext, '/start', { display_name: 'Cross origin' }, 403, 'POST', '/recovery/api', 'https://untrusted.example');
    const forbiddenSocket = await guestContext.request.get(base + '/recovery/api/ws', { headers: { Origin: 'https://untrusted.example' } });
    assert.equal(forbiddenSocket.status(), 403, 'recovery websocket upgrades require the configured origin');
    await request(guestContext, `/meetings/${id}/speaking`, { enabled: false }, 401);
    const preview = await request(guestContext, `/meetings/${id}/preview`);
    assert.equal(preview.members, undefined, 'public preview reveals no roster');

    await host.locator('#created-continue').click();
    await host.locator('#join-consent').check(); await host.locator('#join-listen').click();
    await host.locator('#call-view').waitFor({ state: 'visible' });
    assert.equal(await host.evaluate(() => window.__captures.length), 0, 'listen-only host opens no devices');
    await guest.goto(link); await guest.locator('#join-name').fill('River');
    await guest.locator('#join-consent').check(); await guest.locator('#join-listen').click();
    await guest.locator('#call-view').waitFor({ state: 'visible' });
    assert.equal(await guest.evaluate(() => window.__captures.length), 0, 'listen-only member opens no devices');
    await third.goto(link); await third.locator('#join-name').fill('<img src=x onerror=alert(1)> Jo');
    await third.locator('#join-consent').check(); await third.locator('#join-microphone').click();
    await third.locator('#call-view').waitFor({ state: 'visible' });
    assert.equal(await third.evaluate(() => window.__captures.length), 1);
    assert.equal(await third.evaluate(() => window.__tracks[0].enabled), false, 'microphone joins muted');
    const guestUser = await request(guestContext, '/me'), thirdUser = await request(thirdContext, '/me');
    assert.equal(await host.locator('#participant-list img').count(), 0, 'chosen names are text, never HTML');
    await host.waitForFunction(() => window.__peers.filter(p => p.connectionState === 'connected').length === 2);
    await guest.waitForFunction(() => window.__peers.filter(p => p.connectionState === 'connected').length === 2);
    await host.locator('#encryption-status').filter({ hasText: 'Peer encryption verified' }).waitFor();
    assert.equal(await guest.locator('#microphone-button').isDisabled(), true);
    await request(guestContext, `/meetings/${id}/members/${thirdUser.id}/speak`, { allowed: true }, 401);
    await guest.locator('#hand-button').click();
    const guestRow = host.locator(`.person-row[data-member-id="${guestUser.id}"]`);
    await guestRow.getByRole('button', { name: 'Invite to share' }).click();
    await guest.waitForFunction(() => !document.getElementById('microphone-button').disabled);
    assert.equal(await guest.evaluate(() => window.__captures.length), 0, 'chair approval never opens a microphone');
    await guest.locator('#microphone-button').click();
    await guest.waitForFunction(() => window.__tracks.some(t => t.kind === 'audio' && t.enabled));
    await host.waitForFunction(async () => {
      for (const pc of window.__peers.filter(p => p.connectionState === 'connected')) {
        const stats = [...(await pc.getStats()).values()];
        if (stats.some(s => s.type === 'transport' && s.dtlsState === 'connected' && s.srtpCipher) && stats.some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > .001)) return true;
      }
      return false;
    });
    await guest.locator('#camera-button').click();
    await host.waitForFunction(id => document.querySelector(`#participant-${id}`).classList.contains('video-on'), guestUser.id);
    await guestRow.getByRole('button', { name: 'End share' }).click();
    await guest.waitForFunction(() => document.getElementById('microphone-button').disabled && window.__tracks.filter(t => t.kind === 'audio').every(t => !t.enabled));
    await host.waitForFunction(id => document.getElementById(`video-${id}`).srcObject.getAudioTracks().every(t => !t.enabled), guestUser.id);
    for (const width of [320, 375, 390, 768]) {
      await guest.setViewportSize({ width, height: 844 });
      assert.equal(await guest.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `meeting fits ${width}px`);
    }
    await guest.setViewportSize({ width: 390, height: 844 });
    await guest.screenshot({ path: 'docs/screenshots/recovery-meeting-mobile.png', fullPage: true });
    await host.screenshot({ path: 'docs/screenshots/recovery-meeting.png', fullPage: true });
    assert.equal(await host.locator('body').innerText().then(t => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(t)), false, 'UI never displays network addresses');
    assert.equal(await host.locator('[id*=inspector], [id*=export]').count(), 0);
    await guest.locator('#leave-button').click();
    await guest.locator('#left-view').waitFor({ state: 'visible' });
    assert.equal(await guest.evaluate(() => window.__tracks.every(t => t.readyState === 'ended')), true, 'leave stops every captured track');
    assert.equal(await guest.evaluate(() => window.__peers.every(p => p.connectionState === 'closed')), true, 'leave closes all peer connections');
    await guest.locator('#rejoin-button').click();
    await guest.locator('#join-form').waitFor({ state: 'visible' });
    await guest.locator('#join-consent').check(); await guest.locator('#join-listen').click();
    await guest.locator('#call-view').waitFor({ state: 'visible', timeout: 10000 }).catch(async error => {
      throw Error(`${error.message}\nJoin error: ${await guest.locator('#entry-error').textContent()}`);
    });
    assert.equal(await guest.locator('#microphone-button').isDisabled(), true, 'rejoining resets speaking permission');
    await guest.waitForFunction(() => window.__peers.filter(p => p.connectionState === 'connected').length === 2);
    assert.equal((await request(guestContext, '/me')).id, guestUser.id, 'browser guest session survives a leave/rejoin');
    await guest.locator('#leave-button').click();
    await guest.locator('#rejoin-button').click();
    await guest.locator('#join-form').waitFor({ state: 'visible' });
    await guest.evaluate(() => {
      const capture = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = async constraints => {
        await new Promise(resolve => window.__resolvePermission = resolve);
        return capture(constraints);
      };
    });
    await guest.locator('#join-consent').check(); await guest.locator('#join-microphone').click();
    await guest.waitForFunction(() => !!window.__resolvePermission);
    await guest.locator('#cancel-join').click();
    await guest.evaluate(() => window.__resolvePermission());
    await guest.waitForFunction(() => window.__tracks.length === 3 && window.__tracks.every(t => t.readyState === 'ended'));
    assert.equal(await guest.locator('#call-view').isVisible(), false, 'canceling a pending permission never enters a meeting');
    await guest.evaluate(() => navigator.mediaDevices.getUserMedia = async () => { throw new DOMException('Denied by fixture', 'NotAllowedError'); });
    await guest.locator('#join-microphone').click();
    await guest.locator('#entry-error').filter({ hasText: 'You can join to listen' }).waitFor();
    await guest.locator('#join-listen').click();
    await guest.locator('#call-view').waitFor({ state: 'visible' });
    assert.equal(await guest.evaluate(() => window.__captures.length), 3, 'listen-only entry still works after microphone denial');
    await host.locator('.call-header [data-privacy]').click();
    assert.match(await host.locator('#privacy-dialog').innerText(), /Direct P2P still exposes your IP address/);
    await host.keyboard.press('Escape');
    assert.deepEqual(external, [], 'the app loads no external fonts, analytics, or assets');
    assert.deepEqual(errors, []);
    await guest.goto(base);
    for (const width of [320, 375, 390, 768]) {
      await guest.setViewportSize({ width, height: 844 });
      assert.equal(await guest.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `landing page fits ${width}px`);
    }
  } finally {
    await browser?.close();
    if (server) { server.kill(); await new Promise(r => server.once('exit', r)); }
    await rm(temp, { recursive: true, force: true });
  }
});
