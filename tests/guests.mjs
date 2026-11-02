import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';

// Generated media exercises actual WebRTC without opening physical devices.
function generatedMedia() {
  window.__captures = 0;
  window.__peers = [];
  window.__errors = [];
  window.addEventListener('error', e => window.__errors.push(e.message));
  const Original = RTCPeerConnection;
  window.RTCPeerConnection = class extends Original {
    constructor(...args) { super(...args); window.__peers.push(this); }
  };
  navigator.mediaDevices.getUserMedia = async constraints => {
    window.__captures++;
    const stream = new MediaStream();
    if (constraints.audio !== false) {
      const audio = new AudioContext(), tone = audio.createOscillator();
      const dest = audio.createMediaStreamDestination();
      tone.connect(dest); tone.start(); await audio.resume();
      const track = dest.stream.getAudioTracks()[0], stop = track.stop.bind(track);
      let stopped = false; track.stop = () => { if (stopped) return; stopped = true; stop(); tone.stop(); if (audio.state !== 'closed') audio.close().catch(error => { if (error.name !== 'InvalidStateError') throw error; }); };
      stream.addTrack(track);
      window.__capture = stream;
    }
    if (constraints.video !== false) {
      const canvas = document.createElement('canvas'); canvas.width = 320; canvas.height = 180;
      const context = canvas.getContext('2d'), paint = () => { context.fillStyle = '#ff0088'; context.fillRect(0, 0, 320, 180); };
      paint();
      const timer = setInterval(paint, 100), track = canvas.captureStream(10).getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); };
      stream.addTrack(track);
    }
    return stream;
  };
}

test('open links admit accountless guests with encrypted media and scoped moderation', {timeout: 120000}, async () => {
  const temp = await mkdtemp(join(tmpdir(), 'pvp-guests-'));
  const db = join(temp, 'pvp.sqlite');
  let server, browser;
  let base = process.env.PVP_TEST_URL;
  try {
    if (!base) {
    await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
    const probe = createServer();
    await new Promise(r => probe.listen(0, '127.0.0.1', r));
    const port = probe.address().port;
    await new Promise(r => probe.close(r));
    base = `http://localhost:${port}`;
    server = spawn('signaling/target/debug/pvp-signaling', [], {
      env: {...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: db}, stdio: 'ignore',
    });
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(base + '/health')).ok) break; } catch {}
      await new Promise(r => setTimeout(r, 100));
    }
    }
    browser = await chromium.launch({headless: true});
    const owner = await browser.newContext(), guest = await browser.newContext({viewport: {width: 390, height: 844}}), anonymous = await browser.newContext();
    const request = async (context, path, data, status = 200, method = data ? 'POST' : 'GET', headers = {}) => {
      const response = await context.request.fetch(base + '/api' + path, {
        method, headers: {Origin: base, ...headers}, ...(data ? {data} : {}),
      });
      assert.equal(response.status(), status, `${path}: ${await response.text()}`);
      return response.json();
    };
    const account = await request(owner, '/register', {username: `guest_owner_${Date.now()}`, display_name: 'Meeting owner', password: 'guest-meeting-password'});
    const recordAccount = async () => {
      if (process.env.PVP_TEST_ACCOUNT_FILE) await writeFile(process.env.PVP_TEST_ACCOUNT_FILE, JSON.stringify({id: account.id, username: account.username}), {mode: 0o600});
    };
    await recordAccount();
    const meeting = await request(owner, '/meetings', {name: 'Welcome guests', open_invite: true});
    const other = await request(owner, '/meetings', {name: 'Another open meeting', open_invite: true});
    const privateMeeting = await request(owner, '/meetings', {name: 'Private meeting'});
    const id = meeting.meeting_id;
    await request(anonymous, '/me', null, 401);
    const preview = await request(anonymous, `/meetings/${id}/preview`);
    assert.equal(preview.name, meeting.name);
    assert.equal(preview.members, undefined, 'public preview does not expose the member roster');
    await request(anonymous, `/meetings/${privateMeeting.meeting_id}/preview`, null, 403);
    await request(anonymous, `/meetings/${privateMeeting.meeting_id}/guest`, {display_name: 'Guest'}, 403);
    await request(anonymous, `/meetings/${id}/guest`, {display_name: 'Guest'}, 403, 'POST', {Origin: 'https://other.example'});
    for (const display_name of ['', '   ', 'a'.repeat(61), 'bad\nname']) {
      await request(anonymous, `/meetings/${id}/guest`, {display_name}, 400);
    }
    const cookiesBefore = await owner.cookies();
    await request(owner, `/meetings/${id}/guest`, {display_name: 'Already signed in'}, 400);
    assert.deepEqual(await owner.cookies(), cookiesBefore, 'guest entry never replaces an account session');

    const host = await owner.newPage(), visitor = await guest.newPage();
    for (const page of [host, visitor]) await page.addInitScript(generatedMedia);
    await host.goto(meeting.url);
    await host.locator('#guest-submit').click();
    await host.locator('#group-view').waitFor({state: 'visible'});
    await visitor.goto(meeting.url);
    await visitor.locator('#guest-form').waitFor({state: 'visible'});
    assert.equal(await visitor.locator('#account-auth').isVisible(), false);
    assert.equal(await visitor.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'guest preview fits mobile');
    assert.equal(await visitor.evaluate(() => window.__captures), 0);
    assert.equal((await request(owner, `/meetings/${id}`)).members.length, 1);
    await visitor.locator('#guest-sign-in').click();
    await visitor.locator('#auth-form').waitFor({state: 'visible'});
    assert.equal(new URL(visitor.url()).hash, new URL(meeting.url).hash);
    await visitor.reload();
    await visitor.locator('#guest-name').fill('   ');
    await visitor.locator('#guest-submit').click();
    await visitor.locator('#guest-error').filter({hasText: 'Enter a display name'}).waitFor();
    const displayName = '<img src=x onerror=alert(1)> Guest';
    await visitor.locator('#guest-name').fill(displayName);
    await visitor.locator('#guest-submit').click();
    await visitor.locator('#group-view').waitFor({state: 'visible'});
    const identity = await request(guest, '/me');
    assert.equal(identity.guest, true);
    assert.equal(identity.meeting_id, id);
    assert.equal(identity.display_name, displayName);
    const cookie = (await guest.cookies()).find(c => c.name === 'pvp_guest');
    assert.ok(cookie.httpOnly);
    assert.equal(cookie.sameSite, 'Strict');
    assert.equal(cookie.secure, base.startsWith('https://'));
    assert.equal(cookie.expires, -1, 'guests use a browser-session cookie');
    assert.equal((await guest.cookies()).some(c => c.name === 'pvp_session'), false);
    await host.locator(`#group-tile-${identity.id}`).filter({hasText: 'Guest'}).waitFor();
    assert.equal(await host.locator(`#group-tile-${identity.id} img`).count(), 0);
    for (const page of [host, visitor]) {
      await page.waitForFunction(async () => {
        for (const pc of window.__peers) {
          if (pc.connectionState !== 'connected') continue;
          const stats = [...(await pc.getStats()).values()];
          if (stats.some(s => s.type === 'transport' && s.dtlsState === 'connected' && s.srtpCipher)
              && stats.some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.bytesReceived > 100 && s.totalAudioEnergy > 0.001)) return true;
        }
        return false;
      }, null, {timeout: 30000});
      // RTP can arrive while a mixed audio/video element is still waiting for
      // the first camera frame. Require an advancing audible playback clock.
      await page.waitForFunction(() => [...document.querySelectorAll('#group-grid audio, #group-grid video')].some(media =>
        !media.muted && !media.paused && media.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA
        && media.currentTime > 0 && media.srcObject?.getAudioTracks().length > 0), null, {timeout: 5000});
    }
    const microphones = await Promise.all([host, visitor].map(page => page.evaluate(() => window.__capture.getAudioTracks()[0].id)));
    await visitor.evaluate(() => {
      const audio = document.querySelector('#group-grid audio');
      audio.pause();
      window.__audioPlay = audio.play;
      audio.play = () => Promise.reject(new DOMException('Autoplay blocked', 'NotAllowedError'));
      document.getElementById('group-play').click();
    });
    await visitor.locator('#group-play').waitFor({state: 'visible'});
    await visitor.locator('#group-play').click();
    assert.equal(await visitor.locator('#group-play').isVisible(), true, 'a rejected retry keeps the audio prompt visible');
    await visitor.evaluate(() => { document.querySelector('#group-grid audio').play = window.__audioPlay; });
    await visitor.locator('#group-play').click();
    await visitor.locator('#group-play').waitFor({state: 'hidden'});
    for (const page of [host, visitor]) await page.locator('#group-camera').click();
    for (const page of [host, visitor]) await page.waitForFunction(() => [...document.querySelectorAll('[id^="group-video-"]')].some(video => video.videoWidth > 0));
    for (const page of [host, visitor]) await page.locator('#group-camera').click();
    for (const [index, page] of [host, visitor].entries()) {
      assert.equal(await page.evaluate(() => window.__capture.getAudioTracks()[0].id), microphones[index], 'camera toggles preserve the microphone');
      const before = await page.locator('#group-grid audio').evaluate(audio => audio.currentTime);
      await page.waitForFunction(time => {const audio=document.querySelector('#group-grid audio');return audio&&!audio.paused&&!audio.muted&&audio.currentTime>time+.1;}, before);
    }
    if (server) {
    const stored = await promisify(execFile)('python3', ['-c',
      'import sqlite3,sys,json; d=sqlite3.connect(sys.argv[1]); print(json.dumps([d.execute("SELECT COUNT(*) FROM "+t).fetchone()[0] for t in ["users","sessions","meeting_members"]]))', db]);
    assert.deepEqual(JSON.parse(stored.stdout), [1, 1, 3], 'guest joins do not create accounts, persistent sessions or memberships');
    }
    await request(guest, `/meetings/${other.meeting_id}`, null, 403);
    await request(guest, `/meetings/${privateMeeting.meeting_id}`, null, 403);
    await request(guest, '/meetings', {name: 'Guest cannot host'}, 401);
    await request(guest, '/friends/request', {username: account.username}, 401);
    await request(guest, `/meetings/${id}/members/${account.id}/mute`, {muted: true}, 401);
    await request(owner, `/meetings/${id}/members/${identity.id}/admin`, {admin: true}, 403);

    await host.locator('#group-chat-open').click();
    await visitor.locator('#group-more').click();
    await visitor.locator('#group-chat-open').click();
    await host.waitForFunction(() => document.getElementById('meeting-chat-status').textContent.startsWith('1 participant connected'));
    await visitor.locator('#meeting-chat-text').fill('Hello from an accountless guest');
    await visitor.locator('#meeting-chat-send').click();
    await host.locator('.chat-message').filter({hasText: 'Hello from an accountless guest'}).waitFor();
    await host.locator('#meeting-chat-close').click();
    await visitor.locator('#meeting-chat-close').click();

    await request(owner, `/meetings/${id}/members/${identity.id}/mute`, {muted: true});
    await visitor.waitForFunction(() => document.getElementById('group-mic').disabled && window.__capture.getAudioTracks().every(t => !t.enabled));
    await request(owner, `/meetings/${id}/members/${identity.id}/mute`, {muted: false});
    await visitor.waitForFunction(() => !document.getElementById('group-mic').disabled);
    assert.equal(await visitor.evaluate(() => window.__capture.getAudioTracks()[0].enabled), false);
    const retiredAudio = await visitor.locator('#group-grid audio').elementHandle();
    await visitor.locator('#group-leave').click();
    assert.equal(await retiredAudio.evaluate(audio => !audio.isConnected && audio.paused && audio.srcObject === null), true, 'leaving disposes remote audio playback');
    await host.waitForFunction(() => !document.querySelector('[id^="group-tile-guest-"]'));
    assert.equal((await request(owner, `/meetings/${id}`)).members.length, 1, 'leaving frees the guest slot');
    assert.equal(await visitor.evaluate(() => window.__capture.getTracks().every(t => t.readyState === 'ended')), true);
    await visitor.reload();
    await visitor.locator('#guest-submit').waitFor();
    assert.equal(await visitor.evaluate(() => window.__captures), 0, 'restoring a guest session never starts capture');
    assert.equal((await request(guest, '/me')).id, identity.id);
    await visitor.locator('#guest-submit').click();
    await visitor.locator('#group-view').waitFor({state: 'visible'});
    await request(owner, `/meetings/${id}/members/${identity.id}`, null, 200, 'DELETE');
    await visitor.locator('#group-view').waitFor({state: 'hidden'});
    assert.equal(await visitor.evaluate(() => window.__capture.getTracks().every(t => t.readyState === 'ended')), true);
    await request(guest, `/meetings/${id}`, null, 403);
    await request(guest, `/meetings/${id}/guest`, {display_name: 'Try again'}, 403);
    await visitor.reload();
    await visitor.locator('#guest-error').filter({hasText: 'You were removed from this meeting'}).waitFor();
    assert.equal((await request(owner, `/meetings/${id}`)).members.length, 1);
    await request(guest, '/guest/logout', {}, 200);
    await request(guest, '/me', null, 401);
    await visitor.reload();
    await visitor.locator('#guest-form').waitFor({state: 'visible'});

    const privatePage = await anonymous.newPage();
    await privatePage.goto(privateMeeting.url);
    await privatePage.locator('#guest-error').filter({hasText: 'needs an invitation'}).waitFor();
    assert.equal(await privatePage.locator('#guest-form').isVisible(), false);
    await request(owner, `/meetings/${id}`, null, 200, 'DELETE');
    await request(anonymous, `/meetings/${id}/preview`, null, 403);
    await request(anonymous, `/meetings/${id}/guest`, {display_name: 'Late guest'}, 403);
    for (const page of [host, visitor]) assert.deepEqual(await page.evaluate(() => window.__errors), []);
  } finally {
    await browser?.close();
    if (server) { server.kill(); await new Promise(r => server.once('exit', r)); }
    await rm(temp, {recursive: true, force: true});
  }
});
