import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp, rm, mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';

function media() {
  window.__captures = 0; window.__peers = []; window.__errors = [];
  window.addEventListener('error', event => window.__errors.push(event.message));
  const Peer = RTCPeerConnection;
  window.RTCPeerConnection = class extends Peer { constructor(...args) { super(...args); window.__peers.push(this); } };
  navigator.mediaDevices.getUserMedia = async () => {
    window.__captures++;
    const audio = new AudioContext(), tone = audio.createOscillator(), destination = audio.createMediaStreamDestination();
    tone.connect(destination); tone.start(); await audio.resume();
    const stream = destination.stream, track = stream.getAudioTracks()[0], stop = track.stop.bind(track);
    let stopped = false; track.stop = () => { if (stopped) return; stopped = true; stop(); tone.stop(); if (audio.state !== 'closed') audio.close().catch(error => { if (error.name !== 'InvalidStateError') throw error; }); };
    return stream;
  };
}

test('guests create, share and moderate; Zoom invitations converge across users and restarts', {timeout: 180000}, async () => {
  const temp = await mkdtemp(join(tmpdir(), 'pvp-links-zoom-'));
  let server, browser;
  const probe = createServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
  const base = `http://localhost:${port}`, database = join(temp, 'pvp.sqlite');
  const start = async () => {
    server = spawn('signaling/target/debug/pvp-signaling', [], {env: {...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: database}, stdio: 'ignore'});
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) return; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
    throw Error('Service failed to start');
  };
  const stop = async () => { const process = server; server = null; process.kill(); await new Promise(resolve => process.once('exit', resolve)); };
  try {
    await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
    await start(); browser = await chromium.launch({headless: true});
    const owner = await browser.newContext({permissions: ['clipboard-read', 'clipboard-write']}), outsider = await browser.newContext(), signed = await browser.newContext();
    const request = async (context, path, data, status = 200, method = data ? 'POST' : 'GET', headers = {}) => {
      const response = await context.request.fetch(base + '/api' + path, {method, headers: {Origin: base, ...headers}, ...(data ? {data} : {})});
      assert.equal(response.status(), status, `${path}: ${await response.text()}`); return response.json();
    };
    const host = await owner.newPage(); host.setDefaultTimeout(15000); await host.addInitScript(media); await host.goto(base);
    await host.locator('#home-guest-name').fill('Guest host'); await host.locator('#home-meeting-name').fill('Our weekly catch-up');
    await host.locator('#home-create-link').click(); await host.locator('#meeting-copy').waitFor();
    const link = await host.locator('#meeting-link').inputValue(), id = new URLSearchParams(new URL(link).hash.slice(1)).get('meeting');
    const identity = await request(owner, '/me'); assert.equal(identity.guest, true); assert.equal(identity.scoped_guest, false);
    assert.equal(await host.evaluate(() => window.__captures), 0);
    await host.locator('#meeting-copy').click(); assert.equal(await host.evaluate(() => navigator.clipboard.readText()), link);
    await request(outsider, '/guest/start', {display_name: 'Wrong origin'}, 403, 'POST', {Origin: 'https://other.example'});
    const preview = await request(outsider, `/meetings/${id}/preview`); assert.equal(preview.open_invite, true);
    await request(owner, '/meetings', {name: 'Guest private meeting'}, 400);
    await host.reload(); await host.locator('#meeting-new').click(); await host.locator('#meeting-name').fill('Second guest link');
    assert.equal(await host.locator('#meeting-access').inputValue(), 'open'); await host.locator('#meeting-create').click(); await host.locator('#meeting-copy').waitFor();
    const meetings = await request(owner, '/meetings'); assert.equal(meetings.length, 2);
    const record = await request(owner, `/meetings/${id}`); assert.equal(record.owner_id, identity.id); assert.equal(record.members[0].is_admin, true);
    await request(outsider, `/meetings/${id}/guest`, {display_name: 'Visitor'});
    const visitor = await outsider.newPage(); await visitor.addInitScript(media); await visitor.goto(link); await visitor.locator('#guest-listen').click(); await visitor.locator('#group-view').waitFor({state: 'visible'});
    const visitorIdentity = await request(outsider, '/me');
    await request(outsider, `/meetings/${id}`, null, 401, 'DELETE');
    await request(owner, `/meetings/${id}/members/${visitorIdentity.id}/mute`, {muted: true});
    await visitor.waitForFunction(() => document.getElementById('group-mic').disabled);
    await request(owner, `/meetings/${id}/members/${visitorIdentity.id}`, null, 200, 'DELETE');
    await visitor.locator('#group-view').waitFor({state: 'hidden'});

    await request(signed, '/register', {username: `zoom_user_${Date.now()}`, password: 'zoom-test-password', display_name: 'Signed in'});
    const zoom = await request(outsider, '/zoom', {link: 'https://us02web.zoom.us/j/12345678901?pwd=secret&omn=123'});
    // A group on one network must not spend its sign-in/guest admission budget
    // simply by looking up invitations and comparing link variants.
    for (let i = 0; i < 32; i++) assert.equal((await request(outsider, '/zoom', {link: '12345678901'})).url, zoom.url);
    for (const [context, variant] of [[owner, 'zoommtg://zoom.us/join?confno=12345678901&pwd=changed'], [signed, 'https://company.zoom.us/wc/join/12345678901'], [outsider, 'Meeting ID: 123 4567 8901\nPasscode: 123456']]) {
      assert.equal((await request(context, '/zoom', {link: variant})).url, zoom.url);
    }
    await host.locator('[data-view=settings]').click(); await host.locator('details.sidebar-extras > summary').click(); await host.locator('#zoom-nav').click(); await host.locator('#zoom-input').fill('https://zoom.us/j/12345678901?pwd=private'); await host.locator('#zoom-open').click();
    await host.locator('#zoom-result').waitFor(); assert.equal(await host.locator('#zoom-pvp-link').inputValue(), zoom.url);
    await host.locator('#zoom-copy-message').click(); const message = await host.evaluate(() => navigator.clipboard.readText()); assert.ok(message.includes(zoom.url)); assert.ok(!message.includes('pwd='));
    await host.locator('#zoom-input').fill('https://zoom.us/my/someone'); assert.equal(await host.locator('#zoom-result').isVisible(), false);
    await host.locator('#zoom-open').click(); await host.locator('#zoom-error').filter({hasText: 'numeric meeting ID'}).waitFor();
    await host.locator('#zoom-close').click();
    const signedPage = await signed.newPage(); await signedPage.addInitScript(media); await signedPage.goto(base); await signedPage.locator('[data-view=settings]').click(); await signedPage.locator('details.sidebar-extras > summary').click(); await signedPage.locator('#zoom-nav').click(); await signedPage.locator('#zoom-close').click();
    await host.goto(zoom.url); await host.locator('#guest-submit').click(); await host.locator('#group-view').waitFor({state: 'visible'});
    await signedPage.goto(zoom.url); await signedPage.locator('#guest-submit').click(); await signedPage.locator('#group-view').waitFor({state: 'visible'});
    for (const page of [host, signedPage]) await page.waitForFunction(async () => {
      for (const pc of window.__peers) if (pc.connectionState === 'connected') {
        const stats = [...(await pc.getStats()).values()];
        if (stats.some(s => s.type === 'transport' && s.dtlsState === 'connected' && s.srtpCipher) && stats.some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.bytesReceived > 100)) return true;
      }
      return false;
    }, null, {timeout: 30000});
    const room = await request(owner, `/meetings/${zoom.meeting_id}`); assert.equal(room.members.length, 2); assert.ok(room.members.every(member => !member.is_admin));
    await request(owner, `/meetings/${zoom.meeting_id}/members/${identity.id}/admin`, {admin: true}, 403);
    await request(owner, `/meetings/${zoom.meeting_id}`, null, 403, 'DELETE');
    for (const page of [host, signedPage]) { await page.locator('#group-leave').click(); await page.locator('#group-view').waitFor({state: 'hidden'}); }
    await stop(); await start();
    assert.equal((await request(owner, '/me')).id, identity.id); assert.equal((await request(owner, `/meetings/${id}`)).owner_id, identity.id);
    assert.equal((await request(signed, '/zoom', {link: 'https://zoom.us/j/12345678901?pwd=after-restart'})).url, zoom.url);
    const mobileContext = await browser.newContext({viewport: {width: 390, height: 844}, isMobile: true}), mobile = await mobileContext.newPage(); await mobile.addInitScript(media); await mobile.goto(base);
    await mobile.locator('details.migration-help > summary').click(); await mobile.locator('#home-zoom').click(); await mobile.locator('#zoom-input').fill('123 4567 8901'); await mobile.locator('#zoom-open').click(); await mobile.locator('#zoom-result').waitFor();
    assert.equal(await mobile.locator('#zoom-pvp-link').inputValue(), zoom.url); assert.equal(await mobile.evaluate(() => window.__captures), 0);
    assert.equal(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await mkdir('docs/screenshots', {recursive: true}); await mobile.screenshot({path: 'docs/screenshots/guest-zoom-link.png', animations: 'disabled'});
    await mobile.locator('#zoom-join').click(); await mobile.locator('#guest-name').fill('Mobile Zoom guest'); await mobile.locator('#guest-listen').click(); await mobile.locator('#group-view').waitFor({state: 'visible'});
    assert.equal(await mobile.evaluate(() => window.__captures), 0); await mobile.locator('#group-leave').click();
    await mobile.goto(base); await mobile.locator('#home-guest-name').fill('Mobile host'); await mobile.locator('#home-meeting-name').fill('Mobile link');
    await mobile.locator('#home-create-link').click(); await mobile.locator('#meeting-copy').waitFor();
    for (const width of [320, 390]) {
      await mobile.setViewportSize({width, height: 844});
      assert.equal(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `guest link sharing fits ${width}px`);
    }
    assert.equal(await mobile.evaluate(() => window.__captures), 0);
    for (const page of [host, signedPage, visitor, mobile]) assert.deepEqual(await page.evaluate(() => window.__errors), []);
  } finally { await browser?.close(); if (server) await stop(); await rm(temp, {recursive: true, force: true}); }
});
