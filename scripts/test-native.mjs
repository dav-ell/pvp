import { chromium } from 'playwright';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { createServer } from 'node:http';

const temporary = await mkdtemp(join(tmpdir(), 'pvp-native-'));
const suffix = process.env.PVP_TEST_SUFFIX || `${Date.now()}`.slice(-10), peerName = `peer_${suffix}`, nativeName = `native_${suffix}`;
if (!/^[a-z0-9_]{1,20}$/.test(suffix)) throw new Error('PVP_TEST_SUFFIX must be 1–20 lowercase username characters');
let server, browser, control;
try {
  let base = process.env.PVP_TEST_URL;
  if (!base) {
  await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
  const probe = createServer(); await new Promise(r => probe.listen(0, '127.0.0.1', r));
  const port = probe.address().port; await new Promise(r => probe.close(r)); base = `http://localhost:${port}`;
  server = spawn('signaling/target/debug/pvp-signaling', [], { env: { ...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: join(temporary, 'pvp.sqlite') }, stdio: 'inherit' });
  for (let i = 0; i < 100; i++) { try { if ((await fetch(`${base}/health`)).ok) break; } catch {} await new Promise(r => setTimeout(r, 100)); }
  }
  console.log(`Native verification: ${base} (${nativeName}, ${peerName})`);
  browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required'] });
  const context = await browser.newContext(), page = await context.newPage();
  await page.addInitScript(() => {
    const Original = window.RTCPeerConnection;
    window.RTCPeerConnection = class extends Original { constructor(...a) { super(...a); window.__peer = this; } };
    navigator.mediaDevices.getDisplayMedia = async () => {
      const canvas = document.createElement('canvas'); canvas.width = 960; canvas.height = 540;
      const ctx = canvas.getContext('2d'); const timer = setInterval(() => { ctx.fillStyle = '#ff0088'; ctx.fillRect(0, 0, 960, 540); }, 33);
      const stream = canvas.captureStream(30), track = stream.getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); }; return stream;
    };
    navigator.mediaDevices.getUserMedia = async () => {
      const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 360;
      const ctx = canvas.getContext('2d'); let n = 0;
      const timer = setInterval(() => { ctx.fillStyle = '#24583e'; ctx.fillRect(0, 0, 640, 360); ctx.fillStyle = '#dbedbe'; ctx.fillRect((n++ * 8) % 640, 80, 100, 100); }, 33);
      const stream = canvas.captureStream(30), track = stream.getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); };
      const audio = new AudioContext(), oscillator = audio.createOscillator(), dest = audio.createMediaStreamDestination(); oscillator.connect(dest); oscillator.start(); await audio.resume();
      const sound = dest.stream.getAudioTracks()[0], stopSound = sound.stop.bind(sound);
      sound.stop = () => { stopSound(); oscillator.stop(); audio.close(); }; stream.addTrack(sound); return stream;
    };
  });
  page.on('pageerror', e => console.error('Browser peer:', e.message));
  await page.goto(base); await page.locator('#show-account').click(); await page.locator('#register-tab').click();
  await page.locator('#display-name').fill('Jamie Chen'); await page.locator('#username').fill(peerName);
  await page.locator('#password').fill('native-test-passphrase-123'); await page.locator('#auth-submit').click(); await page.locator('#connection-dot.online').waitFor(); await page.locator('[data-view=people]').click();
  control = createServer(async (req, res) => {
    try {
      if (req.url?.startsWith('/screenshot/') && req.method === 'POST') {
        const name = req.url.split('/').at(-1);
        if (!/^native-[a-z-]+$/.test(name)) throw new Error('Invalid screenshot name');
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const screenshots = name === 'native-inspector' ? '.build/inspector/screenshots' : 'docs/screenshots';
        await mkdir(screenshots, { recursive: true });
        await writeFile(`${screenshots}/${name}.png`, Buffer.concat(chunks));
      }
      switch (req.url) {
        case '/accept-request': await page.locator('#requests-tab').click(); await page.getByRole('button', { name: 'Accept request' }).click(); await page.locator('#friends-tab').click(); await page.locator('.friend-card .button.primary').waitFor(); break;
        case '/call': await page.locator('.friend-card .button.primary').click(); break;
        case '/answer': await page.locator('#incoming-dialog').waitFor({ state: 'visible' }); await page.locator('#accept-call').click(); break;
        case '/verify-bandwidth-low': await page.waitForFunction(()=>window.__peer.getSenders().find(s=>s.track?.kind==='video')?.getParameters().encodings[0].maxBitrate===64000); break;
        case '/verify-bandwidth-auto': await page.waitForFunction(()=>window.__peer.getSenders().find(s=>s.track?.kind==='video')?.getParameters().encodings[0].maxBitrate===1800000); break;
        case '/verify': { const transports = await page.evaluate(async () => [...(await window.__peer.getStats()).values()].filter((s) => s.type === 'transport')); if (!transports.some((s) => s.dtlsState === 'connected' && s.dtlsCipher && s.srtpCipher)) throw new Error('Browser encryption was not negotiated'); const code = (await page.locator('#call-security').textContent()).split(': ')[1]; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ code })); return; }
        case '/verify-audio':
        case '/audio-stats': {
          if (req.url === '/verify-audio') {
            const initial = await page.evaluate(async () => [...(await window.__peer.getStats()).values()].find(s => s.type === 'inbound-rtp' && s.kind === 'audio')?.totalAudioEnergy || 0);
            await page.waitForFunction(async initial => [...(await window.__peer.getStats()).values()].some(s => s.type === 'inbound-rtp' && s.kind === 'audio' && s.totalAudioEnergy > initial + 0.003), initial, { timeout: 20000 });
          }
          const audio = await page.evaluate(async () => [...(await window.__peer.getStats()).values()].find(s => s.type === 'inbound-rtp' && s.kind === 'audio'));
          res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ energy: audio?.totalAudioEnergy || 0, bytes: audio?.bytesReceived || 0 })); return;
        }
        case '/share': await page.locator('#share-screen').click(); await page.waitForFunction(() => document.getElementById('share-screen').getAttribute('aria-pressed') === 'true'); break;
        case '/stop-share': await page.locator('#share-screen').click(); await page.waitForFunction(() => document.getElementById('share-screen').getAttribute('aria-pressed') === 'false'); break;
        case '/hangup': await page.locator('#end-call').click(); break;
        case '/wait-ended': await page.locator('#call-view').waitFor({ state: 'hidden' }); break;
      }
      res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ ok: true }));
    } catch (error) { res.statusCode = 500; res.end(JSON.stringify({ error: error.message })); }
  });
  await new Promise(r => control.listen(0, '127.0.0.1', r));
  const flutter = process.env.PVP_FLUTTER || (existsSync('.build/flutter-security-sdk/bin/flutter') ? resolve('.build/flutter-security-sdk/bin/flutter') : 'flutter');
  const nativeEnvironment = { ...process.env };
  if (process.env.PVP_TEST_SIGNING_IDENTITY) {
    if (!/^[0-9a-fA-F]{40}$/.test(process.env.PVP_TEST_SIGNING_IDENTITY) || !/^[A-Z0-9]{10}$/.test(process.env.PVP_TEST_TEAM || '')) throw new Error('Use a certificate SHA-1 and a 10-character team ID for native test signing');
    const signing = join(temporary, 'signing.xcconfig');
    await writeFile(signing, `CODE_SIGN_IDENTITY = ${process.env.PVP_TEST_SIGNING_IDENTITY}\nDEVELOPMENT_TEAM = ${process.env.PVP_TEST_TEAM}\nCODE_SIGN_STYLE = Manual\n`);
    nativeEnvironment.XCODE_XCCONFIG_FILE = signing;
  }
  const child = spawn(flutter, ['test', '-d', 'macos', 'integration_test/native_call_test.dart',
    `--dart-define=PVP_SERVICE=${base}`, `--dart-define=PVP_PEER=${peerName}`, `--dart-define=PVP_NATIVE_USER=${nativeName}`, `--dart-define=PVP_TEST_AUDIO=${process.env.PVP_TEST_AUDIO === '1'}`, `--dart-define=PVP_CONTROL=http://localhost:${control.address().port}`],
    { cwd: process.env.PVP_NATIVE_PROJECT || 'desktop', stdio: 'inherit', env: nativeEnvironment });
  const exit = await new Promise(r => child.once('exit', r)); if (exit !== 0) process.exitCode = exit || 1;
} finally {
  await browser?.close(); if (control) await new Promise(r => control.close(r));
  if (server) { server.kill(); await new Promise(r => server.once('exit', r)); }
  await rm(temporary, { recursive: true, force: true });
}
