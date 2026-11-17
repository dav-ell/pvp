import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testBrowsers } from './browser-engines.mjs';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

function mediaFixture({ portrait }) {
  const capture = async ({ audio, video }, sharing = false) => {
    const stream = new MediaStream();
    if (audio !== false) {
      const context = new AudioContext();
      const tone = context.createOscillator(), destination = context.createMediaStreamDestination();
      tone.connect(destination); tone.start(); await context.resume();
      const track = destination.stream.getAudioTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { stop(); if (context.state !== 'closed') { tone.stop(); context.close(); } };
      stream.addTrack(track);
    }
    if (video !== false) {
      const canvas = document.createElement('canvas');
      canvas.width = sharing ? 1280 : portrait ? 360 : 640;
      canvas.height = sharing ? 720 : portrait ? 640 : 360;
      const graphics = canvas.getContext('2d');
      const paint = () => {
        graphics.fillStyle = sharing ? '#214d3e' : portrait ? '#685a82' : '#48667d';
        graphics.fillRect(0, 0, canvas.width, canvas.height);
        graphics.fillStyle = '#dceab6'; graphics.fillRect(canvas.width * .2, canvas.height * .25, canvas.width * .6, canvas.height * .5);
      };
      paint();
      const timer = setInterval(paint, 100);
      const track = canvas.captureStream(10).getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); };
      stream.addTrack(track);
    }
    return stream;
  };
  const native = navigator.mediaDevices;
  Object.defineProperty(navigator, 'mediaDevices', { value: new Proxy(native, {
    get(target, key) {
      if (key === 'getUserMedia') return capture;
      if (key === 'getDisplayMedia') return () => capture({ audio: false, video: true }, true);
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) });
  window.__callErrors = [];
  addEventListener('error', event => window.__callErrors.push(event.message));
}

async function wake(page, touch = false) {
  if (touch) await page.touchscreen.tap(5, 160);
  else await page.mouse.move(5, 160);
  await page.waitForFunction(() => !document.querySelector('#group-view').classList.contains('controls-idle'));
}

async function fitted(page) {
  await page.waitForFunction(() => {
    const rect = node => node.getBoundingClientRect();
    const tiles = [...document.querySelectorAll('#group-grid>.group-tile')].filter(node => !node.inert).map(rect);
    const grid = rect(document.querySelector('#group-grid'));
    const dock = rect(document.querySelector('.call-dock'));
    return tiles.every(tile => tile.width > 100 && tile.height > 90 &&
      tile.left >= grid.left - 1 && tile.right <= grid.right + 1 && tile.top >= grid.top - 1 && tile.bottom <= grid.bottom + 1) &&
      tiles.every((tile, index) => tiles.slice(index + 1).every(other =>
        tile.right <= other.left + 1 || tile.left >= other.right - 1 || tile.bottom <= other.top + 1 || tile.top >= other.bottom - 1)) &&
      grid.bottom <= dock.top + 1 && document.documentElement.scrollWidth <= innerWidth;
  }, null, { timeout: 10000 });
}

for (const [engine, type] of Object.entries(testBrowsers)) {
  test('four-person call fits phones and supports focus and idle controls (' + engine + ')', { timeout: 120000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'pvp-call-layout-'));
    let server, browser;
    try {
      let base = process.env.PVP_TEST_URL;
      if (!base) {
      await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
      const probe = createServer();
      await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
      const port = probe.address().port;
      await new Promise(resolve => probe.close(resolve));
      base = 'http://localhost:' + port;
      server = spawn('signaling/target/debug/pvp-signaling', [], {
        env: { ...process.env, PVP_BIND: '127.0.0.1:' + port, PVP_ORIGIN: base, PVP_DATABASE: join(directory, 'test.sqlite') },
        stdio: 'ignore',
      });
      for (let i = 0; i < 100; i++) {
        try { if ((await fetch(base + '/health')).ok) break; } catch {}
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      }
      browser = await type.launch({ headless: true });
      const owner = await browser.newContext({ viewport: { width: 1440, height: 900 } });
      const post = async (path, data) => {
        const response = await owner.request.post(base + '/api' + path, { headers: { Origin: base }, data });
        assert.equal(response.status(), 200, await response.text());
        return response.json();
      };
      const output = join('.build/call-layout', process.env.PVP_TEST_URL ? 'production' : 'local', engine);
      await mkdir(output, { recursive: true });
      const username = 'pvp_ui_' + Date.now() + '_' + engine[0];
      const displayName = process.env.PVP_TEST_URL ? 'PVP mobile call verification' : 'David';
      const account = await post('/register', { username, display_name: displayName, password: randomBytes(24).toString('hex') });
      const record = { id: account.id, username, displayName, meetings: [] };
      if (process.env.PVP_TEST_URL) await writeFile(join(output, 'account.json'), JSON.stringify(record));
      const meeting = await post('/meetings', { name: 'Jessica and David — evening catch-up', open_invite: true });
      record.meetings.push(meeting.meeting_id);
      if (process.env.PVP_TEST_URL) await writeFile(join(output, 'account.json'), JSON.stringify(record));
      const host = await owner.newPage();
      await host.addInitScript(mediaFixture, { portrait: false });
      await host.goto(meeting.url); await host.locator('#guest-submit').click();
      await host.locator('#group-camera').click();
      const pages = [host];
      for (const name of ['Jessica', 'A participant with a long display name', 'Morgan']) {
        const context = await browser.newContext({ viewport: { width: 390, height: 700 }, isMobile: true, hasTouch: true });
        const page = await context.newPage();
        await page.addInitScript(mediaFixture, { portrait: true });
        await page.goto(meeting.url); await page.locator('#guest-name').fill(name);
        await page.locator(name === 'Morgan' ? '#guest-listen' : '#guest-submit').click();
        if (name !== 'Morgan') await page.locator('#group-camera').click();
        pages.push(page);
      }
      // A centered, width-limited focused grid puts Restore under the heading on wide screens.
      for (const width of [1920, 2560]) {
        await host.setViewportSize({ width, height: 1000 });
        await host.locator('#group-view[data-count="4"]').waitFor();
        await wake(host);
        for (const selector of ['#group-self-maximize', '.group-tile:not(.self) .participant-expand']) {
          const restore = host.locator(selector).first();
          await restore.click();
          await host.locator('#group-view.participant-focused').waitFor();
          await restore.click({ timeout: 3000 });
          await host.locator('#group-view:not(.participant-focused)').waitFor();
        }
      }
      const mobile = pages[1];
      await mobile.locator('#group-view[data-count="4"]').waitFor();
      await mobile.waitForFunction(() => document.querySelectorAll('#group-grid .group-tile[data-video="on"]').length >= 3);
      await wake(host); await host.locator('#group-share').click();
      await mobile.waitForFunction(id => document.getElementById('group-video-' + id).videoWidth === 1280, account.id);
      for (const [width, height] of [[320, 600], [390, 700], [430, 760], [700, 700], [701, 700], [844, 390]]) {
        await mobile.setViewportSize({ width, height });
        await wake(mobile, true); await fitted(mobile);
        assert.equal(await mobile.locator('#group-health .quality-summary').count(), 0);
      }
      await mobile.setViewportSize({ width: 390, height: 700 });
      await wake(mobile, true); await fitted(mobile);
      await mobile.screenshot({ path: join(output, 'four-person-grid.png') });
      await mobile.evaluate(() => {
        window.__originalCallMedia = [...document.querySelectorAll('#group-grid video')].map(video => ({ video, stream: video.srcObject }));
      });
      await mobile.waitForFunction(() => document.querySelector('#group-view').classList.contains('controls-idle'));
      await mobile.waitForFunction(() => getComputedStyle(document.querySelector('.call-dock')).opacity === '0');
      assert.equal(await mobile.locator('.call-heading').evaluate(header => header.inert), true);
      await mobile.screenshot({ path: join(output, 'four-person-idle.png') });
      const expand = mobile.locator('#group-tile-' + account.id + ' .participant-expand');
      await mobile.touchscreen.tap(50, 180);
      await mobile.waitForFunction(() => !document.querySelector('#group-view').classList.contains('controls-idle'));
      assert.equal(await mobile.locator('#group-grid').evaluate(grid => grid.classList.contains('maximized')), false, 'first tap only reveals controls');
      await expand.tap();
      await mobile.locator('#group-view.participant-focused').waitFor();
      assert.equal(await expand.getAttribute('aria-expanded'), 'true');
      await mobile.waitForFunction(id => document.getElementById('group-tile-' + id).getBoundingClientRect().height >= 690, account.id);
      await mobile.evaluate(() => Promise.all(document.getAnimations().filter(animation => animation.effect.getTiming().iterations !== Infinity).map(animation => animation.finished.catch(() => {}))));
      await mobile.screenshot({ path: join(output, 'screen-share-focused.png') });
      const focusedBounds = await mobile.locator('#group-tile-' + account.id).boundingBox();
      assert.ok(focusedBounds.height >= 690, JSON.stringify(await mobile.evaluate(() => {
        return Object.fromEntries(['group-view', 'group-media', 'group-grid'].map(id => {
          const node = document.getElementById(id), rect = node.getBoundingClientRect(), style = getComputedStyle(node);
          return [id, { height: rect.height, y: rect.y, position: style.position, padding: style.padding, display: style.display }];
        }));
      })));
      await mobile.waitForFunction(() => document.querySelector('#group-view').classList.contains('controls-idle'));
      await mobile.touchscreen.tap(180, 300);
      await mobile.waitForFunction(() => !document.querySelector('#group-view').classList.contains('controls-idle'));
      assert.equal(await expand.getAttribute('aria-expanded'), 'true', 'wake tap preserves focused participant');
      await expand.tap();
      await fitted(mobile);
      await mobile.locator('#group-self-maximize').tap();
      await mobile.locator('#group-grid>.self.maximized').waitFor();
      await mobile.locator('#group-back').tap();
      await fitted(mobile);
      assert.equal(await mobile.evaluate(() => window.__originalCallMedia.every(({ video, stream }) => video.isConnected && video.srcObject === stream)), true);
      await mobile.locator('#group-more').tap();
      await mobile.waitForTimeout(3500);
      assert.equal(await mobile.locator('#group-view').evaluate(stage => stage.classList.contains('controls-idle')), false, 'dialog keeps chrome awake');
      await mobile.locator('#group-audio-open').tap();
      await mobile.locator('#group-quality-summary').filter({ hasText: /target.*Sending/ }).waitFor();
      await mobile.locator('#group-audio-close').tap();
      await host.mouse.move(-1, -1);
      await host.waitForFunction(() => document.querySelector('#group-view').classList.contains('controls-idle'));
      await host.mouse.move(280, 200);
      await host.waitForFunction(() => !document.querySelector('#group-view').classList.contains('controls-idle'));
      await post('/meetings/' + meeting.meeting_id + '/speaking', { enabled: true });
      await mobile.locator('#group-hand:not([hidden])').waitFor({ state: 'attached' });
      await mobile.setViewportSize({ width: 320, height: 600 });
      await wake(mobile, true); await fitted(mobile);
      const handDock = await mobile.locator('.call-dock').boundingBox();
      assert.ok(handDock.x >= 0 && handDock.x + handDock.width <= 321);
      await mobile.screenshot({ path: join(output, 'raise-hand-320.png') });
      for (const page of pages) assert.deepEqual(await page.evaluate(() => window.__callErrors), []);
      await writeFile(join(output, 'evidence.json'), JSON.stringify({ engine, participants: 4, gridFits: true, touchWake: true, desktopHoverWake: true, focusedParticipant: true, stableMedia: true }, null, 2));
    } finally {
      await browser?.close();
      if (server) { server.kill(); await new Promise(resolve => server.once('exit', resolve)); }
      await rm(directory, { recursive: true, force: true });
    }
  });
}
