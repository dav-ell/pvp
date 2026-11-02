import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { chromium } from 'playwright';

let service, directory, browser, page, context, base;
const errors = [];
const settle = () => page.evaluate(() => Promise.all(
  document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity && animation.playState !== 'paused').map(animation => animation.finished.catch(() => {})),
));

before(async () => {
  await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
  const probe = createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  base = `http://localhost:${port}`;
  directory = await mkdtemp(join(tmpdir(), 'pvp-motion-'));
  service = spawn('signaling/target/debug/pvp-signaling', [], {
    env: { ...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: join(directory, 'test.sqlite') },
    stdio: 'ignore',
  });
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { if ((await fetch(`${base}/health`)).ok) { ready = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, 'isolated service started');
  browser = await chromium.launch({ headless: true, ...(process.env.PVP_CHROME ? { executablePath: process.env.PVP_CHROME } : {}) });
  context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'no-preference' });
  page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(base);
  await page.locator('#show-account').click(); await page.locator('#register-tab').click();
  await page.locator('#display-name').fill('Alex Morgan');
  await page.locator('#username').fill('motion_alex');
  await page.locator('#password').fill('local-motion-test-passphrase');
  await page.locator('#auth-submit').click();
  await page.locator('#connection-dot.online').waitFor();
  await page.locator('[data-view=people]').click();
  const self = await (await context.request.get(`${base}/api/me`)).json();
  for (const [username, name] of [['motion_jamie', 'Jamie Chen'], ['motion_sam', 'Sam Rivera']]) {
    const friend = await browser.newContext();
    const registration = await friend.request.post(`${base}/api/register`, {
      headers: { Origin: base }, data: { username, display_name: name, password: 'local-motion-test-passphrase' },
    });
    assert.equal(registration.status(), 200);
    assert.equal((await context.request.post(`${base}/api/friends/request`, {
      headers: { Origin: base }, data: { username },
    })).status(), 200);
    assert.equal((await friend.request.post(`${base}/api/friends/${self.id}/accept`, {
      headers: { Origin: base },
    })).status(), 200);
    await friend.close();
  }
  await page.waitForFunction(() => document.querySelectorAll('.friend-card').length === 2);
  await settle();
}, { timeout: 60000 });

after(async () => {
  await browser?.close();
  if (service) {
    const exited = new Promise(resolve => service.once('exit', resolve));
    service.kill();
    await exited;
  }
  if (directory) await rm(directory, { recursive: true, force: true });
});

test('navigation switches immediately and stays correct through rapid reversals', async () => {
  const state = await page.evaluate(() => {
    document.querySelector('[data-view="recent"]').click();
    const immediate = !document.querySelector('#recent-view').hidden;
    const animating = document.querySelector('#recent-view').getAnimations().some(a => a.playState === 'running');
    document.querySelector('[data-view="people"]').click();
    document.querySelector('[data-view="settings"]').click();
    document.querySelector('[data-view="people"]').click();
    return { immediate, animating, friends: !document.querySelector('#people-view').hidden,
      otherHidden: document.querySelector('#recent-view').hidden && document.querySelector('#settings-view').hidden };
  });
  assert.deepEqual(state, { immediate: true, animating: true, friends: true, otherHidden: true });
  await settle();
  const marker = await page.locator('.pvp-nav-signal').boundingBox();
  const selected = await page.locator('.sidebar nav .nav-item.active').boundingBox();
  assert.ok(marker.y >= selected.y && marker.y + marker.height <= selected.y + selected.height);
  assert.ok(marker.x >= selected.x && marker.x + marker.width <= selected.x + selected.width);
});

test('unchanged friend updates stay still; filtering introduces only the new result', async () => {
  await page.locator('#friend-search').fill('Jamie');
  await settle();
  const result = await page.evaluate(() => {
    const list = document.querySelector('#friend-list');
    document.querySelector('#friend-search').dispatchEvent(new Event('input'));
    return { count: list.children.length,
      animations: [...list.children].flatMap(node => node.getAnimations()).length };
  });
  assert.deepEqual(result, { count: 1, animations: 0 });
  await page.locator('#friend-search').fill('');
  await settle();
});

test('animated dialogs preserve autofocus, Escape and return focus', async () => {
  await page.locator('#add-friend').click();
  await page.locator('#friend-username').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#friend-username').evaluate(node => document.activeElement === node), true);
  await page.keyboard.press('Escape');
  await page.locator('#friend-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#add-friend').evaluate(node => document.activeElement === node), true);
  await page.locator('#add-friend').click();
  await page.locator('#close-friend').click();
  await page.locator('#friend-dialog').waitFor({ state: 'hidden' });
});

test('changing reduced-motion preference stops JavaScript and CSS effects in flight', async () => {
  await page.evaluate(async () => {
    const { reveal } = await import('/motion.js');
    reveal(document.querySelector('#friend-list'), { delay: 200 });
  });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running'));
  const result = await page.evaluate(async () => {
    const { reveal } = await import('/motion.js');
    reveal(document.querySelector('#friend-list'));
    document.querySelector('[data-view="recent"]').click();
    return { visible: !document.querySelector('#recent-view').hidden,
      running: document.getAnimations().some(a => a.playState === 'running') };
  });
  assert.deepEqual(result, { visible: true, running: false });
  await page.locator('[data-view="people"]').click();
  await page.emulateMedia({ reducedMotion: 'no-preference' });
});

test('motion keeps mobile layouts in bounds and invitation surfaces centered', async () => {
  for (const width of [390, 860, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForFunction(()=>innerWidth<=700?document.getElementById('group-desktop-actions').parentElement.id==='group-more-content':document.getElementById('group-desktop-actions').parentElement.classList.contains('call-dock'));
    await settle();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const center = await page.evaluate(async () => {
      const invite = document.querySelector('#group-incoming');
      invite.hidden = false;
      await Promise.all(invite.getAnimations().map(a => a.finished.catch(() => {})));
      const rect = invite.getBoundingClientRect();
      invite.hidden = true;
      return { x: rect.x + rect.width / 2, viewport: innerWidth / 2 };
    });
    assert.ok(Math.abs(center.x - center.viewport) < 1,JSON.stringify({width,...center}));
  }
  if (process.env.PVP_MOTION_CAPTURE) {
    await mkdir(process.env.PVP_MOTION_CAPTURE, { recursive: true });
    await page.screenshot({ path: join(process.env.PVP_MOTION_CAPTURE, 'motion-friends.png') });
    await page.locator('#add-friend').click();
    await settle();
    await page.screenshot({ path: join(process.env.PVP_MOTION_CAPTURE, 'motion-dialog.png') });
    await page.keyboard.press('Escape');
  }
  assert.deepEqual(errors, []);
});
