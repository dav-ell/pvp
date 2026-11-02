import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

test('friend autocomplete respects account opt-out and exact username requests', async () => {
  let base = process.env.PVP_TEST_URL, server, temporary, browser;
  const accounts = [];
  try {
    if (!base) {
      await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
      const probe = createServer();
      await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
      const port = probe.address().port;
      await new Promise(resolve => probe.close(resolve));
      base = 'http://localhost:' + port;
      temporary = await mkdtemp(join(tmpdir(), 'pvp-discovery-'));
      server = spawn('signaling/target/debug/pvp-signaling', [], {
        env: {...process.env, PVP_BIND: '127.0.0.1:' + port, PVP_ORIGIN: base, PVP_DATABASE: join(temporary, 'db.sqlite')},
        stdio: 'ignore',
      });
      for (let i = 0; i < 100; i++) {
        try { if ((await fetch(base + '/health')).ok) break; } catch {}
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    browser = await chromium.launch({headless: true});
    const contexts = await Promise.all([browser.newContext(), browser.newContext()]);
    const prefix = 'fd' + Date.now();
    for (let i = 0; i < contexts.length; i++) {
      const username = prefix + '_' + i;
      const response = await contexts[i].request.post(base + '/api/register', {
        headers: {Origin: base}, data: {username, display_name: 'Discovery test', password: 'test-discovery-passphrase-123'},
      });
      assert.equal(response.status(), 200);
      accounts.push(await response.json());
      if (process.env.PVP_DISCOVERY_ACCOUNT_RECORD) await writeFile(process.env.PVP_DISCOVERY_ACCOUNT_RECORD, JSON.stringify(accounts));
    }
    const page = await contexts[0].newPage();
    await page.goto(base);
    await page.locator('[data-view=people]').click();
    await page.locator('#add-friend').click();
    await page.locator('#friend-username').fill(prefix);
    await page.waitForFunction(() => document.querySelectorAll('#friend-suggestions option').length === 1);
    assert.equal(await page.locator('#friend-suggestions option').getAttribute('value'), accounts[1].username);
    const other = await contexts[1].newPage();
    await other.goto(base);
    await other.locator('[data-view="settings"]').first().click();
    await other.waitForFunction(() => !document.querySelector('#discovery-enabled').disabled && document.querySelector('#discovery-enabled').checked);
    await other.locator('#discovery-enabled').uncheck();
    await other.waitForFunction(() => document.querySelector('#discovery-status').textContent === 'Saved to your account');
    await other.reload();
    await other.locator('[data-view="settings"]').first().click();
    await other.waitForFunction(() => !document.querySelector('#discovery-enabled').checked);
    await page.locator('#friend-username').fill(accounts[1].username);
    await page.waitForFunction(() => document.querySelector('#friend-discovery-status').textContent.startsWith('No suggestions.'));
    assert.equal(await page.locator('#friend-suggestions option').count(), 0);
    await page.locator('#friend-form [type="submit"]').click();
    await page.waitForFunction(() => !document.querySelector('#friend-dialog').open);
    const response = await contexts[1].request.get(base + '/api/friends');
    assert.equal((await response.json())[0].status, 'received');
  } finally {
    await browser?.close();
    if (server) { server.kill(); await new Promise(resolve => server.once('exit', resolve)); }
    if (temporary) await rm(temporary, {recursive: true, force: true});
  }
});
