import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { requireEncryptedSdp, safetyCode } from '../web/security.js';
let browser, server, temp, base, contexts, pages, users;
const suffix = Date.now().toString().slice(-10), password = 'security-test-passphrase-123';
const fp = (b) => Array(32).fill(b).join(':');
const sdp = `v=0\r\na=fingerprint:sha-256 ${fp('AA')}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n`;
async function request(i, path, data, method = 'POST', origin = base) {
  return contexts[i].request.fetch(`${base}/api${path}`, { method, headers: { Origin: origin }, ...(data ? { data } : {}) });
}
async function connect(i) {
  await pages[i].goto(`${base}/health`);
  await pages[i].evaluate(() => {
    window.events = []; window.socket = new WebSocket(`${location.origin.replace(/^http/, 'ws')}/api/ws`);
    window.socket.onmessage = (e) => { const m = JSON.parse(e.data); if (m.type === 'ping') window.socket.send(JSON.stringify({ type: 'pong' })); else window.events.push(m); };
  });
  await pages[i].waitForFunction(() => window.socket.readyState === WebSocket.OPEN);
}
async function send(i, message) { await pages[i].evaluate((m) => window.socket.send(JSON.stringify(m)), message); }
async function event(i, type) {
  await pages[i].waitForFunction((t) => window.events.some((m) => m.type === t), type);
  return pages[i].evaluate((t) => window.events.splice(window.events.findIndex((m) => m.type === t), 1)[0], type);
}
async function call() { await send(0, { type: 'call', peer_id: users[1].id }); const m = await event(0, 'calling'); await event(1, 'incoming'); await send(1, { type: 'accept', call_id: m.call_id }); await event(0, 'call-accepted'); await event(1, 'call-accepted'); return m.call_id; }
before(async () => {
  await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
  const probe = createServer(); await new Promise((r) => probe.listen(0, '127.0.0.1', r)); const port = probe.address().port; await new Promise((r) => probe.close(r));
  base = `http://localhost:${port}`; temp = await mkdtemp(join(tmpdir(), 'pvp-security-'));
  server = spawn('signaling/target/debug/pvp-signaling', [], { env: { ...process.env, PVP_BIND: `127.0.0.1:${port}`, PVP_ORIGIN: base, PVP_DATABASE: join(temp, 'pvp.sqlite') }, stdio: 'ignore' });
  for (let n = 0; n < 100; n++) { try { if ((await fetch(`${base}/health`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 100)); }
  browser = await chromium.launch({ headless: true }); contexts = []; pages = []; users = [];
  for (let i = 0; i < 3; i++) {
    contexts.push(await browser.newContext()); pages.push(await contexts[i].newPage());
    const response = await request(i, '/register', { username: `secure${i}_${suffix}`, password, display_name: i ? `Security ${i}` : '<img src=x onerror=alert(1)>' });
    assert.equal(response.status(), 200); users.push(await response.json()); await connect(i);
  }
});
after(async () => { await browser?.close(); if (server) { server.kill(); await new Promise((r) => server.once('exit', r)); } if (temp) await rm(temp, { recursive: true, force: true }); });
test('security headers also protect failures; CSRF and request size are enforced', async () => {
  const response = await request(0, '/friends/request', { username: 'unused' }, 'POST', 'https://attacker.example');
  assert.equal(response.status(), 403); assert.equal(response.headers()['x-content-type-options'], 'nosniff'); assert.ok(response.headers()['content-security-policy'].includes("frame-ancestors 'none'"));
  assert.equal((await request(0, '/friends/request', { username: 'x'.repeat(17000) })).status(), 413);
  const anonymous = await browser.newContext(); assert.equal((await anonymous.request.get(`${base}/api/friends`)).status(), 401); await anonymous.close();
});
test('unaccepted friends cannot call; a third account cannot control another call', async () => {
  await send(0, { type: 'call', peer_id: users[1].id }); assert.match((await event(0, 'error')).message, /accepted/);
  assert.equal((await request(0, '/friends/request', { username: users[1].username })).status(), 200);
  await send(0, { type: 'call', peer_id: users[1].id }); await event(0, 'error');
  assert.equal((await request(0, `/friends/${users[1].id}/accept`)).status(), 400);
  assert.equal((await request(1, `/friends/${users[0].id}/accept`)).status(), 200);
  const id = await call();
  for (const type of ['accept', 'hangup', 'decline']) { await send(2, { type, call_id: id }); await event(2, 'error'); }
  await send(2, { type: 'signal', call_id: id, payload: { type: 'offer', sdp } }); await event(2, 'error');
  await send(0, { type: 'hangup', call_id: id }); await event(0, 'call-ended'); await event(1, 'call-ended');
});
test('rejects plaintext, absent fingerprints, relay candidates, wrong roles, replays and floods', async () => {
  const id = await call();
  for (const bad of [sdp.replace('UDP/TLS/RTP/SAVPF', 'RTP/AVP'), 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n', `${sdp}a=crypto:1 inline:secret\r\n`]) {
    await send(0, { type: 'signal', call_id: id, payload: { type: 'offer', sdp: bad } }); await event(0, 'error');
  }
  await send(1, { type: 'signal', call_id: id, payload: { type: 'offer', sdp } }); await event(1, 'error');
  await send(0, { type: 'signal', call_id: id, payload: { type: 'offer', sdp } }); assert.equal((await event(1, 'signal')).payload.sdp, sdp);
  await send(0, { type: 'signal', call_id: id, payload: { type: 'offer', sdp } }); await event(0, 'error');
  const candidate = { candidate: 'candidate:1 1 udp 1 127.0.0.1 12345 typ host', sdpMid: '0', sdpMLineIndex: 0 };
  for (const bad of [{ ...candidate, candidate: candidate.candidate.replace('typ host', 'typ\tRELAY') }, { ...candidate, sdpMLineIndex: 999999 }, { ...candidate, candidate: 'x'.repeat(3000) }, { ...candidate, extra: 'x'.repeat(5000) }]) {
    await send(0, { type: 'signal', call_id: id, payload: { type: 'candidate', candidate: bad } }); await event(0, 'error');
  }
  await pages[0].evaluate(({ id, candidate }) => { for (let n = 0; n < 129; n++) window.socket.send(JSON.stringify({ type: 'signal', call_id: id, payload: { type: 'candidate', candidate } })); }, { id, candidate });
  assert.match((await event(0, 'error')).message, /limit/);
  await send(0, { type: 'hangup', call_id: id }); await event(0, 'call-ended'); await event(1, 'call-ended');
});
test('removing a friendship terminates an active call and prevents further signaling', async () => {
  const id = await call(); assert.equal((await request(1, `/friends/${users[0].id}`, undefined, 'DELETE')).status(), 200);
  assert.equal((await event(0, 'call-ended')).reason, 'removed'); await event(1, 'call-ended');
  await send(0, { type: 'signal', call_id: id, payload: { type: 'offer', sdp } }); await event(0, 'error');
  await send(0, { type: 'call', peer_id: users[1].id }); await event(0, 'error');
});
test('display names are rendered as text and foreign origins cannot open sockets', async () => {
  const foreign = await contexts[0].request.get(`${base}/api/ws`, { headers: { Origin: 'https://attacker.example' } }); assert.equal(foreign.status(), 403);
  await pages[0].goto(base); await pages[0].locator('#connection-dot.online').waitFor();
  assert.equal(await pages[0].locator('#my-name').textContent(), '<img src=x onerror=alert(1)>');
  assert.equal(await pages[0].locator('#my-name img').count(), 0);
});
test('replacement closes the superseded socket and leaves the new connection usable', async () => {
  const replacement = await contexts[1].newPage();
  try {
    await replacement.goto(`${base}/health`);
    await replacement.evaluate(() => {
      window.events = [];
      window.socket = new WebSocket(`${location.origin.replace(/^http/, 'ws')}/api/ws`);
      window.socket.onmessage = e => {
        const message = JSON.parse(e.data);
        if (message.type === 'ping') window.socket.send(JSON.stringify({type:'pong'}));
        else window.events.push(message);
      };
    });
    await replacement.waitForFunction(() => window.socket.readyState === WebSocket.OPEN);
    await event(1, 'replaced');
    await pages[1].waitForFunction(() => window.socket.readyState === WebSocket.CLOSED);
    await replacement.waitForFunction(() => window.events.some(m => m.type === 'server-capabilities'));
    assert.equal((await request(1, '/me', undefined, 'GET')).status(), 200);
    assert.equal(await replacement.evaluate(() => window.socket.readyState), 1);
  } finally {
    await replacement.close();
    await connect(1);
  }
});
test('passwords are salted Argon2id; stolen database session hashes cannot authenticate', async () => {
  const script = `import sqlite3,json,sys
with sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True) as db:
 print(json.dumps({'passwords':[r[0] for r in db.execute('SELECT password FROM users')], 'tokens':[r[0] for r in db.execute('SELECT token FROM sessions')]}))`;
  const { stdout } = await promisify(execFile)('python3', ['-c', script, join(temp, 'pvp.sqlite')]);
  const records = JSON.parse(stdout);
  assert.equal(records.passwords.length, 3);
  for (const hash of records.passwords) {
    assert.match(hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    assert.ok(!hash.includes(password));
  }
  assert.equal(new Set(records.passwords).size, 3);
  const token = (await contexts[0].cookies()).find(c => c.name === 'pvp_session').value;
  const hash = createHash('sha256').update(token).digest('hex');
  assert.ok(records.tokens.includes(hash));
  assert.ok(!records.tokens.includes(token));
  const anonymous = await browser.newContext();
  try {
    const stolen = await anonymous.request.get(`${base}/api/me`, {headers:{Cookie:`pvp_session=${hash}`}});
    assert.equal(stolen.status(), 401);
    assert.equal((await anonymous.request.post(`${base}/api/login`, {headers:{Origin:base},data:{username:"' OR 1=1 --",password}})).status(), 401);
  } finally { await anonymous.close(); }
  if (process.platform !== 'win32') {
    for (const name of ['pvp.sqlite', 'pvp.sqlite-wal', 'pvp.sqlite-shm']) {
      assert.equal((await stat(join(temp, name))).mode & 0o777, 0o600);
    }
  }
});
test('portable backups preserve accounts but cannot revive sessions on restore', async () => {
  const source = join(temp, 'pvp.sqlite');
  const directory = join(temp, 'portable');
  const script = (await readFile('scripts/backup-meetings.sh','utf8')).match(/<<'PY'\n([\s\S]*?)\nPY/)[1]
    .replace("sqlite3.connect('/var/lib/pvp/pvp.sqlite')", 'sqlite3.connect(sys.argv[2])');
  await promisify(execFile)('python3', ['-c', 'import os,sys;os.mkdir(sys.argv[1],0o700)', directory]);
  await promisify(execFile)('python3', ['-c', script, directory, source]);
  const { stdout } = await promisify(execFile)('python3', ['-c', `import sqlite3,json,sys
with sqlite3.connect(sys.argv[1]) as live,sqlite3.connect(sys.argv[2]) as backup:
 print(json.dumps([live.execute('SELECT COUNT(*) FROM sessions').fetchone()[0],backup.execute('SELECT COUNT(*) FROM sessions').fetchone()[0],live.execute('SELECT COUNT(*) FROM users').fetchone()[0],backup.execute('SELECT COUNT(*) FROM users').fetchone()[0]]))`, source, join(directory,'pvp.sqlite')]);
  const [liveSessions, backupSessions, liveUsers, backupUsers] = JSON.parse(stdout);
  assert.ok(liveSessions > 0); assert.equal(backupSessions, 0); assert.equal(backupUsers, liveUsers);
});
test('changing source addresses cannot bypass the account password-guess budget', async () => {
  for (let n = 1; n <= 31; n++) {
    const response = await contexts[2].request.post(`${base}/api/login`, {
      headers:{Origin:base,'X-Forwarded-For':`198.51.100.${n}`},
      data:{username:n % 2 ? users[2].username.toUpperCase() : ` ${users[2].username} `,password:'wrong-password-test-only'},
    });
    assert.equal(response.status(), n <= 30 ? 401 : 429);
  }
  // A throttled account must not prevent a different account signing in.
  assert.equal((await request(1, '/login', {username:users[1].username,password})).status(), 200);
});
test('logging out an older session leaves the current device connected; current logout revokes immediately', async () => {
  const old = await browser.newContext(); await old.addCookies(await contexts[0].cookies());
  assert.equal((await request(0, '/login', { username: users[0].username, password })).status(), 200);
  await connect(0);
  assert.equal((await old.request.post(`${base}/api/logout`, { headers: { Origin: base } })).status(), 200);
  assert.equal(await pages[0].evaluate(() => window.socket.readyState), 1);
  assert.equal((await request(0, '/me', undefined, 'GET')).status(), 200);
  assert.equal((await request(0, '/logout')).status(), 200);
  await pages[0].waitForFunction(() => window.socket.readyState === WebSocket.CLOSED);
  assert.equal((await request(0, '/me', undefined, 'GET')).status(), 401); await old.close();
});
test('verification codes are symmetric and change with the certificate', async () => {
  requireEncryptedSdp(sdp); assert.throws(() => requireEncryptedSdp(sdp.replace('UDP/TLS/RTP/SAVPF', 'RTP/AVP')));
  const b = sdp.replaceAll('AA', 'BB'), c = sdp.replaceAll('AA', 'CC'); assert.equal(await safetyCode(sdp, b), await safetyCode(b, sdp)); assert.notEqual(await safetyCode(sdp, b), await safetyCode(sdp, c));
});

test('an initial session failure preserves credentials typed before submission', async () => {
  const context = await browser.newContext(), page = await context.newPage();
  let release, arrived;
  const delayed = new Promise(r => { release = r; });
  const intercepted = new Promise(r => { arrived = r; });
  await page.route('**/api/me', async route => { const response = await route.fetch(); arrived(); await delayed; await route.fulfill({ response }); });
  try {
    await page.goto(base); await intercepted;
    await page.locator('#show-account').click(); await page.locator('#register-tab').click();
    await page.locator('#display-name').fill('Still typing');
    await page.locator('#username').fill('typing_regression');
    await page.locator('#password').fill(password);
    const late = page.waitForResponse(r => r.url().endsWith('/api/me')); release(); await late;
    await page.waitForTimeout(100);
    assert.equal(await page.locator('#password').inputValue(), password);
    assert.equal(await page.locator('#register-tab').getAttribute('class'), 'selected');
    assert.equal(await page.locator('#auth-form').evaluate(f => f.checkValidity()), true);
  } finally { release(); await context.close(); }
});

test('a delayed initial session response cannot undo a successful sign-in', async () => {
  const context = await browser.newContext(), page = await context.newPage();
  let release, arrived;
  const delayed = new Promise((r) => { release = r; });
  const intercepted = new Promise((r) => { arrived = r; });
  await page.route('**/api/me', async (route) => { const response = await route.fetch(); arrived(); await delayed; await route.fulfill({ response }); });
  try {
    await page.goto(base); await intercepted;
    await page.locator('#show-account').click(); await page.locator('#register-tab').click(); await page.locator('#display-name').fill('Session race test');
    await page.locator('#username').fill(`race_${suffix}`); await page.locator('#password').fill(password);
    await page.locator('#auth-submit').click(); await page.locator('#connection-dot.online').waitFor();
    const late = page.waitForResponse((r) => r.url().endsWith('/api/me')); release(); await late;
    await page.waitForTimeout(100);
    assert.equal(await page.locator('#app-view').isVisible(), true);
    assert.equal(await page.locator('#auth-view').isVisible(), false);
  } finally { release(); await context.close(); }
});
