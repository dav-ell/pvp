import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { fingerprints, requireEncryptedSdp, requireCandidate, safetyCode, inspectEncryptionReport, connectionProof } from '../web/security.js';
import { PvpMesh } from '../packages/pvp-call/src/mesh.js';

const fp = (byte) => Array(32).fill(byte).join(':');
const sdp = (byte) => `v=0\r\na=fingerprint:sha-256 ${fp(byte)}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n`;
const options = { localSdp: sdp('AA'), remoteSdp: sdp('BB'), connectionState: 'connected' };
const fixture = () => new Map([
  ['l', { id: 'l', type: 'local-candidate', candidateType: 'host' }],
  ['r', { id: 'r', type: 'remote-candidate', candidateType: 'srflx' }],
  ['p', { id: 'p', type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r', state: 'succeeded' }],
  ['lc', { id: 'lc', type: 'certificate', fingerprintAlgorithm: 'sha-256', fingerprint: fp('AA') }],
  ['rc', { id: 'rc', type: 'certificate', fingerprintAlgorithm: 'sha-256', fingerprint: fp('BB') }],
  ['t', { id: 't', type: 'transport', selectedCandidatePairId: 'p', localCertificateId: 'lc', remoteCertificateId: 'rc', dtlsState: 'connected', dtlsCipher: 'observed-DTLS-cipher', srtpCipher: 'SRTP_AEAD_AES_128_GCM' }],
]);
const peer = (report = fixture()) => ({
  connectionState: 'connected', localDescription: { sdp: options.localSdp }, remoteDescription: { sdp: options.remoteSdp }, getStats: async () => report,
});

test('verification code stays compatible, symmetric and bound to both complete SDPs', async () => {
  const canonical = `PVP-call-v1\n${['aa'.repeat(32), 'bb'.repeat(32)].join('\n')}`;
  const expected = createHash('sha256').update(canonical).digest('hex').slice(0, 24).match(/.{4}/g).join(' ');
  assert.equal(await safetyCode(sdp('AA'), sdp('BB')), expected);
  assert.equal(await safetyCode(sdp('BB'), sdp('AA')), expected);
  assert.notEqual(await safetyCode(sdp('AA'), sdp('CC')), expected);
  const multiple = `${sdp('AA')}m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 ${fp('BB')}\r\n`;
  await assert.rejects(safetyCode(multiple, 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n'), /certificate/i);
  await assert.rejects(safetyCode(sdp('AA'), sdp('AA')), /certificates/i);
  assert.deepEqual(fingerprints('a=fingerprint:sha-256 aa:bb\r\n'), []);
  assert.deepEqual(fingerprints(null), []);
});

test('extra unused fingerprints cannot pad two substituted certificate sets into the same code', async () => {
  const withExtra = (first, extra) => `${sdp(first)}m=video 0 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 ${fp(extra)}\r\n`;
  // The former union-only input produced {A,B,C} on both sides even though the
  // signaled remote certificate sets were different. Neither is a pair code.
  await assert.rejects(safetyCode(sdp('AA'), withExtra('BB', 'CC')), /one certificate per endpoint/);
  await assert.rejects(safetyCode(sdp('BB'), withExtra('AA', 'CC')), /one certificate per endpoint/);
  const observed = await inspectEncryptionReport(fixture(), { ...options, remoteSdp: withExtra('BB', 'CC') });
  assert.equal(observed.encryptionState, 'confirmed', 'encryption and availability of a pair code remain separate');
  assert.equal(observed.code, null);
  assert.equal(observed.failure, null);
});

test('negotiation validation rejects version tricks, controls and non-encrypted active media', () => {
  requireEncryptedSdp(sdp('AA'));
  for (const bad of [
    sdp('AA').replace('v=0', 'v=0unsafe'),
    sdp('AA').replace('m=audio 9', 'm=audio 00'),
    sdp('AA').replace('v=0\r\n', 'v=0\r'),
    sdp('AA').replace('v=0', 'v=0\x01'),
    sdp('AA').replace('UDP/TLS/RTP/SAVPF', 'RTP/AVP'),
    `${sdp('AA')}a=crypto:1 inline:secret\r\n`,
  ]) assert.throws(() => requireEncryptedSdp(bad));
});

test('direct candidates require valid bounded priorities, ports and safe media IDs', () => {
  const candidate = { candidate: 'candidate:1 1 udp 1 192.0.2.1 12345 typ host', sdpMid: '0' };
  requireCandidate(candidate);
  for (const value of [
    candidate.candidate.replace('candidate:1', 'candidate:'),
    candidate.candidate.replace('12345', '65536'),
    candidate.candidate.replace('12345', '0'),
    candidate.candidate.replace('udp 1', 'udp 4294967296'),
    candidate.candidate.replace('udp 1', 'udp +1'),
    candidate.candidate.replace('typ host', 'typ\tRELAY'),
  ]) assert.throws(() => requireCandidate({ ...candidate, candidate: value }));
  assert.throws(() => requireCandidate({ ...candidate, sdpMid: '0\nunsafe' }));
});

test('proof uses actual ciphers, selected direct path and matching certificate observations', async () => {
  const proof = await inspectEncryptionReport(fixture(), options);
  assert.equal(proof.encryptionState, 'confirmed');
  assert.equal(proof.routeState, 'direct');
  assert.equal(proof.certificateState, 'matched');
  assert.equal(proof.failure, null);
  assert.equal(proof.transports[0].dtlsCipher, 'observed-DTLS-cipher');
  assert.equal(proof.transports[0].srtpCipher, 'SRTP_AEAD_AES_128_GCM');
  assert.equal(proof.code, await safetyCode(sdp('AA'), sdp('BB')));
  assert.ok(!JSON.stringify(proof).includes('identityVerified'), 'transport evidence never asserts identity');
  assert.ok(!JSON.stringify(proof).includes('192.0.2'), 'no addresses enter this proof');
});

test('missing cipher/certificate stats and disconnected peers never confirm encryption', async () => {
  for (const field of ['dtlsCipher', 'srtpCipher', 'localCertificateId', 'remoteCertificateId']) {
    const stats = fixture(); delete stats.get('t')[field];
    const proof = await inspectEncryptionReport(stats, options);
    assert.equal(proof.encryptionState, 'unavailable', field);
    assert.equal(proof.failure, null, 'unsupported observations are not a failure');
  }
  const stats = fixture(); stats.get('rc').fingerprintAlgorithm = 'sha-384';
  assert.equal((await inspectEncryptionReport(stats, options)).encryptionState, 'unavailable');
  assert.equal((await inspectEncryptionReport(new Map(), options)).encryptionState, 'unavailable');
  const interrupted = await inspectEncryptionReport(fixture(), { ...options, connectionState: 'disconnected' });
  assert.equal(interrupted.encryptionState, 'waiting'); assert.equal(interrupted.routeState, 'waiting');
});

test('only observed encrypted SRTP profiles confirm media encryption; unknown profiles stay nonfatal', async () => {
  for (const profile of ['AEAD_AES_128_GCM', 'SRTP_AEAD_AES_256_GCM', 'AES_CM_128_HMAC_SHA1_80', 'SRTP_AES_CM_128_HMAC_SHA1_32', 'SRTP_AES128_CM_HMAC_SHA1_80', 'SRTP_AES128_CM_HMAC_SHA1_32']) {
    const stats = fixture(); stats.get('t').srtpCipher = profile;
    const proof = await inspectEncryptionReport(stats, options);
    assert.equal(proof.encryptionState, 'confirmed', profile);
    assert.equal(proof.transports[0].srtpCipher, profile, 'the UI retains the observed name');
  }
  const unknown = fixture(); unknown.get('t').srtpCipher = 'FUTURE_UNRECOGNIZED_PROFILE';
  const proof = await inspectEncryptionReport(unknown, options);
  assert.equal(proof.encryptionState, 'unavailable'); assert.equal(proof.failure, null);
  for (const profile of ['SRTP_NULL_HMAC_SHA1_80', 'SRTP_NULL_HMAC_SHA1_32', 'SRTP_NULL_SHA1_80', 'SRTP_NULL_SHA1_32', 'NULL', 'PLAINTEXT']) {
    const stats = fixture(); stats.get('t').srtpCipher = profile;
    const rejected = await inspectEncryptionReport(stats, options);
    assert.equal(rejected.encryptionState, 'failed', profile); assert.match(rejected.failure, /unencrypted SRTP/i);
  }
});

test('proof does not guess a route from nomination or ignore a second transport', async () => {
  const stats = fixture();
  delete stats.get('t').selectedCandidatePairId; stats.get('p').nominated = true;
  assert.equal((await inspectEncryptionReport(stats, options)).routeState, 'unavailable');
  stats.get('t').selectedCandidatePairId = 'p';
  stats.set('stale', { id: 'stale', type: 'candidate-pair', state: 'succeeded', nominated: true, localCandidateId: 'relay', remoteCandidateId: 'r' });
  stats.set('relay', { id: 'relay', type: 'local-candidate', candidateType: 'relay' });
  assert.equal((await inspectEncryptionReport(stats, options)).routeState, 'direct', 'an unselected historical relay is not the active route');
  stats.set('t2', { ...stats.get('t'), id: 't2', selectedCandidatePairId: 'stale' });
  const proof = await inspectEncryptionReport(stats, options);
  assert.equal(proof.routeState, 'rejected'); assert.equal(proof.encryptionState, 'failed');
});

test('unselected historical transports never fail the call; every explicit selection is enforced', async () => {
  const stats = fixture();
  stats.set('old-cert', { id: 'old-cert', type: 'certificate', fingerprintAlgorithm: 'sha-256', fingerprint: fp('CC') });
  stats.set('historical', {
    id: 'historical', type: 'transport', dtlsState: 'failed', srtpCipher: 'SRTP_NULL_HMAC_SHA1_80',
    localCertificateId: 'lc', remoteCertificateId: 'old-cert',
  });
  const unknown = await inspectEncryptionReport(stats, options);
  assert.equal(unknown.failure, null, 'unused failed DTLS, old certificate and NULL profile are not the selected connection');
  assert.equal(unknown.encryptionState, 'unavailable', 'ambiguous positive evidence is not promoted to confirmed');
  stats.get('historical').selectedCandidatePairId = 'p';
  let rejected = await inspectEncryptionReport(stats, options);
  assert.equal(rejected.certificateState, 'mismatch'); assert.equal(rejected.encryptionState, 'failed');
  stats.get('historical').remoteCertificateId = 'rc';
  rejected = await inspectEncryptionReport(stats, options);
  assert.equal(rejected.encryptionState, 'failed', 'a second selected failed DTLS transport is enforced');
  stats.get('historical').dtlsState = 'connected';
  rejected = await inspectEncryptionReport(stats, options);
  assert.match(rejected.failure, /unencrypted SRTP/i, 'a second selected NULL profile is enforced');
});

test('certificate substitution and lost DTLS fail the proof instead of showing a shield', async () => {
  const stats = fixture(); stats.get('rc').fingerprint = fp('CC');
  let proof = await inspectEncryptionReport(stats, options);
  assert.equal(proof.encryptionState, 'failed'); assert.equal(proof.certificateState, 'mismatch'); assert.match(proof.failure, /certificate/i);
  for (const state of ['failed', 'closed']) {
    const lost = fixture(); lost.get('t').dtlsState = state;
    proof = await inspectEncryptionReport(lost, options);
    assert.equal(proof.encryptionState, 'failed'); assert.match(proof.failure, /lost/i);
  }
});

test('unsupported getStats and teardown during observation never produce stale confirmation', async () => {
  const unsupported = peer(); unsupported.getStats = async () => { throw Error('not supported'); };
  assert.equal((await connectionProof(unsupported)).encryptionState, 'unavailable');
  let release; const pc = peer(); pc.getStats = () => new Promise((resolve) => { release = resolve; });
  const result = connectionProof(pc); pc.connectionState = 'closed'; release(fixture());
  assert.equal((await result).encryptionState, 'unavailable');
  assert.equal((await connectionProof(null)).encryptionState, 'unavailable');
});

test('shared mesh monitoring closes definite security failures while unsupported stats stay nonfatal', async () => {
  for (const [change, expected] of [
    [(stats) => { stats.get('rc').fingerprint = fp('CC'); }, /certificate/i],
    [(stats) => { stats.get('r').candidateType = 'relay'; }, /relay/i],
    [(stats) => { stats.get('t').dtlsState = 'failed'; }, /lost/i],
    [(stats) => { stats.get('t').srtpCipher = 'SRTP_NULL_SHA1_80'; }, /unencrypted SRTP/i],
    [(stats) => { stats.get('t').srtpCipher = 'FUTURE_UNRECOGNIZED_PROFILE'; }, null],
    [(stats) => { stats.delete('rc'); }, null],
  ]) {
    const stats = fixture(); change(stats);
    const link = { peer: { id: 'peer' }, pc: peer(stats) };
    const errors = [], closed = [];
    const mesh = { links: new Map([['peer', link]]), valid: (l) => mesh.links.get('peer') === l, notify() {}, closeLink(id) { closed.push(id); mesh.links.delete(id); }, onError(error) { errors.push(error.message); } };
    await PvpMesh.prototype.sample.call(mesh);
    if (expected) { assert.deepEqual(closed, ['peer']); assert.match(errors[0], expected); }
    else { assert.deepEqual(closed, []); assert.deepEqual(errors, []); }
  }
});

test('live WebRTC provides matching proof; manual comparisons expire when the connection changes', { timeout: 45000 }, async () => {
  const files = new Map(await Promise.all([
    ['/trust.js', 'web/trust.js'], ['/security.js', 'web/security.js'], ['/packages/pvp-call/src/security.js', 'packages/pvp-call/src/security.js'],
  ].map(async ([route, path]) => [route, await readFile(path, 'utf8')])));
  const server = createServer((request, response) => {
    const source = files.get(request.url);
    response.writeHead(200, { 'Content-Type': source ? 'text/javascript' : 'text/html' });
    response.end(source || '<!doctype html><div id="proof"></div>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required'] });
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(`http://localhost:${server.address().port}`);
    await page.evaluate(async () => {
      const { mountTrustPanel } = await import('/trust.js');
      const { connectionProof } = await import('/security.js');
      window.a = new RTCPeerConnection({ iceServers: [], bundlePolicy: 'max-bundle' });
      window.b = new RTCPeerConnection({ iceServers: [], bundlePolicy: 'max-bundle' });
      window.audio = new AudioContext();
      window.oscillator = audio.createOscillator();
      const output = audio.createMediaStreamDestination(); oscillator.connect(output); oscillator.start(); await audio.resume();
      for (const pc of [a, b]) pc.addTrack(output.stream.getAudioTracks()[0], output.stream);
      const gathered = (pc) => pc.iceGatheringState === 'complete' ? Promise.resolve() : new Promise((resolve) => pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') resolve(); }));
      await a.setLocalDescription(await a.createOffer()); await gathered(a);
      await b.setRemoteDescription(a.localDescription); await b.setLocalDescription(await b.createAnswer()); await gathered(b);
      await a.setRemoteDescription(b.localDescription);
      window.proof = connectionProof;
      window.livePeers = [{ id: 'peer', name: '<img src=x onerror=alert(1)>', pc: a }];
      window.failures = [];
      window.panel = mountTrustPanel(document.querySelector('#proof'), { getPeers: () => livePeers, onSecurityFailure: (peer, error) => failures.push(error.message) });
    });
    await page.waitForFunction(async () => (await proof(a)).encryptionState === 'confirmed', null, { timeout: 20000 });
    const proofs = await page.evaluate(async () => [await proof(a), await proof(b)]);
    const codeEvidence = await page.evaluate(async () => {
      const { safetyCode, fingerprints } = await import('/security.js');
      try { return { code: await safetyCode(a.localDescription.sdp, a.remoteDescription.sdp) }; }
      catch (error) { return { error: error.message, local: fingerprints(a.localDescription.sdp), remote: fingerprints(a.remoteDescription.sdp) }; }
    });
    assert.match(proofs[0].code || '', /^[0-9a-f]{4}(?: [0-9a-f]{4}){5}$/, JSON.stringify(codeEvidence));
    assert.equal(proofs[0].encryptionState, 'confirmed'); assert.equal(proofs[1].encryptionState, 'confirmed');
    assert.equal(proofs[0].code, proofs[1].code);
    assert.equal(proofs[0].routeState, 'direct'); assert.equal(proofs[1].routeState, 'direct');
    assert.ok(proofs.every((p) => p.transports.every((t) => t.dtlsCipher && t.srtpCipher && t.localFingerprint && t.remoteFingerprint)));
    await page.evaluate(() => panel.refresh());
    assert.equal(await page.locator('.trust-peer img').count(), 0, 'peer names render as text');
    assert.equal(await page.locator('.trust-identity').textContent(), 'Code not compared. Identity is not independently verified.');
    assert.equal(await page.locator('.trust-state').textContent(), 'Encryption observed', await page.locator('.trust-observations').textContent());
    await page.locator('.trust-compare').click();
    assert.match(await page.locator('.trust-identity').textContent(), /You confirmed/);
    // Same negotiated certificate code in a different connection object must
    // still lose the human acknowledgement. A new connection needs a new check.
    await page.evaluate(async () => {
      const pc = { connectionState: a.connectionState, localDescription: a.localDescription, remoteDescription: a.remoteDescription, getStats: () => a.getStats() };
      livePeers = [{ id: 'peer', name: 'Peer', pc }]; await panel.refresh();
    });
    assert.match(await page.locator('.trust-identity').textContent(), /not compared/);
    await page.evaluate(async () => {
      livePeers[0].pc.getStats = async () => { throw Error('unavailable'); }; await panel.refresh();
    });
    assert.equal(await page.locator('.trust-state').textContent(), 'Encryption evidence unavailable');
    assert.equal(await page.locator('.trust-compare').isDisabled(), true);
    assert.deepEqual(await page.evaluate(() => failures), []);
    await page.evaluate(async () => {
      livePeers[0].pc.getStats = async () => {
        const report = await a.getStats();
        const entries = [...report.values()].map((s) => ({ ...s }));
        const transport = entries.find((s) => s.type === 'transport');
        entries.find((s) => s.id === transport.remoteCertificateId).fingerprint = Array(32).fill('CC').join(':');
        return new Map(entries.map((s) => [s.id, s]));
      };
      await panel.refresh(); await panel.refresh();
    });
    assert.equal(await page.locator('.trust-state').textContent(), 'Security check failed');
    assert.equal(await page.evaluate(() => failures.length), 1, 'definite failure is reported once, never for missing observations');
    await page.evaluate(() => { panel.destroy(); a.close(); b.close(); oscillator.stop(); audio.close(); });
    assert.equal(await page.locator('#proof').textContent(), '');
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
