import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectReport, captureCommand, mediaCaptureCommand, endpointLabel } from '../web/inspector.js';

// Documentation-only address ranges; these fixtures never enter the client UI.
const fixture = () => new Map([
  ['l', { id: 'l', type: 'local-candidate', address: '192.0.2.10', port: 50000, protocol: 'udp', candidateType: 'host' }],
  ['r', { id: 'r', type: 'remote-candidate', address: '198.51.100.20', port: 60000, protocol: 'udp', candidateType: 'srflx' }],
  ['p', { id: 'p', type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r', state: 'succeeded', nominated: true, bytesSent: 12345, bytesReceived: 23456, requestsSent: 3 }],
  ['other', { id: 'other', type: 'candidate-pair', state: 'succeeded', nominated: true }],
  ['t', { id: 't', type: 'transport', selectedCandidatePairId: 'p', dtlsState: 'connected', dtlsCipher: 'observed-cipher' }],
]);
test('inspector follows the selected transport, preserves observed values, and follows path changes', () => {
  const stats = fixture(), first = inspectReport(stats, { connectionState: 'connected' });
  assert.equal(first.direct, true); assert.equal(first.bytesSent, 12345); assert.equal(first.bytesReceived, 23456);
  assert.equal(endpointLabel(first.remote), '198.51.100.20:60000');
  assert.equal(first.pairs.find(p => p.id === 'other').selected, false);
  stats.get('t').selectedCandidatePairId = 'other';
  const changed = inspectReport(stats, { connectionState: 'connected' });
  assert.equal(changed.selectedPairId, 'other'); assert.equal(changed.remote, null); assert.equal(changed.direct, false);
});
test('unknown, ambiguous, disconnected and relayed paths never claim direct connectivity', () => {
  const stats = fixture();
  stats.set('extra', { ...stats.get('t'), id: 'extra' });
  assert.equal(inspectReport(stats, { connectionState: 'connected' }).selectedPairId, null);
  stats.delete('extra'); stats.delete('t');
  assert.equal(inspectReport(stats, { connectionState: 'connected' }).selectedPairId, null);
  stats.delete('other'); assert.equal(inspectReport(stats, { connectionState: 'connected' }).selectedPairId, 'p');
  stats.get('r').candidateType = 'relay'; const relayed = inspectReport(stats, { connectionState: 'connected' });
  assert.equal(relayed.relayed, true); assert.equal(relayed.direct, false);
  stats.get('r').candidateType = 'srflx'; assert.equal(inspectReport(stats, { connectionState: 'disconnected' }).direct, false);
  stats.delete('r'); assert.equal(inspectReport(stats, { connectionState: 'connected' }).direct, false);
  const empty = inspectReport(new Map()); assert.equal(empty.bytesSent, null); assert.equal(empty.dtlsState, null);
});
test('tcpdump filters require literal IPs and valid ports; hidden addresses and shell injection are rejected', () => {
  const observed = inspectReport(fixture(), { connectionState: 'connected' });
  assert.equal(captureCommand(observed.remote), "sudo tcpdump -i pktap,all -nn -tttt 'udp and host 198.51.100.20 and port 60000'");
  assert.equal(captureCommand({ address: '2001:db8::1', port: 443, protocol: 'tcp' }, 'linux'), "sudo tcpdump -i any -nn -tttt 'tcp and host 2001:db8::1 and port 443'");
  for (const address of ['peer.local', "198.51.100.20'; echo malicious", '999.1.2.3', '::1%en0']) assert.equal(captureCommand({ address, port: 1234, protocol: 'udp' }), null);
  for (const port of [0, 65536, '443', -1]) assert.equal(captureCommand({ address: '127.0.0.1', port, protocol: 'tcp' }), null);
  const hidden = { local: { address: '127.0.0.1', port: 50000, protocol: 'udp', candidateType: 'host' }, remote: { address: '', port: 60000, protocol: 'udp' } };
  assert.ok(mediaCaptureCommand(hidden).includes('host 127.0.0.1 and port 50000'));
  hidden.local.candidateType = 'srflx'; assert.equal(mediaCaptureCommand(hidden), null, 'never treat a public NAT mapping as a local socket');
});
