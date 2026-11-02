import { connectionProof } from './security.js';

// A view of current WebRTC evidence. Comparison acknowledgements stay in this
// panel's memory, are bound to a peer connection + certificate code, and expire
// when it closes. They are never account identity assertions.
export function mountTrustPanel(host, { getPeers, onSecurityFailure = () => {} } = {}) {
  if (!host || typeof getPeers !== 'function') throw new Error('A trust panel host and peer provider are required.');
  const document = host.ownerDocument;
  const setText = (node, text) => { if (node.textContent !== text) node.textContent = text; };
  const make = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const intro = make('p', 'See what your browser reports for each connection. Encryption and checking who you are talking to are separate checks.', 'trust-intro');
  const empty = make('p', 'Connection evidence will appear when someone joins.', 'trust-empty');
  const list = make('div', undefined, 'trust-peers');
  const limits = make('details', undefined, 'trust-limits');
  limits.append(make('summary', 'What this can and cannot prove'));
  limits.append(make('p', 'WebRTC encrypts audio and video between participants. The PVP service exchanges invitations and connection details; it does not carry call audio or video. It can see setup metadata, and participants can see one another’s network addresses.'));
  limits.append(make('p', 'The code checks the certificates for this connection, not a permanent account identity. A compromised app or device can misreport evidence or capture media. Other participants can record outside PVP. This panel is not an independent security audit.'));
  limits.append(make('p', 'For an independent check, compare the complete code through a trusted channel outside this call and its chat. Browser tools such as chrome://webrtc-internals can show the underlying DTLS, SRTP and ICE observations.'));
  host.replaceChildren(intro, empty, list, limits);
  const records = new Map();
  let stopped = false, pending = false;

  const create = (peer) => {
    const row = make('article', undefined, 'trust-peer');
    const title = make('h3', peer.name || 'Participant');
    const state = make('p', 'Waiting for connection evidence', 'trust-state');
    state.setAttribute('role', 'status');
    const route = make('p', undefined, 'trust-route');
    const identity = make('p', 'Code not compared', 'trust-identity');
    const explanation = make('p', 'Compare all six groups with this person in person or through another trusted app. If any group differs, leave the call.', 'trust-compare-help');
    const code = make('code', 'Available after negotiation', 'trust-code');
    code.setAttribute('aria-label', 'Connection verification code');
    const compare = make('button', 'I compared all six groups — they match', 'button secondary trust-compare');
    compare.type = 'button'; compare.disabled = true;
    const details = make('details', undefined, 'trust-evidence');
    const raw = make('pre', undefined, 'trust-observations');
    details.append(make('summary', 'Show connection evidence'), raw);
    row.append(title, state, route, identity, code, explanation, compare, details);
    list.append(row);
    const record = { pc: peer.pc, code: null, compared: false, failureNotified: null, row, title, state, route, identity, codeNode: code, compare, raw };
    compare.addEventListener('click', () => {
      if (compare.disabled || !record.code) return;
      record.compared = true;
      record.identity.textContent = 'You confirmed the codes match for this connection.';
      compare.textContent = 'Codes compared for this connection';
      compare.disabled = true;
    });
    return record;
  };
  const render = (peer, record, proof) => {
    record.title.textContent = peer.name || 'Participant';
    record.row.dataset.encryptionState = proof.encryptionState;
    record.row.dataset.routeState = proof.routeState;
    if (record.code !== proof.code) {
      record.compared = false;
      record.code = proof.code;
    }
    setText(record.state, proof.encryptionState === 'confirmed' ? 'Encryption observed'
      : proof.encryptionState === 'failed' ? 'Security check failed'
        : proof.encryptionState === 'waiting' ? 'Waiting for connection evidence'
          : 'Encryption evidence unavailable');
    record.route.textContent = proof.routeState === 'direct' ? 'Direct connection observed'
      : proof.routeState === 'rejected' ? 'Relay connection rejected'
        : proof.routeState === 'waiting' ? 'Waiting for a direct connection'
          : 'Direct route evidence unavailable';
    record.identity.textContent = record.compared ? 'You confirmed the codes match for this connection.' : 'Code not compared. Identity is not independently verified.';
    record.codeNode.textContent = proof.code || (proof.encryptionState === 'waiting' ? 'Available after negotiation' : 'Verification code unavailable for this connection');
    record.compare.disabled = record.compared || !proof.code || proof.encryptionState !== 'confirmed';
    record.compare.textContent = record.compared ? 'Codes compared for this connection' : 'I compared all six groups — they match';
    const cert = proof.certificateState === 'matched' ? 'Observed certificates match negotiation' : proof.certificateState === 'mismatch' ? 'Certificate mismatch' : 'Certificate evidence unavailable';
    const rows = [`Observed: ${proof.sampledAt}`, `Peer connection: ${proof.connectionState}`, `Certificates: ${cert}`];
    for (const t of proof.transports) rows.push(
      `Transport: ${t.id || 'unavailable'}`,
      `DTLS: ${t.dtlsState || 'unavailable'}`,
      `DTLS cipher: ${t.dtlsCipher || 'unavailable'}`,
      `SRTP cipher: ${t.srtpCipher || 'unavailable'}`,
      `Local SHA-256: ${t.localFingerprint || 'unavailable'}`,
      `Peer SHA-256: ${t.remoteFingerprint || 'unavailable'}`,
      `Selected candidate types: ${t.localCandidateType || 'unavailable'} / ${t.remoteCandidateType || 'unavailable'}`,
    );
    if (proof.failure) rows.push(proof.failure);
    record.raw.textContent = rows.join('\n');
    if (proof.failure && record.failureNotified !== proof.failure) {
      record.failureNotified = proof.failure;
      onSecurityFailure(peer, new Error(proof.failure));
    }
  };
  const refresh = async () => {
    if (stopped || pending) return;
    pending = true;
    try {
      const peers = getPeers().filter((p) => p?.id && p.pc).slice(0, 16);
      const live = new Set(peers.map((p) => p.id));
      for (const [id, record] of records) if (!live.has(id)) { record.row.remove(); records.delete(id); }
      empty.hidden = peers.length > 0;
      await Promise.all(peers.map(async (peer) => {
        let record = records.get(peer.id);
        if (record && record.pc !== peer.pc) { record.row.remove(); records.delete(peer.id); record = null; }
        if (!record) { record = create(peer); records.set(peer.id, record); }
        const proof = await connectionProof(peer.pc);
        if (stopped || records.get(peer.id) !== record || !getPeers().some((p) => p.id === peer.id && p.pc === peer.pc)) return;
        render(peer, record, proof);
      }));
    } finally { pending = false; }
  };
  const timer = setInterval(() => { if (host.isConnected) refresh().catch(() => {}); }, 1500);
  refresh().catch(() => {});
  return {
    refresh,
    destroy() { stopped = true; clearInterval(timer); records.clear(); host.replaceChildren(); },
  };
}
