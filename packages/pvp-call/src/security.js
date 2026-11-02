export const isRelay = (text) => /\btyp\s+relay\b/i.test(text);

export function fingerprints(sdp) {
  if (typeof sdp !== "string") return [];
  return [
    ...new Set(
      [...sdp.matchAll(/^a=fingerprint:sha-256 ((?:[0-9a-f]{2}:){31}[0-9a-f]{2})\r?$/gim)].map((m) =>
        m[1].replaceAll(":", "").toLowerCase(),
      ),
    ),
  ].sort();
}

export function requireEncryptedSdp(sdp) {
  if (
    typeof sdp !== "string" ||
    sdp.length > 48000 ||
    sdp.split(/\r?\n/, 1)[0] !== "v=0" ||
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)/.test(sdp) ||
    isRelay(sdp)
  )
    throw new Error("Invalid encrypted peer negotiation.");
  let inherited = false,
    section = null;
  const sections = [];
  for (const raw of sdp.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length > 4096 || line.startsWith("a=crypto:"))
      throw new Error("Unencrypted or unsupported peer negotiation.");
    if (line.startsWith("m=")) {
      const [kind, port, protocol, format] = line.slice(2).split(/\s+/);
      if (
        !format ||
        !/^\d+$/.test(port) ||
        +port > 65535 ||
        sections.length >= 8 ||
        !(["audio", "video"].includes(kind)
          ? protocol === "UDP/TLS/RTP/SAVPF"
          : kind === "application" && protocol === "UDP/DTLS/SCTP")
      )
        throw new Error("An encrypted WebRTC transport is required.");
      section = { active: +port !== 0, fingerprint: inherited };
      sections.push(section);
    } else if (line.startsWith("a=fingerprint:")) {
      if (
        !/^a=fingerprint:sha-256 (?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i.test(line)
      )
        throw new Error("A valid SHA-256 certificate fingerprint is required.");
      if (section) section.fingerprint = true;
      else inherited = true;
    }
  }
  if (
    !sections.some((s) => s.active) ||
    sections.some((s) => s.active && !s.fingerprint)
  )
    throw new Error("Missing encrypted peer certificate.");
}

export function requireCandidate(c) {
  const words = typeof c?.candidate === "string" ? c.candidate.trim().split(/\s+/) : [];
  const uint = (value, max) => /^\d+$/.test(value || "") && Number(value) <= max;
  if (
    !c ||
    typeof c.candidate !== "string" ||
    c.candidate.length > 2048 ||
    /[\r\n\0]/.test(c.candidate) ||
    isRelay(c.candidate) ||
    words.length < 8 ||
    !/^candidate:\S+$/.test(words[0]) ||
    !["1", "2"].includes(words[1]) ||
    !["udp", "tcp"].includes(words[2]?.toLowerCase()) ||
    !uint(words[3], 4294967295) ||
    !uint(words[5], 65535) ||
    Number(words[5]) === 0 ||
    words[6] !== "typ" ||
    !["host", "srflx", "prflx"].includes(words[7]) ||
    (c.sdpMid != null &&
      (typeof c.sdpMid !== "string" || c.sdpMid.length > 64 || /[\x00-\x1f\x7f]/.test(c.sdpMid))) ||
    (c.sdpMLineIndex != null &&
      (!Number.isInteger(c.sdpMLineIndex) ||
        c.sdpMLineIndex < 0 ||
        c.sdpMLineIndex >= 8)) ||
    (c.sdpMid == null && c.sdpMLineIndex == null)
  )
    throw new Error("Invalid direct peer candidate.");
}

export async function safetyCode(local, remote) {
  // Validate each endpoint independently. A union alone could conceal one
  // missing certificate when the other SDP happened to contain two.
  requireEncryptedSdp(local);
  requireEncryptedSdp(remote);
  const localKeys = fingerprints(local), remoteKeys = fingerprints(remote);
  // PVP uses max-bundle and one certificate per endpoint. Do not let extra,
  // unused fingerprints pad both sides into an equal set: that would lose the
  // binding between the displayed code and the two actual endpoint keys.
  if (localKeys.length !== 1 || remoteKeys.length !== 1)
    throw new Error("A verification code requires one certificate per endpoint.");
  const values = [
    ...new Set([...localKeys, ...remoteKeys]),
  ].sort();
  if (values.length < 2) throw new Error("Missing peer certificates.");
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`PVP-call-v1\n${values.join("\n")}`),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 24)
    .match(/.{4}/g)
    .join(" ");
}

const observedText = (value) => typeof value === "string" && value.length ? value.slice(0, 256) : null;
const normalizedFingerprint = (value) => {
  if (typeof value !== "string") return null;
  const normalized = value.replaceAll(":", "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
};
const encryptedSrtpProfiles = new Set([
  "AEAD_AES_128_GCM", "AEAD_AES_256_GCM",
  "AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32",
  // libwebrtc's observed stats spelling for the same encrypted AES-CM profiles.
  "AES128_CM_HMAC_SHA1_80", "AES128_CM_HMAC_SHA1_32",
]);
const plaintextSrtpProfiles = new Set([
  "NULL_SHA1_80", "NULL_SHA1_32", "NULL_HMAC_SHA1_80", "NULL_HMAC_SHA1_32",
  "NULL", "NONE", "PLAINTEXT",
]);
const srtpProfile = (value) => typeof value === "string" ? value.toUpperCase().replace(/^SRTP_/, "") : null;

/** Inspect live browser evidence, separately from human verification of a peer.
 * Missing/unsupported stats never mean plaintext or a verified identity.
 * No addresses, SDP, raw certificates, credentials or media enter this result.
 */
export async function inspectEncryptionReport(report, {
  localSdp,
  remoteSdp,
  connectionState = "unknown",
  sampledAt = new Date().toISOString(),
} = {}) {
  const proof = {
    schemaVersion: 1, sampledAt, connectionState,
    encryptionState: "waiting", routeState: "waiting", certificateState: "waiting",
    code: null, failure: null, transports: [],
  };
  if (!localSdp || !remoteSdp) return proof;
  try {
    requireEncryptedSdp(localSdp);
    requireEncryptedSdp(remoteSdp);
  } catch {
    return { ...proof, encryptionState: "failed", failure: "The call did not negotiate the required encrypted transport and certificates." };
  }
  // Unsupported multi-certificate negotiation can still have live encrypted
  // transport evidence; it cannot safely use PVP's existing pair-code format.
  try { proof.code = await safetyCode(localSdp, remoteSdp); } catch { /* No pair code. */ }
  const local = fingerprints(localSdp), remote = fingerprints(remoteSdp);
  const hasMedia = [localSdp, remoteSdp].some((sdp) => /^m=(?:audio|video) (?!0(?:\s|$))\d+ /m.test(sdp));
  const all = report && typeof report.values === "function" ? [...report.values()] : [];
  const byId = new Map(all.map((s) => [s.id, s]));
  const transports = all.filter((s) => s.type === "transport");
  const explicitlySelected = (transport) => typeof transport.selectedCandidatePairId === "string" && transport.selectedCandidatePairId.length > 0;
  const selected = [];
  let certificateMismatch = false, certificatesComplete = transports.length > 0;
  for (const transport of transports) {
    const certificate = (id) => {
      const value = byId.get(id);
      return value?.type === "certificate" && typeof value.fingerprintAlgorithm === "string" && value.fingerprintAlgorithm.toLowerCase() === "sha-256"
        ? normalizedFingerprint(value.fingerprint) : null;
    };
    const localFingerprint = certificate(transport.localCertificateId);
    const remoteFingerprint = certificate(transport.remoteCertificateId);
    certificateMismatch ||= explicitlySelected(transport) && (!!(localFingerprint && !local.includes(localFingerprint)) || !!(remoteFingerprint && !remote.includes(remoteFingerprint)));
    certificatesComplete &&= !!localFingerprint && !!remoteFingerprint;
    const pair = byId.get(transport.selectedCandidatePairId);
    const localCandidate = pair?.type === "candidate-pair" ? byId.get(pair.localCandidateId) : null;
    const remoteCandidate = pair?.type === "candidate-pair" ? byId.get(pair.remoteCandidateId) : null;
    const localType = localCandidate?.type === "local-candidate" ? observedText(localCandidate.candidateType) : null;
    const remoteType = remoteCandidate?.type === "remote-candidate" ? observedText(remoteCandidate.candidateType) : null;
    // Only an explicit selection can establish the active route. Historical or
    // nominated candidate-pairs do not establish which path is carrying media.
    selected.push({ state: pair?.state, localType, remoteType });
    proof.transports.push({
      id: observedText(transport.id),
      dtlsState: observedText(transport.dtlsState),
      dtlsCipher: observedText(transport.dtlsCipher),
      srtpCipher: observedText(transport.srtpCipher),
      localFingerprint, remoteFingerprint,
      localCandidateType: localType, remoteCandidateType: remoteType,
    });
  }
  const relayed = selected.some((p) => p.localType === "relay" || p.remoteType === "relay");
  // Historical/unused transports can remain in a report. A negative observation
  // on one of those must not terminate the current call. Enforce every explicit
  // selection, including when multiple selected transports prevent one summary.
  const activeTransports = transports.filter(explicitlySelected);
  const lostDtls = connectionState !== "closed" && activeTransports.some((t) => ["failed", "closed"].includes(t.dtlsState));
  const plaintextSrtp = hasMedia && activeTransports.some((t) => plaintextSrtpProfiles.has(srtpProfile(t.srtpCipher)));
  if (certificateMismatch || relayed || lostDtls || plaintextSrtp) {
    proof.encryptionState = "failed";
    proof.routeState = relayed ? "rejected" : "unavailable";
    proof.certificateState = certificateMismatch ? "mismatch" : certificatesComplete ? "matched" : "unavailable";
    proof.failure = certificateMismatch ? "The observed certificate does not match this call’s negotiated certificate."
      : relayed ? "A relay path was rejected. PVP requires direct media."
        : plaintextSrtp ? "An unencrypted SRTP profile was rejected."
          : "The encrypted transport was lost.";
    return proof;
  }
  const connected = connectionState === "connected";
  proof.certificateState = certificatesComplete ? "matched" : connected ? "unavailable" : "waiting";
  const directTypes = ["host", "srflx", "prflx"];
  proof.routeState = connected && selected.length > 0 && selected.every((p) => p.state === "succeeded" && directTypes.includes(p.localType) && directTypes.includes(p.remoteType))
    ? "direct" : connected ? "unavailable" : "waiting";
  // Cipher strings are observations from WebRTC, not hard-coded security claims.
  const encrypted = connected && certificatesComplete && proof.transports.every((t) => t.dtlsState === "connected" && t.dtlsCipher && (!hasMedia || encryptedSrtpProfiles.has(srtpProfile(t.srtpCipher))));
  proof.encryptionState = encrypted ? "confirmed" : connected ? "unavailable" : "waiting";
  return proof;
}

export async function connectionProof(pc) {
  const unavailable = () => ({
    schemaVersion: 1, sampledAt: new Date().toISOString(), connectionState: pc?.connectionState || "unknown",
    encryptionState: "unavailable", routeState: "unavailable", certificateState: "unavailable",
    code: null, failure: null, transports: [],
  });
  if (!pc || pc.connectionState === "closed") return unavailable();
  const localSdp = pc.localDescription?.sdp, remoteSdp = pc.remoteDescription?.sdp;
  let report, timer;
  try {
    report = await Promise.race([
      pc.getStats(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Connection evidence timed out.")), 3000); }),
    ]);
  } catch { /* Unsupported observations remain unavailable. */ }
  finally { clearTimeout(timer); }
  // Capture current descriptions after getStats; a teardown cannot yield stale
  // confirmation. A changed negotiation waits for the next sample.
  if (pc.connectionState === "closed" || pc.localDescription?.sdp !== localSdp || pc.remoteDescription?.sdp !== remoteSdp) return unavailable();
  const connectionState = pc.connectionState;
  const proof = await inspectEncryptionReport(report, { localSdp, remoteSdp, connectionState });
  if (pc.connectionState !== connectionState || pc.localDescription?.sdp !== localSdp || pc.remoteDescription?.sdp !== remoteSdp) return unavailable();
  return proof;
}
