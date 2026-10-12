export const isRelay = (text) => /\btyp\s+relay\b/i.test(text);

export function fingerprints(sdp) {
  return [
    ...new Set(
      [...sdp.matchAll(/^a=fingerprint:sha-256 ([0-9a-f:]+)\r?$/gim)].map((m) =>
        m[1].replaceAll(":", "").toLowerCase(),
      ),
    ),
  ].sort();
}

export function requireEncryptedSdp(sdp) {
  if (
    typeof sdp !== "string" ||
    sdp.length > 48000 ||
    !sdp.startsWith("v=0") ||
    sdp.includes("\0") ||
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
      section = { active: port !== "0", fingerprint: inherited };
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
  if (
    !c ||
    typeof c.candidate !== "string" ||
    c.candidate.length > 2048 ||
    /[\r\n\0]/.test(c.candidate) ||
    isRelay(c.candidate) ||
    !/^candidate:\S+ [12] (?:udp|tcp) \d+ \S+ \d+ typ (?:host|srflx|prflx)(?:\s|$)/i.test(
      c.candidate,
    ) ||
    (c.sdpMid != null &&
      (typeof c.sdpMid !== "string" || c.sdpMid.length > 64)) ||
    (c.sdpMLineIndex != null &&
      (!Number.isInteger(c.sdpMLineIndex) ||
        c.sdpMLineIndex < 0 ||
        c.sdpMLineIndex >= 8)) ||
    (c.sdpMid == null && c.sdpMLineIndex == null)
  )
    throw new Error("Invalid direct peer candidate.");
}

export async function safetyCode(local, remote) {
  const values = [
    ...new Set([...fingerprints(local), ...fingerprints(remote)]),
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
