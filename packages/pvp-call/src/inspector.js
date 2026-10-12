// Observations only: no DNS guesses, synthetic packets, or assumed addresses.
export function ipLiteral(value) {
  if (typeof value !== "string" || value.length > 64) return null;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value))
    return value.split(".").every((n) => Number(n) <= 255) ? value : null;
  if (!value.includes(":") || !/^[a-fA-F0-9:.]+$/.test(value)) return null;
  try {
    new URL(`http://[${value}]/`);
    return value;
  } catch {
    return null;
  }
}
const text = (value) =>
  typeof value === "string" && value.length ? value.slice(0, 256) : null;
const number = (value) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
export function endpoint(candidate) {
  if (!candidate) return null;
  const raw = candidate.address ?? candidate.ip;
  return {
    id: text(candidate.id),
    address: text(raw),
    ip: ipLiteral(raw),
    port:
      Number.isInteger(candidate.port) &&
      candidate.port > 0 &&
      candidate.port <= 65535
        ? candidate.port
        : null,
    protocol: ["udp", "tcp"].includes(candidate.protocol)
      ? candidate.protocol
      : null,
    candidateType: text(candidate.candidateType),
    url: text(candidate.url),
    relatedAddress: text(candidate.relatedAddress),
    relatedPort: number(candidate.relatedPort),
    timestamp: number(candidate.timestamp),
    source: "WebRTC statistics",
  };
}
export function endpointLabel(value) {
  if (!value) return "Address unavailable";
  const address = value.address || "Address unavailable";
  return `${address.includes(":") ? `[${address}]` : address}:${value.port ?? "port unavailable"}`;
}
export function captureCommand(value, platform = "mac") {
  const ip = ipLiteral(value?.address ?? value?.ip);
  if (
    !ip ||
    !Number.isInteger(value.port) ||
    value.port < 1 ||
    value.port > 65535 ||
    !["udp", "tcp"].includes(value.protocol)
  )
    return null;
  // Only validated IP literals, numeric ports and fixed protocols enter a shell command.
  const filter = `${value.protocol} and host ${ip} and port ${value.port}`;
  return `sudo tcpdump -i ${platform === "mac" ? "pktap,all" : "any"} -nn -tttt '${filter}'`;
}
export function mediaCaptureCommand(evidence, platform = "mac") {
  return (
    captureCommand(evidence?.remote, platform) ||
    (evidence?.local?.candidateType === "host"
      ? captureCommand(evidence.local, platform)
      : null)
  );
}
export function inspectReport(
  reports,
  {
    sampledAt = new Date().toISOString(),
    connectionState = "unknown",
    iceState = "unknown",
    configuredServers = [],
  } = {},
) {
  const all = [...reports.values()],
    byId = new Map(all.map((s) => [s.id, s]));
  const transports = all.filter((s) => s.type === "transport");
  const selectors = transports.filter((s) => s.selectedCandidatePairId);
  const selectedTransport = selectors.length === 1 ? selectors[0] : null;
  const succeeded = all.filter(
    (s) =>
      s.type === "candidate-pair" &&
      s.state === "succeeded" &&
      (s.selected === true || s.nominated === true),
  );
  const selected = selectedTransport
    ? byId.get(selectedTransport.selectedCandidatePairId)
    : selectors.length === 0 && succeeded.length === 1
      ? succeeded[0]
      : null;
  const pair = selected?.type === "candidate-pair" ? selected : null;
  const transport =
    selectedTransport ||
    (pair && byId.get(pair.transportId)) ||
    (transports.length === 1 ? transports[0] : null);
  const local = endpoint(byId.get(pair?.localCandidateId)),
    remote = endpoint(byId.get(pair?.remoteCandidateId));
  const directTypes = ["host", "srflx", "prflx"];
  const direct =
    connectionState === "connected" &&
    pair?.state === "succeeded" &&
    directTypes.includes(local?.candidateType) &&
    directTypes.includes(remote?.candidateType);
  return {
    schemaVersion: 1,
    sampledAt,
    source: "WebRTC statistics; not a packet capture",
    connectionState,
    iceState,
    selectedPairId: pair?.type === "candidate-pair" ? text(pair.id) : null,
    selectionSource: selectedTransport
      ? "transport.selectedCandidatePairId"
      : pair
        ? "unique succeeded nominated/selected pair"
        : "unavailable",
    direct,
    relayed:
      local?.candidateType === "relay" || remote?.candidateType === "relay",
    local,
    remote,
    dtlsState: text(transport?.dtlsState),
    dtlsCipher: text(transport?.dtlsCipher),
    srtpCipher: text(transport?.srtpCipher),
    bytesSent: number(pair?.bytesSent),
    bytesReceived: number(pair?.bytesReceived),
    packetsSent: number(pair?.packetsSent),
    packetsReceived: number(pair?.packetsReceived),
    rttSeconds: number(pair?.currentRoundTripTime),
    configuredServers: configuredServers
      .filter((s) => typeof s === "string" && /^stuns?:/.test(s))
      .map((s) => s.slice(0, 256)),
    candidates: all
      .filter((s) => ["local-candidate", "remote-candidate"].includes(s.type))
      .slice(0, 128)
      .map((s) => ({
        ...endpoint(s),
        side: s.type === "local-candidate" ? "local" : "remote",
      })),
    pairs: all
      .filter((s) => s.type === "candidate-pair")
      .slice(0, 128)
      .map((s) => ({
        id: text(s.id),
        state: text(s.state),
        selected: s.id === pair?.id,
        nominated: s.nominated === true,
        local: endpoint(byId.get(s.localCandidateId)),
        remote: endpoint(byId.get(s.remoteCandidateId)),
        requestsSent: number(s.requestsSent),
        requestsReceived: number(s.requestsReceived),
        responsesSent: number(s.responsesSent),
        responsesReceived: number(s.responsesReceived),
        bytesSent: number(s.bytesSent),
        bytesReceived: number(s.bytesReceived),
        timestamp: number(s.timestamp),
      })),
    media: all
      .filter(
        (s) =>
          ["inbound-rtp", "outbound-rtp"].includes(s.type) &&
          s.isRemote !== true,
      )
      .map((s) => ({
        id: text(s.id),
        direction: s.type === "inbound-rtp" ? "incoming" : "outgoing",
        kind: text(s.kind ?? s.mediaType),
        packets: number(s.packetsReceived ?? s.packetsSent),
        bytes: number(s.bytesReceived ?? s.bytesSent),
        packetsLost: number(s.packetsLost),
        timestamp: number(s.timestamp),
      })),
  };
}
