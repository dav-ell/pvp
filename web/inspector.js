// Compatibility entry point: implementation is shared with embedding apps.
export * from '../packages/pvp-call/src/inspector.js';

// Browser reports keep route types and counters without exposing sockets or
// engine identifiers, which can encode addresses on some WebRTC implementations.
export function publicObservation(evidence) {
  if (!evidence) return null;
  const path = candidate => candidate && {
    candidateType: candidate.candidateType, protocol: candidate.protocol,
  };
  const { local, remote, candidates, pairs, media, configuredServers, selectedPairId, ...summary } = evidence;
  return {
    ...summary,
    local: path(local), remote: path(remote),
    candidates: candidates.map(candidate => ({ ...path(candidate), side: candidate.side })),
    pairs: pairs.map(({ id, local, remote, ...pair }) => ({ ...pair, local: path(local), remote: path(remote) })),
    media: media.map(({ id, ...row }) => row),
  };
}
