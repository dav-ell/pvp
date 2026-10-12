export interface Participant {
  id: string;
  epoch: string;
  name?: string;
}
export interface CallMember extends Participant {
  name: string;
  mic: boolean;
  camera: boolean;
}
export interface Preferences {
  preset: string;
  resolution: number;
  fps: number;
  video: number;
  audio: number;
}
export interface PeerSignal {
  type: "offer" | "answer" | "candidate" | "retry";
  generation: number;
  fromEpoch: string;
  toEpoch: string;
  sdp?: string;
  candidate?: RTCIceCandidateInit;
}
export type CallPacket =
  | { kind: "sync" | "leave" }
  | { kind: "state"; state: { epoch: string; mic: boolean; camera: boolean } }
  | { kind: "signal"; to: string; signal: PeerSignal };
export type CallEvent =
  | { kind: "roster"; members: CallMember[] }
  | { kind: "signal"; from: string; signal: PeerSignal };
export interface ConnectionEvidence {
  direct: boolean;
  relayed: boolean;
  bytesSent: number | null;
  bytesReceived: number | null;
  rttSeconds: number | null;
  dtlsState: string | null;
  media: {
    kind: string | null;
    direction: "incoming" | "outgoing";
    bytes: number | null;
  }[];
  [key: string]: unknown;
}
export interface PeerLink {
  peer: Participant;
  pc: RTCPeerConnection;
  remote: MediaStream;
  generation: number;
  speaking: boolean;
  error: string | null;
  code?: string;
  evidence?: ConnectionEvidence;
}
export class MediaController {
  constructor(options?: {
    capture?: (constraints: MediaStreamConstraints) => Promise<MediaStream>;
    Stream?: typeof MediaStream;
    changed?: (stream: MediaStream) => void;
  });
  stream: MediaStream;
  get(kind: "audio" | "video"): MediaStreamTrack | null;
  enable(
    kind: "audio" | "video",
    constraints?: boolean | MediaTrackConstraints,
  ): Promise<MediaStreamTrack | null>;
  mute(muted: boolean): void;
  disable(kind: "audio" | "video"): void;
  stop(): void;
}
export class PvpMesh {
  constructor(options: {
    self: Participant;
    stream: MediaStream;
    send: (to: string, signal: PeerSignal) => void;
    onChange?: (mesh: PvpMesh) => void;
    onStream?: (id: string, stream: MediaStream | null) => void;
    onError?: (error: Error) => void;
    preferences?: Preferences;
    iceServers?: RTCIceServer[];
    Factory?: typeof RTCPeerConnection;
    Stream?: typeof MediaStream;
  });
  self: Participant;
  stream: MediaStream;
  links: Map<string, PeerLink>;
  preferences: Preferences;
  setPeers(peers: Participant[]): void;
  receive(from: string, signal: PeerSignal): Promise<boolean>;
  updateStream(stream?: MediaStream): Promise<void>;
  presence(speaking: boolean): void;
  sample(): Promise<void>;
  retry(id: string, failures?: number): void;
  close(): void;
}
export class CallRoom {
  constructor(options: {
    roster: () => {
      id: string;
      name?: string;
      connected: boolean;
      occupied?: boolean;
    }[];
    deliver: (id: string, event: CallEvent) => void;
    limit?: number;
  });
  members: Map<string, CallMember>;
  receive(authenticatedId: string, packet: CallPacket): void;
  snapshot(): { kind: "roster"; members: CallMember[] };
  broadcast(): void;
  remove(id: string): void;
  clear(): void;
}
export const DEFAULT_ICE_SERVERS: readonly RTCIceServer[];
export function createPeerConnection(options?: {
  iceServers?: RTCIceServer[];
  Factory?: typeof RTCPeerConnection;
}): RTCPeerConnection;
export function validateSignal(signal: PeerSignal): PeerSignal;
export function requireEncryptedSdp(sdp: string): void;
export function requireCandidate(candidate: RTCIceCandidateInit): void;
export function isRelay(candidate: string): boolean;
export function safetyCode(local: string, remote: string): Promise<string>;
export function inspectReport(
  stats: RTCStatsReport,
  options?: {
    connectionState?: string;
    iceState?: string;
    sampledAt?: string;
    configuredServers?: string[];
  },
): ConnectionEvidence;
export function cameraQuality(
  preferences: Preferences,
  attendees: number,
  high: boolean,
  captureHeight?: number,
): { height: number; fps: number; scale: number; small: boolean };
export function groupVideoKbps(
  preferences: Preferences,
  attendees: number,
): number;
