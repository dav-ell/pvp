import { validateSignal } from "./mesh.js";

// A signaling-only room. Identity is supplied by the authenticated game session,
// never by a caller's packet. No card state or media is stored here.
export class CallRoom {
  constructor({ deliver, roster, limit = 4 }) {
    this.deliver = deliver;
    this.roster = roster;
    this.limit = limit;
    this.members = new Map();
  }
  receive(id, packet) {
    const players = this.roster();
    const player = players.find(
      (p) => p.id === id && p.connected && p.occupied !== false,
    );
    if (!player)
      throw Error("Only connected players can join this table call.");
    if (!packet || typeof packet !== "object")
      throw Error("Invalid table call.");
    if (packet.kind === "sync") {
      this.deliver(id, this.snapshot());
      return;
    }
    if (packet.kind === "leave") {
      this.remove(id);
      return;
    }
    if (packet.kind === "state") {
      const state = packet.state;
      if (
        !state ||
        !/^[a-zA-Z0-9_-]{8,100}$/.test(state.epoch || "") ||
        typeof state.mic !== "boolean" ||
        typeof state.camera !== "boolean"
      )
        throw Error("Invalid call state.");
      if (!this.members.has(id) && this.members.size >= this.limit)
        throw Error("This call is full.");
      this.members.set(id, {
        id,
        name: String(player.name || "Player").slice(0, 28),
        epoch: state.epoch,
        mic: state.mic,
        camera: state.camera,
      });
      this.broadcast();
      return;
    }
    if (packet.kind !== "signal") throw Error("Invalid table call event.");
    const from = this.members.get(id),
      to = this.members.get(packet.to);
    if (
      !from ||
      !to ||
      id === packet.to ||
      !players.some((p) => p.id === to.id && p.connected)
    )
      throw Error("Only joined call participants can exchange signaling.");
    const signal = validateSignal(packet.signal);
    if (signal.fromEpoch !== from.epoch || signal.toEpoch !== to.epoch) return;
    this.deliver(to.id, { kind: "signal", from: id, signal });
  }
  snapshot() {
    return {
      kind: "roster",
      members: [...this.members.values()].map((m) => ({ ...m })),
    };
  }
  broadcast() {
    const players = this.roster();
    for (const [id, m] of this.members) {
      const p = players.find(
        (p) => p.id === id && p.connected && p.occupied !== false,
      );
      if (!p) this.members.delete(id);
      else m.name = String(p.name || "Player").slice(0, 28);
    }
    const event = this.snapshot();
    for (const player of players)
      if (player.connected && player.occupied !== false)
        this.deliver(player.id, event);
  }
  remove(id) {
    if (this.members.delete(id)) this.broadcast();
  }
  clear() {
    this.members.clear();
    this.broadcast();
  }
}
