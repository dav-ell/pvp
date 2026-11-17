// Fixed-time simulation for the illustrated landing page. Room bounds come
// from the layout, while peer coordinates stay local to each room.
export const STEP_SECONDS = 1 / 120;

export const FIELD_PRESETS = Object.freeze({
  elastic: Object.freeze({
    drift: 31, home: 1.8, roomDrag: 3.0, rebound: .18,
    tether: 23, spring: 58, peerDrag: 8.2, breathe: 2.6, throwSpeed: 275,
  }),
  buoyant: Object.freeze({
    drift: 48, home: 1.55, roomDrag: 2.2, rebound: .34,
    tether: 17, spring: 52, peerDrag: 6.5, breathe: 4.5, throwSpeed: 355,
  }),
});

const edgePadding = 8;
const roomGap = 5;
const contactTolerance = 1e-7;
const maxRoomSpeed = 940;
const maxPeerSpeed = 1080;
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function limitSpeed(body, maxSpeed) {
  const speed = Math.hypot(body.vx, body.vy);
  if (speed > maxSpeed) {
    body.vx *= maxSpeed / speed;
    body.vy *= maxSpeed / speed;
  }
}

function initialPoints(peers, radius, random) {
  const angle = random() * Math.PI * 2;
  return Array.from({ length: peers }, (_, index) => {
    const direction = angle + index * Math.PI * (3 - Math.sqrt(5)) + (random() - .5) * .2;
    const distance = peers === 1 ? 0 : radius * Math.sqrt((index + 1) / peers) * (.65 + random() * .14);
    const x = Math.cos(direction) * distance;
    const y = Math.sin(direction) * distance;
    return { x, y, homeX: x, homeY: y, vx: 0, vy: 0 };
  });
}

function nearbySprings(points) {
  const springs = [];
  const connected = new Set();
  for (const [a, point] of points.entries()) {
    const neighbors = points.flatMap((other, b) =>
      a === b ? [] : [{ b, length: Math.hypot(point.x - other.x, point.y - other.y) }],
    ).sort((left, right) => left.length - right.length).slice(0, 2);
    for (const { b, length } of neighbors) {
      const key = Math.min(a, b) * points.length + Math.max(a, b);
      if (!connected.has(key)) {
        connected.add(key);
        springs.push({ a, b, length });
      }
    }
  }
  return springs;
}

function createRoom(room, random) {
  const { slot, x, y, radius, peers, bounds } = room;
  const points = initialPoints(peers, radius, random);
  return {
    slot, x, y, radius, points, vx: 0, vy: 0, homeX: x, homeY: y,
    phase: random() * Math.PI * 2,
    rate: .28 + random() * .22,
    mass: .7 + radius / 100,
    // The envelope includes the hull, focus ring, captions, and peer travel.
    left: bounds.left - x, right: bounds.right - x,
    top: bounds.top - y, bottom: bounds.bottom - y,
    springs: nearbySprings(points),
  };
}

function keepPeerInside(point, radius) {
  const distance = Math.hypot(point.x, point.y);
  if (distance <= radius) return;
  const nx = point.x / distance, ny = point.y / distance;
  point.x = nx * radius;
  point.y = ny * radius;
  const outward = Math.max(0, point.vx * nx + point.vy * ny);
  point.vx -= outward * nx;
  point.vy -= outward * ny;
}

function followPointer(body, x, y, maxSpeed) {
  body.vx = (x - body.x) * 43;
  body.vy = (y - body.y) * 43;
  limitSpeed(body, maxSpeed);
}

function advancePeers(room, grab, tuning, time) {
  const { points, springs } = room;
  const grabbed = grab?.peer == null ? null : points[grab.peer];
  const dt = STEP_SECONDS;
  const damping = Math.exp(-tuning.peerDrag * dt);
  for (const [index, point] of points.entries()) {
    const phase = time * .9 + room.phase + index * 1.7;
    const homeX = point.homeX + Math.sin(phase) * tuning.breathe;
    const homeY = point.homeY + Math.cos(phase * .86) * tuning.breathe;
    point.vx = point.vx * damping + (homeX - point.x) * tuning.tether * dt;
    point.vy = point.vy * damping + (homeY - point.y) * tuning.tether * dt;
  }

  for (const { a, b, length } of springs) {
    const from = points[a], to = points[b];
    const dx = to.x - from.x, dy = to.y - from.y;
    const distance = Math.hypot(dx, dy);
    if (distance === 0) continue;
    const change = (distance - length) * tuning.spring * dt / distance;
    from.vx += dx * change;
    from.vy += dy * change;
    to.vx -= dx * change;
    to.vy -= dy * change;
  }

  // A small soft separation keeps the hit targets legible in dense rooms.
  const gap = Math.min(18, room.radius / 3);
  for (const [index, from] of points.entries()) {
    for (let other = index + 1; other < points.length; other++) {
      const to = points[other];
      const dx = to.x - from.x, dy = to.y - from.y;
      const distance = Math.hypot(dx, dy);
      if (distance >= gap) continue;
      const directionX = distance ? dx / distance : 1;
      const directionY = distance ? dy / distance : 0;
      const impulse = (gap - distance) * 145 * dt;
      from.vx -= directionX * impulse;
      from.vy -= directionY * impulse;
      to.vx += directionX * impulse;
      to.vy += directionY * impulse;
    }
  }

  if (grabbed) followPointer(grabbed, grab.x - room.x - grab.offsetX, grab.y - room.y - grab.offsetY, maxPeerSpeed);
  for (const point of points) {
    limitSpeed(point, maxPeerSpeed);
    point.x += point.vx * dt;
    point.y += point.vy * dt;
    keepPeerInside(point, room.radius);
  }
}

function sweepRoom(room, axis, delta, edge, obstacles, rooms, tuning, held) {
  if (delta === 0) return;
  const across = axis === 'x' ? 'y' : 'x';
  const [start, end, near, far] = axis === 'x'
    ? ['left', 'right', 'top', 'bottom']
    : ['top', 'bottom', 'left', 'right'];
  const initial = room[axis], velocity = axis === 'x' ? 'vx' : 'vy';
  const positive = delta > 0;
  const acrossStart = room[across] + room[near], acrossEnd = room[across] + room[far];
  let destination = clamp(initial + delta, edgePadding - room[start], edge - edgePadding - room[end]);
  let blocker;
  const clip = (obstacleStart, obstacleEnd, obstacleNear, obstacleFar, other) => {
    if (acrossEnd <= obstacleNear + contactTolerance || acrossStart >= obstacleFar - contactTolerance) return;
    if (positive && initial + room[end] <= obstacleStart + contactTolerance && destination + room[end] > obstacleStart) {
      destination = obstacleStart - room[end];
      blocker = other;
    } else if (!positive && initial + room[start] >= obstacleEnd - contactTolerance && destination + room[start] < obstacleEnd) {
      destination = obstacleEnd - room[start];
      blocker = other;
    }
  };
  for (const obstacle of obstacles) clip(obstacle[start], obstacle[end], obstacle[near], obstacle[far]);
  for (const other of rooms) {
    if (other === room) continue;
    clip(
      other[axis] + other[start] - roomGap, other[axis] + other[end] + roomGap,
      other[across] + other[near] - roomGap, other[across] + other[far] + roomGap, other,
    );
  }
  room[axis] = destination;
  if (destination === initial + delta) return;
  if (blocker) {
    // The stationary room receives part of the motion when the held one
    // nudges it. Bounding the impulse also keeps repeated contact gentle.
    const impulse = room[velocity] * room.mass / (room.mass + blocker.mass);
    blocker[velocity] = clamp(blocker[velocity] + impulse * .5, -260, 260);
  }
  room[velocity] = held ? (destination - initial) / STEP_SECONDS : -room[velocity] * tuning.rebound;
}

function roomBox(room, x = room.x, y = room.y, padding = 0) {
  return {
    left: x + room.left - padding, right: x + room.right + padding,
    top: y + room.top - padding, bottom: y + room.bottom + padding,
  };
}

function overlaps(a, b) {
  return a.left < b.right - contactTolerance && a.right > b.left + contactTolerance &&
    a.top < b.bottom - contactTolerance && a.bottom > b.top + contactTolerance;
}

function carryMotion(room, previous, bodies, obstacles, width, height) {
  const old = previous.rooms.get(room.slot);
  if (!old || old.radius !== room.radius || old.points.length !== room.points.length) return;
  for (const [index, point] of room.points.entries()) {
    const { x, y, vx, vy } = old.points[index];
    Object.assign(point, { x, y, vx, vy });
  }
  const bounds = roomBox(room, old.x, old.y);
  if (bounds.left < edgePadding || bounds.right > width - edgePadding ||
      bounds.top < edgePadding || bounds.bottom > height - edgePadding ||
      obstacles.some(obstacle => overlaps(bounds, obstacle)) ||
      bodies.some(other => other !== room && overlaps(bounds, roomBox(other, other.x, other.y, roomGap)))) return;
  const { x, y, vx, vy } = old;
  Object.assign(room, { x, y, vx, vy });
}

export function createField(width, height, exclusions, placedRooms, { preset = 'elastic', seed = 0x505650, previous } = {}) {
  const tuning = FIELD_PRESETS[preset];
  if (!tuning) throw new RangeError('Unknown room motion preset.');
  const bodies = placedRooms.map(room => createRoom(room, seededRandom(seed ^ Math.imul(room.slot + 1, 0x9e3779b9))));
  const rooms = new Map(bodies.map(room => [room.slot, room]));
  const obstacles = exclusions.map(({ left, right, top, bottom }) => ({
    left: left - edgePadding, right: right + edgePadding,
    top: top - edgePadding, bottom: bottom + edgePadding,
  }));
  if (previous) {
    for (const room of bodies) carryMotion(room, previous, bodies, obstacles, width, height);
  }
  let time = previous?.elapsed ?? 0;
  let activeGrab = null;

  function grab(slot, peer, x, y) {
    const room = rooms.get(slot);
    if (!room || activeGrab || !Number.isFinite(x) || !Number.isFinite(y)) return false;
    const body = peer == null ? room : room.points[peer];
    if (!body) return false;
    activeGrab = {
      slot, peer: peer ?? null, x, y,
      offsetX: x - (peer == null ? body.x : room.x + body.x),
      offsetY: y - (peer == null ? body.y : room.y + body.y),
    };
    return true;
  }

  function move(x, y) {
    if (!activeGrab || !Number.isFinite(x) || !Number.isFinite(y)) return;
    activeGrab.x = x;
    activeGrab.y = y;
  }

  function release({ cancel = false } = {}) {
    if (!activeGrab) return;
    const room = rooms.get(activeGrab.slot);
    const body = activeGrab.peer == null ? room : room.points[activeGrab.peer];
    limitSpeed(body, cancel ? 0 : tuning.throwSpeed);
    activeGrab = null;
  }

  function step() {
    const dt = STEP_SECONDS;
    time += dt;
    const damping = Math.exp(-tuning.roomDrag * dt);
    for (const room of bodies) {
      const held = activeGrab?.slot === room.slot && activeGrab.peer == null;
      if (held) followPointer(room, activeGrab.x - activeGrab.offsetX, activeGrab.y - activeGrab.offsetY, maxRoomSpeed);
      else {
        const phase = time * room.rate + room.phase;
        const tideX = Math.sin(phase) * tuning.drift;
        const tideY = Math.cos(phase * .79 + room.phase) * tuning.drift * .73;
        room.vx = room.vx * damping + clamp((room.homeX + tideX - room.x) * tuning.home, -180, 180) * dt;
        room.vy = room.vy * damping + clamp((room.homeY + tideY - room.y) * tuning.home, -180, 180) * dt;
      }
      limitSpeed(room, maxRoomSpeed);
      sweepRoom(room, 'x', room.vx * dt, width, obstacles, bodies, tuning, held);
      sweepRoom(room, 'y', room.vy * dt, height, obstacles, bodies, tuning, held);
      advancePeers(room, activeGrab?.slot === room.slot ? activeGrab : null, tuning, time);
    }
  }

  return {
    rooms, step, grab, move, release,
    get activeGrab() { return activeGrab; },
    get elapsed() { return time; },
  };
}
