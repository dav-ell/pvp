import { forwardingEnabled } from './group-quality.js';
import { treeParent } from './group-video.js';
import { createField, STEP_SECONDS } from './network-physics.js';

const NS = 'http://www.w3.org/2000/svg';
const example = [2, 6, 3, 8, 4, 5, 6, 3];
const colors = ['#367d68', '#b26655', '#5b79a7', '#947636', '#528664', '#8067a6'];
const noteTravelSeconds = .34;
const noteHandoffSeconds = .09;
const noteHopSeconds = noteTravelSeconds + noteHandoffSeconds;
const make = (tag, attributes = {}) => {
  const node = document.createElementNS(NS, tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, String(value));
  return node;
};

// Counts are the entire public model. No identifiable room or endpoint enters it.
export function roomDistribution(value) {
  if (value?.version !== 1 || value.connections !== 'illustrated' || !Array.isArray(value.rooms) || value.rooms.length > 16) throw Error('Room activity unavailable');
  const seen = new Set(); let total = 0, peers = 0;
  const rows = value.rooms.map(row => {
    if (!Number.isInteger(row.peers) || row.peers < 1 || row.peers > 16 || !Number.isInteger(row.count) || row.count < 1 || row.count > 256 || seen.has(row.peers)) throw Error('Room activity unavailable');
    seen.add(row.peers); total += row.count; peers += row.count * row.peers;
    return { peers: row.peers, count: row.count };
  });
  if (total > 256) throw Error('Room activity unavailable');
  return { rows: rows.sort((a, b) => a.peers - b.peers), total, peers };
}
export function sampledRooms(distribution, limit = 8) {
  const rows = distribution.rows.map(row => ({ ...row })), result = [];
  while (result.length < limit && rows.some(row => row.count > 0)) {
    for (const row of rows) if (row.count > 0 && result.length < limit) { result.push(row.peers); row.count--; }
  }
  return result;
}
export function graphTopology(peers) {
  if (!Number.isInteger(peers) || peers < 1 || peers > 16) throw Error('Invalid peer count');
  const ids = Array.from({ length: peers }, (_, i) => String(i).padStart(2, '0'));
  const mesh = [];
  for (let a = 0; a < peers; a++) for (let b = a + 1; b < peers; b++) mesh.push([a, b]);
  const forwarding = forwardingEnabled(peers);
  const routes = forwarding ? ids.slice(1).map(id => [ids.indexOf(treeParent(ids, ids[0], id)), ids.indexOf(id)]) : ids.slice(1).map((_, i) => [0, i + 1]);
  const depth = Array(peers).fill(0);
  for (const [parent, child] of routes) depth[child] = depth[parent] + 1;
  return { mesh, routes, depth, forwarding, forwarders: new Set(routes.filter(([parent]) => parent !== 0).map(([parent]) => parent)) };
}

export const intersects = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
const expand = (rect, padding) => ({ left: rect.left - padding, top: rect.top - padding, right: rect.right + padding, bottom: rect.bottom + padding });
// The same envelope covers paint and hit targets, including a stretched shell.
export function roomBounds(x, y, radius) {
  const half = Math.max(radius + 17, 49);
  return { left: x - half, right: x + half, top: y - radius - 17, bottom: y + radius + 45 };
}
export function layoutRooms(width, height, exclusions, rooms) {
  if (!(width > 0 && height > 0)) return [];
  const blocked = exclusions.map(rect => expand(rect, 16));
  const nominal = width > 1100 ? 82 : width > 800 ? 65 : 48;
  const anchors = [[.11,.25], [.89,.25], [.12,.72], [.88,.72], [.34,.08], [.66,.08], [.35,.87], [.65,.87]];
  const placed = [];
  for (let slot = 0; slot < rooms.length; slot++) {
    const [ax, ay] = anchors[slot % anchors.length];
    const minimum = rooms[slot] > 10 ? 48 : 28;
    const size = Math.round(nominal * (.75 + Math.min(rooms[slot], 10) * .028));
    const radii = [...new Set([size, Math.round(size * .82), Math.round(size * .66), minimum].filter(r => r >= minimum))];
    let best;
    for (const radius of radii) {
      const origin = roomBounds(0, 0, radius), left = 8 - origin.left, right = width - 8 - origin.right, top = 8 - origin.top, bottom = height - 8 - origin.bottom;
      if (right < left || bottom < top) continue;
      const xs = [left, right, Math.max(left, Math.min(right, width * ax))];
      const ys = [top, bottom, Math.max(top, Math.min(bottom, height * ay))];
      for (let x = left; x <= right; x += 24) xs.push(x);
      for (let y = top; y <= bottom; y += 24) ys.push(y);
      for (const x of xs) for (const y of ys) {
        const bounds = roomBounds(x, y, radius);
        if (blocked.some(rect => intersects(bounds, rect)) || placed.some(room => intersects(bounds, expand(room.bounds, 7)))) continue;
        const score = Math.hypot(x - width * ax, y - height * ay) + (nominal - radius) * 3.8;
        if (!best || score < best.score) best = { slot, x, y, radius, bounds, score };
      }
    }
    if (best) placed.push(best);
  }
  return placed;
}

const outlineDirections = Array.from({ length: 16 }, (_, index) => {
  const angle = index * 2 * Math.PI / 16;
  return { x: Math.cos(angle), y: Math.sin(angle), wave: Math.cos(angle * 3 + .4) * .045 };
});
const midpoint = (a, b) => `${(a.x + b.x) / 2} ${(a.y + b.y) / 2}`;
function bubblePath(room) {
  const { points, radius } = room;
  const outline = outlineDirections.map(({ x, y, wave }) => {
    const extent = Math.max(...points.map(point => point.x * x + point.y * y));
    const reach = Math.max(radius * (.66 + wave), extent + 13);
    return { x: x * reach, y: y * reach };
  });
  return `M ${midpoint(outline.at(-1), outline[0])} ${outline.map((point, i) =>
    `Q ${point.x} ${point.y} ${midpoint(point, outline[(i + 1) % outline.length])}`).join(' ')} Z`;
}

function positionEdge(line, a, b) {
  line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
  line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
}

function shapeFor(peers, radius, slot) {
  const topology = graphTopology(peers);
  const color = colors[slot % colors.length];
  const shape = make('g', { class: 'room-shape', color, 'aria-hidden': 'true' });
  const light = { x1: '12%', y1: '0%', x2: '85%', y2: '100%' };
  const gradient = make('linearGradient', { id: `bubble-${slot}`, ...light });
  gradient.append(make('stop', { offset: 0, 'stop-color': color, 'stop-opacity': .08 }),
    make('stop', { offset: .48, 'stop-color': color, 'stop-opacity': .17 }),
    make('stop', { offset: 1, 'stop-color': color, 'stop-opacity': .29 }));
  const rim = make('linearGradient', { id: `bubble-rim-${slot}`, ...light });
  rim.append(make('stop', { offset: 0, 'stop-color': color, 'stop-opacity': .4 }),
    make('stop', { offset: 1, 'stop-color': color }));
  const defs = make('defs'); defs.append(gradient, rim); shape.append(defs);
  const hull = make('path', { class: 'room-hull', fill: `url(#bubble-${slot})` });
  hull.style.setProperty('--bubble-rim', `url(#bubble-rim-${slot})`);
  shape.append(hull);
  const links = make('g', { class: 'room-links' });
  const edges = [];
  const edge = ([a, b], name) => {
    const line = make('line', { class: name });
    edges.push({ a, b, line }); links.append(line);
  };
  // Batch the quiet audio mesh so a dense room updates one SVG path per frame.
  const mesh = topology.forwarding ? make('path', { class: 'room-edge audio-edge' }) : null;
  if (mesh) links.append(mesh);
  else for (const pair of topology.mesh) edge(pair, 'room-edge');
  if (topology.forwarding) for (const pair of topology.routes) edge(pair, 'video-route');
  shape.append(links);
  const noteLayer = make('g', { class: 'room-notes' }); shape.append(noteLayer);
  const nodeRadius = Math.max(4.5, Math.min(8, radius * (peers > 10 ? .085 : .115)));
  const nodes = Array.from({ length: peers }, (_, index) => {
    const node = make('g', {
      class: `peer-point${index === 0 ? ' video-source' : ''}${topology.forwarders.has(index) ? ' forwarding-peer' : ''}`,
      'data-peer-index': index,
    });
    node.append(make('circle', { class: 'peer-hit', r: Math.max(13, nodeRadius + 4) }),
      make('circle', { class: 'room-node', r: nodeRadius }));
    if (topology.forwarders.has(index)) node.append(make('circle', { class: 'forwarder-ring', r: nodeRadius + 3 }));
    if (index === 0) node.append(make('circle', { class: 'node-core', r: nodeRadius * .39 }));
    shape.append(node);
    return node;
  });
  const text = make('text', { class: 'room-caption', x: 0, y: radius + 26, 'text-anchor': 'middle' });
  const caption = make('tspan', { x: 0 }); caption.textContent = `${peers} ${peers === 1 ? 'peer' : 'peers'}`; text.append(caption);
  if (topology.forwarding) {
    const detail = make('tspan', { class: 'room-route-caption', x: 0, dy: 12 });
    detail.textContent = 'Video via peers'; text.append(detail);
  }
  shape.append(text);
  return { shape, hull, edges, mesh, nodes, noteLayer, topology };
}

function noteRoutes(topology, peers, peer) {
  if (!topology.forwarding) {
    return Array.from({ length: peers }, (_, index) => index)
      .filter(index => index !== peer).map(index => [peer, index, 0]);
  }
  if (peer === 0) return topology.routes.map(([a, b]) => [a, b, topology.depth[b] - 1]);
  // The marked source owns the video tree. Trace its route to a selected peer.
  const path = [];
  while (peer !== 0) {
    const [parent] = topology.routes.find(([, child]) => child === peer);
    path.push([parent, peer, topology.depth[peer] - 1]);
    peer = parent;
  }
  return path.reverse();
}

function mount() {
  const host = document.getElementById('room-network'), home = document.getElementById('auth-view');
  if (!host || !home) return;
  const hero = host.parentElement, copy = hero.querySelector('.network-copy'), footer = hero.querySelector('.network-footer');
  const state = document.getElementById('network-state'), count = document.getElementById('network-count');
  const mode = document.getElementById('network-mode'), motion = document.getElementById('network-motion');
  const focus = document.createElement('p');
  focus.className = 'network-focus-text'; focus.setAttribute('aria-live', 'polite'); copy.append(focus);
  const reduce = matchMedia('(prefers-reduced-motion: reduce)'), scenes = new Map();
  const exampleCounts = [...example], trends = example.map((_, i) => i % 2 ? -1 : 1);
  const preset = new URLSearchParams(location.search).get('network-preset') === 'buoyant' ? 'buoyant' : 'elastic';
  host.dataset.preset = preset;
  let paused = false, distribution = null, unavailable = false, exampleMode = false;
  let timer, request, generation = 0, active = false, onscreen = true, exampleTimer, exampleTick = 0;
  let layoutFrame, motionFrame, previousTime, remainder = 0, layoutSignature = '';
  let field, gesture, selected, protectedAreas = [];
  const svg = make('svg', { role: 'group', preserveAspectRatio: 'none' });
  const mask = make('mask', { id: 'network-copy-mask', maskUnits: 'userSpaceOnUse' });
  const background = make('rect', { fill: 'white' });
  const safeArea = make('g', { mask: 'url(#network-copy-mask)' });
  const defs = make('defs'); mask.append(background); defs.append(mask); svg.append(defs, safeArea);
  host.replaceChildren(svg);

  const isLive = () => !!distribution?.total && !exampleMode;
  const isStill = () => paused || reduce.matches || !active;

  function scheduleExample() {
    if (isStill() || isLive()) { clearTimeout(exampleTimer); exampleTimer = undefined; return; }
    if (exampleTimer || !scenes.size || gesture) return;
    exampleTimer = setTimeout(() => {
      exampleTimer = undefined;
      const visible = [...scenes.keys()], slot = visible[exampleTick % visible.length];
      if (isStill() || isLive() || slot == null || gesture) return;
      if (exampleCounts[slot] <= 2) trends[slot] = 1;
      if (exampleCounts[slot] >= 8) trends[slot] = -1;
      exampleCounts[slot] += trends[slot]; host.dataset.exampleStep = String(++exampleTick);
      render(); scheduleExample();
    }, 6800);
  }

  function drawNote(scene, points) {
    if (!scene.note) return;
    const note = scene.note;
    for (const { a, b, hop, forwards, line, dot } of note.routes) {
      const time = note.elapsed - hop * noteHopSeconds;
      const from = points[a], to = points[b];
      const traveling = !note.static && time >= 0 && time < (forwards ? noteHopSeconds : noteTravelSeconds);
      line.classList.toggle('note-route-active', note.static || time >= 0);
      positionEdge(line, from, to);
      dot.toggleAttribute('hidden', !traveling);
      if (traveling) {
        const progress = Math.min(1, time / noteTravelSeconds);
        dot.setAttribute('cx', from.x + (to.x - from.x) * progress);
        dot.setAttribute('cy', from.y + (to.y - from.y) * progress);
      }
    }
  }

  function paint() {
    for (const [slot, room] of field?.rooms ?? []) {
      const scene = scenes.get(slot);
      scene.root.setAttribute('transform', `translate(${room.x} ${room.y})`);
      scene.hull.setAttribute('d', bubblePath(room));
      if (scene.mesh) scene.mesh.setAttribute('d', scene.topology.mesh.map(([a, b]) => {
        const from = room.points[a], to = room.points[b];
        return `M ${from.x} ${from.y} L ${to.x} ${to.y}`;
      }).join(' '));
      for (const { a, b, line } of scene.edges) positionEdge(line, room.points[a], room.points[b]);
      scene.nodes.forEach((node, index) => {
        const point = room.points[index];
        node.setAttribute('transform', `translate(${point.x} ${point.y})`);
      });
      drawNote(scene, room.points);
    }
  }

  function tick(now) {
    motionFrame = undefined;
    if (isStill() || !field?.rooms.size) return;
    remainder += previousTime == null ? STEP_SECONDS : Math.min(.05, (now - previousTime) / 1000);
    previousTime = now;
    while (remainder >= STEP_SECONDS) {
      field.step(); remainder -= STEP_SECONDS;
      const note = selected?.note;
      if (note && !note.static) {
        note.elapsed += STEP_SECONDS;
        if (note.elapsed > note.duration) {
          selected.noteLayer.replaceChildren(); selected.note = null;
        }
      }
    }
    paint();
    motionFrame = requestAnimationFrame(tick);
  }

  function updateMotion() {
    if (isStill()) {
      cancelAnimationFrame(motionFrame); motionFrame = undefined;
      previousTime = undefined; remainder = 0;
      endGesture(true);
      if (reduce.matches && selected?.note) {
        selected.note.static = true; paint();
      }
    } else if (motionFrame == null && field?.rooms.size) {
      motionFrame = requestAnimationFrame(tick);
    }
    motion.disabled = reduce.matches;
    motion.setAttribute('aria-pressed', String(paused || reduce.matches));
    motion.setAttribute('aria-label', reduce.matches ? 'Network motion disabled by your reduced-motion preference' : paused ? 'Resume network motion' : 'Pause network motion');
    motion.textContent = paused || reduce.matches ? '▷' : 'Ⅱ';
    scheduleExample();
  }

  function exclusions() {
    const origin = host.getBoundingClientRect(), rects = [];
    const sx = host.clientWidth / origin.width, sy = host.clientHeight / origin.height;
    const add = rect => {
      if (rect.width && rect.height) rects.push({
        left: (rect.left - origin.left) * sx, right: (rect.right - origin.left) * sx,
        top: (rect.top - origin.top) * sy, bottom: (rect.bottom - origin.top) * sy,
      });
    };
    for (const element of copy.querySelectorAll('.network-eyebrow,h1,.network-description,.network-fine')) {
      const range = document.createRange(); range.selectNodeContents(element);
      for (const rect of range.getClientRects()) add(rect);
    }
    for (const button of copy.querySelectorAll('.network-actions button')) add(button.getBoundingClientRect());
    add(footer.getBoundingClientRect()); add(focus.getBoundingClientRect());
    return rects;
  }

  function describe(scene) {
    const { peers, topology } = scene;
    const description = `${peers} ${peers === 1 ? 'peer' : 'peers'}. ${peers === 1 ? 'A place for someone else to join.' : topology.forwarding ? 'Video can pass through another peer. Audio stays direct.' : `${topology.mesh.length} illustrated peer connections.`} ${isLive() ? 'Anonymous room size.' : 'An example, not a live room.'}`;
    if (focus.textContent !== description) focus.textContent = description;
  }

  function activate(scene, peer = 0) {
    if (selected) {
      selected.root.classList.remove('room-selected');
      selected.noteLayer.replaceChildren(); selected.note = null;
    }
    selected = scene; scene.root.classList.add('room-selected');
    describe(scene);
    const path = noteRoutes(scene.topology, scene.peers, peer);
    const routes = path.map(([a, b, hop]) => {
      const line = make('line', { class: 'room-note-route', 'data-note-hop': hop });
      const dot = make('circle', { class: 'room-note', r: 3.6, hidden: '' });
      scene.noteLayer.append(line, dot);
      return { a, b, hop, forwards: path.some(([source]) => source === b), line, dot };
    });
    if (routes.length) {
      scene.note = { routes, elapsed: 0, static: isStill(), duration: noteHopSeconds * (1 + Math.max(...path.map(([, , hop]) => hop))) + .32 };
    }
    paint();
  }

  function pointerPoint(event) {
    const bounds = svg.getBoundingClientRect();
    return {
      x: (event.clientX - bounds.left) * host.clientWidth / bounds.width,
      y: (event.clientY - bounds.top) * host.clientHeight / bounds.height,
    };
  }

  function endGesture(cancel = false) {
    if (!gesture) return;
    const current = gesture;
    gesture = null;
    if (current.dragging) field.release({ cancel });
    current.scene.root.classList.remove('room-grabbed');
    if (current.scene.root.hasPointerCapture(current.id)) current.scene.root.releasePointerCapture(current.id);
    if (!cancel && !current.dragging) activate(current.scene, current.peer ?? 0);
    scheduleExample();
  }

  function newScene(slot) {
    const root = make('g', { class: 'room-cluster', tabindex: 0, role: 'button', 'data-slot': slot });
    const scene = { root };
    root.addEventListener('pointerenter', () => { if (!gesture) describe(scene); });
    root.addEventListener('pointerleave', () => {
      if (gesture || document.activeElement === root) return;
      if (selected) describe(selected); else focus.textContent = '';
    });
    root.addEventListener('focus', () => describe(scene));
    root.addEventListener('blur', () => { if (selected !== scene) focus.textContent = ''; });
    root.addEventListener('click', event => { if (event.detail === 0) activate(scene); });
    root.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault(); if (!event.repeat) activate(scene);
      }
    });
    root.addEventListener('pointerdown', event => {
      if (gesture || event.button !== 0 || !event.isPrimary) return;
      const start = pointerPoint(event);
      if (protectedAreas.some(rect => start.x >= rect.left && start.x <= rect.right && start.y >= rect.top && start.y <= rect.bottom)) return;
      const peer = event.target.closest('.peer-point')?.dataset.peerIndex;
      gesture = { id: event.pointerId, scene, peer: peer == null ? null : Number(peer), start, dragging: false, touch: event.pointerType === 'touch' };
      root.setPointerCapture(event.pointerId);
    });
    root.addEventListener('pointermove', event => {
      if (gesture?.id !== event.pointerId) return;
      const point = pointerPoint(event);
      if (!gesture.dragging) {
        const dx = point.x - gesture.start.x, dy = point.y - gesture.start.y;
        if (Math.hypot(dx, dy) < (gesture.touch ? 8 : 5)) return;
        if (isStill() || (gesture.touch && Math.abs(dy) > Math.abs(dx))) { endGesture(true); return; }
        gesture.dragging = field.grab(slot, gesture.peer, gesture.start.x, gesture.start.y) !== false;
        if (!gesture.dragging) { endGesture(true); return; }
        root.classList.add('room-grabbed');
      }
      field.move(point.x, point.y);
    });
    root.addEventListener('pointerup', event => { if (gesture?.id === event.pointerId) endGesture(); });
    for (const type of ['pointercancel', 'lostpointercapture']) {
      root.addEventListener(type, event => { if (gesture?.id === event.pointerId) endGesture(true); });
    }
    safeArea.append(root); scenes.set(slot, scene);
    return scene;
  }

  function render() {
    const width = host.clientWidth, height = host.clientHeight;
    if (!width || !height) { updateMotion(); return; }
    const live = isLive(), limit = width <= 700 ? 6 : 8;
    const rooms = live ? sampledRooms(distribution, limit) : exampleCounts.slice(0, limit);
    const blocked = exclusions();
    const signature = JSON.stringify([width, height, blocked, rooms]);
    if (signature !== layoutSignature) {
      layoutSignature = signature; endGesture(true);
      const layout = layoutRooms(width, height, blocked, rooms);
      protectedAreas = blocked.map(rect => expand(rect, 8));
      svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
      for (const [name, value] of Object.entries({ x: 0, y: 0, width, height })) {
        mask.setAttribute(name, value); background.setAttribute(name, value);
      }
      mask.replaceChildren(background, ...protectedAreas.map(b => make('rect', {
        x: b.left, y: b.top, width: b.right - b.left, height: b.bottom - b.top, rx: 8, fill: 'black',
      })));
      const visible = new Set(layout.map(room => room.slot));
      for (const [slot, scene] of scenes) {
        if (visible.has(slot)) continue;
        if (selected === scene) { selected = null; focus.textContent = ''; }
        if (document.activeElement === scene.root) {
          (reduce.matches ? document.getElementById('network-create') : motion).focus({ preventScroll: true });
          focus.textContent = '';
        }
        scene.root.remove(); scenes.delete(slot);
      }
      for (const { slot, radius } of layout) {
        const scene = scenes.get(slot) || newScene(slot), peers = rooms[slot];
        if (scene.peers !== peers || scene.radius !== radius) {
          Object.assign(scene, shapeFor(peers, radius, slot), { peers, radius, note: null });
          scene.root.replaceChildren(scene.shape);
          scene.root.dataset.peers = String(peers);
          scene.root.dataset.topology = scene.topology.forwarding ? 'forwarding' : 'direct';
        }
      }
      field = createField(width, height, blocked, layout.map(room => ({ ...room, peers: rooms[room.slot] })), { preset, previous: field });
      paint();
    }
    for (const scene of scenes.values()) {
      scene.root.setAttribute('aria-label', `${live ? 'Shared room size' : 'Example room'}: ${scene.peers} ${scene.peers === 1 ? 'peer' : 'peers'}. ${scene.peers > 1 ? 'Activate to send an illustrated note.' : ''}`.trim());
    }
    const described = [...scenes.values()].find(scene => scene.root === document.activeElement) ?? selected;
    if (described) describe(described);
    host.dataset.source = live ? 'live' : 'example';
    host.dataset.visibleRooms = String(scenes.size);
    svg.setAttribute('aria-label', live ? 'Shared room patterns' : 'Example room patterns');
    host.setAttribute('aria-label', live ? 'Anonymous live room sizes, with illustrated peer connections' : 'Illustration of peer-to-peer rooms; not live activity');
    state.textContent = live ? 'Live room shapes' : 'P2P, illustrated'; state.dataset.live = String(live);
    count.textContent = unavailable ? 'Live activity unavailable · showing an example' : distribution?.total ? `${distribution.total} opt-in ${distribution.total === 1 ? 'room' : 'rooms'} · ${distribution.peers} ${distribution.peers === 1 ? 'peer' : 'peers'}${distribution.total > scenes.size ? ' · a selection shown' : ''}` : 'No rooms sharing activity right now';
    mode.hidden = !distribution?.total; mode.textContent = exampleMode ? 'See live rooms' : 'See an example';
    mode.setAttribute('aria-pressed', String(exampleMode)); updateMotion();
  }

  function scheduleLayout() {
    if (!layoutFrame) layoutFrame = requestAnimationFrame(() => { layoutFrame = undefined; render(); });
  }

  async function refresh() {
    if (!active) return;
    const mine = ++generation, controller = new AbortController(); request = controller;
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch('/api/network', { credentials: 'omit', cache: 'no-store', signal: controller.signal });
      if (!response.ok) throw Error('Unavailable');
      const value = roomDistribution(await response.json()); if (mine !== generation || !active) return;
      distribution = value; unavailable = false; render();
    } catch {
      if (mine !== generation || !active) return;
      distribution = null; unavailable = true; render();
    } finally {
      clearTimeout(timeout);
      if (mine === generation) { request = null; if (active) timer = setTimeout(refresh, 15000); }
    }
  }

  function visibility() {
    const next = !home.hidden && !document.hidden && onscreen;
    if (next !== active) {
      active = next;
      if (active) refresh();
      else { ++generation; clearTimeout(timer); request?.abort(); request = null; }
    }
    updateMotion();
  }

  motion.onclick = () => { paused = !paused; updateMotion(); };
  mode.onclick = () => {
    exampleMode = !exampleMode; focus.textContent = '';
    if (selected) {
      selected.root.classList.remove('room-selected');
      selected.noteLayer.replaceChildren(); selected.note = null; selected = null;
    }
    render();
  };
  reduce.addEventListener('change', updateMotion);
  new IntersectionObserver(([entry]) => { onscreen = entry.isIntersecting; visibility(); }).observe(hero);
  const resize = new ResizeObserver(scheduleLayout);
  resize.observe(host); resize.observe(copy); resize.observe(footer);
  new MutationObserver(() => { visibility(); scheduleLayout(); }).observe(home, { attributes: true, attributeFilter: ['hidden'] });
  document.addEventListener('visibilitychange', visibility);
  document.fonts?.ready.then(scheduleLayout); document.fonts?.addEventListener('loadingdone', scheduleLayout);
  render(); visibility();
}
if (typeof document !== 'undefined') mount();
