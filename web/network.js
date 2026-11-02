import { forwardingEnabled } from './group-quality.js';
import { treeParent } from './group-video.js';

const NS = 'http://www.w3.org/2000/svg';
const example = [2, 6, 3, 8, 4, 5, 6, 3];
const colors = ['#557f6d', '#a47664', '#6d86a2', '#92865c', '#76896b', '#8b7a95'];
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
// These bounds include the orbit, two caption lines, halo, rotation and the full
// drift envelope. They are CSS pixels, just like the measured copy rectangles.
export function roomBounds(x, y, radius) {
  const half = Math.max(radius + 15, 51) + 18;
  return { left: x - half, right: x + half, top: y - radius - 33, bottom: y + radius + 61 };
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
    const radii = [...new Set([nominal, Math.round(nominal * .82), Math.round(nominal * .66), minimum].filter(r => r >= minimum))];
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

function animateSignal(dot, from, to, depth, index) {
  const start = .09 + (depth - 1) * .33, end = start + .29, at = p => `translate(${p.x}px, ${p.y}px)`;
  dot.animate([{ transform: at(from), opacity: 0, offset: 0 }, { transform: at(from), opacity: 0, offset: start }, { transform: at(from), opacity: .65, offset: start + .025 }, { transform: at(to), opacity: .65, offset: end - .025 }, { transform: at(to), opacity: 0, offset: end }, { transform: at(to), opacity: 0, offset: 1 }], { duration: 6500 + index * 310, delay: -index * 710, iterations: Infinity, easing: 'linear' });
}
const cancelTree = node => { for (const animation of node.getAnimations({ subtree: true })) animation.cancel(); };
function shapeFor(peers, radius, index) {
  const topology = graphTopology(peers), color = colors[index % colors.length], shape = make('g', { class: 'room-shape' });
  const nodeRadius = Math.max(3.4, Math.min(8, radius * .077)), rotation = index * .77 + .4;
  const points = Array.from({ length: peers }, (_, n) => {
    if (topology.forwarding) {
      if (n === 0) return { x: -radius * .83, y: 0 };
      if (n <= 4) return { x: -radius * .04, y: ((n - 1) / 3 * 1.55 - .775) * radius };
      const leaves = peers - 5;
      return { x: radius * .83, y: leaves === 1 ? 0 : ((n - 5) / (leaves - 1) * 1.7 - .85) * radius };
    }
    const angle = rotation + n * 2 * Math.PI / peers, r = peers === 1 ? 0 : radius * (.68 + ((n * 7 + index) % 4) * .085);
    return { x: Math.cos(angle) * r, y: Math.sin(angle) * r };
  });
  shape.append(make('circle', { class: 'room-orbit', r: radius + 12, stroke: color }));
  const links = make('g', { class: 'room-links' }); links.style.setProperty('--breath-delay', `${-index * .8}s`);
  for (const [a, b] of topology.mesh) links.append(make('line', { class: `room-edge${topology.forwarding ? ' audio-edge' : ''}`, x1: points[a].x, y1: points[a].y, x2: points[b].x, y2: points[b].y, stroke: color }));
  shape.append(links);
  if (topology.forwarding) for (const [a, b] of topology.routes) shape.append(make('line', { class: 'video-route', x1: points[a].x, y1: points[a].y, x2: points[b].x, y2: points[b].y, stroke: color }));
  for (const [a, b] of topology.routes) {
    const dot = make('circle', { class: 'room-signal', r: Math.max(1.4, radius * .026), fill: color, 'aria-hidden': 'true' });
    shape.append(dot); animateSignal(dot, points[a], points[b], topology.depth[b], index);
  }
  points.forEach((point, n) => {
    const node = make('g', { class: `peer-point${n === 0 ? ' video-source' : ''}${topology.forwarders.has(n) ? ' forwarding-peer' : ''}`, transform: `translate(${point.x} ${point.y})` });
    const halo = make('circle', { class: 'node-halo', r: nodeRadius + 3, stroke: color });
    halo.style.setProperty('--pulse-delay', `${-index * .7 - n * .43}s`); halo.style.setProperty('--pulse-period', `${4.6 + n % 4 * .6}s`);
    node.append(halo, make('circle', { class: 'room-node', r: nodeRadius, stroke: color }));
    if (topology.forwarders.has(n)) node.append(make('circle', { class: 'forwarder-ring', r: nodeRadius + 3, stroke: color }));
    if (n === 0) node.append(make('circle', { class: 'node-core', r: nodeRadius * .48, fill: color }));
    shape.append(node);
  });
  const text = make('text', { class: 'room-caption', x: 0, y: radius + 30, 'text-anchor': 'middle' });
  const caption = make('tspan', { x: 0 }); caption.textContent = `${String(peers).padStart(2, '0')} ${peers === 1 ? 'PEER' : 'PEERS'}`; text.append(caption);
  if (topology.forwarding) { const detail = make('tspan', { class: 'room-route-caption', x: 0, dy: 12 }); detail.textContent = 'VIDEO VIA PEERS'; text.append(detail); }
  shape.append(text);
  return { shape, topology };
}

function mount() {
  const host = document.getElementById('room-network'), home = document.getElementById('auth-view'); if (!host || !home) return;
  const hero = host.parentElement, copy = hero.querySelector('.network-copy'), footer = hero.querySelector('.network-footer');
  const state = document.getElementById('network-state'), count = document.getElementById('network-count'), mode = document.getElementById('network-mode'), motion = document.getElementById('network-motion');
  const focus = document.createElement('p'); focus.className = 'network-focus-text'; focus.setAttribute('aria-live', 'polite'); copy.append(focus);
  const reduce = matchMedia('(prefers-reduced-motion: reduce)'), scenes = new Map(), exampleCounts = [...example], trends = example.map((n, i) => i % 2 ? -1 : 1);
  let paused = false, distribution = null, unavailable = false, exampleMode = false, timer, request, generation = 0, active = false, onscreen = true, exampleTimer, exampleTick = 0, frame, geometrySignature = '';
  const svg = make('svg', { role: 'group', preserveAspectRatio: 'none' }), defs = make('defs'), mask = make('mask', { id: 'network-copy-mask', maskUnits: 'userSpaceOnUse' });
  const background = make('rect', { fill: 'white' }), safeArea = make('g', { mask: 'url(#network-copy-mask)' }); mask.append(background); defs.append(mask); svg.append(defs, safeArea); host.replaceChildren(svg);
  const isLive = () => !!distribution?.total && !exampleMode;
  const isStill = () => paused || reduce.matches || document.hidden || !onscreen || home.hidden;
  function scheduleExample() {
    if (isStill() || !active || isLive()) { clearTimeout(exampleTimer); exampleTimer = undefined; return; }
    if (exampleTimer || !scenes.size) return;
    exampleTimer = setTimeout(() => {
      exampleTimer = undefined;
      const visible = [...scenes.keys()], slot = visible[exampleTick % visible.length];
      if (isStill() || !active || isLive() || slot == null) return;
      if (exampleCounts[slot] <= 2) trends[slot] = 1;
      if (exampleCounts[slot] >= 8) trends[slot] = -1;
      exampleCounts[slot] += trends[slot]; host.dataset.exampleStep = String(++exampleTick); render(); scheduleExample();
    }, 6800);
  }
  function updateMotion() {
    const still = isStill(); host.classList.toggle('network-still', still);
    for (const animation of host.getAnimations({ subtree: true })) {
      if (reduce.matches && animation.effect.getTiming().iterations !== Infinity) { try { animation.finish(); } catch {} }
      else if (still) animation.pause(); else if (animation.playState === 'paused') animation.play();
    }
    motion.disabled = reduce.matches; motion.setAttribute('aria-pressed', String(still));
    motion.setAttribute('aria-label', reduce.matches ? 'Network motion disabled by your reduced-motion preference' : paused ? 'Resume network motion' : 'Pause network motion'); motion.textContent = still ? '▷' : 'Ⅱ'; scheduleExample();
  }
  function exclusions() {
    const origin = host.getBoundingClientRect(), rects = [], sx = host.clientWidth / origin.width, sy = host.clientHeight / origin.height;
    const add = rect => { if (rect.width && rect.height) rects.push({ left: (rect.left - origin.left) * sx, right: (rect.right - origin.left) * sx, top: (rect.top - origin.top) * sy, bottom: (rect.bottom - origin.top) * sy }); };
    // Measure line boxes, not a breakpoint or a guessed headline width.
    for (const element of copy.querySelectorAll('.network-eyebrow,h1,.network-description,.network-fine')) {
      const range = document.createRange(); range.selectNodeContents(element);
      for (const rect of range.getClientRects()) add(rect);
    }
    for (const button of copy.querySelectorAll('.network-actions button')) add(button.getBoundingClientRect());
    add(footer.getBoundingClientRect());
    // Reserve the short explanation even when it is empty, so keyboard or hover
    // never moves a graph into the copy while the text is being read.
    add(focus.getBoundingClientRect());
    return rects;
  }
  function describe(scene) {
    const { peers, topology } = scene;
    focus.textContent = `${peers} ${peers === 1 ? 'peer' : 'peers'}. ${peers === 1 ? 'A place for someone else to join.' : topology.forwarding ? 'Video can pass through another peer. Audio stays direct.' : `${topology.mesh.length} illustrated peer connections.`} ${isLive() ? 'Anonymous room size.' : 'An example, not a live room.'}`;
  }
  function newScene(slot) {
    const root = make('g', { class: 'room-cluster', tabindex: 0, role: 'button', 'data-slot': slot }), drift = make('g', { class: 'room-float' });
    drift.style.setProperty('--room-period', `${13 + slot * 1.2}s`); drift.style.setProperty('--room-delay', `${-slot * 1.7}s`); root.append(drift);
    const scene = { root, drift, peers: 0, radius: 0, topology: null, layers: new Set() };
    root.addEventListener('pointerenter', () => describe(scene)); root.addEventListener('focus', () => describe(scene)); root.addEventListener('click', () => describe(scene));
    root.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); describe(scene); } });
    root.addEventListener('blur', () => { focus.textContent = ''; }); root.addEventListener('pointerleave', () => { if (document.activeElement !== root) focus.textContent = ''; });
    safeArea.append(root); scenes.set(slot, scene); return scene;
  }
  function replaceShape(scene, peers, radius, slot, immediate = false) {
    const previous = [...scene.layers], next = shapeFor(peers, radius, slot);
    scene.peers = peers; scene.radius = radius; scene.topology = next.topology;
    scene.root.dataset.peers = String(peers); scene.root.dataset.topology = next.topology.forwarding ? 'forwarding' : 'direct';
    scene.root.setAttribute('aria-label', `${isLive() ? 'Shared room size' : 'Example room'}: ${peers} ${peers === 1 ? 'peer' : 'peers'}. ${next.topology.forwarding ? 'Video forwarding illustrated; audio stays direct.' : `${next.topology.mesh.length} illustrated direct connections.`}`);
    scene.currentShape = next.shape; scene.layers.add(next.shape); scene.drift.append(next.shape);
    if (!immediate && !isStill()) next.shape.animate([{ opacity: 0, transform: 'scale(.94)' }, { opacity: 1, transform: 'scale(1)' }], { duration: 650, easing: 'cubic-bezier(.2,.7,.2,1)' });
    for (const old of previous) {
      const retire = () => { cancelTree(old); old.remove(); scene.layers.delete(old); };
      if (immediate || isStill() || scene.layers.size > 3) retire();
      else old.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 320 }).finished.catch(() => {}).then(retire);
    }
  }
  function render() {
    const width = host.clientWidth, height = host.clientHeight; if (!width || !height) { updateMotion(); return; }
    const live = isLive(), limit = width <= 700 ? 6 : 8, rooms = live ? sampledRooms(distribution, limit) : exampleCounts.slice(0, limit), blocked = exclusions();
    const geometry = JSON.stringify([width, height, blocked]), moved = geometry !== geometrySignature; geometrySignature = geometry;
    const layout = layoutRooms(width, height, blocked, rooms);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`); svg.setAttribute('aria-label', live ? 'Shared room patterns' : 'Example room patterns');
    for (const [name, value] of Object.entries({ x: 0, y: 0, width, height })) { mask.setAttribute(name, value); background.setAttribute(name, value); }
    for (const old of [...mask.children].slice(1)) old.remove();
    for (const rect of blocked) { const b = expand(rect, 8); mask.append(make('rect', { x: b.left, y: b.top, width: b.right - b.left, height: b.bottom - b.top, rx: 8, fill: 'black' })); }
    const visible = new Set(layout.map(room => room.slot));
    for (const [slot, scene] of scenes) if (!visible.has(slot)) { if (document.activeElement === scene.root) { (motion.disabled ? document.getElementById('network-create') : motion).focus({ preventScroll: true }); focus.textContent = ''; } cancelTree(scene.root); scene.root.remove(); scenes.delete(slot); }
    for (const room of layout) {
      const scene = scenes.get(room.slot) || newScene(room.slot), peers = rooms[room.slot];
      // Responsive moves are immediate: never animate a graph across the text.
      if (moved) for (const layer of [...scene.layers]) if (layer !== scene.currentShape) { cancelTree(layer); layer.remove(); scene.layers.delete(layer); }
      scene.root.setAttribute('transform', `translate(${room.x} ${room.y})`);
      if (scene.peers !== peers || scene.radius !== room.radius) replaceShape(scene, peers, room.radius, room.slot, moved || scene.radius !== room.radius);
      scene.root.setAttribute('aria-label', `${live ? 'Shared room size' : 'Example room'}: ${peers} ${peers === 1 ? 'peer' : 'peers'}. ${scene.topology.forwarding ? 'Video forwarding illustrated; audio stays direct.' : `${scene.topology.mesh.length} illustrated direct connections.`}`);
    }
    host.dataset.source = live ? 'live' : 'example'; host.dataset.visibleRooms = String(layout.length);
    host.setAttribute('aria-label', live ? 'Anonymous live room sizes, with illustrated peer connections' : 'Illustration of peer-to-peer rooms; not live activity');
    state.textContent = live ? 'Live room shapes' : 'P2P, illustrated'; state.dataset.live = String(live);
    count.textContent = unavailable ? 'Live activity unavailable · showing an example' : distribution?.total ? `${distribution.total} opt-in ${distribution.total === 1 ? 'room' : 'rooms'} · ${distribution.peers} ${distribution.peers === 1 ? 'peer' : 'peers'}${distribution.total > layout.length ? ' · a selection shown' : ''}` : 'No rooms sharing activity right now';
    mode.hidden = !distribution?.total; mode.textContent = exampleMode ? 'See live rooms' : 'See an example'; mode.setAttribute('aria-pressed', String(exampleMode)); updateMotion();
  }
  function scheduleLayout() { if (!frame) frame = requestAnimationFrame(() => { frame = undefined; render(); }); }
  async function refresh() {
    if (!active) return;
    const mine = ++generation, controller = new AbortController(); request = controller;
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch('/api/network', { credentials: 'omit', cache: 'no-store', signal: controller.signal }); if (!response.ok) throw Error('Unavailable');
      const value = roomDistribution(await response.json()); if (mine !== generation || !active) return;
      distribution = value; unavailable = false; render();
    } catch { if (mine !== generation || !active) return; distribution = null; unavailable = true; render(); }
    finally { clearTimeout(timeout); if (mine === generation) { request = null; if (active) timer = setTimeout(refresh, 15000); } }
  }
  function visibility() {
    const next = !home.hidden && !document.hidden && onscreen;
    if (next !== active) { active = next; if (active) refresh(); else { ++generation; clearTimeout(timer); request?.abort(); request = null; } }
    updateMotion();
  }
  motion.onclick = () => { paused = !paused; updateMotion(); };
  mode.onclick = () => { exampleMode = !exampleMode; focus.textContent = ''; render(); };
  reduce.addEventListener('change', updateMotion);
  new IntersectionObserver(([entry]) => { onscreen = entry.isIntersecting; visibility(); }, { threshold: 0 }).observe(hero);
  const resize = new ResizeObserver(scheduleLayout); resize.observe(host); resize.observe(copy); resize.observe(footer);
  new MutationObserver(() => { visibility(); scheduleLayout(); }).observe(home, { attributes: true, attributeFilter: ['hidden'] });
  document.addEventListener('visibilitychange', visibility); document.fonts?.ready.then(scheduleLayout); document.fonts?.addEventListener('loadingdone', scheduleLayout);
  render(); visibility();
}
if (typeof document !== 'undefined') mount();
