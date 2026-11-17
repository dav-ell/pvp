import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { chromium, webkit } from 'playwright';

const engines = { chromium, webkit };
const { values: options } = parseArgs({
  options: {
    root: { type: 'string', default: fileURLToPath(new URL('..', import.meta.url)) },
    out: { type: 'string', default: '.build/network-harness' },
    browser: { type: 'string', default: 'chromium' },
    preset: { type: 'string', default: 'elastic' },
  },
});
const root = resolve(options.root);
const output = resolve(options.out);
const browsers = options.browser === 'both' ? Object.keys(engines) : [options.browser];
assert.ok(browsers.every(name => Object.hasOwn(engines, name)), 'Choose chromium, webkit or both.');

const presets = options.preset === 'both' ? ['elastic', 'buoyant'] : [options.preset];
assert.ok(presets.every(name => ['elastic', 'buoyant', 'baseline'].includes(name)),
  'Choose elastic, buoyant, both or baseline.');

const origin = 'http://127.0.0.1';
const desktop = { width: 1440, height: 1000 };
const fixtures = [
  { name: 'desktop-example', viewport: desktop, rooms: [] },
  { name: 'desktop-dense', viewport: desktop, rooms: [{ peers: 3, count: 2 }, { peers: 8, count: 3 }, { peers: 16, count: 3 }] },
  { name: 'touch', viewport: { width: 390, height: 844 }, rooms: [], touch: true },
  { name: 'reduced-motion', viewport: desktop, rooms: [], reduced: true },
];

async function fixtureRoute(route, rooms) {
  const url = new URL(route.request().url());
  if (url.origin !== origin) return route.abort();
  if (url.pathname === '/api/network') {
    return route.fulfill({ json: { version: 1, connections: 'illustrated', rooms } });
  }
  if (url.pathname.startsWith('/api/')) return route.fulfill({ status: 401, json: { error: 'Sign in required' } });
  const path = url.pathname === '/' ? '/index.html' : url.pathname;
  const parts = decodeURIComponent(path).split('/').slice(1);
  if (parts.some(part => part === '..' || part.includes('\\'))) return route.abort();
  const directory = parts[0] === 'packages' ? root : join(root, 'web');
  await route.fulfill({ path: join(directory, ...parts) });
}

async function measure(page) {
  return page.evaluate(() => {
    const host = document.querySelector('#room-network');
    const rect = element => {
      const { x, y, width, height } = element.getBoundingClientRect();
      return { x, y, width, height };
    };
    const center = element => {
      const { x, y, width, height } = rect(element);
      return { x: x + width / 2, y: y + height / 2 };
    };
    const protectedRects = [...document.querySelectorAll(
      '.network-eyebrow, #network-heading, .network-description, .network-fine',
    )].flatMap(element => {
      const range = document.createRange();
      range.selectNodeContents(element);
      return [...range.getClientRects()];
    });
    for (const element of document.querySelectorAll('.network-actions button, .network-focus-text, .network-footer')) {
      protectedRects.push(element.getBoundingClientRect());
    }
    const rooms = [...host.querySelectorAll('.room-cluster')].map(room => {
      const hull = room.querySelector('.room-hull') || room;
      const bounds = hull.getBoundingClientRect();
      const visibleNote = [...room.querySelectorAll('.room-note')].some(note => note.getBoundingClientRect().width > 0 &&
        getComputedStyle(note).visibility !== 'hidden' && getComputedStyle(note).display !== 'none' &&
        Number(getComputedStyle(note).opacity) > 0);
      const shape = [...room.querySelectorAll('.room-shape')].at(-1);
      return {
        slot: room.dataset.slot, peers: Number(room.dataset.peers), bounds: rect(hull),
        nodes: [...(shape?.querySelectorAll('.room-node') ?? [])].map(center),
        visibleNote,
        highlightedRoutes: room.querySelectorAll('.note-route-active').length,

        protectedOverlap: protectedRects.some(other =>
          other.width && other.height && bounds.left < other.right &&
          bounds.right > other.left && bounds.top < other.bottom && bounds.bottom > other.top),
      };
    });
    return {
      source: host.dataset.source,
      roomCountText: document.querySelector('#network-count').textContent,
      focusText: document.querySelector('.network-focus-text').textContent,
      motionDisabled: document.querySelector('#network-motion').disabled,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth,
      protectedRects: protectedRects.filter(rect => rect.width && rect.height)
        .map(({ x, y, width, height }) => ({ x, y, width, height })),
      field: rect(host),
      renderedPreset: host.dataset.preset,
      rooms,
    };
  });
}

async function dragTarget(page) {
  return page.evaluate(() => {
    const rooms = [...document.querySelectorAll('#room-network .room-cluster')]
      .sort((a, b) => Number(b.dataset.peers) - Number(a.dataset.peers));
    for (const room of rooms) {
      const shape = [...room.querySelectorAll('.room-shape')].at(-1);
      const nodes = [...(shape?.querySelectorAll('.room-node') ?? [])];
      for (const [index, node] of nodes.entries()) {
        const bounds = node.getBoundingClientRect();
        const x = bounds.x + bounds.width / 2, y = bounds.y + bounds.height / 2;
        const hit = document.elementFromPoint(x, y);
        const peer = node.closest('.peer-point');
        if (hit && room.contains(hit) && (!peer || hit.closest('.peer-point') === peer)) {
          return { x, y, slot: room.dataset.slot, index };
        }
      }
    }
    return null;
  });
}

async function hullTargets(page) {
  return page.evaluate(() => {
    const targets = [];
    for (const hull of document.querySelectorAll('#room-network .room-hull')) {
      const bounds = hull.getBoundingClientRect();
      const slot = hull.closest('.room-cluster').dataset.slot;
      for (const u of [.25, .4, .6, .75]) {
        for (const v of [.25, .4, .6, .75]) {
          const x = bounds.x + bounds.width * u, y = bounds.y + bounds.height * v;
          if (document.elementFromPoint(x, y) === hull) targets.push({ x, y, slot });
        }
      }
    }
    return targets;
  });
}

const length = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
const pixels = value => Math.round(value * 100) / 100;
const roomAt = (frame, slot) => frame?.rooms.find(room => room.slot === slot);
const center = ({ x, y, width, height }) => ({ x: x + width / 2, y: y + height / 2 });

function hullDrag(frame, targets) {
  const { field, protectedRects } = frame;
  const width = Math.min(field.width, desktop.width);
  const bottom = Math.min(field.y + field.height, desktop.height);
  const intersects = (a, b) => a.x < b.x + b.width && a.x + a.width > b.x &&
    a.y < b.y + b.height && a.y + a.height > b.y;
  for (const start of targets) {
    const bounds = roomAt(frame, start.slot)?.bounds;
    if (!bounds) continue;
    for (const [dx, dy] of [[72, 0], [-72, 0], [0, 72], [0, -72]]) {
      const clear = [.33, .66, 1].every(progress => {
        const rect = { ...bounds, x: bounds.x + dx * progress, y: bounds.y + dy * progress };
        return rect.x >= field.x + 8 && rect.x + rect.width <= field.x + width - 8 &&
          rect.y >= field.y + 8 && rect.y + rect.height <= bottom - 8 &&
          !protectedRects.some(protectedRect => intersects(rect, protectedRect));
      });
      if (clear) return { start, end: { x: start.x + dx, y: start.y + dy }, moveMs: 160 };
    }
  }
  return null;
}

async function drag(page, { start, end, moveMs }) {
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  for (let step = 1; step <= 10; step++) {
    await page.mouse.move(start.x + (end.x - start.x) * step / 10, start.y + (end.y - start.y) * step / 10);
    await page.clock.runFor(moveMs / 10);
  }
}

function imageRegion(viewport, ...rects) {
  const x = Math.max(0, Math.floor(Math.min(...rects.map(rect => rect.x))) - 8);
  const y = Math.max(0, Math.floor(Math.min(...rects.map(rect => rect.y))) - 8);
  const right = Math.min(viewport.width, Math.ceil(Math.max(...rects.map(rect => rect.x + rect.width))) + 8);
  const bottom = Math.min(viewport.height, Math.ceil(Math.max(...rects.map(rect => rect.y + rect.height))) + 8);
  return { x, y, width: right - x, height: bottom - y };
}

// Decode screenshots in the browser to keep the harness dependency-free.
// The difference image retains the region's context and marks changed pixels in coral.
async function comparePixels(page, directory, shots, frames, viewport, { name, before, after, slot }) {
  const a = roomAt(frames[before], slot), b = roomAt(frames[after], slot);
  if (!a || !b) return null;
  const clip = imageRegion(viewport, a.bounds, b.bounds);
  if (clip.width <= 0 || clip.height <= 0) return null;
  const { dataUrl, ...result } = await page.evaluate(async ({ shots, clip }) => {
    const canvas = document.createElement('canvas');
    canvas.width = clip.width;
    canvas.height = clip.height;
    const context = canvas.getContext('2d', { willReadFrequently: true });
    const images = await Promise.all(shots.map(async shot => {
      const image = new Image();
      image.src = 'data:image/png;base64,' + shot;
      await image.decode();
      return image;
    }));
    const [a, b] = images.map(image => {
      context.drawImage(image, -clip.x, -clip.y);
      return context.getImageData(0, 0, clip.width, clip.height);
    });
    let changedPixels = 0;
    for (let i = 0; i < a.data.length; i += 4) {
      const difference = Math.max(
        Math.abs(a.data[i] - b.data[i]),
        Math.abs(a.data[i + 1] - b.data[i + 1]),
        Math.abs(a.data[i + 2] - b.data[i + 2]),
      );
      if (difference >= 12) {
        b.data.set([255, 75, 115, 255], i);
        changedPixels++;
      } else {
        for (let channel = 0; channel < 3; channel++) b.data[i + channel] = (b.data[i + channel] + 255) / 2;
      }
    }
    context.putImageData(b, 0, 0);
    return { dataUrl: canvas.toDataURL(), changedPixels, totalPixels: clip.width * clip.height };
  }, { shots: [shots[before], shots[after]], clip });
  const filename = 'diff-' + name + '.png';
  await writeFile(join(directory, filename), Buffer.from(dataUrl.split(',')[1], 'base64'));
  return { ...result, clip, filename };
}

function graphTravel(a, b) {
  return pixels(Math.max(0, ...a.rooms.flatMap(room => {
    const next = roomAt(b, room.slot);
    if (!next || next.nodes.length !== room.nodes.length) return [Infinity];
    return room.nodes.map((point, i) => length(point, next.nodes[i]));
  }), ...(a.rooms.length === b.rooms.length ? [] : [Infinity])));
}

function motionMetrics(frames, gesture) {
  const distance = (a, b) => pixels(length(a, b));
  if (gesture?.type !== 'drag-toward-heading') return null;
  const { slot, index } = gesture.start;
  const nodes = name => frames[name].rooms.find(room => room.slot === slot)?.nodes ?? [];
  const idle = nodes('01-idle'), grab = nodes('02-grab');
  const release = nodes('03-release'), settled = nodes('04-settle');
  const paused = nodes('05-paused'), pausedLater = nodes('06-paused-later');
  const travel = (a, b) => a[index] && b[index] ? distance(a[index], b[index]) : null;
  return {
    targetTravelDuringGrabPx: travel(idle, grab),
    largestOtherPeerTravelDuringGrabPx: Math.max(0, ...idle.map((node, i) =>
      i !== index && grab[i] ? distance(node, grab[i]) : 0)),
    largestRelativeDeformationPx: Math.max(0, ...idle.map((node, i) =>
      i !== index && idle[index] && grab[index] && grab[i]
        ? pixels(Math.abs(length(node, idle[index]) - length(grab[i], grab[index]))) : 0)),
    targetTravelAfterReleasePx: travel(grab, release),
    targetTravelWhileSettlingPx: travel(release, settled),
    targetTravelWhilePausedPx: travel(paused, pausedLater),
  };
}

async function runFixture(browser, engine, preset, fixture) {
  const baseline = preset === 'baseline';
  const directory = join(output, preset, engine, fixture.name);
  await mkdir(directory, { recursive: true });
  const context = await browser.newContext({
    viewport: fixture.viewport,
    hasTouch: !!fixture.touch,
    isMobile: !!fixture.touch,
    reducedMotion: fixture.reduced ? 'reduce' : 'no-preference',
    serviceWorkers: 'block',
  });
  context.setDefaultTimeout(10000);
  const errors = [];
  try {
    await context.route('**/*', route => fixtureRoute(route, fixture.rooms));
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    const time = new Date('2026-01-01T00:00:00Z');
    await page.clock.install({ time });
    await page.clock.pauseAt(new Date(time.getTime() + 1000));
    await page.goto(baseline ? origin : origin + '/?network-preset=' + preset);
    await page.locator('#room-network[data-source="' + (fixture.rooms.length ? 'live' : 'example') + '"] .room-node').first().waitFor({ state: 'attached' });
    await page.evaluate(() => document.fonts.ready);
    await page.clock.runFor(250);

    const frames = {}, shots = {};
    const frame = async name => {
      frames[name] = await measure(page);
      shots[name] = (await page.screenshot({ path: join(directory, name + '.png'), scale: 'css' })).toString('base64');
    };
    await frame('01-idle');
    const target = await dragTarget(page);
    let gesture = null, roomGesture = null, activatedSlot = null;
    if (target && !fixture.touch && !fixture.reduced) {
      const heading = await page.locator('#network-heading').boundingBox();
      const dx = heading.x + heading.width / 2 - target.x;
      const dy = heading.y + heading.height / 2 - target.y;
      const distance = Math.hypot(dx, dy) || 1;
      const end = { x: target.x + dx / distance * 140, y: target.y + dy / distance * 140 };
      gesture = { type: 'drag-toward-heading', start: target, end, moveMs: 160 };
      await drag(page, gesture);
      await frame('02-grab');
      await page.mouse.up();
      await page.clock.runFor(160);
      await frame('03-release');
      await page.clock.runFor(900);
      await frame('04-settle');
      if (!baseline && fixture.name === 'desktop-example') {
        roomGesture = hullDrag(frames['04-settle'], await hullTargets(page));
        if (roomGesture) {
          await drag(page, roomGesture);
          await frame('04a-room-grab');
          await page.mouse.up();
          await page.clock.runFor(900);
        }
      }
      const noteTarget = await dragTarget(page);
      if (noteTarget) {
        activatedSlot = noteTarget.slot;
        await frame('04b-before-note');
        await page.mouse.click(noteTarget.x, noteTarget.y);
        await page.clock.runFor(220);
        await frame('04c-note');
      }
      await page.locator('#network-motion').click();
      await frame('05-paused');
      await page.clock.runFor(600);
      await frame('06-paused-later');
    } else if (target && fixture.touch) {
      gesture = { type: 'tap', at: target };
      activatedSlot = target.slot;
      await page.touchscreen.tap(target.x, target.y);
      await page.clock.runFor(160);
      await frame('02-touch');
    } else if (fixture.reduced) {
      const keyboardRoom = page.locator('.room-cluster').filter({ has: page.locator('.room-edge') }).first();
      activatedSlot = await keyboardRoom.getAttribute('data-slot');
      await keyboardRoom.focus();
      await page.keyboard.press('Enter');
      await frame('02-keyboard');
      await page.clock.runFor(600);
      await frame('03-keyboard-later');
    }

    const metrics = motionMetrics(frames, gesture);
    if (roomGesture && metrics) {
      const slot = roomGesture.start.slot;
      const before = roomAt(frames['04-settle'], slot);
      const after = roomAt(frames['04a-room-grab'], slot);
      metrics.roomTravelDuringHullGrabPx = before && after ? pixels(length(center(before.bounds), center(after.bounds))) : null;
    }
    const visual = {};
    const compare = async (name, before, after, slot) => {
      visual[name] = await comparePixels(page, directory, shots, frames, fixture.viewport, { name, before, after, slot });
    };
    if (frames['02-grab']) {
      await compare('peer-grab', '01-idle', '02-grab', target.slot);
      await compare('pause', '05-paused', '06-paused-later', target.slot);
    }
    if (frames['04a-room-grab']) {
      await compare('room-grab', '04-settle', '04a-room-grab', roomGesture.start.slot);
    }
    if (frames['04c-note']) {
      await compare('note', '04b-before-note', '04c-note', activatedSlot);
    }
    if (frames['03-keyboard-later']) {
      await compare('reduced-motion', '02-keyboard', '03-keyboard-later', activatedSlot);
    }
    const geometryWarnings = Object.entries(frames).flatMap(([name, result]) => [
      ...(result.horizontalOverflow ? [name + ': horizontal overflow'] : []),
      ...result.rooms.filter(room => room.protectedOverlap).map(room => name + ': protected overlap in room ' + room.slot),
    ]);
    const failures = [];
    if (!baseline) {
      failures.push(...geometryWarnings);
      const expect = (condition, description) => { if (!condition) failures.push(description); };
      expect(frames['01-idle'].renderedPreset === preset, 'Requested preset is active');
      const activatedFrame = frames['04c-note'] || frames['02-touch'] || frames['02-keyboard'];
      const activated = roomAt(activatedFrame, activatedSlot);
      expect(!!activatedFrame?.focusText.trim(), 'Activation exposes room text');
      if (fixture.reduced) {
        expect(activatedFrame?.motionDisabled && activated?.highlightedRoutes > 0 && !activated?.visibleNote,
          'Reduced-motion keyboard activation highlights a route without a moving note');
        expect(graphTravel(frames['02-keyboard'], frames['03-keyboard-later']) <= .25, 'Reduced-motion peers remain still');
        expect(visual['reduced-motion']?.changedPixels === 0, 'Reduced-motion graph pixels remain unchanged');
      } else {
        expect(activated?.visibleNote || activated?.highlightedRoutes > 0, 'Activation displays a note or highlighted route');
      }
      if (!fixture.touch && !fixture.reduced) {
        expect(metrics?.targetTravelDuringGrabPx >= 12, 'A 140 px pull moves the selected peer visibly');
        expect(metrics?.largestOtherPeerTravelDuringGrabPx >= 1, 'A neighboring peer follows the pull');
        expect(metrics?.largestRelativeDeformationPx >= 3, 'The peer pull stretches the graph');
        expect(visual['peer-grab']?.changedPixels >= 64, 'Peer grab materially changes the screenshot');
        expect(visual.note?.changedPixels >= 8, 'Note activation is visible in the screenshot');
        if (frames['05-paused']) {
          expect(graphTravel(frames['05-paused'], frames['06-paused-later']) <= .25, 'Paused peers remain still');
          expect(visual.pause?.changedPixels === 0, 'Paused graph pixels remain unchanged');
        }
        if (fixture.name === 'desktop-example') {
          expect(metrics?.roomTravelDuringHullGrabPx >= 12, 'A 72 px hull grab moves the room visibly');
          expect(visual['room-grab']?.changedPixels >= 64, 'Hull grab materially changes the screenshot');
        }
      }
    }
    const report = { engine, preset, fixture, gesture, roomGesture, activatedSlot, metrics, visual, frames, geometryWarnings, failures, errors };
    await writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
    return {
      engine, preset, scenario: fixture.name, directory, errors, metrics, visual, failures,
      capturedGesture: fixture.reduced || !!gesture,
      geometryWarnings,
    };
  } finally {
    await context.close();
  }
}

const summary = [];
await mkdir(output, { recursive: true });
for (const engine of browsers) {
  const browser = await engines[engine].launch();
  try {
    for (const preset of presets) {
      for (const fixture of fixtures) {
        try {
          summary.push(await runFixture(browser, engine, preset, fixture));
        } catch (error) {
          summary.push({
            engine, preset, scenario: fixture.name,
            errors: [error.message], failures: [], capturedGesture: false,
          });
        }
      }
    }
  } finally {
    await browser.close();
  }
}
const summaryPath = join(output, 'summary.json');
await writeFile(summaryPath, JSON.stringify(summary, null, 2) + '\n');
console.log(summaryPath);
for (const result of summary) {
  for (const message of [...result.errors, ...result.failures]) {
    console.error(`${result.preset}/${result.engine}/${result.scenario}: ${message}`);
  }
}
if (summary.some(result => result.errors.length || result.failures.length || !result.capturedGesture)) process.exitCode = 1;
