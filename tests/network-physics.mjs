import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createField, FIELD_PRESETS, STEP_SECONDS } from '../web/network-physics.js';

const width = 960, height = 640;
const obstacle = { left: 385, top: 155, right: 595, bottom: 435 };
const layout = (slot, x, y, peers = 6, radius = 68) => ({
  slot, x, y, peers, radius,
  bounds: { left: x - 85, top: y - 82, right: x + 85, bottom: y + 94 },
});
const scene = [layout(0, 164, 240, 16), layout(1, 340, 530), layout(2, 734, 290, 3)];
const makeField = options => createField(width, height, [obstacle], scene, options);
const closeTo = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
const worldPoint = (room, index) => ({ x: room.x + room.points[index].x, y: room.y + room.points[index].y });
const EPSILON = 1e-6;

function tick(field, count) {
  for (let i = 0; i < count; i++) field.step();
}

function edges(room) {
  return { left: room.x + room.left, right: room.x + room.right, top: room.y + room.top, bottom: room.y + room.bottom };
}

function apart(a, b, padding) {
  return a.right <= b.left - padding + EPSILON || a.left >= b.right + padding - EPSILON ||
    a.bottom <= b.top - padding + EPSILON || a.top >= b.bottom + padding - EPSILON;
}

function assertSafe(field) {
  const rooms = [...field.rooms.values()];
  for (const [index, room] of rooms.entries()) {
    const box = edges(room);
    assert.ok(box.left >= 8 - EPSILON && box.right <= width - 8 + EPSILON);
    assert.ok(box.top >= 8 - EPSILON && box.bottom <= height - 8 + EPSILON);
    assert.ok(apart(box, obstacle, 8), 'rooms stay clear of protected copy');
    for (const other of rooms.slice(index + 1)) assert.ok(apart(box, edges(other), 5), 'room envelopes never overlap');
    for (const point of room.points) {
      assert.ok(Math.hypot(point.x, point.y) <= room.radius + EPSILON, 'peers remain inside their room envelope');
      assert.ok(Math.hypot(point.vx, point.vy) <= 1080 + EPSILON, 'peer velocities are finite and bounded');
    }
    assert.ok(Math.hypot(room.vx, room.vy) <= 940 + EPSILON, 'room velocities are finite and bounded');
  }
}

test('fixed steps and a seed reproduce every frame of a dense drag and release', () => {
  for (const preset of Object.keys(FIELD_PRESETS)) {
    const field = makeField({ preset, seed: 42 });
    const repeat = makeField({ preset, seed: 42 });
    for (let i = 0; i < 480; i++) {
      for (const model of [field, repeat]) {
        if (i === 60) {
          const { x, y } = worldPoint(model.rooms.get(0), 0);
          assert.ok(model.grab(0, 0, x, y));
        }
        if (i > 60 && i < 100) model.move(170 + (i - 60) * 4, 240 - (i - 60) * 2);
        if (i === 100) model.release();
        model.step();
        assertSafe(model);
      }
      assert.deepEqual([...field.rooms], [...repeat.rooms]);
    }
    assert.ok(Math.abs(field.elapsed - 480 * STEP_SECONDS) < EPSILON);
  }
});

test('dragging a peer stretches its neighbors and recovers toward its resting position', () => {
  const field = makeField({ seed: 42 });
  const room = field.rooms.get(0), index = 0;
  const original = room.points.map(({ x, y }) => ({ x, y }));
  const origin = worldPoint(room, index);
  field.grab(0, index, origin.x, origin.y);
  field.move(origin.x + 118, origin.y);
  tick(field, 26);
  const stretch = closeTo(original[index], room.points[index]);
  assert.ok(stretch > 35, 'the selected peer visibly follows the pointer');
  assert.ok(room.points.slice(1).some((point, i) => closeTo(original[i + 1], point) > 5), 'nearby peers follow the stretch');
  assertSafe(field);
  field.release();
  tick(field, 240);
  assert.ok(closeTo(original[index], room.points[index]) < stretch * .2, 'the network settles near its resting geometry');
  assert.equal(field.activeGrab, null);
});

test('a dragged room can push another room, while obstacles and viewport bounds stay hard', () => {
  const field = createField(width, height, [obstacle], [layout(0, 111, 536), layout(1, 294, 536)]);
  field.grab(0, null, 111, 536);
  field.move(960, 536);
  for (let i = 0; i < 170; i++) {
    field.step();
    assertSafe(field);
  }
  assert.ok(field.rooms.get(0).x > 140, 'the body travels with the grab');
  assert.ok(field.rooms.get(1).x > 315, 'contact transfers motion to a neighboring body');
  field.release({ cancel: true });
  const room = field.rooms.get(0);
  assert.equal(Math.hypot(room.vx, room.vy), 0);
  field.grab(0, null, room.x, room.y);
  field.move(500, 330);
  for (let i = 0; i < 240; i++) {
    field.step();
    assertSafe(field);
  }
  assert.ok(apart(edges(room), obstacle, 8));
});

test('refresh keeps safe unchanged slots and clears a grab from the old field', () => {
  const field = makeField({ seed: 42 });
  tick(field, 200);
  const old = field.rooms.get(0);
  const point = worldPoint(old, 0);
  field.grab(0, 0, point.x, point.y);
  const next = createField(width, height, [obstacle], [scene[0], { ...scene[1], peers: 7 }, scene[2]], { seed: 42, previous: field });
  assert.equal(next.elapsed, field.elapsed);
  assert.equal(next.activeGrab, null);
  assert.deepEqual(next.rooms.get(0), old);
  assert.equal(next.rooms.get(1).points.length, 7);
  assertSafe(next);
});

test('invalid input cannot hijack a grab or introduce non-finite motion', () => {
  const field = makeField();
  assert.equal(field.grab(99, null, 1, 1), false);
  assert.equal(field.grab(0, 99, 1, 1), false);
  assert.equal(field.grab(0, null, NaN, 1), false);
  assert.equal(field.grab(0, null, 164, 240), true);
  assert.equal(field.grab(1, null, 340, 530), false);
  field.move(Infinity, NaN);
  tick(field, 5);
  assertSafe(field);
});
