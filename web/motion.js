// PVP moves like a signal: quick response, a short travel, a soft landing.
// Effects never delay an action or retain a departing media surface.
const preference = matchMedia('(prefers-reduced-motion: reduce)');
const running = new Set();
const active = new WeakMap();
const scopes = new WeakMap();
const settle = 'cubic-bezier(.16, 1, .3, 1)';

function animate(node, frames, options = {}) {
  active.get(node)?.cancel();
  if (preference.matches || !node?.isConnected || !node.getClientRects().length) return;
  const animation = node.animate(frames, { duration: 240, easing: settle, ...options });
  active.set(node, animation);
  running.add(animation);
  const release = () => {
    running.delete(animation);
    if (active.get(node) === animation) active.delete(node);
  };
  animation.finished.then(release, release);
}

preference.addEventListener('change', () => {
  if (preference.matches) for (const animation of running) animation.cancel();
});

export function reveal(node, { direction = 1, delay = 0 } = {}) {
  if (!node) return;
  animate(node, [
    { opacity: .35, transform: `translate3d(${direction * 10}px, 6px, 0) scale(.992)` },
    { opacity: 1, transform: 'translate3d(0, 0, 0) scale(1)' },
  ], { delay });
}

// Recreated rows keep their visual positions. Only new rows enter; presence and
// statistics updates don't replay a whole list. Stagger is capped at 72 ms.
export function captureList(root, scope = '') {
  const previous = new Map();
  const sameScope = scopes.get(root) === scope;
  scopes.set(root, scope);
  if (!preference.matches && root.getClientRects().length && sameScope) {
    for (const node of [...root.children].slice(0, 32)) {
      const key = node.dataset.motionKey || node.dataset.peerId;
      if (key) previous.set(key, node.getBoundingClientRect());
    }
  }
  return () => {
    if (preference.matches || !root.getClientRects().length) return;
    [...root.children].slice(0, 32).forEach((node, index) => {
      const key = node.dataset.motionKey || node.dataset.peerId;
      const before = previous.get(key);
      if (!before) {
        reveal(node, { delay: Math.min(index * 18, 72) });
      } else {
        const after = node.getBoundingClientRect();
        const x = before.left - after.left, y = before.top - after.top;
        if (Math.abs(x) + Math.abs(y) > 1) animate(node, [
          { transform: `translate3d(${x}px, ${y}px, 0)` },
          { transform: 'translate3d(0, 0, 0)' },
        ]);
      }
    });
  };
}

// A single shared marker travels between destinations, including keyboard
// navigation. It is decorative and never participates in hit testing.
const nav = document.querySelector('.sidebar nav');
const marker = document.createElement('span');
marker.className = 'pvp-nav-signal';
marker.setAttribute('aria-hidden', 'true');
nav.append(marker);
export function moveNavigation() {
  const selected = nav.querySelector('.nav-item.active');
  marker.hidden = !selected;
  if (!selected) return;
  for (const item of nav.querySelectorAll('.nav-item')) {
    if (item === selected) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  marker.style.height = '2px';
  marker.style.width = `${Math.max(12, selected.offsetWidth - 32)}px`;
  marker.style.transform = `translate3d(${selected.offsetLeft + 16}px, ${selected.offsetTop + selected.offsetHeight - 6}px, 0)`;
}
new ResizeObserver(moveNavigation).observe(nav);
moveNavigation();
