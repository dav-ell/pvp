import { animate } from './motion.js';

const idleDelay = 3200;
const chromeSelector = '.call-top, .call-heading, .call-dock, .call-controls, #call-timer, .quality-summary, .group-small-button, .participant-expand';

export function bindCallControls() {
  let stage, timer, pointerHeld = false, suppressClick = false;
  const reveal = () => {
    if (!stage) return;
    stage.classList.remove('controls-idle');
    for (const node of stage.querySelectorAll('[data-idle-inert]')) {
      node.inert = false;
      delete node.dataset.idleInert;
    }
  };
  const show = () => {
    if (!stage) return;
    reveal();
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (pointerHeld || document.querySelector('dialog[open]')) {
        show();
        return;
      }
      stage.classList.add('controls-idle');
      for (const node of stage.querySelectorAll(chromeSelector)) {
        if (!node.inert) { node.inert = true; node.dataset.idleInert = ''; }
      }
    }, idleDelay);
  };
  document.addEventListener('pointerdown', event => {
    suppressClick = false;
    if (!stage?.contains(event.target)) return;
    const essential = event.target.closest('.sharing-banner, .playback-banner, .enable-playback, .mic-status, .muted-nudge');
    suppressClick = stage.classList.contains('controls-idle') && !essential;
    pointerHeld = true;
    show();
  }, true);
  for (const type of ['pointerup', 'pointercancel']) {
    document.addEventListener(type, event => {
      pointerHeld = false;
      if (type === 'pointercancel') suppressClick = false;
      if (stage?.contains(event.target)) show();
    }, true);
  }
  // The first tap wakes the controls without triggering a concealed action.
  document.addEventListener('click', event => {
    if (!suppressClick) return;
    suppressClick = false;
    event.preventDefault(); event.stopImmediatePropagation();
  }, true);
  for (const type of ['pointermove', 'wheel']) {
    document.addEventListener(type, event => {
      if (event.pointerType !== 'touch' && stage?.contains(event.target)) show();
    }, { passive: true });
  }
  document.addEventListener('pointerenter', event => {
    if (event.pointerType !== 'touch' && event.target === stage) show();
  }, { capture: true, passive: true });
  document.addEventListener('keydown', show, true);
  document.addEventListener('focusin', event => {
    if (stage?.contains(event.target) && event.target.matches(':focus-visible')) show();
  });
  document.addEventListener('close', show, true);
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (!document.hidden) show();
  });
  window.addEventListener('focus', show);
  window.addEventListener('blur', () => { pointerHeld = false; });
  return nextStage => {
    if (stage === nextStage) return;
    clearTimeout(timer);
    reveal();
    stage = nextStage;
    pointerHeld = false;
    suppressClick = false;
    show();
  };
}

export function fitGroupGrid(stage, count) {
  const media = stage.querySelector('#group-media');
  const grid = stage.querySelector('#group-grid');
  const { width, height } = media.getBoundingClientRect();
  if (!width || !height || !count) return;
  let columns = width < 600 ? Math.min(2, count) : count <= 4 ? Math.min(2, count) : count <= 9 ? 3 : 4;
  if (width > height * 2.2 && count <= 4) columns = count;
  grid.style.setProperty('--group-columns', columns);
  grid.style.setProperty('--group-rows', Math.ceil(count / columns));
  grid.style.setProperty('--group-min-height', count > 4 ? '150px' : '0px');
}

// Presentation only: preserve video/audio elements and their peer connections.
export function bindSelfPreview(stage, tile) {
  if (!tile || tile._previewToggle) return;
  const button = document.createElement('button');
  button.type = 'button'; button.className = 'self-preview-toggle';
  const label = document.createElement('span'); label.className = 'preview-action'; button.append(label);
  const update = () => {
    const expanded = stage.classList.contains('self-expanded');
    button.setAttribute('aria-expanded', String(expanded));
    button.setAttribute('aria-label', expanded ? 'Shrink your video preview' : 'Expand your video preview');
    label.textContent = expanded ? 'Shrink preview' : 'You · Expand';
  };
  let motion;
  button.addEventListener('click', () => {
    const before = tile.getBoundingClientRect();
    motion?.cancel();
    stage.classList.toggle('self-expanded');
    update();
    const after = tile.getBoundingClientRect();
    if (!before.width || !before.height || !after.width || !after.height) return;
    motion = animate(tile, [
      { transform: `translate(${before.left - after.left}px, ${before.top - after.top}px) scale(${before.width / after.width}, ${before.height / after.height})` },
      { transform: 'none' },
    ], { duration: 220 });
  });
  tile.append(button); tile._previewToggle = { update, cancel: () => motion?.cancel() }; update();
}

export function syncPairStage(stage, count) {
  const pair = count === 2;
  stage.classList.toggle('pair-stage', pair);
  const self = stage.querySelector('.group-tile.self');
  if (!pair && stage.classList.contains('self-expanded')) {
    stage.classList.remove('self-expanded');
    self?._previewToggle?.cancel();
  }
  if (self) { bindSelfPreview(stage, self); self._previewToggle.update(); }
}

export function resetStage(stage) {
  stage?.classList.remove('self-expanded', 'pair-stage', 'participant-focused');
  const preview = stage?.querySelector('.self-preview-toggle')?.parentElement._previewToggle;
  preview?.cancel();
  preview?.update();
}

// Mobile keyboards resize the visual viewport even when CSS dvh does not.
// Preserve browser zoom; measurements at non-default scale must not reflow it.
export function bindViewport() {
  const viewport = globalThis.visualViewport;
  let scheduled = false;
  const update = () => {
    scheduled = false;
    if (viewport && viewport.scale !== 1) return;
    const height = Math.round(viewport?.height || innerHeight);
    if (height > 0) document.documentElement.style.setProperty('--pvp-viewport-height', `${height}px`);
  };
  const schedule = () => { if (!scheduled) { scheduled = true; requestAnimationFrame(update); } };
  viewport?.addEventListener('resize', schedule, {passive:true});
  addEventListener('resize', schedule, {passive:true});
  update();
}
