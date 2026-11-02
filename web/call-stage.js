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
  button.addEventListener('click', () => { stage.classList.toggle('self-expanded'); update(); });
  tile.append(button); tile._previewToggle = { update, button }; update();
}

export function syncPairStage(stage, count) {
  const pair = count === 2;
  stage.classList.toggle('pair-stage', pair);
  if (!pair) stage.classList.remove('self-expanded');
  const self = stage.querySelector('.group-tile.self');
  if (self) { bindSelfPreview(stage, self); self._previewToggle.update(); }
}

export function resetStage(stage) {
  stage?.classList.remove('self-expanded', 'pair-stage');
  stage?.querySelector('.self-preview-toggle')?.setAttribute('aria-expanded', 'false');
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
