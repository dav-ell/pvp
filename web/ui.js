// Shared presentation primitives. These never acquire media or change call intent.
const NS='http://www.w3.org/2000/svg';
export function icon(name){const svg=document.createElementNS(NS,'svg'),use=document.createElementNS(NS,'use');svg.classList.add('icon');svg.setAttribute('aria-hidden','true');svg.setAttribute('viewBox','0 0 24 24');use.setAttribute('href',`/icons.svg#${name}`);svg.append(use);return svg;}
export function labeledAction(button,name,label){
  if(button.dataset.copied==='true'&&name!=='check')return button;
  let glyph=button.querySelector(':scope > svg'),text=button.querySelector(':scope > .control-label');
  if(!text){button.replaceChildren();glyph=icon(name);text=document.createElement('span');text.className='control-label';button.append(glyph,text);}
  if(glyph.dataset.icon!==name){glyph.replaceChildren();const use=document.createElementNS(NS,'use');use.setAttribute('href',`/icons.svg#${name}`);glyph.append(use);glyph.dataset.icon=name;}
  if(text.textContent!==label)text.textContent=label;
  return button;
}
export function callAction(button,{glyph,label,action=label,pressed,active=false,always=false,busy=false,badge=0,add=false}){
  labeledAction(button,glyph,label==='Camera'?'Camera':action==='Share screen'?'Share':action);button.classList.remove('sheet-row');button.classList.add('call-action');button.classList.toggle('active',active);button.classList.toggle('with-caption',always);button.classList.toggle('capture-add',add);
  button.setAttribute('aria-label',badge?`${label}, ${badge} unread`:label);button.dataset.tooltip=action;button.removeAttribute('title');
  if(pressed===undefined)button.removeAttribute('aria-pressed');else button.setAttribute('aria-pressed',String(pressed));
  button.setAttribute('aria-busy',String(busy));button.dataset.busy=String(busy);
  let dot=button.querySelector('.unread-badge');if(badge){if(!dot){dot=document.createElement('span');dot.className='unread-badge';dot.setAttribute('aria-hidden','true');button.append(dot);}dot.textContent=badge>9?'9+':String(badge);}else dot?.remove();
}
export function rowAction(button,glyph,label){button.querySelector('.unread-badge')?.remove();button.removeAttribute('aria-pressed');labeledAction(button,glyph,label);button.classList.remove('call-action','with-caption','capture-add');button.classList.add('sheet-row');button.setAttribute('aria-label',label);return button;}
let labels=false;try{labels=localStorage.getItem('pvp.ui.labels')==='true';}catch{}
export function showLabels(value=labels){labels=value;document.documentElement.classList.toggle('show-control-labels',labels);document.querySelectorAll('[data-control-labels]').forEach(box=>box.checked=labels);try{localStorage.setItem('pvp.ui.labels',String(labels));}catch{}document.dispatchEvent(new CustomEvent('pvp-ui-labels'));}
export function bindLabels(){document.querySelectorAll('[data-control-labels]').forEach(box=>box.onchange=()=>showLabels(box.checked));showLabels();}
export function openSheet(dialog,from=document.activeElement){if(dialog.open)return;dialog._returnFocus=from;dialog.showModal();}
export function closeSheet(dialog){if(dialog.open)dialog.close();}
export function bindSheet(dialog){dialog.addEventListener('close',()=>{const target=dialog._returnFocus;dialog._returnFocus=null;if(target?.isConnected&&!target.closest('[hidden]'))target.focus({preventScroll:true});});}
export function copied(button,restore){labeledAction(button,'check','Copied');button.dataset.copied='true';clearTimeout(button._copiedTimer);button._copiedTimer=setTimeout(()=>{delete button.dataset.copied;if(button.isConnected)restore();},1400);}
export function videoState(tile,video,on){
  if(tile._videoSource!==video.srcObject){tile._videoSource=video.srcObject;tile._videoOn=undefined;}
  if(tile._videoOn===on)return;tile._videoCleanup?.();tile._videoOn=on;const generation=tile._videoGeneration=(tile._videoGeneration||0)+1;tile.dataset.video='off';
  if(!on)return;
  const ready=()=>{if(tile._videoGeneration===generation&&tile._videoOn&&video.videoWidth>0)tile.dataset.video='on';};
  // WebKit can defer a frame callback for a hidden preview. Media events still
  // report the first decoded frame, so listen to both without a timer/fake frame.
  video.addEventListener('loadeddata',ready);video.addEventListener('resize',ready);video.addEventListener('playing',ready);
  const callback=video.requestVideoFrameCallback?.(ready);
  tile._videoCleanup=()=>{for(const event of ['loadeddata','resize','playing'])video.removeEventListener(event,ready);if(callback!==undefined)video.cancelVideoFrameCallback?.(callback);};
  if(video.readyState>=2)ready();
}
export function participantAvatar(tile,name){let avatar=tile.querySelector(':scope > .participant-avatar');if(!avatar){avatar=document.createElement('div');avatar.className='participant-avatar';avatar.setAttribute('aria-hidden','true');tile.append(avatar);}avatar.textContent=name.trim().split(/\s+/).slice(0,2).map(n=>n[0]||'').join('').toUpperCase();}
export function stateBadge(tile,{muted=false,listening=false,adminMuted=false,sharing=false}){
 let badge=tile.querySelector('.participant-state');const value=adminMuted?'Muted by admin':listening?'Listening':muted?'Microphone muted':sharing?'Sharing screen':'';
 if(!value){badge?.remove();return;}if(!badge){badge=document.createElement('span');badge.className='participant-state';tile.querySelector('.group-tile-caption').append(badge);}if(badge.dataset.state===value)return;badge.dataset.state=value;badge.replaceChildren(icon(adminMuted||muted&&!listening?'mic-off':listening?'headphones':'screen-share'));badge.setAttribute('aria-label',value);badge.title=value;
}
