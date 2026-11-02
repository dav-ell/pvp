import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

function generatedMedia() {
  window.__captures = []; window.__peers = []; window.__errors = [];
  addEventListener('error', e => window.__errors.push(e.message));
  const Peer = RTCPeerConnection;
  window.RTCPeerConnection = class extends Peer { constructor(...args) { super(...args); window.__peers.push(this); } };
  const capture = async constraints => {
    window.__captures.push(constraints);
    const stream = new MediaStream();
    if (constraints.audio !== false) {
      const audio = new AudioContext(), oscillator = audio.createOscillator(), output = audio.createMediaStreamDestination();
      oscillator.connect(output); oscillator.start(); await audio.resume();
      const track = output.stream.getAudioTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { stop(); oscillator.stop(); audio.close(); };
      stream.addTrack(track);
    }
    if (constraints.video !== false) {
      const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 360;
      const paint = () => { const g = canvas.getContext('2d'); g.fillStyle = '#284536'; g.fillRect(0, 0, 640, 360); g.fillStyle = '#f3be7c'; g.fillRect(0, 0, 640, 35); g.fillStyle = '#fffdf8'; g.fillRect(0, 325, 640, 35); };
      paint(); const timer = setInterval(paint, 60), track = canvas.captureStream(15).getVideoTracks()[0], stop = track.stop.bind(track);
      track.stop = () => { clearInterval(timer); stop(); }; stream.addTrack(track);
    }
    return stream;
  };
  const native = navigator.mediaDevices;
  Object.defineProperty(navigator, 'mediaDevices', {value:new Proxy(native,{get(target,key){if(key==='getUserMedia')return capture;const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;}})});
}

for (const [name, engine] of Object.entries({ chromium, webkit })) test(`room-first entry, pair stage, evidence and leave/rejoin (${name})`, {timeout:120000}, async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'pvp-rooms-')); let service, browser;
  try {
    await promisify(execFile)('cargo', ['build', '--quiet', '--manifest-path', 'signaling/Cargo.toml']);
    const probe = createServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
    const base = `http://localhost:${port}`;
    service = spawn('signaling/target/debug/pvp-signaling', [], {env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temporary,'rooms.sqlite')},stdio:'ignore'});
    for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
    browser = await engine.launch({headless:true});
    const ownerContext = await browser.newContext({viewport:{width:1440,height:900},reducedMotion:'reduce'});
    const guestContext = await browser.newContext({viewport:{width:390,height:844},reducedMotion:'reduce'});
    const owner = await ownerContext.newPage(), guest = await guestContext.newPage();
    for(const page of [owner,guest]){page.setDefaultTimeout(12000);await page.addInitScript(generatedMedia);}
    await owner.goto(base);
    assert.equal(await owner.locator('#account-auth').isVisible(), false);
    await owner.locator('#show-account').click();await owner.locator('#register-tab').click();
    await owner.locator('#display-name').fill('Alex');await owner.locator('#username').fill(`rooms_${name}_${Date.now()}`);await owner.locator('#password').fill('room-experience-password-123');await owner.locator('#auth-submit').click();
    await owner.locator('#connection-dot.online').waitFor();await owner.locator('#meeting-new').waitFor();
    assert.equal(await owner.locator('#people-view').isVisible(),false,'accounts return to Rooms');
    await owner.locator('#meeting-new').click();await owner.locator('#meeting-name').fill('Sunday circle');await owner.locator('#meeting-create').click();
    const url = await owner.locator('#meeting-link').inputValue();
    assert.equal(await owner.evaluate(()=>window.__captures.length),0,'creating a room does not request devices');
    await owner.locator('#meeting-join').click();await owner.locator('#guest-listen').click();await owner.locator('#group-view').waitFor({state:'visible'});
    await guest.goto(url);await guest.locator('#guest-name').fill('Sam');await guest.locator('#guest-name').press('Enter');await guest.locator('#group-view').waitFor({state:'visible'});
    await guest.waitForFunction(()=>window.__peers.some(pc=>pc.connectionState==='connected'));
    assert.equal(await guest.evaluate(()=>window.__captures.length),0,'listening never captures a microphone');
    await owner.locator('#group-camera').click();await guest.waitForFunction(()=>document.querySelector('#group-grid .group-tile:not(.self)')?.dataset.video==='on');
    await guest.evaluate(()=>{window.__firstRemote=document.querySelector('#group-grid .group-tile:not(.self)');window.__firstVideo=window.__firstRemote.querySelector('video');window.__firstPeer=window.__peers.find(pc=>pc.connectionState==='connected');});
    for(const [width,height] of [[320,740],[390,844],[844,390],[1440,900]]) {
      await guest.setViewportSize({width,height});
      await guest.waitForFunction(()=>Math.abs(document.getElementById('group-view').getBoundingClientRect().height-innerHeight)<1);
      const stage = await guest.locator('#group-grid .group-tile:not(.self)').boundingBox();
      assert.ok(stage && Math.abs(stage.x)<1 && Math.abs(stage.y)<1 && Math.abs(stage.width-width)<1 && Math.abs(stage.height-height)<1,`pair fills ${width}x${height}: ${JSON.stringify(stage)}`);
      assert.equal(await guest.locator('#group-grid .group-tile:not(.self) video').evaluate(video=>getComputedStyle(video).objectFit),'contain','remote frame preserves top/bottom');
      assert.equal(await guest.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no horizontal page overflow');
      for(const id of ['group-mic','group-camera','group-more','group-leave']){const r=await guest.locator('#'+id).boundingBox();assert.ok(r&&r.x>=0&&r.y>=0&&r.x+r.width<=width+1&&r.y+r.height<=height+1&&r.height>=44,`${id} fits ${width}x${height}`);}
    }
    await guest.setViewportSize({width:390,height:844});await guest.locator('#group-camera').click();
    await guest.waitForFunction(()=>document.querySelector('#group-grid .self')?.dataset.video==='on').catch(async error=>{
      console.log('Preview evidence',await guest.evaluate(()=>{const tile=document.querySelector('#group-grid .self'),v=tile.querySelector('video');return {captures:window.__captures,toast:document.getElementById('toast').textContent,tile:tile.dataset,display:getComputedStyle(tile).display,video:{width:v.videoWidth,height:v.videoHeight,ready:v.readyState,paused:v.paused,muted:v.muted,error:v.error?.message,tracks:v.srcObject?.getTracks().map(t=>({kind:t.kind,enabled:t.enabled,ready:t.readyState}))},camera:document.getElementById('group-camera').outerHTML,errors:window.__errors};}));
      throw error;
    });
    const thumbnail = await guest.locator('#group-grid .self').boundingBox();
    await guest.locator('#group-grid .self .self-preview-toggle').click();
    const expanded = await guest.locator('#group-grid .self').boundingBox();assert.ok(expanded.width>thumbnail.width*2&&expanded.height>thumbnail.height*2,'tap expands self feed');
    await guest.locator('#group-grid .self .self-preview-toggle').click();
    assert.equal(await guest.evaluate(()=>window.__firstRemote===document.querySelector('#group-grid .group-tile:not(.self)')&&window.__firstVideo===window.__firstRemote.querySelector('video')&&window.__firstPeer===window.__peers.find(pc=>pc.connectionState==='connected')),true,'layout changes preserve media nodes and peer');
    await guest.locator('#group-quality-summary').filter({hasText:/Balanced/}).waitFor();
    await guest.waitForFunction(()=>document.getElementById('group-quality-summary').textContent.includes('Sending'));
    await guest.locator('#group-trust').click();
    await guest.locator('.trust-state').filter({hasText:'Encryption observed'}).waitFor();
    await guest.locator('.trust-route').filter({hasText:'Direct connection observed'}).waitFor();
    assert.match(await guest.locator('.trust-code').textContent(),/^[0-9a-f]{4}(?: [0-9a-f]{4}){5}$/);
    assert.match(await guest.locator('.trust-identity').textContent(),/not independently verified/);
    await guest.locator('#trust-close').click();
    // Losing observations must not leave an old positive security badge behind,
    // and unavailable statistics must not end otherwise-working media.
    await guest.evaluate(()=>{const pc=window.__firstPeer;window.__realStats=pc.getStats.bind(pc);pc.getStats=()=>Promise.reject(Error('Fixture evidence unavailable'));});
    await guest.locator('#group-trust').filter({hasText:'Connection evidence'}).waitFor();
    assert.equal(await guest.evaluate(()=>window.__firstPeer.connectionState),'connected');
    await guest.evaluate(()=>window.__firstPeer.getStats=window.__realStats);
    await guest.locator('#group-trust').filter({hasText:'Encryption observed'}).waitFor();
    const output=join('.build/room-upgrade-evidence',name);await mkdir(output,{recursive:true});
    await guest.screenshot({path:join(output,'pair-mobile.png')});await owner.screenshot({path:join(output,'pair-desktop.png')});
    await owner.evaluate(()=>{window.__stayRoom=document.getElementById('group-heading').textContent;});
    await guest.locator('#group-leave').click();await guest.locator('#guest-listen').waitFor();
    assert.equal(await owner.locator('#group-view').isVisible(),true,'other person remains in the room');
    assert.equal(await owner.locator('#group-heading').textContent(),'Sunday circle');
    await guest.locator('#guest-listen').click();await guest.locator('#group-view').waitFor({state:'visible'});
    await guest.waitForFunction(()=>window.__peers.some(pc=>pc.connectionState==='connected'));
    assert.equal(await guest.locator('#group-heading').textContent(),'Sunday circle','same invitation rejoins the same group');
    assert.equal(await guest.locator('#group-mic').textContent(),'Use mic');
    assert.deepEqual(await guest.evaluate(()=>window.__errors),[]);assert.deepEqual(await owner.evaluate(()=>window.__errors),[]);
    await guest.locator('#group-leave').click();await owner.locator('#group-leave').click();
    await owner.locator('#guest-back-rooms').click();
    for(const width of [320,390,768]){
      await owner.setViewportSize({width,height:900});
      assert.equal(await owner.locator('#meetings-dialog').isVisible(),true);
      assert.equal(await owner.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'room library fits narrow screens');
      const create=await owner.locator('#meeting-new').boundingBox();assert.ok(create&&create.x>=0&&create.x+create.width<=width+1,'create stays reachable');
    }
    await writeFile(join(output,'evidence.json'),JSON.stringify({engine:name,viewports:[[320,740],[390,844],[844,390],[1440,900]],stableMedia:true,containFit:true,realEncryptionEvidence:true,rejoin:true},null,2));
  } finally {await browser?.close();if(service){const exited=new Promise(resolve=>service.once('exit',resolve));service.kill();await exited;}await rm(temporary,{recursive:true,force:true});}
});
