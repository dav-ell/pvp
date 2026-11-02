import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium,webkit} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';

async function screenshot(page,path){
  await page.evaluate(()=>Promise.all(document.getAnimations().filter(a=>a.effect?.getComputedTiming().iterations!==Infinity&&a.playState!=='paused').map(a=>a.finished.catch(()=>{}))));
  await page.screenshot({path});
}
function mediaFixture(){
  window.__peers=[];window.__captures=[];window.__errors=[];
  addEventListener('error',e=>window.__errors.push(e.message));
  const Peer=RTCPeerConnection;
  window.RTCPeerConnection=class extends Peer{constructor(...args){super(...args);window.__peers.push(this);}};
  const native=navigator.mediaDevices;
  const capture=async constraints=>{
    window.__captures.push(constraints);const stream=new MediaStream();
    if(constraints.audio!==false){
      const context=new AudioContext(),tone=context.createOscillator(),output=context.createMediaStreamDestination();
      tone.connect(output);tone.start();await context.resume();
      const audio=output.stream.getAudioTracks()[0],stop=audio.stop.bind(audio);
      let stopped=false;audio.stop=()=>{if(stopped)return;stopped=true;stop();tone.stop();if(context.state!=='closed')context.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};stream.addTrack(audio);
    }
    if(constraints.video!==false){
      const canvas=document.createElement('canvas');canvas.width=640;canvas.height=360;
      const paint=()=>{const g=canvas.getContext('2d');g.fillStyle='#524c75';g.fillRect(0,0,640,360);g.fillStyle='#ddd7ff';g.fillRect((Date.now()/10)%600,100,40,60);};paint();
      const timer=setInterval(paint,50),video=canvas.captureStream(15).getVideoTracks()[0],stop=video.stop.bind(video);
      video.stop=()=>{clearInterval(timer);stop();};stream.addTrack(video);
    }
    return stream;
  };
  Object.defineProperty(navigator,'mediaDevices',{value:new Proxy(native,{get(t,k){if(k==='getUserMedia')return capture;const v=Reflect.get(t,k,t);return typeof v==='function'?v.bind(t):v;}})});
}

for(const [engine,type] of Object.entries({chromium,webkit}))test(`polished real call, accessible controls and stable media (${engine})`,{timeout:90000},async()=>{
  const directory=await mkdtemp(join(tmpdir(),'pvp-polish-'));let server,browser;
  try{
    await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
    const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
    server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(directory,'test.sqlite')},stdio:'ignore'});
    for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
    browser=await type.launch({headless:true});const owner=await browser.newContext({viewport:{width:1440,height:900}}),host=await owner.newPage();owner.setDefaultTimeout(10000);
    await host.addInitScript(mediaFixture);
    const post=async(path,data)=>{const response=await owner.request.post(base+'/api'+path,{headers:{Origin:base},data});assert.equal(response.status(),200,await response.text());return response.json();};
    const self=await post('/register',{username:`polish_${engine}_${Date.now()}`,display_name:'Alex Morgan',password:'polish-fixture-password-123'});
    const meeting=await post('/meetings',{name:'Evening catch-up',open_invite:true});await host.goto(meeting.url);await host.locator('#guest-submit').click();await host.locator('#group-view').waitFor({state:'visible'});
    const output=join('.build/polish-release/screens',engine);await mkdir(output,{recursive:true});await screenshot(host,join(output,'solo-desktop.png'));
    await host.locator('#group-add').click();await host.locator('#group-people-close').click();assert.equal(await host.evaluate(()=>document.activeElement.id),'group-add');
    assert.equal(await host.locator('.sidebar').isVisible(),false);assert.equal(await host.locator('#group-heading').textContent(),'Evening catch-up');
    const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true}),guest=await context.newPage();context.setDefaultTimeout(10000);await guest.addInitScript(mediaFixture);
    await guest.goto(meeting.url);await guest.locator('#guest-name').fill('Jamie Chen');await screenshot(guest,join(output,'invitation-mobile.png'));
    await guest.locator('#guest-listen').click();await guest.locator('#group-view').waitFor({state:'visible'});
    await guest.waitForFunction(()=>window.__peers.some(p=>p.connectionState==='connected'));
    if(await guest.locator('#group-play').isVisible())await guest.locator('#group-play').click();
    await guest.waitForFunction(()=>[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&!a.muted&&a.currentTime>.2));
    assert.equal(await guest.locator('#group-mic').textContent(),'Use mic');assert.equal(await guest.evaluate(()=>window.__captures.length),0);
    await guest.evaluate(()=>{window.__originalPeer=window.__peers.find(p=>p.connectionState==='connected');window.__originalTile=document.querySelector('#group-grid .group-tile:not(.self)');window.__originalVideo=window.__originalTile.querySelector('video');window.__originalAudio=window.__originalTile.querySelector('audio');});
    for(const width of [320,360,390,430,860,1440]){
      await guest.setViewportSize({width,height:844});
      await guest.waitForFunction(()=>innerWidth<=700?document.getElementById('group-desktop-actions').parentElement.id==='group-more-content':document.getElementById('group-desktop-actions').parentElement.classList.contains('call-dock'));
      for(const id of ['group-mic','group-camera','group-more','group-leave']){const r=await guest.locator('#'+id).boundingBox();assert.ok(r.x>=0&&r.x+r.width<=width+.5&&r.height>=44,`${id} fits ${width}: ${JSON.stringify(r)}`);}
      assert.equal(await guest.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    }
    await guest.setViewportSize({width:390,height:844});await guest.waitForFunction(()=>document.getElementById('group-desktop-actions').parentElement.id==='group-more-content');await screenshot(guest,join(output,'duo-mobile.png'));
    await guest.locator('#group-more').click();assert.equal(await guest.locator('#group-switch-camera').isVisible(),false);
    await guest.locator('#group-more-dialog [data-control-labels]').check();await guest.locator('#group-more-close').click();
    assert.equal(await guest.evaluate(()=>document.activeElement.id),'group-more');assert.equal(await guest.locator('html').evaluate(el=>el.classList.contains('show-control-labels')),true);
    const stored=await context.newPage();await stored.goto(base);assert.equal(await stored.locator('html').evaluate(el=>el.classList.contains('show-control-labels')),true);await stored.close();
    await host.locator('#group-chat-open').click();for(const text of ['Hello Jamie','Ready when you are']){await host.locator('#meeting-chat-text').fill(text);await host.locator('#meeting-chat-send').click();}
    await host.locator('#meeting-chat-close').click();await guest.locator('#group-more .unread-badge').filter({hasText:'2'}).waitFor();
    await guest.locator('#group-more').click();await screenshot(guest,join(output,'more-mobile.png'));await guest.locator('#group-chat-open').click();await guest.locator('.chat-message').filter({hasText:'Ready when you are'}).waitFor();await guest.locator('#meeting-chat-close').click();
    assert.equal(await guest.locator('#group-more .unread-badge').count(),0);assert.equal(await guest.evaluate(()=>document.activeElement.id),'group-more');
    await guest.locator('#group-back').click();await guest.locator('#call-return-strip').waitFor({state:'visible'});await guest.locator('#call-return-strip').click();
    assert.equal(await guest.evaluate(()=>window.__originalPeer===window.__peers.find(p=>p.connectionState==='connected')&&window.__originalTile===document.querySelector('#group-grid .group-tile:not(.self)')&&window.__originalVideo===window.__originalTile.querySelector('video')&&window.__originalAudio===window.__originalTile.querySelector('audio')),true,'navigation and resize preserve actual media nodes and peers');
    await guest.locator('#group-mic').click();await guest.locator('#group-mic').filter({hasText:/^Mute$/}).waitFor();assert.equal(await guest.locator('#group-mic').getAttribute('aria-pressed'),'true');await guest.locator('#group-mic').click();assert.equal(await guest.locator('#group-mic').getAttribute('aria-pressed'),'false');
    await host.locator('#group-camera').click();await guest.waitForFunction(id=>document.getElementById(`group-tile-${id}`)?.dataset.video==='on',self.id);
    await host.locator('#group-camera').click();await guest.waitForFunction(id=>document.getElementById(`group-tile-${id}`)?.dataset.video==='off',self.id);
    await guest.emulateMedia({reducedMotion:'reduce'});await guest.locator('#group-more').click();await guest.locator('#group-audio-open').click();await guest.locator('#group-audio-dialog').waitFor({state:'visible'});await screenshot(guest,join(output,'audio-mobile.png'));await guest.keyboard.press('Escape');
    assert.equal(await guest.evaluate(()=>document.activeElement.id),'group-more');
    await screenshot(host,join(output,'duo-desktop.png'));
    assert.deepEqual(await guest.evaluate(()=>window.__errors),[]);assert.deepEqual(await host.evaluate(()=>window.__errors),[]);
    await writeFile(join(output,'evidence.json'),JSON.stringify({engine,widths:[320,360,390,430,860,1440],stableMedia:true,unread:true,focus:true,labels:true,cameraFrames:true},null,2));
    await guest.locator('#group-leave').click();await host.locator('#group-leave').click();
  }finally{await browser?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(directory,{recursive:true,force:true});}
});
