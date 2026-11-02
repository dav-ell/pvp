import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { spawn,execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp,rm,mkdir,writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { treeFor,treeParent,treeChildren } from '../web/group-video.js';
let server,browser,base=process.env.PVP_TEST_URL,temp;const contexts=[],pages=[],users=[];
const count=3,suffix=process.env.PVP_TEST_SUFFIX||Date.now().toString().slice(-9);
const overlay=count>5&&process.env.PVP_GROUP_DISABLE_ALL!=='1';
const wait=(page,fn,arg,timeout=60000)=>page.waitForFunction(fn,arg,{timeout});
async function request(i,path,data,method='POST'){const r=await contexts[i].request.fetch(`${base}/api${path}`,{method,headers:{Origin:base},...(data?{data}:{})});assert.equal(r.status(),200,`${path}: ${await r.text()}`);return r.json();}
before(async()=>{
 if(!base){
 await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));base=`http://localhost:${port}`;
 temp=await mkdtemp(join(tmpdir(),'pvp-groups-'));server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
 for(let i=0;i<100;i++){try{if((await fetch(`${base}/health`)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 }
 browser=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});
 for(let i=0;i<count;i++){
  const context=await browser.newContext({viewport:{width:1280,height:900}});contexts.push(context);
  users.push(await request(i,'/register',{username:`group${i}_${suffix}`,display_name:`Group participant ${i}`,password:'group-test-passphrase-123'}));
  if(process.env.PVP_TEST_ACCOUNT_FILE)await writeFile(process.env.PVP_TEST_ACCOUNT_FILE,JSON.stringify(users.map(u=>({id:u.id,username:u.username})),null,2));
  const page=await context.newPage();pages.push(page);page.on('pageerror',e=>{console.error(`Participant ${i} error:`,e.message);});
  await page.addInitScript(({index,disableOverlay})=>{
   // Force trickled candidates to precede the offer, as can happen on phones.
   const sendSignal=WebSocket.prototype.send;
   WebSocket.prototype.send=function(data){let msg;try{msg=JSON.parse(data);}catch{}if(msg?.type==='room-signal'&&msg.payload?.type==='offer'){setTimeout(()=>sendSignal.call(this,data),150);return;}return sendSignal.call(this,data);};
   window.__peers=[];window.__packets=[];window.__packetCount=0;window.__errors=[];window.addEventListener('error',e=>window.__errors.push(e.message));
   const Original=RTCPeerConnection;window.RTCPeerConnection=class extends Original{
    constructor(...a){super(...a);window.__peers.push(this);const attach=dc=>{const send=dc.send.bind(dc);dc.send=data=>{if(dc.label==='pvp-group-video'&&window.__tamper&&data instanceof ArrayBuffer){const corrupt=data.slice(0);const bytes=new Uint8Array(corrupt);bytes[bytes.length-1]^=1;return send(corrupt);}return send(data);};dc.addEventListener('message',e=>{if(dc.label==='pvp-group-video'&&e.data instanceof ArrayBuffer){try{const h=JSON.parse(new TextDecoder().decode(new Uint8Array(e.data,2,new DataView(e.data).getUint16(0))));window.__packetCount++;window.__packets.push(JSON.parse(h.m));if(window.__packets.length>1000)window.__packets.shift();}catch{}}});};this.addEventListener('datachannel',e=>attach(e.channel));const create=this.createDataChannel.bind(this);this.createDataChannel=(...a)=>{const dc=create(...a);attach(dc);return dc;};}
   };
   if(disableOverlay)window.VideoEncoder=undefined;
   navigator.mediaDevices.getUserMedia=async constraints=>{
    window.__constraints=constraints;
    const canvas=document.createElement('canvas');canvas.width=854;canvas.height=480;const ctx=canvas.getContext('2d');ctx.fillStyle=index===0?'#ff0088':'#24583e';ctx.fillRect(0,0,854,480);
    const timer=setInterval(()=>{ctx.fillRect(0,0,854,480);},200),stream=canvas.captureStream(5),track=stream.getVideoTracks()[0],stop=track.stop.bind(track);track.stop=()=>{clearInterval(timer);stop();};
    const audio=new AudioContext(),tone=audio.createOscillator(),gain=audio.createGain(),dest=audio.createMediaStreamDestination();gain.gain.value=.01;tone.connect(gain);gain.connect(dest);tone.start();await audio.resume();const sound=dest.stream.getAudioTracks()[0],stopSound=sound.stop.bind(sound);let soundStopped=false;sound.stop=()=>{if(soundStopped)return;soundStopped=true;stopSound();tone.stop();if(audio.state!=='closed')audio.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};stream.addTrack(sound);if(constraints.video===false){stream.getVideoTracks().forEach(t=>{t.stop();stream.removeTrack(t);});}if(constraints.video===false)for(const t of stream.getVideoTracks()){t.stop();stream.removeTrack(t);}
    const settings=sound.getSettings.bind(sound);let echo=constraints.audio?.echoCancellation;
    sound.getSettings=()=>({...settings(),echoCancellation:echo});sound.applyConstraints=async c=>{if('echoCancellation' in c)echo=c.echoCancellation;};
    if(constraints.audio===false){sound.stop();stream.removeTrack(sound);window.__camera=track;}else window.__capture=stream;return stream;
   };
   navigator.mediaDevices.getDisplayMedia=async()=>{const canvas=document.createElement('canvas');canvas.width=1920;canvas.height=1080;const ctx=canvas.getContext('2d');ctx.fillStyle='#00ccff';const timer=setInterval(()=>ctx.fillRect(0,0,1920,1080),100),stream=canvas.captureStream(10),track=stream.getVideoTracks()[0],stop=track.stop.bind(track);track.stop=()=>{clearInterval(timer);stop();};window.__display=track;return stream;};
  },{index:i,disableOverlay:process.env.PVP_GROUP_DISABLE_ALL==='1'||(i===count-1&&process.env.PVP_GROUP_DISABLE_LAST==='1')});
  await page.goto(base);await page.locator('#connection-dot.online').waitFor();await page.locator('[data-view=people]').click();
 }
 for(let i=1;i<count;i++){await request(0,'/friends/request',{username:users[i].username});await request(i,`/friends/${users[0].id}/accept`);}
 await pages[0].waitForFunction(n=>document.querySelectorAll('.friend-card').length===n,count-1);
}, {timeout:120000});
after(async()=>{await browser?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}if(temp)await rm(temp,{recursive:true,force:true});});
test('voice room discovery, microphone-only capture, mesh growth and return to solo', {timeout:120000}, async()=>{
 const host=pages[0];await host.locator('details.voice-directory > summary').click();await host.locator('#open-voice').click();await host.locator('#group-view').waitFor();
 await host.waitForFunction(()=>document.body.classList.contains('call-stage')&&document.getElementById('group-view').getAnimations().every(animation=>animation.playState!=='running'));
 const bounds=await host.locator('#group-view').boundingBox();
 assert.ok(bounds.x<=1&&bounds.width>=1278,'active room uses the full desktop viewport');
 assert.equal(await host.locator('.sidebar').isVisible(),false,'active room hides navigation');
 await host.locator('#group-back').click();await host.locator('[data-view=settings]').first().click();
 await host.locator('#settings-view').waitFor();
 assert.equal(await host.locator('#group-view').isVisible(),false);
 await host.locator('#return-call').click();
 await host.locator('#group-more').click();await host.locator('#group-fullscreen').click();
 await host.waitForFunction(()=>!!document.fullscreenElement);
 await host.locator('#group-more').click();await host.locator('#group-fullscreen').click();
 await host.waitForFunction(()=>!document.fullscreenElement);
 await host.setViewportSize({width:560,height:800});
 const mobileCall=await host.locator('#group-view').boundingBox();
 assert.ok(mobileCall.x<=1&&mobileCall.width>=558,'active room uses the full mobile viewport');
 assert.equal(await host.locator('.sidebar').isVisible(),false,'mobile active room hides navigation');
 await host.setViewportSize({width:1280,height:900});
 await host.evaluate(()=>{navigator.clipboard.writeText=async value=>{window.__roomLink=value;};});
 await host.locator('#group-copy-link').click();
 const roomLink=await host.evaluate(()=>window.__roomLink);
 assert.match(roomLink,/#voice=/);
 assert.equal(await host.evaluate(()=>window.__constraints.video),false);
 assert.equal(await host.evaluate(()=>window.__capture.getVideoTracks().length),0);
 for(let i=1;i<3;i++){
   await pages[i].locator('details.voice-directory > summary').click();
   await pages[i].locator('#voice-rooms button').waitFor();
   assert.equal(await pages[i].evaluate(()=>!!window.__capture),false);
   if(i===1){await pages[i].goto(roomLink);await pages[i].locator('#voice-link-join').waitFor();assert.equal(await pages[i].evaluate(()=>!!window.__capture),false);await pages[i].locator('#voice-link-join').click();}
   else await pages[i].locator('#voice-rooms button').click();
   await pages[i].locator('#group-view').waitFor();
   assert.equal(await pages[i].evaluate(()=>window.__constraints.video),false);
 }
 for(const page of pages)await page.waitForFunction(()=>window.__peers.filter(p=>p.connectionState==='connected').length===2);
 for(const page of pages)await page.waitForFunction(()=>{const audio=[...document.querySelectorAll('#group-grid audio')];return audio.length===2&&audio.every(a=>!a.muted&&!a.paused&&a.readyState>=2&&a.currentTime>0);});
 for(const page of pages)assert.equal(await page.evaluate(()=>document.querySelector('#toast')?.textContent.includes('Unexpected group signal')||false),false);
 let audioId=await host.evaluate(()=>window.__capture.getAudioTracks()[0].id);
 await host.locator('#group-mic').click();
 assert.equal(await host.evaluate(()=>window.__constraints.audio.echoCancellation),true);
 await host.evaluate(()=>{
   const track=window.__capture.getAudioTracks()[0],apply=track.applyConstraints.bind(track);
   track.applyConstraints=async constraints=>{window.__echoConstraints=constraints;return apply(constraints);};
 });
 await host.locator('#group-more').click();await host.locator('#group-audio-open').click();
 await host.locator('#group-echo-cancellation').uncheck();
 await host.waitForFunction(()=>!document.querySelector('#group-echo-cancellation').disabled);
 assert.deepEqual(await host.evaluate(()=>window.__echoConstraints),{echoCancellation:false});
 assert.equal(await host.evaluate(id=>window.__peers.every(p=>p.getSenders().some(s=>s.track?.id===id&&!s.track.enabled))&&window.__capture.getAudioTracks()[0].readyState==='live',audioId),true,'group echo toggle keeps the muted microphone on every peer');
 await host.locator('#group-echo-cancellation').check();
 await host.waitForFunction(()=>!document.querySelector('#group-echo-cancellation').disabled);
 // Force a browser that needs a new microphone source, then fail the second
 // peer's replacement after the first has succeeded.
 await host.evaluate(()=>{
   window.__echoStream=window.__capture;window.__echoOld=window.__capture.getAudioTracks()[0];
   window.__echoOld.applyConstraints=async()=>{};
   const sender=window.__peers[1].getSenders().find(s=>s.track?.kind==='audio'),replace=sender.replaceTrack.bind(sender);
   window.__failEcho=true;
   sender.replaceTrack=async track=>{if(window.__failEcho&&track!==window.__echoOld){window.__failEcho=false;throw Error('Peer replacement failed');}return replace(track);};
 });
 await host.locator('#group-echo-cancellation').click();
 await host.waitForFunction(()=>!document.querySelector('#group-echo-cancellation').disabled);
 assert.equal(await host.locator('#group-echo-cancellation').isChecked(),true);
 assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].readyState),'ended','failed capture is stopped');
 assert.equal(await host.evaluate(()=>window.__peers.every(p=>p.getSenders().some(s=>s.track===window.__echoOld&&!s.track.enabled))),true,'partial failure restores every group sender');
 await host.locator('#group-echo-cancellation').uncheck();
 await host.waitForFunction(()=>!document.querySelector('#group-echo-cancellation').disabled);
 assert.equal(await host.locator('#group-echo-cancellation').isChecked(),false);
 assert.equal(await host.evaluate(()=>window.__echoOld.readyState),'ended');
 audioId=await host.evaluate(()=>{window.__capture=window.__echoStream;return window.__capture.getAudioTracks()[0].id;});
 assert.equal(await host.evaluate(id=>window.__peers.every(p=>p.getSenders().some(s=>s.track?.id===id&&!s.track.enabled)),audioId),true,'replacement microphone reaches every group peer and stays muted');
 await host.locator('#group-echo-cancellation').check();
 await host.waitForFunction(()=>!document.querySelector('#group-echo-cancellation').disabled);
 await host.locator('#group-audio-close').click();
 await host.evaluate(()=>{window.__realCapture=navigator.mediaDevices.getUserMedia;navigator.mediaDevices.getUserMedia=async c=>{if(c.audio===false)throw new DOMException('Camera denied','NotAllowedError');return window.__realCapture(c);};});
 await host.locator('#group-camera').click();
 await host.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Camera denied'));
 assert.equal(await host.evaluate(()=>window.__capture.getVideoTracks().length),0);
 await host.evaluate(()=>navigator.mediaDevices.getUserMedia=window.__realCapture);
 await host.locator('#group-camera').click();
 try { for(let i=1;i<3;i++)await pages[i].waitForFunction(id=>document.querySelector(`#group-video-${id}`).videoWidth>0,users[0].id); }catch(e){console.log('Video opt-in diagnostics',JSON.stringify(await Promise.all(pages.map(p=>p.evaluate(async()=>({toast:document.querySelector('#toast').textContent,constraints:window.__constraints,streams:window.__capture?.getTracks().map(t=>({id:t.id,kind:t.kind,enabled:t.enabled,ready:t.readyState})),peers:await Promise.all(window.__peers.filter(p=>p.connectionState==='connected').map(async p=>({senders:p.getSenders().map(s=>({kind:s.track?.kind,ready:s.track?.readyState,encodings:s.getParameters().encodings})),directions:p.getTransceivers().map(t=>({direction:t.currentDirection,mid:t.mid,kind:t.receiver.track.kind})),stats:[...(await p.getStats()).values()].filter(s=>s.type==='outbound-rtp'||s.type==='inbound-rtp').map(s=>({kind:s.kind,frames:s.framesEncoded,received:s.framesDecoded,bytes:s.bytesSent}))}))),videos:[...document.querySelectorAll('#group-grid video')].map(v=>({width:v.videoWidth,paused:v.paused,tracks:v.srcObject?.getTracks().map(t=>({kind:t.kind,muted:t.muted,ready:t.readyState}))}))}))))));throw e;}
 assert.equal(await host.evaluate(()=>window.__constraints.audio),false);
 assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].id),audioId);
 assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false,'camera opt-in preserves mute');
 assert.equal(await host.evaluate(()=>window.__peers.filter(p=>p.connectionState==='connected').length),2);
 await host.locator('#group-camera').click();
 await host.waitForFunction(()=>window.__camera.readyState==='ended');
 assert.equal(await host.evaluate(()=>window.__capture.getVideoTracks().length),0);
 await host.locator('#group-mic').click();
 if(process.env.PVP_TEST_SCREENSHOTS!=='0'){await mkdir('docs/screenshots',{recursive:true});await host.screenshot({path:'docs/screenshots/voice-room-web.png'});}
 await pages[2].locator('#group-leave').click();await pages[1].locator('#group-leave').click();
 await host.waitForFunction(()=>document.querySelectorAll('#group-grid .group-tile').length===1);
 assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].readyState),'live');
 await host.locator('#group-leave').click();
 await pages[1].waitForFunction(()=>document.querySelectorAll('#voice-rooms button').length===0);
 if(process.env.PVP_TEST_SCREENSHOTS!=='0')await host.screenshot({path:'docs/screenshots/friends-discord-web.png'});
 assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].readyState),'ended');
});
