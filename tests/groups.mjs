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
let server,browser,base,temp;const contexts=[],pages=[],users=[];
const count=Number(process.env.PVP_GROUP_TEST_SIZE||6),suffix=Date.now().toString().slice(-9);
const overlay=count>5&&process.env.PVP_GROUP_DISABLE_ALL!=='1';
const wait=(page,fn,arg,timeout=60000)=>page.waitForFunction(fn,arg,{timeout});
async function request(i,path,data,method='POST'){const r=await contexts[i].request.fetch(`${base}/api${path}`,{method,headers:{Origin:base},...(data?{data}:{})});assert.equal(r.status(),200,`${path}: ${await r.text()}`);return r.json();}
before(async()=>{
 await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));base=`http://localhost:${port}`;
 temp=await mkdtemp(join(tmpdir(),'pvp-groups-'));server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
 for(let i=0;i<100;i++){try{if((await fetch(`${base}/health`)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 browser=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});
 for(let i=0;i<count;i++){
  const context=await browser.newContext({viewport:{width:1280,height:900}});contexts.push(context);
  users.push(await request(i,'/register',{username:`group${i}_${suffix}`,display_name:`Group participant ${i}`,password:'group-test-passphrase-123'}));
  const page=await context.newPage();pages.push(page);page.on('pageerror',e=>{console.error(`Participant ${i} error:`,e.message);});
  await page.addInitScript(({index,disableOverlay})=>{
   // Force trickled candidates to precede the offer, as can happen on phones.
   const sendSignal=WebSocket.prototype.send;
   WebSocket.prototype.send=function(data){let msg;try{msg=JSON.parse(data);}catch{}if(msg?.type==='room-signal'&&msg.payload?.type==='offer'){setTimeout(()=>sendSignal.call(this,data),150);return;}return sendSignal.call(this,data);};
   window.__peers=[];window.__packets=[];window.__packetCount=0;window.__errors=[];document.addEventListener('pvp-media-health',event=>{if(event.detail.type==='quality')window.__quality=event.detail;});window.addEventListener('error',e=>window.__errors.push(e.message));
   const Original=RTCPeerConnection;window.RTCPeerConnection=class extends Original{
    constructor(...a){super(...a);window.__peers.push(this);const attach=dc=>{const send=dc.send.bind(dc);dc.send=data=>{if(dc.label==='pvp-group-video'&&window.__tamper&&data instanceof ArrayBuffer){const corrupt=data.slice(0);const bytes=new Uint8Array(corrupt);bytes[bytes.length-1]^=1;return send(corrupt);}return send(data);};dc.addEventListener('message',e=>{if(dc.label==='pvp-group-video'&&e.data instanceof ArrayBuffer){try{const h=JSON.parse(new TextDecoder().decode(new Uint8Array(e.data,2,new DataView(e.data).getUint16(0))));window.__packetCount++;window.__packets.push(JSON.parse(h.m));if(window.__packets.length>1000)window.__packets.shift();}catch{}}});};this.addEventListener('datachannel',e=>attach(e.channel));const create=this.createDataChannel.bind(this);this.createDataChannel=(...a)=>{const dc=create(...a);attach(dc);return dc;};}
   };
   if(disableOverlay)window.VideoEncoder=undefined;
   navigator.mediaDevices.getUserMedia=async constraints=>{
    const canvas=document.createElement('canvas');canvas.width=854;canvas.height=480;const ctx=canvas.getContext('2d');ctx.fillStyle=index===0?'#ff0088':'#24583e';ctx.fillRect(0,0,854,480);
    const timer=setInterval(()=>{ctx.fillRect(0,0,854,480);},200),stream=canvas.captureStream(5),track=stream.getVideoTracks()[0],stop=track.stop.bind(track);track.stop=()=>{clearInterval(timer);stop();};
    const audio=new AudioContext(),tone=audio.createOscillator(),gain=audio.createGain(),dest=audio.createMediaStreamDestination();gain.gain.value=.01;tone.connect(gain);gain.connect(dest);tone.start();await audio.resume();const sound=dest.stream.getAudioTracks()[0],stopSound=sound.stop.bind(sound);let soundStopped=false;sound.stop=()=>{if(soundStopped)return;soundStopped=true;stopSound();tone.stop();if(audio.state!=='closed')audio.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};stream.addTrack(sound);if(constraints.video===false)for(const t of stream.getVideoTracks()){t.stop();stream.removeTrack(t);}
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
test('tree degree and path are bounded for every source in a 16-member room',()=>{
 const ids=Array.from({length:16},(_,i)=>String(i).padStart(2,'0'));
 for(const source of ids){const tree=treeFor(ids,source);assert.equal(tree[0],source);for(const id of ids){assert.ok(treeChildren(ids,source,id).length<=4);if(id!==source){let hops=0,node=id;while(node!==source){node=treeParent(ids,source,node);assert.ok(node);assert.ok(++hops<=2);}}}}
});
test(`${count}-participant browser room: explicit admission, encrypted mesh audio, ${!overlay?'direct video':'signed encrypted forwarded video'}, recovery and screen share`,{timeout:240000},async()=>{
 const host=pages[0];await host.locator('details.people-options > summary').click();await host.locator('#new-group').click();for(const box of await host.locator('#group-picker-form input').all())await box.check();await host.locator('#group-picker-form button[type=submit]').click();await host.locator('#group-view').waitFor({state:'visible'});
 for(let i=1;i<count;i++){await pages[i].locator('#group-incoming').waitFor({state:'visible'});assert.equal(await pages[i].evaluate(()=>!!window.__capture),false,'invitation does not capture media');assert.ok((await pages[i].locator('#group-invite-detail').textContent()).includes('outside your friends list'));await pages[i].locator('#group-join').click();}
 for(const page of pages){
  try{await wait(page,n=>window.__peers.filter(p=>p.connectionState==='connected').length===n,count-1,90000);}catch(error){console.log('Group diagnostics',await Promise.all(pages.map(p=>p.evaluate(()=>({peers:window.__peers.map(p=>({connection:p.connectionState,ice:p.iceConnectionState,signaling:p.signalingState})),toast:document.getElementById('toast').textContent,heading:document.getElementById('group-heading').textContent,errors:window.__errors})))));throw error;}
  await wait(page,async n=>{const peers=window.__peers.filter(p=>p.connectionState==='connected');return peers.length===n&&(await Promise.all(peers.map(async p=>[...(await p.getStats()).values()].some(s=>s.type==='inbound-rtp'&&s.kind==='audio'&&s.bytesReceived>100&&s.totalAudioEnergy>0)))).every(Boolean);},count-1,90000);
  assert.ok(await page.evaluate(()=>{const audio=[...document.querySelectorAll('.group-tile:not(.self) audio')];return audio.length===window.__peers.filter(peer=>peer.connectionState==='connected').length&&audio.every(sink=>!sink.paused&&!sink.muted&&sink.srcObject?.getAudioTracks().some(track=>track.enabled));}),'every separate remote audio sink is playing');
  const transports=await page.evaluate(async()=>Promise.all(window.__peers.filter(p=>p.connectionState==='connected').map(async p=>[...(await p.getStats()).values()].filter(s=>s.type==='transport').map(s=>({dtls:s.dtlsState,cipher:s.dtlsCipher,srtp:s.srtpCipher})))));
  assert.ok(transports.every(t=>t.some(s=>s.dtls==='connected'&&s.cipher&&s.srtp)),'all peer links negotiate encryption');
 }
 if(!overlay)for(const page of pages)assert.equal(await page.evaluate(()=>window.__packets.length),0,'small calls never send overlay video');
 for(const page of pages){assert.equal(await page.evaluate(()=>window.__capture.getVideoTracks().length),0);await page.locator('#group-camera').click();}
 console.log('All encrypted audio links connected');
 const sourceId=users[0].id,order=treeFor(users.map(u=>u.id),sourceId),victimIndex=users.findIndex(u=>u.id===order[1]);
 const receiverIndex=users.findIndex((u,i)=>i!==0&&i!==victimIndex&&!(i===count-1&&process.env.PVP_GROUP_DISABLE_LAST==='1'));const receiver=pages[receiverIndex];
 if(!overlay)await wait(receiver,id=>document.getElementById(`group-video-${id}`)?.videoWidth>0,sourceId);else await wait(receiver,id=>{const c=document.getElementById(`group-canvas-${id}`);return c&&!c.hidden&&c.width>0;},sourceId,90000);
 await wait(receiver,({id,fallback})=>{let canvas=document.getElementById(`group-canvas-${id}`);if(fallback){const video=document.getElementById(`group-video-${id}`);if(!video?.videoWidth)return false;canvas=document.createElement('canvas');canvas.width=video.videoWidth;canvas.height=video.videoHeight;canvas.getContext('2d').drawImage(video,0,0);}if(!canvas?.width)return false;const pixel=canvas.getContext('2d').getImageData(10,10,1,1).data;return pixel[0]>200&&pixel[1]<40&&pixel[2]>80;},{id:sourceId,fallback:!overlay},30000);
 const pixel=await receiver.evaluate(({id,fallback})=>{let c=document.getElementById(`group-canvas-${id}`);if(fallback){const v=document.getElementById(`group-video-${id}`);c=document.createElement('canvas');c.width=v.videoWidth;c.height=v.videoHeight;c.getContext('2d').drawImage(v,0,0);}return [...c.getContext('2d').getImageData(10,10,1,1).data];},{id:sourceId,fallback:!overlay});
 assert.ok(pixel[0]>200&&pixel[1]<40&&pixel[2]>80,'decoded forwarded frame contains the source pixels');
 if(count>5&&overlay){const ids=users.map(u=>u.id),leaf=ids.find(id=>id!==sourceId&&treeParent(ids,sourceId,id)!==sourceId),leafPage=pages[ids.indexOf(leaf)];await wait(leafPage,source=>window.__packets.some(m=>m.source===source),sourceId,90000);assert.ok(treeParent(ids,sourceId,leaf)!==sourceId,'observed source packets arrived at a second-hop leaf');}
 if(overlay)for(const page of pages){
  await wait(page,()=>window.__quality?.sent.peers.some(peer=>peer.path==='encoded-forwarding'&&peer.rows.some(row=>row.width>0&&row.height>0&&row.fps>0&&row.kbps>0)),null,30000);
  assert.match(await page.evaluate(()=>window.__quality.sent.label),/Encoded forwarding .* encoder payload · delivery unverified/,'forwarded camera quality uses actual encoded output, not disabled RTP or preview dimensions');
 }
 console.log('Source pixels verified');
 await receiver.locator(`#group-tile-${sourceId} .group-small-button`).last().click();
 const downloadEvent=receiver.waitForEvent('download',{timeout:10000});await receiver.locator('#group-export').click();let download;try{download=await downloadEvent;}catch(e){console.log('Export diagnostics',await receiver.evaluate(()=>({toast:document.getElementById('toast').textContent,detail:document.getElementById('group-inspector-detail').textContent,errors:window.__errors})));throw e;}
 const {readFile}=await import('node:fs/promises');const report=JSON.parse(await readFile(await download.path(),'utf8'));
 assert.equal(report.peers.length,count-1);assert.ok(report.peers.every(p=>p.media?.selectedPairId&&p.media.dtlsState==='connected'&&['host','srflx','prflx'].includes(p.media.local?.candidateType)&&['host','srflx','prflx'].includes(p.media.remote?.candidateType)),'observed selected paths use peer candidates and encrypted transports');for(const p of report.peers){const pair=p.media.pairs.find(q=>q.selected);assert.equal(p.media.direct,pair?.state==='succeeded','UI does not call an in-progress ICE observation verified');}if(overlay)assert.ok(report.peers.some(p=>p.overlay.receivedBytes>0));assert.ok(!JSON.stringify(report).includes('overlay-key'),'export excludes media keys');
 for(const p of report.peers){
  assert.equal(p.receivingForwardedVideo,!!p.receivingEncodedVideo&&treeParent(users.map(u=>u.id),p.peerId,users[receiverIndex].id)!==p.peerId,'forwarding means an intermediate hop');
  assert.equal(p.forwarder,p.receivingForwardedVideo?treeParent(users.map(u=>u.id),p.peerId,users[receiverIndex].id):null);
  if(p.peerId===sourceId&&p.receivingEncodedVideo)assert.ok((await receiver.locator('#group-inspector-detail').textContent()).includes(p.receivingForwardedVideo?'immediate forwarder':'received directly from source'));
 }
 // Each viewer requests an independent stream ceiling, including when forwarding was active.
 await wait(receiver,()=>/You · ↓ .* · ↑ .*MB\/min/.test(document.getElementById('group-bandwidth').textContent));
 const receiveCamera=receiver.locator('#group-bandwidth-controls select[data-direction="receive"][data-source="camera"]');
 await receiveCamera.selectOption('64');
 await wait(host,()=>window.__peers.filter(p=>p.connectionState==='connected').flatMap(p=>p.getSenders()).some(s=>s.track?.kind==='video'&&s.getParameters().encodings?.some(e=>e.maxBitrate===64000)),null,15000);
 assert.ok(await host.evaluate(()=>window.__peers.filter(p=>p.connectionState==='connected').flatMap(p=>p.getSenders()).some(s=>s.track?.kind==='video'&&s.getParameters().encodings?.some(e=>e.maxBitrate!==64000))),'another viewer retains an independent limit');
 await receiveCamera.selectOption('8000');
 await wait(host,()=>window.__peers.filter(p=>p.connectionState==='connected').flatMap(p=>p.getSenders()).some(s=>s.track?.kind==='video'&&s.getParameters().encodings?.some(e=>e.maxBitrate===8000000)),null,15000);
 await receiveCamera.selectOption('');
 if(overlay)await wait(receiver,id=>document.getElementById(`group-canvas-${id}`)?.hidden===false,sourceId,30000);
 console.log('Connection report exported');
 await receiver.locator('#group-inspect-close').click();
 if(overlay){
  await host.evaluate(()=>window.__tamper=true);
  await wait(receiver,id=>document.getElementById(`group-canvas-${id}`)?.hidden===true,sourceId,15000);
  await host.evaluate(()=>window.__tamper=false);
  await wait(receiver,id=>document.getElementById(`group-canvas-${id}`)?.hidden===false,sourceId,30000);
 }
 if(overlay)console.log('Tamper rejection and recovery verified');
 await host.locator('#group-mic').click();assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false);
 if(count<=8)await wait(receiver,({id,fallback})=>fallback?document.getElementById(`group-video-${id}`)?.videoHeight>=480:document.getElementById(`group-canvas-${id}`)?.height>=480,{id:sourceId,fallback:!overlay},30000);

 await host.locator('#group-share').click();await wait(receiver,id=>document.getElementById(`group-video-${id}`)?.videoWidth===1920,sourceId,90000);assert.equal(await host.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false,'screen share preserves microphone mute');
 await receiver.locator(`#group-tile-${sourceId} [data-maximize]`).click();
 await wait(receiver,id=>document.getElementById(`group-tile-${id}`).classList.contains('maximized'),sourceId);
 const bounds=await receiver.locator(`#group-tile-${sourceId}`).boundingBox();assert.ok(bounds.width>1100&&bounds.height>500,'maximized share fills the call area');
 await wait(host,async()=>{const senders=window.__peers.filter(p=>p.connectionState==='connected').flatMap(p=>p.getSenders()).filter(s=>s.track?.kind==='video');return senders.some(s=>s.getParameters().encodings?.some(e=>e.maxBitrate===6000000));},null,15000);
 await receiver.locator(`#group-tile-${sourceId} [data-maximize]`).click();
 await host.locator('#group-share').click();await wait(host,()=>window.__display.readyState==='ended');
 await host.locator('#group-mic').click();
 if(process.env.PVP_GROUP_TEST_SCREENSHOTS==='1'){await mkdir('.build/groups/screenshots',{recursive:true});await receiver.screenshot({path:'.build/groups/screenshots/browser-group.png'});}
 // A failed pair is recreated and every participant receives audio again.
 const initiator=pages[users.map(u=>u.id).indexOf([...users.map(u=>u.id)].sort()[0])];
 const oldCount=await initiator.evaluate(()=>window.__peers.length);
 await initiator.evaluate(()=>{const pc=window.__peers.find(p=>p.connectionState==='connected');Object.defineProperty(pc,'connectionState',{configurable:true,get:()=> 'failed'});pc.dispatchEvent(new Event('connectionstatechange'));delete pc.connectionState;});
 await wait(initiator,n=>window.__peers.length>n,oldCount,20000);
 for(const page of pages)await wait(page,async n=>{const peers=window.__peers.filter(p=>p.connectionState==='connected');return peers.length===n&&(await Promise.all(peers.map(async p=>[...(await p.getStats()).values()].some(s=>s.type==='inbound-rtp'&&s.kind==='audio'&&s.totalAudioEnergy>0)))).every(Boolean);},count-1,30000);
 // Removing a forwarder changes the tree, rotates keys, and keeps the call alive.
 const victim=pages[victimIndex];await victim.locator('#group-leave').click();await victim.locator('#group-view').waitFor({state:'hidden'});assert.equal(await victim.evaluate(()=>window.__capture.getTracks().every(t=>t.readyState==='ended')),true);
 if(!overlay||count===6)await wait(receiver,id=>document.getElementById(`group-video-${id}`)?.videoWidth>0&&document.getElementById(`group-canvas-${id}`)?.hidden,sourceId);else await wait(receiver,id=>{const c=document.getElementById(`group-canvas-${id}`);return c&&!c.hidden&&c.width>0;},sourceId,60000);
 if(count===9&&overlay)await wait(receiver,id=>document.getElementById(`group-canvas-${id}`)?.height>=480,sourceId,30000);
 if(count===6&&overlay){await receiver.waitForTimeout(2500);const packets=await receiver.evaluate(()=>window.__packetCount);await receiver.waitForTimeout(1500);assert.equal(await receiver.evaluate(()=>window.__packetCount),packets,'forwarding stops when the sixth participant leaves');}
 assert.equal(await host.locator('#group-view').isVisible(),true);
 for(const page of pages.filter((_,i)=>i!==victimIndex))await page.locator('#group-leave').click();
 for(const page of pages){await page.locator('#group-view').waitFor({state:'hidden'});assert.equal(await page.evaluate(()=>window.__peers.every(p=>p.connectionState==='closed')),true);assert.deepEqual(await page.evaluate(()=>window.__errors),[]);}
});
