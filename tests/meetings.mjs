import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
import {meetingId} from '../web/meetings.js';
async function moderate(page,id,action){await page.locator('#group-people').click();const row=page.locator(`#group-people-content [data-member-id="${id}"]`);await row.locator('summary').click();await row.locator(`[data-action="${action}"]`).click();await page.locator('#group-people-close').click();}
test('meeting link parsing binds admission to this service',()=>{
 const id='a'.repeat(64),origin='https://lopixel.space';
 assert.equal(meetingId(`${origin}/#meeting=${id}`,origin),id);
 assert.equal(meetingId(`https://other.example/#meeting=${id}`,origin),null);
 assert.equal(meetingId(`https://user:password@lopixel.space/#meeting=${id}`,origin),null);
});
test('permanent browser meeting: explicit capture, owner-offline encrypted call, repeated use, restart and migration',{timeout:150000},async()=>{
 const temp=await mkdtemp(join(tmpdir(),'pvp-meetings-'));let browser,server;let db=join(temp,'pvp.sqlite');
 try {
  await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
  const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
  const start=async()=>{server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:db},stdio:'ignore'});for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('Service not ready');};
  const stop=async()=>{server.kill();await new Promise(r=>server.once('exit',r));server=null;};
  await start();browser=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});const peers=[];
  const request=async(i,path,data,method='POST',status=200)=>{const r=await peers[i].context.request.fetch(base+'/api'+path,{method,headers:{Origin:base},...(data?{data}:{})});assert.equal(r.status(),status,`${path}: ${await r.text()}`);return r.json();};
  for(let i=0;i<4;i++){
   const context=await browser.newContext(),page=await context.newPage();peers.push({context,page});
   peers[i].user=await request(i,'/register',{username:`meeting${i}_${Date.now().toString().slice(-9)}`,display_name:`Meeting member ${i}`,password:'meeting-test-password-123'});
   await page.addInitScript(()=>{
    window.__captures=0;window.__peers=[];window.__errors=[];window.addEventListener('error',e=>window.__errors.push(e.message));
    const Original=RTCPeerConnection;window.RTCPeerConnection=class extends Original{constructor(...a){super(...a);window.__peers.push(this);}};
    navigator.mediaDevices.getUserMedia=async constraints=>{window.__captures++;const c=document.createElement('canvas');c.width=320;c.height=180;const g=c.getContext('2d'),timer=setInterval(()=>{g.fillStyle='#ff0088';g.fillRect(0,0,320,180);},100),stream=c.captureStream(10),v=stream.getVideoTracks()[0],stop=v.stop.bind(v);v.stop=()=>{clearInterval(timer);stop();};const audio=new AudioContext(),tone=audio.createOscillator(),dest=audio.createMediaStreamDestination();tone.connect(dest);tone.start();await audio.resume();const sound=dest.stream.getAudioTracks()[0],stopSound=sound.stop.bind(sound);let soundStopped=false;sound.stop=()=>{if(soundStopped)return;soundStopped=true;stopSound();tone.stop();if(audio.state!=='closed')audio.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};stream.addTrack(sound);if(constraints.video===false){v.stop();stream.removeTrack(v);}if(constraints.audio===false){sound.stop();stream.removeTrack(sound);}else window.__capture=stream;return stream;};
   });await page.goto(base);await page.locator('#connection-dot.online').waitFor();
  }
  for(let i=1;i<3;i++){await request(0,'/friends/request',{username:peers[i].user.username});await request(i,`/friends/${peers[0].user.id}/accept`);}
  const owner=peers[0].page;await owner.waitForFunction(()=>document.querySelectorAll('.friend-card').length===2);
  await owner.locator('#meeting-links-nav').click();assert.equal(await owner.locator('#people-view').isVisible(),false);assert.equal(await owner.locator('#meetings-dialog').evaluate(el=>el.tagName),'SECTION');assert.equal(await owner.locator('.sidebar').isVisible(),true);await owner.locator('#meeting-new').click();await owner.locator('#meeting-name').fill('Weekly team meeting');await owner.locator('#meeting-access').selectOption('private');await owner.locator('#meeting-create-form details > summary').click();for(const b of await owner.locator('#meetings-content input[type=checkbox]').all())await b.check();await owner.locator('#meeting-create').click();await owner.locator('#meeting-link').waitFor({state:'attached'});const url=await owner.locator('#meeting-link').inputValue(),id=new URL(url).hash.split('=')[1];assert.match(id,/^[0-9a-f]{64}$/);assert.equal(await owner.evaluate(()=>window.__captures),0);
  await request(3,`/meetings/${id}`,null,'GET',403);await request(3,`/meetings/${id}/members`,{peer_id:peers[3].user.id},'POST',403);
  const adminRow=owner.locator(`[data-member-id="${peers[1].user.id}"]`);
  await adminRow.locator('summary').click();await adminRow.getByRole('button',{name:'Make admin',exact:true}).click();
  await adminRow.locator('button').filter({hasText:/^Remove admin$/}).waitFor({state:'attached'});
  await request(2,`/meetings/${id}/members/${peers[2].user.id}/admin`,{admin:true},'POST',403);
  await request(2,`/meetings/${id}/members/${peers[1].user.id}/mute`,{muted:true},'POST',403);
  await owner.getByRole('button',{name:'All rooms',exact:true}).click();
  await owner.locator('#meeting-new').click();
  await owner.locator('#meeting-name').fill('Open invite meeting');
  await owner.locator('#meeting-access').selectOption('open');
  await owner.locator('#meeting-create').click();await owner.locator('#meeting-link').waitFor({state:'attached'});
  const openUrl=await owner.locator('#meeting-link').inputValue(),openId=new URL(openUrl).hash.split('=')[1];
  const outsider=peers[3];await outsider.page.goto(openUrl);await outsider.page.locator('#guest-submit').waitFor();
  assert.equal(await outsider.page.evaluate(()=>window.__captures),0,'open preview keeps capture off');
  let openMeeting=await request(3,`/meetings/${openId}`,null,'GET');assert.equal(openMeeting.open_invite,true);assert.equal(openMeeting.members.length,1,'preview does not enroll');
  await request(3,`/meetings/${openId}/members/${peers[0].user.id}/mute`,{muted:true},'POST',403);
  await owner.locator('#meeting-join').click();await owner.locator('#guest-submit').click();await owner.locator('#group-view').waitFor({state:'visible'});
  await outsider.page.locator('#guest-submit').click();await outsider.page.locator('#group-view').waitFor({state:'visible'});
  await outsider.page.waitForFunction(async()=>{for(const pc of window.__peers){if(pc.connectionState!=='connected')continue;const stats=[...(await pc.getStats()).values()];if(stats.some(s=>s.type==='transport'&&s.dtlsState==='connected'&&s.srtpCipher)&&stats.some(s=>s.type==='inbound-rtp'&&s.kind==='audio'&&s.bytesReceived>100))return true;}return false;},null,{timeout:30000});
  openMeeting=await request(0,`/meetings/${openId}`,null,'GET');assert.equal(openMeeting.members.length,2);assert.equal(openMeeting.members.find(m=>m.id===outsider.user.id).is_admin,false);
  await owner.locator('#group-chat-open').click();await outsider.page.locator('#group-chat-open').click();
  await owner.waitForFunction(()=>document.getElementById('meeting-chat-status').textContent.startsWith('1 participant connected to chat'));
  await owner.locator('#meeting-chat-text').fill('<img src=x onerror=alert(1)> hello 🌍');await owner.locator('#meeting-chat-form button[type=submit]').click();
  await outsider.page.locator('.chat-message').filter({hasText:'<img src=x onerror=alert(1)> hello 🌍'}).waitFor();assert.equal(await outsider.page.locator('.chat-message img').count(),0,'text is rendered without interpreting HTML');
  const fileBytes=Buffer.from(Array.from({length:70000},(_,i)=>i%256));
  await owner.locator('#meeting-chat-file').setInputFiles({name:'arbitrary.bin',mimeType:'application/octet-stream',buffer:fileBytes});
  const incoming=outsider.page.locator('.chat-message').filter({hasText:'arbitrary.bin'});await incoming.getByRole('button',{name:'Accept file',exact:true}).waitFor();assert.equal(await incoming.getByRole('link',{name:'Save file'}).count(),0,'no unsolicited transfer');
  await incoming.getByRole('button',{name:'Accept file',exact:true}).click();await incoming.getByRole('link',{name:'Save file'}).waitFor();
  const downloaded=outsider.page.waitForEvent('download');await incoming.getByRole('link',{name:'Save file'}).click();const download=await downloaded,stream=await download.createReadStream(),chunks=[];for await(const chunk of stream)chunks.push(chunk);assert.deepEqual(Buffer.concat(chunks),fileBytes,'chunked binary attachment is byte-identical');
  const png=Buffer.from(await owner.evaluate(()=>{const c=document.createElement('canvas');c.width=c.height=2;c.getContext('2d').fillRect(0,0,2,2);return c.toDataURL('image/png').split(',')[1];}),'base64');
  await owner.locator('#meeting-chat-file').setInputFiles({name:'image.png',mimeType:'image/png',buffer:png});const image=outsider.page.locator('.chat-message').filter({hasText:'image.png'});await image.getByRole('button',{name:'Accept file',exact:true}).click();await image.locator('img').waitFor();await image.locator('img').evaluate(img=>img.decode());
  await owner.locator('#meeting-chat-close').click();
  await request(0,`/meetings/${openId}/members/${outsider.user.id}`,null,'DELETE');
  await outsider.page.locator('#group-view').waitFor({state:'hidden'});await request(3,`/meetings/${openId}`,null,'GET',403);
  await owner.locator('#group-leave').click();await owner.locator('#group-view').waitFor({state:'hidden'});
  assert.equal(await owner.evaluate(()=>{const retired=window.__peers.find(p=>p.connectionState==='closed');let closed=false;retired.ondatachannel({channel:{label:'pvp-group-chat',readyState:'open',send:()=>{},close:()=>{closed=true;}}});return closed;}),true,'late channels cannot restore chat after leaving');
  await request(0,`/meetings/${openId}`,null,'DELETE');
  await owner.close(); // The creator does not have to be present.
  for(const peer of peers.slice(1,3)){await peer.page.goto(url);await peer.page.reload();await peer.page.locator('#guest-submit').waitFor();assert.equal(await peer.page.evaluate(()=>window.__captures),0);}
  const joinCall=async()=>{
   for(const peer of peers.slice(1,3)){await peer.page.locator('#guest-submit').click();await peer.page.locator('#group-view').waitFor({state:'visible'});}
   for(const peer of peers.slice(1,3)){
    let observed=false;const end=Date.now()+30000;
    while(Date.now()<end){
     const stats=await peer.page.evaluate(async()=>{const pc=window.__peers.find(p=>p.connectionState==='connected');return pc?[...(await pc.getStats()).values()].map(s=>JSON.parse(JSON.stringify(s))):[];});
     observed=stats.some(s=>s.type==='inbound-rtp'&&s.kind==='audio'&&s.bytesReceived>100)&&stats.some(s=>s.type==='transport'&&s.dtlsState==='connected'&&s.dtlsCipher&&s.srtpCipher);
     if(observed)break;await new Promise(r=>setTimeout(r,100));
    }
    assert.ok(observed,'real encrypted audio traffic observed');assert.match(await peer.page.locator('#group-heading').textContent(),/Weekly team meeting/);
   }
  };
  await joinCall();console.log('First encrypted meeting joined');let m=await request(1,`/meetings/${id}`,null,'GET');assert.equal(m.participants.length,2);
  await peers[1].page.locator('#group-camera').click();
  const source=peers[1].user.id;await peers[2].page.waitForFunction(id=>{const v=document.getElementById(`group-video-${id}`),c=document.getElementById(`group-canvas-${id}`);return v?.videoWidth>0&&c?.hidden;},source,{timeout:30000});
  const admin=peers[1].page,target=peers[2].page,targetId=peers[2].user.id;
  const tile=admin.locator(`#group-tile-${targetId}`);
  await moderate(admin,targetId,'mute');
  await target.waitForFunction(()=>document.getElementById('group-mic').disabled&&window.__capture.getAudioTracks().every(t=>!t.enabled));
  await admin.waitForFunction(id=>document.getElementById(`group-video-${id}`).srcObject.getAudioTracks().every(t=>!t.enabled),targetId);
  // A modified sender can ignore the mute; honest receivers still block its audio.
  await target.evaluate(()=>window.__capture.getAudioTracks().forEach(t=>t.enabled=true));
  assert.equal(await admin.evaluate(id=>document.getElementById(`group-video-${id}`).srcObject.getAudioTracks()[0].enabled,targetId),false);
  await target.evaluate(()=>window.__capture.getAudioTracks().forEach(t=>t.enabled=false));
  await moderate(admin,targetId,'allow');
  await target.waitForFunction(()=>!document.getElementById('group-mic').disabled);
  assert.equal(await target.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false,'allow unmute never turns on a microphone');
  await target.locator('#group-mic').click();assert.equal(await target.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),true);
  await moderate(admin,targetId,'mute');await target.waitForFunction(()=>document.getElementById('group-mic').disabled);
  const leave=async()=>{for(const peer of peers.slice(1,3)){await peer.page.locator('#group-leave').click();await peer.page.locator('#group-view').waitFor({state:'hidden'});}};
  await leave();assert.equal((await request(1,`/meetings/${id}`,null,'GET')).participants.length,0);
  for(const peer of peers.slice(1,3)){await peer.page.goto(url);await peer.page.reload();await peer.page.locator('#guest-submit').waitFor();}await joinCall();console.log('Meeting reuse joined');await leave();
  console.log('Restarting service');await stop();await start();for(const peer of peers.slice(1,3)){await peer.page.goto(url);await peer.page.reload();await peer.page.locator('#guest-submit').waitFor();}await joinCall();console.log('Meeting reuse joined');await leave();
  console.log('Migrating database');await stop();const migrated=join(temp,'restored.sqlite');await promisify(execFile)('python3',['-c','import sqlite3,sys; source=sqlite3.connect(sys.argv[1]); dest=sqlite3.connect(sys.argv[2]); source.backup(dest); dest.close(); source.close()',db,migrated]);db=migrated;await start();for(const peer of peers.slice(1,3)){await peer.page.goto(url);await peer.page.reload();await peer.page.locator('#guest-submit').waitFor();}assert.equal((await request(1,`/meetings/${id}`,null,'GET')).url,url);await joinCall();
  assert.equal((await request(1,`/meetings/${id}`,null,'GET')).members.find(m=>m.id===peers[1].user.id).is_admin,true,'admin appointment survives restore');
  await target.waitForFunction(()=>document.getElementById('group-mic').disabled&&window.__capture.getAudioTracks().every(t=>!t.enabled));
  admin.once('dialog',dialog=>dialog.accept());await moderate(admin,targetId,'kick');
  await target.locator('#group-view').waitFor({state:'hidden'});await request(2,`/meetings/${id}`,null,'GET',403);
  assert.equal(await target.evaluate(()=>window.__capture.getTracks().every(t=>t.readyState==='ended')),true);
  await request(0,`/meetings/${id}/members/${peers[1].user.id}/admin`,{admin:false});
  await request(1,`/meetings/${id}/members/${peers[2].user.id}/mute`,{muted:false},'POST',403);
  await request(0,`/meetings/${id}/members/${peers[1].user.id}`,null,'DELETE');await peers[1].page.locator('#group-view').waitFor({state:'hidden'});await request(1,`/meetings/${id}`,null,'GET',403);
  await request(0,`/meetings/${id}`,null,'DELETE');await peers[2].page.locator('#group-view').waitFor({state:'hidden'});await request(2,`/meetings/${id}`,null,'GET',403);
  assert.deepEqual(await request(0,'/meetings',null,'GET'),[]);for(const peer of peers.slice(1,3))assert.deepEqual(await peer.page.evaluate(()=>window.__errors),[]);
 }finally{await browser?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
});
