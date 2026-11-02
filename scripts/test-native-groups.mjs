import { chromium } from 'playwright';
import { spawn,execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp,rm,writeFile,mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join,resolve } from 'node:path';
import { createServer } from 'node:http';
const temp=await mkdtemp(join(tmpdir(),'pvp-native-groups-')),suffix=Date.now().toString().slice(-9),native=`nativeg_${suffix}`;
let server,browser,control;
try{
 await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
 server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
 for(let i=0;i<100;i++){try{if((await fetch(`${base}/health`)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 browser=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});const peers=[];
 for(let i=0;i<(process.env.PVP_TEST_VOICE==='1'||process.env.PVP_TEST_LISTENER==='1'?2:5);i++){
  const context=await browser.newContext(),page=await context.newPage();const response=await context.request.post(`${base}/api/register`,{headers:{Origin:base},data:{username:`browserg${i}_${suffix}`,display_name:`Browser ${i}`,password:'native-group-passphrase-123'}});if(response.status()!==200)throw Error(await response.text());const user=await response.json();
  await page.addInitScript(()=>{
   const Original=window.RTCPeerConnection;window.__peers=[];window.RTCPeerConnection=class extends Original{constructor(...args){super(...args);window.__peers.push(this);}};

   navigator.mediaDevices.getUserMedia=async constraints=>{const canvas=document.createElement('canvas');canvas.width=854;canvas.height=480;const ctx=canvas.getContext('2d');const timer=setInterval(()=>{ctx.fillStyle='#ff0088';ctx.fillRect(0,0,854,480);},200),stream=canvas.captureStream(5),track=stream.getVideoTracks()[0],stop=track.stop.bind(track);track.stop=()=>{clearInterval(timer);stop();};const audio=new AudioContext(),tone=audio.createOscillator(),gain=audio.createGain(),dest=audio.createMediaStreamDestination();gain.gain.value=.01;tone.connect(gain);gain.connect(dest);tone.start();await audio.resume();const sound=dest.stream.getAudioTracks()[0],stopSound=sound.stop.bind(sound);sound.stop=()=>{stopSound();tone.stop();audio.close();};stream.addTrack(sound);if(constraints.audio===false){sound.stop();stream.removeTrack(sound);}if(constraints.video===false)for(const track of stream.getVideoTracks()){track.stop();stream.removeTrack(track);}return stream;};
  });
  page.on('pageerror',e=>console.error('Browser group:',e.message));await page.goto(base);await page.locator('#connection-dot.online').waitFor();peers.push({page,context,user});
 }
 control=createServer(async(req,res)=>{
  try{
   console.log('Native integration command',new URL(req.url,'http://localhost').pathname);
   if(req.url==='/screenshot/native-listening'&&req.method==='POST'){const parts=[];for await(const part of req)parts.push(part);await mkdir('.build/polish-release/screens/native',{recursive:true});await writeFile('.build/polish-release/screens/native/listening.png',Buffer.concat(parts));res.end('{}');return;}
   if(req.url==='/peers'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({peers:peers.map(p=>p.user)}));return;}
   if(req.url==='/accept-requests')for(const peer of peers){const response=await peer.context.request.get(`${base}/api/friends`);const friends=await response.json();const request=friends.find(f=>f.username===native);if(!request)throw Error('Native request missing');const accepted=await peer.context.request.post(`${base}/api/friends/${request.id}/accept`,{headers:{Origin:base}});if(accepted.status()!==200)throw Error(await accepted.text());}
   if(req.url==='/join-voice')for(const peer of peers){await peer.page.locator('#voice-rooms button').waitFor();await peer.page.locator('#voice-rooms button').click();}
   if(req.url==='/join')for(const peer of peers){await peer.page.locator('#group-incoming').waitFor({state:'visible'});await peer.page.locator('#group-join').click();await peer.page.locator('#group-view').waitFor();await peer.page.locator('#group-camera').click();}
   if(req.url?.startsWith('/join-meeting?')){const id=new URL(req.url,'http://localhost').searchParams.get('id');for(const peer of peers){await peer.page.goto(`${base}/#meeting=${id}`);await peer.page.locator('#guest-submit').waitFor();await peer.page.locator('#guest-submit').click();await peer.page.locator('#group-view').waitFor();await peer.page.locator('#group-camera').click();}}
   if(req.url?.startsWith('/moderate?')){const params=new URL(req.url,'http://localhost').searchParams,action=params.get('action'),actor=Number(params.get('actor')),target=Number(params.get('target')),page=peers[actor].page;await page.locator('#group-people').click();const row=page.locator(`#group-people-content [data-member-id="${peers[target].user.id}"]`);await row.locator('summary').click();await row.locator(`[data-action=${action}]`).click();await page.locator('#group-people-close').click();if(action==='mute')await peers[target].page.waitForFunction(()=>document.getElementById('group-mic').disabled);if(action==='allow'){await peers[target].page.waitForFunction(()=>!document.getElementById('group-mic').disabled);const muted=await peers[target].page.evaluate(()=>document.getElementById('group-mic').textContent==='Unmute');if(!muted)throw Error('Allow unmute turned on microphone');}}

   if(req.url?.startsWith('/native-target-meeting?')){const params=new URL(req.url,'http://localhost').searchParams,nativeId=params.get('native'),actor=Number(params.get('actor')||0);const response=await peers[actor].context.request.post(`${base}/api/meetings`,{headers:{Origin:base},data:{name:'Native moderation target',peer_ids:[nativeId]}});if(response.status()!==200)throw Error(await response.text());const m=await response.json();res.setHeader('Content-Type','application/json');res.end(JSON.stringify(m));return;}
   if(req.url?.startsWith('/pair-join?')){const params=new URL(req.url,'http://localhost').searchParams,id=params.get('meeting'),page=peers[Number(params.get('actor')||0)].page;await page.goto(`${base}/#meeting=${id}`);await page.locator('#guest-listen').click();await page.locator('#group-view').waitFor({state:'visible'});await page.locator('#group-mic').click();await page.locator('#group-mic').filter({hasText:/^Mute$/}).waitFor();}
   if(req.url?.startsWith('/pair-mute?')||req.url?.startsWith('/pair-kick?')){const params=new URL(req.url,'http://localhost').searchParams,meeting=params.get('meeting'),nativeId=params.get('native'),kick=req.url.startsWith('/pair-kick?');const response=await peers[0].context.request.fetch(`${base}/api/meetings/${meeting}/members/${nativeId}${kick?'':'/mute'}`,{method:kick?'DELETE':'POST',headers:{Origin:base},...(!kick?{data:{muted:params.get('muted')==='true'}}:{})});if(response.status()!==200)throw Error(await response.text());}
   if(req.url?.startsWith('/native-link?')){const url=new URL(req.url,'http://localhost').searchParams.get('url');const app=resolve('desktop/build/macos/Build/Products/Debug/PVP.app');await promisify(execFile)('open',['-a',app,url]);}
   if(req.url==='/chat-send-browser'){
    const page=peers[0].page;await page.locator('#group-chat-open').click();await page.waitForFunction(()=>document.getElementById('meeting-chat-status').textContent.startsWith('5 participants connected to chat'));
    await page.locator('#meeting-chat-text').fill('Browser → native chat 🌍');await page.locator('#meeting-chat-form button[type=submit]').click();
    await page.locator('#meeting-chat-file').setInputFiles({name:'browser-native.bin',mimeType:'application/octet-stream',buffer:Buffer.from(Array.from({length:70000},(_,i)=>i%256))});
    const png=Buffer.from(await page.evaluate(()=>{const c=document.createElement('canvas');c.width=c.height=2;c.getContext('2d').fillRect(0,0,2,2);return c.toDataURL('image/png').split(',')[1];}),'base64');await page.locator('#meeting-chat-file').setInputFiles({name:'browser-native.png',mimeType:'image/png',buffer:png});
   }
   if(req.url==='/chat-receive-native'){
    const page=peers[0].page;await page.locator('.chat-message').filter({hasText:'Native → browser chat 🌍'}).waitFor();const file=page.locator('.chat-message').filter({hasText:'native-browser.bin'});await file.getByRole('button',{name:'Accept file',exact:true}).click();await file.getByRole('link',{name:'Save file'}).waitFor();const next=page.waitForEvent('download');await file.getByRole('link',{name:'Save file'}).click();const stream=await(await next).createReadStream(),parts=[];for await(const part of stream)parts.push(part);const bytes=Buffer.concat(parts);if(!bytes.equals(Buffer.from(Array.from({length:70000},(_,i)=>(255-i)%256&255))))throw Error('Native/browser binary mismatch');await page.locator('#meeting-chat-close').click();
   }
   if(req.url?.startsWith('/verify-forwarded?')){
    const params=new URL(req.url,'http://localhost').searchParams,source=params.get('source'),leaf=params.get('leaf'),peer=peers.find(p=>p.user.id===leaf);if(!peer)throw Error('Unknown leaf');
    await peer.page.waitForFunction(id=>{const c=document.getElementById(`group-canvas-${id}`);return c&&!c.hidden&&c.width>0;},source,{timeout:30000});
    const pixel=await peer.page.evaluate(id=>[...document.getElementById(`group-canvas-${id}`).getContext('2d').getImageData(10,10,1,1).data],source);if(pixel[0]<200||pixel[1]>40)throw Error('Wrong forwarded pixels');
   }
   if(req.url?.startsWith('/verify-bandwidth?')){
    const params=new URL(req.url,'http://localhost').searchParams,kbps=Number(params.get('kbps')),page=peers[0].page;
    await page.waitForFunction(kbps=>{const rates=window.__peers.filter(p=>p.connectionState==='connected').flatMap(p=>p.getSenders()).filter(s=>s.track?.kind==='video').map(s=>s.getParameters().encodings?.[0]?.maxBitrate);return kbps===0?!rates.includes(64000):rates.includes(kbps*1000)&&rates.some(n=>n!==kbps*1000);},kbps,{timeout:30000});
   }
   if(req.url==='/enable-video')for(const peer of peers)await peer.page.locator('#group-camera').click();
   if(req.url==='/disable-video')for(const peer of peers)await peer.page.locator('#group-camera').click();
   if(req.url==='/leave')for(const peer of peers)if(await peer.page.locator('#group-view').isVisible())await peer.page.locator('#group-leave').click();
   res.setHeader('Content-Type','application/json');res.end(JSON.stringify({ok:true}));
  }catch(e){res.statusCode=500;res.end(JSON.stringify({error:e.message}));}
 });await new Promise(r=>control.listen(0,'127.0.0.1',r));
 const env={...process.env};if(process.env.PVP_TEST_SIGNING_IDENTITY){const signing=join(temp,'signing.xcconfig');await writeFile(signing,`CODE_SIGN_IDENTITY = ${process.env.PVP_TEST_SIGNING_IDENTITY}\nDEVELOPMENT_TEAM = ${process.env.PVP_TEST_TEAM}\nCODE_SIGN_STYLE = Manual\n`);env.XCODE_XCCONFIG_FILE=signing;}
 const child=spawn(process.env.PVP_FLUTTER||resolve('.build/flutter-security-sdk/bin/flutter'),['test','-d','macos',process.env.PVP_TEST_LISTENER==='1'?'integration_test/native_listener_test.dart':process.env.PVP_TEST_VOICE==='1'?'integration_test/native_voice_test.dart':'integration_test/native_group_test.dart',`--dart-define=PVP_SERVICE=${base}`,`--dart-define=PVP_NATIVE_USER=${native}`,`--dart-define=PVP_CONTROL=http://localhost:${control.address().port}`,`--dart-define=PVP_TEST_MEETINGS=${process.env.PVP_TEST_MEETINGS==='1'}`,`--dart-define=PVP_TEST_STRICT_RESOLUTION=${process.env.PVP_TEST_STRICT_RESOLUTION==='1'}`],{cwd:'desktop',stdio:'inherit',env});const exit=await new Promise(r=>child.once('exit',r));if(exit!==0){process.exitCode=exit||1;for(const peer of peers)console.error('Browser media summary',await peer.page.evaluate(async()=>({capture:document.getElementById('group-self-video').srcObject?.getTracks().map(t=>({kind:t.kind,state:t.readyState,enabled:t.enabled,settings:t.getSettings()})),errors:document.getElementById('toast').textContent,peers:await Promise.all(window.__peers.filter(p=>p.signalingState!=='closed').map(async p=>({state:p.connectionState,senders:p.getSenders().map(s=>({kind:s.track?.kind,enc:s.getParameters().encodings})),media:[...(await p.getStats()).values()].filter(s=>['inbound-rtp','outbound-rtp'].includes(s.type)).map(s=>({kind:s.kind,side:s.type,w:s.frameWidth,h:s.frameHeight,bytes:s.bytesSent||s.bytesReceived}))})))})));}
}finally{await browser?.close();if(control)await new Promise(r=>control.close(r));if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
