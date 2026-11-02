import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium,webkit} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
function fixture(){
  window.__requests=[];window.__peers=[];window.__tracks=[];window.__errors=[];window.__mode='allowed';
  window.addEventListener('error',e=>window.__errors.push(e.message));
  window.__sockets=[];const Socket=WebSocket;window.WebSocket=class extends Socket{constructor(...a){super(...a);window.__sockets.push(this);}};
  const Peer=RTCPeerConnection;window.RTCPeerConnection=class extends Peer{constructor(...a){super(...a);window.__peers.push(this);}};
  const capture=async c=>{
    window.__requests.push({audio:c.audio,video:c.video,active:navigator.userActivation?.isActive});
    if(window.__mode!=='allowed'&&window.__mode!=='pending')throw new DOMException('Fixture capture',window.__mode);
    const audio=new AudioContext(),tone=audio.createOscillator(),dest=audio.createMediaStreamDestination();tone.connect(dest);tone.start();audio.resume().catch(()=>{});
    const stream=dest.stream,track=stream.getAudioTracks()[0],stop=track.stop.bind(track);window.__tracks.push(track);
    let stopped=false;track.stop=()=>{if(stopped)return;stopped=true;stop();tone.stop();if(audio.state!=='closed')audio.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};
    if(window.__mode==='pending')await new Promise(resolve=>window.__grant=resolve);
    return stream;
  };
  const native=navigator.mediaDevices;
  Object.defineProperty(navigator,'mediaDevices',{value:new Proxy(native,{get(t,k){if(k==='getUserMedia')return capture;const v=Reflect.get(t,k,t);return typeof v==='function'?v.bind(t):v;}})});
}
for(const [engine,type] of Object.entries({chromium,webkit}))test(`mobile meeting recovery, listening and media upgrade (${engine})`,{timeout:180000},async()=>{
  const temp=await mkdtemp(join(tmpdir(),'pvp-mobile-'));let server,browser;
  try{
    let base=process.env.PVP_TEST_URL;
    if(!base){
      await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
      const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));base=`http://localhost:${port}`;
      server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'test.sqlite')},stdio:'ignore'});
      for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
    }
    browser=await type.launch({headless:true});
    const owner=await browser.newContext(),host=await owner.newPage();owner.setDefaultTimeout(12000);host.on('pageerror',e=>console.error(engine,'HOST',e.message));await host.addInitScript(fixture);
    const req=async(path,data)=>{const r=await owner.request.post(base+'/api'+path,{headers:{Origin:base},data});assert.equal(r.status(),200,await r.text());return r.json();};
    const account=await req('/register',{username:`guest_owner_${Date.now()}`,display_name:'Meeting host',password:'mobile-meeting-test-password'});
    if(process.env.PVP_TEST_ACCOUNT_FILE)await writeFile(process.env.PVP_TEST_ACCOUNT_FILE.replace('.json',`-${engine}.json`),JSON.stringify({id:account.id,username:account.username}),{mode:0o600});
    const meeting=await req('/meetings',{name:'Evening catch-up',open_invite:true});
    await host.goto(meeting.url);await host.locator('#guest-submit').click();await host.locator('#group-view').waitFor({state:'visible'});
    const context=await browser.newContext({viewport:{width:390,height:700},isMobile:true,hasTouch:true}),page=await context.newPage();context.setDefaultTimeout(12000);page.on('pageerror',e=>console.error(engine,'GUEST',e.message));if(process.env.PVP_TEST_DEBUG)page.on('response',r=>{if(r.status()>=400)console.error(engine,'HTTP',r.status(),new URL(r.url()).pathname);});await page.addInitScript(fixture);await page.goto(meeting.url);await page.locator('#guest-name').fill('Mobile visitor');
    for(const width of [320,360,390,430]){
      await page.setViewportSize({width,height:700});
      const geometry=await page.evaluate(()=>Object.fromEntries(['guest-name','guest-submit','guest-listen'].map(id=>{const el=document.getElementById(id),r=el.getBoundingClientRect();return[id,{x:r.x,right:r.right,bottom:r.bottom,height:r.height,font:getComputedStyle(el).fontSize}];})));
      for(const r of Object.values(geometry)){assert.ok(r.x>=0&&r.right<=width,JSON.stringify(geometry));assert.ok(r.height>=48);}
      assert.equal(geometry['guest-name'].font,'16px');if(width===390)assert.ok(geometry['guest-listen'].bottom<700);
    }
    await page.setViewportSize({width:390,height:700});
    await page.evaluate(()=>window.__mode='NotAllowedError');await page.locator('#guest-submit').click();
    await page.locator('#guest-error').filter({hasText:'couldn’t access'}).waitFor();
    assert.equal(await page.evaluate(()=>window.__requests[0].active),true,'capture begins within the tap');
    await page.waitForTimeout(6500);assert.equal(await page.locator('#guest-error').isVisible(),true);
    await page.locator('#guest-listen').click();await page.locator('#group-view').waitFor({state:'visible'});
    assert.equal(await page.evaluate(()=>window.__requests.length),1,'listening never captures');
    if(await page.locator('#group-play').isVisible())await page.locator('#group-play').click();
    await page.waitForFunction(()=>[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&!a.muted&&a.currentTime>.2),null,{timeout:15000});
    await page.locator('#group-call-status').filter({hasText:'Listening'}).waitFor();
    const peerCount=await page.evaluate(()=>window.__peers.length);
    await page.locator('#group-mic').click();await page.locator('#meeting-mic-status').filter({hasText:'couldn’t access'}).waitFor();assert.equal(await page.locator('#group-view').isVisible(),true);
    await page.evaluate(()=>window.__mode='allowed');await page.locator('#meeting-mic-retry').click();
    await page.locator('#group-mic').filter({hasText:/^Mute$/}).waitFor();assert.equal(await page.evaluate(()=>window.__peers.length),peerCount,'upgrade retains peer connections');
    await host.waitForFunction(()=>!document.getElementById('group-play').hidden||[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&a.currentTime>.2));
    if(await host.locator('#group-play').isVisible())await host.locator('#group-play').click();
    await host.waitForFunction(()=>[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&a.currentTime>.2),null,{timeout:15000}).catch(async error=>{console.error(engine,'host playback',await host.evaluate(async()=>({audio:[...document.querySelectorAll('audio')].map(a=>({time:a.currentTime,paused:a.paused,ready:a.readyState,tracks:a.srcObject?.getTracks().map(t=>({kind:t.kind,muted:t.muted,state:t.readyState}))})),peers:await Promise.all(window.__peers.map(async pc=>({state:pc.connectionState,stats:[...(await pc.getStats()).values()].filter(s=>s.type==='inbound-rtp'&&s.kind==='audio')})))})));throw error;});
    await page.locator('#group-more').click();await page.locator('#group-chat-open').click();await page.locator('#meeting-chat-text').fill('Listening upgrade kept the call');await page.locator('#meeting-chat-send').click();
    await host.locator('#group-chat-open').click();await host.locator('.chat-message').filter({hasText:'Listening upgrade kept the call'}).waitFor();await host.locator('#meeting-chat-close').click();await page.locator('#meeting-chat-close').click();
    const captureCount=await page.evaluate(()=>window.__requests.length);await page.locator('#group-mic').click();await page.evaluate(()=>window.__sockets.at(-1).close());await page.locator('#guest-error').filter({hasText:'Reconnecting'}).waitFor();await page.locator('#group-view').waitFor({state:'visible'});await page.locator('#group-mic').filter({hasText:'Unmute'}).waitFor();assert.equal(await page.evaluate(()=>window.__requests.length),captureCount,'live reconnect preserves capture and mute');
    const tab=await context.newPage();await tab.addInitScript(fixture);await tab.goto(meeting.url);await tab.locator('#guest-form').waitFor({state:'visible'});assert.equal(await tab.evaluate(()=>window.__sockets.length),0,'preview in a second tab leaves the existing call alone');assert.equal(await page.locator('#group-view').isVisible(),true);await tab.locator('#guest-listen').click();await tab.locator('#group-view').waitFor({state:'visible'});await page.locator('#guest-takeover').waitFor();await page.locator('#guest-takeover').click();await tab.close();await page.locator('#guest-listen').click();await page.locator('#group-view').waitFor({state:'visible'});
    const priorId=await context.request.get(base+'/api/me').then(r=>r.json()).then(m=>m.id);
    await page.reload();await page.locator('#guest-listen').filter({hasText:'Rejoin'}).waitFor();assert.equal(await page.evaluate(()=>window.__requests.length),0);assert.equal(await page.locator('#guest-name').inputValue(),'Mobile visitor');
    await page.evaluate(()=>window.__mode='pending');await page.locator('#guest-submit').click();await page.waitForTimeout(8100);await page.locator('#guest-status').filter({hasText:'Still waiting'}).waitFor();
    await page.locator('#guest-listen').click();await page.locator('#group-view').waitFor({state:'visible'});await page.evaluate(()=>window.__grant());await page.waitForFunction(()=>window.__tracks.every(t=>t.readyState==='ended'));assert.equal(await page.locator('#group-mic').textContent(),'Use mic');
    assert.equal(await context.request.get(base+'/api/me').then(r=>r.json()).then(m=>m.id),priorId);
    for(const width of [320,390,700]){await page.setViewportSize({width,height:700});for(const id of ['group-mic','group-camera','group-more','group-leave']){await page.locator('#'+id).scrollIntoViewIfNeeded();const r=await page.locator('#'+id).boundingBox();assert.ok(r.x>=0&&r.x+r.width<=width+.5,`${id}: ${JSON.stringify(r)}`);assert.ok(r.height>=44);}}
    await page.setViewportSize({width:390,height:700});await page.screenshot({path:`.build/mobile-release/${engine}-call.png`,fullPage:true});
    await page.locator('#group-leave').click();await page.locator('#guest-status').filter({hasText:'You left'}).waitFor();await page.reload();await page.locator('#guest-listen').waitFor().catch(async error=>{console.error(engine,'after leave reload',await page.evaluate(()=>({url:location.href,title:document.title,entryHidden:document.getElementById('meeting-entry-view').hidden,formHidden:document.getElementById('guest-form').hidden,status:document.getElementById('guest-status').textContent,error:document.getElementById('guest-error').textContent,authHidden:document.getElementById('auth-view').hidden,errors:window.__errors})));throw error;});assert.equal(await page.locator('#guest-eyebrow').textContent(),'YOU’RE INVITED');
    for(const mode of ['NotFoundError','NotReadableError']){await page.evaluate(mode=>window.__mode=mode,mode);await page.locator('#guest-submit').click();await page.locator('#guest-error').filter({hasText:mode==='NotFoundError'?'No microphone':'unavailable right now'}).waitFor();}
    await page.screenshot({path:`.build/mobile-release/${engine}-recovery.png`,fullPage:true});
    await host.locator('#group-leave').click();
    const otherContext=await browser.newContext(),other=await otherContext.newPage();otherContext.setDefaultTimeout(12000);await other.addInitScript(fixture);await other.goto(meeting.url);await other.locator('#guest-name').fill('Second guest');await other.locator('#guest-listen').click();await other.locator('#group-view').waitFor({state:'visible'});await other.locator('#group-leave').click();
    const secondId=await otherContext.request.get(base+'/api/me').then(r=>r.json()).then(m=>m.id);
    const ordered=priorId<secondId?[page,other]:[other,page];
    for(const listener of ordered){
      const speaker=ordered.find(p=>p!==listener);
      for(const p of ordered){await p.reload();await p.locator('#guest-form').waitFor({state:'visible'});await p.evaluate(()=>window.__mode='allowed');}
      await listener.locator('#guest-listen').click();await listener.locator('#group-view').waitFor({state:'visible'});await speaker.locator('#guest-submit').click();await speaker.locator('#group-view').waitFor({state:'visible'});
      await listener.waitForFunction(()=>!document.getElementById('group-play').hidden||[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&a.currentTime>.2));if(await listener.locator('#group-play').isVisible())await listener.locator('#group-play').click();
      await listener.waitForFunction(()=>[...document.querySelectorAll('#group-grid audio')].some(a=>!a.paused&&a.currentTime>.2));
      assert.equal(await listener.evaluate(()=>window.__requests.length),0);
      await listener.locator('#group-mic').click();await listener.locator('#group-mic').filter({hasText:/^Mute$/}).waitFor();assert.equal(await listener.evaluate(()=>window.__peers.filter(p=>p.connectionState==='connected').length),1);
      for(const p of ordered)await p.locator('#group-leave').click();
    }
    assert.deepEqual(await page.evaluate(()=>window.__errors),[]);assert.deepEqual(await host.evaluate(()=>window.__errors),[]);
  }finally{await browser?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
});
