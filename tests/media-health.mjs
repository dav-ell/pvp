import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {chromium} from 'playwright';
import {MutedSpeechDetector, OutboundVideoStats, EncodedVideoStats, sentVideoLabel} from '../web/media-health.js';

test('muted speech requires sustained local sound and resets for listeners and moderation',()=>{
  const detector=new MutedSpeechDetector(), muted={muted:true,active:true};
  assert.equal(detector.update(.1,muted,0),false);
  assert.equal(detector.update(.1,muted,300),false);
  assert.equal(detector.update(.1,muted,650),true);
  assert.equal(detector.update(.1,{...muted,moderated:true},700),false);
  assert.equal(detector.update(.1,muted,750),false,'approval does not inherit an old nudge');
  assert.equal(detector.update(.1,{...muted,active:false},1500),false,'listen-only/inactive sessions are excluded');
  assert.equal(detector.update(.1,{muted:false,active:true},2200),false);
  assert.equal(detector.update(.1,muted,2300),false);
  assert.equal(detector.update(0,muted,3600),false,'silence clears the detection');
});

test('encoded forwarding requires fresh output, uses observed VP8 dimensions and measures one shared encoder payload',()=>{
  const meter=new EncodedVideoStats();meter.reset('first');
  const peers=()=>[{id:'a',path:'encoded-forwarding',rows:meter.fresh(1500)},{id:'b',path:'encoded-forwarding',rows:meter.fresh(1500)}];
  assert.deepEqual(meter.fresh(1000),[]);
  assert.match(sentVideoLabel(peers(),{camera:true}),/Encoded forwarding · quality unavailable/);
  const key=new Uint8Array(100);key.set([0,0,0,0x9d,0x01,0x2a,128,2,104,1]); // Actual VP8 keyframe: 640×360.
  meter.observe({type:'key',byteLength:100},{},'first',key,1000);
  meter.observe({type:'delta',byteLength:200},{},'first',new Uint8Array(200),1500);
  assert.equal(meter.rows[0].width,640);assert.equal(meter.rows[0].height,360);
  assert.equal(meter.rows[0].fps,2);assert.equal(meter.rows[0].kbps,3.2);
  const label=sentVideoLabel(peers(),{camera:true});
  assert.match(label,/Encoded forwarding 640 × 360 · 2 fps · 3 Kbps encoder payload/);
  assert.match(label,/delivery unverified/);assert.ok(!label.includes('per connection'));
  assert.deepEqual(meter.fresh(5500),[],'no output for four seconds invalidates the observation');
  meter.reset('second');assert.deepEqual(meter.fresh(1500),[],'reconfiguring alone reports no output');
  meter.observe({type:'key',byteLength:100},{},'first',key,1600);
  assert.deepEqual(meter.fresh(1600),[],'late chunks cannot be assigned to a new encoder configuration');
  meter.observe({type:'delta',byteLength:100},{},'second',new Uint8Array(100),1700);
  assert.equal(meter.rows[0].width,null,'without a keyframe or output decoder config, dimensions remain unknown');
});

test('real VideoEncoder output supplies encoded quality; targets without chunks and stale output remain unavailable',{timeout:30000},async()=>{
  const source=await readFile(new URL('../web/media-health.js',import.meta.url));
  const server=createServer((request,response)=>{response.setHeader('Content-Type',request.url==='/media-health.js'?'text/javascript':'text/html');response.end(request.url==='/media-health.js'?source:'<!doctype html><title>Encoder output regression</title>');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
  try {
    browser=await chromium.launch({headless:true,...(process.env.PVP_CHROME?{executablePath:process.env.PVP_CHROME}:{} )});
    const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
    const result=await page.evaluate(async()=>{
      const {EncodedVideoStats,sentVideoLabel}=await import('/media-health.js'),meter=new EncodedVideoStats();meter.reset(1);
      const encoder=new VideoEncoder({output:(chunk,metadata)=>{const data=new Uint8Array(chunk.byteLength);chunk.copyTo(data);meter.observe(chunk,metadata,1,data);},error:error=>{throw error;}});
      encoder.configure({codec:'vp8',width:160,height:90,bitrate:80000,framerate:10,latencyMode:'realtime'});
      const before=sentVideoLabel([{path:'encoded-forwarding',rows:meter.fresh()}],{camera:true});
      const canvas=document.createElement('canvas');canvas.width=160;canvas.height=90;const context=canvas.getContext('2d');
      for(let i=0;i<5;i++){context.fillStyle=`hsl(${i*60} 70% 50%)`;context.fillRect(0,0,160,90);const frame=new VideoFrame(canvas,{timestamp:i*120000});encoder.encode(frame,{keyFrame:i===0});frame.close();await new Promise(resolve=>setTimeout(resolve,120));}
      await encoder.flush();const rows=meter.fresh(),row=rows[0];
      const after=sentVideoLabel([{path:'encoded-forwarding',rows}],{camera:true});
      const stale=sentVideoLabel([{path:'encoded-forwarding',rows:meter.fresh(row.at+4000)}],{camera:true});
      encoder.close();return{before,after,stale,row};
    });
    assert.match(result.before,/quality unavailable/);
    assert.equal(result.row.width,160);assert.equal(result.row.height,90);
    assert.ok(result.row.fps>0&&result.row.fps<15);assert.ok(result.row.kbps>0);
    assert.match(result.after,/Encoded forwarding 160 × 90/);assert.match(result.after,/encoder payload · delivery unverified/);
    assert.match(result.stale,/quality unavailable/);
  }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
});

test('app recovers a removed microphone without unmuting, preserves peers, never captures for listeners and cancels a pending fallback on leave', {timeout:120000}, async()=>{
  const temp=await mkdtemp(join(tmpdir(),'pvp-media-health-'));
  let service,browser;
  const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));
  const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
  const base=`http://localhost:${port}`;
  try {
    await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
    service=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
    let ready=false;for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok){ready=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,100));}assert.ok(ready);
    browser=await chromium.launch({headless:true,...(process.env.PVP_CHROME?{executablePath:process.env.PVP_CHROME}:{}),args:['--autoplay-policy=no-user-gesture-required']});
    const host=await browser.newContext(),listener=await browser.newContext(),pages=[await host.newPage(),await listener.newPage()];
    for(const page of pages)await page.addInitScript(()=>{
      window.__captures=[];window.__peers=[];window.__health=[];window.__inputs=[{kind:'audioinput',deviceId:'usb',label:'USB microphone'},{kind:'audioinput',deviceId:'default',label:'Built-in microphone'}];
      document.addEventListener('pvp-media-health',event=>window.__health.push(event.detail));
      const Peer=RTCPeerConnection;window.RTCPeerConnection=class extends Peer{constructor(...args){super(...args);window.__peers.push(this);}};
      navigator.mediaDevices.enumerateDevices=async()=>window.__inputs;
      const create=async constraints=>{
        const audio=new AudioContext(),tone=audio.createOscillator(),gain=audio.createGain(),destination=audio.createMediaStreamDestination();
        gain.gain.value=.15;tone.connect(gain);gain.connect(destination);tone.start();await audio.resume();
        const track=destination.stream.getAudioTracks()[0],settings=track.getSettings.bind(track),stop=track.stop.bind(track);
        const id=constraints.audio?.deviceId?.exact||'default';track.getSettings=()=>({...settings(),deviceId:id});
        let stopped=false;track.stop=()=>{if(stopped)return;stopped=true;stop();tone.stop();if(audio.state!=='closed')audio.close().catch(error=>{if(error.name!=='InvalidStateError')throw error;});};
        const stream=new MediaStream([track]);window.__captures.push({constraints,stream,track});return stream;
      };
      navigator.mediaDevices.getUserMedia=constraints=>window.__delayCapture?new Promise(resolve=>window.__releaseCapture=async()=>resolve(await create(constraints))):create(constraints);
    });
    const request=async(context,path,data)=>{const response=await context.request.post(base+'/api'+path,{headers:{Origin:base},data});assert.ok(response.ok(),`${path}: ${await response.text()}`);return response.json();};
    await request(host,'/guest/start',{display_name:'Microphone host'});
    const meeting=await request(host,'/meetings',{name:'Microphone continuity',open_invite:true});
    const [a,b]=pages;await a.goto(meeting.url);await a.locator('#guest-submit').click();await a.locator('#group-view').waitFor({state:'visible'});
    await b.goto(meeting.url);await b.locator('#guest-name').fill('Listener');await b.locator('#guest-listen').click();await b.locator('#group-view').waitFor({state:'visible'});
    await a.waitForFunction(()=>window.__peers.some(peer=>peer.connectionState==='connected'));
    await a.locator('#group-mic').click();
    await a.evaluate(()=>{window.__beforePeer=window.__peers.find(peer=>peer.connectionState==='connected');window.__beforeTrack=window.__beforePeer.getSenders().find(sender=>sender.track?.kind==='audio').track;window.__beforeStream=window.__captures[0].stream;window.__beforeTrack.getSettings=()=>({deviceId:'usb'});window.__inputs=[{kind:'audioinput',deviceId:'default',label:'Built-in microphone'}];navigator.mediaDevices.dispatchEvent(new Event('devicechange'));});
    await a.waitForFunction(()=>window.__health.some(event=>event.type==='microphone'&&event.status==='switched'));
    assert.deepEqual(await a.evaluate(()=>{const sender=window.__beforePeer.getSenders().find(sender=>sender.track?.kind==='audio');return{replaced:sender.track!==window.__beforeTrack,muted:!sender.track.enabled,streamSame:window.__beforeStream.getAudioTracks().includes(sender.track),peerSame:window.__beforePeer.connectionState==='connected',videoUntouched:window.__captures.at(-1).constraints.video===false};}),{replaced:true,muted:true,streamSame:true,peerSame:true,videoUntouched:true});
    assert.equal(await b.evaluate(()=>window.__captures.length),0);
    await b.evaluate(()=>navigator.mediaDevices.dispatchEvent(new Event('devicechange')));
    await new Promise(resolve=>setTimeout(resolve,250));assert.equal(await b.evaluate(()=>window.__captures.length),0,'device changes must not opt listeners into capture');
    await b.locator('#group-mic').click();
    await b.waitForFunction(()=>window.__peers.some(peer=>peer.getSenders().some(sender=>sender.track?.kind==='audio')));
    const guest=await (await listener.request.get(base+'/api/me')).json();
    await request(host,`/meetings/${meeting.meeting_id}/members/${guest.id}/mute`,{muted:true});
    await b.waitForFunction(()=>document.getElementById('group-mic').disabled);
    await b.evaluate(()=>{window.__moderatedSender=window.__peers.find(peer=>peer.connectionState==='connected').getSenders().find(sender=>sender.track?.kind==='audio');window.__moderatedOld=window.__moderatedSender.track;window.__moderatedOld.stop();window.__moderatedOld.dispatchEvent(new Event('ended'));});
    await b.waitForFunction(()=>window.__moderatedSender.track!==window.__moderatedOld&&window.__moderatedSender.track?.readyState==='live');
    assert.equal(await b.evaluate(()=>!window.__moderatedSender.track.enabled&&document.getElementById('group-mic').disabled),true,'fallback preserves admin mute and does not grant permission to speak');
    await a.evaluate(()=>{window.__delayCapture=true;const track=window.__beforeStream.getAudioTracks()[0];track.stop();track.dispatchEvent(new Event('ended'));});
    await a.waitForFunction(()=>typeof window.__releaseCapture==='function');
    await a.locator('#group-leave').click();await a.evaluate(()=>window.__releaseCapture());
    await a.waitForFunction(()=>window.__captures.at(-1).track.readyState==='ended');
    assert.equal(await a.evaluate(()=>window.__peers.every(peer=>peer.connectionState==='closed')),true);
    await b.locator('#group-leave').click();
    // The direct-call client uses the same audio-only replacement path.
    const stamp=Date.now();
    const alice=await request(host,'/register',{username:`mic_a_${stamp}`,display_name:'Direct caller',password:'media-health-regression-password'});
    const bob=await request(listener,'/register',{username:`mic_b_${stamp}`,display_name:'Direct receiver',password:'media-health-regression-password'});
    await request(host,'/friends/request',{username:bob.username});await request(listener,`/friends/${alice.id}/accept`,{});
    await a.goto(base);await b.goto(base);
    for(const page of pages){await page.locator('#connection-dot.online').waitFor();await page.locator('[data-view=people]').first().click();}
    await a.locator('.friend-card .button.primary').click();await b.locator('#incoming-dialog').waitFor();await b.locator('#accept-call').click();
    await a.waitForFunction(()=>window.__peers.some(peer=>peer.connectionState==='connected'));
    await a.locator('#toggle-mic').click();
    await a.evaluate(()=>{window.__directPeer=window.__peers.find(peer=>peer.connectionState==='connected');window.__directSender=window.__directPeer.getSenders().find(sender=>sender.track?.kind==='audio');window.__directOld=window.__directSender.track;window.__directOld.stop();window.__directOld.dispatchEvent(new Event('ended'));});
    await a.waitForFunction(()=>window.__directSender.track!==window.__directOld&&window.__directSender.track?.readyState==='live');
    assert.equal(await a.evaluate(()=>!window.__directSender.track.enabled&&window.__directPeer.connectionState==='connected'),true,'direct fallback keeps the active peer and user mute');
    await a.locator('#end-call').click();await b.locator('#call-view').waitFor({state:'hidden'});
  } finally {await browser?.close();if(service){service.kill();await new Promise(resolve=>service.once('exit',resolve));}await rm(temp,{recursive:true,force:true});}
});

test('sent quality uses fresh outbound evidence, resets counter baselines and never substitutes preview dimensions',()=>{
  const meter=new OutboundVideoStats();
  const report=(bytes,timestamp,extra={})=>new Map([['video',{id:'video',type:'outbound-rtp',kind:'video',bytesSent:bytes,timestamp,...extra}],['preview',{id:'preview',type:'media-source',kind:'video',width:1920,height:1080}]]);
  meter.sample(report(100,1000),1000);
  assert.equal(meter.rows[0].width,null);assert.equal(meter.rows[0].height,null);assert.equal(meter.rows[0].kbps,null);
  assert.match(sentVideoLabel([{rows:meter.fresh(1000)}],{camera:true}),/resolution unavailable/);
  meter.sample(report(1100,2000,{frameWidth:640,frameHeight:360,framesPerSecond:15}),2000);
  assert.equal(meter.rows[0].kbps,8);
  assert.match(sentVideoLabel([{rows:meter.fresh(2000)}],{camera:true}),/640 × 360 · 15 fps · 8 Kbps/);
  assert.equal(meter.fresh(6000).length,0,'old observations are never presented as live');
  meter.sample(report(20,3000),3000);assert.equal(meter.rows[0].kbps,null,'counter reset needs a new baseline');
  meter.sample(report(200,9000),9000);assert.equal(meter.rows[0].kbps,null,'long sampling gaps are not a current rate');
  assert.equal(sentVideoLabel([],{camera:true}),'Sent quality unavailable');
  assert.equal(sentVideoLabel([]),'Camera off');
});

test('real generated microphone stays silent on WebRTC while its local clone detects muted sound; replacement and cancellation release capture', {timeout:30000}, async()=>{
  const source=await readFile(new URL('../web/media-health.js',import.meta.url));
  const server=createServer((request,response)=>{
    response.setHeader('Content-Type',request.url==='/media-health.js'?'text/javascript':'text/html');
    response.end(request.url==='/media-health.js'?source:'<!doctype html><title>Generated media health regression</title>');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try {
    browser=await chromium.launch({headless:true,...(process.env.PVP_CHROME?{executablePath:process.env.PVP_CHROME}:{}),args:['--autoplay-policy=no-user-gesture-required']});
    const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
    const result=await page.evaluate(async()=>{
      const {monitorLocalMicrophone,replaceMicrophone,OutboundVideoStats}=await import('/media-health.js');
      let captures=0;navigator.mediaDevices.getUserMedia=async()=>{captures++;throw Error('Physical capture forbidden');};
      const audio=new AudioContext();await audio.resume();
      const oscillator=audio.createOscillator(),gain=audio.createGain(),destination=audio.createMediaStreamDestination();
      gain.gain.value=.15;oscillator.connect(gain);gain.connect(destination);oscillator.start();
      const old=destination.stream.getAudioTracks()[0],stream=new MediaStream([old]);old.enabled=false;
      const canvas=document.createElement('canvas');canvas.width=640;canvas.height=360;
      const paint=()=>{const context=canvas.getContext('2d');context.fillStyle=`hsl(${Date.now()%360} 70% 50%)`;context.fillRect(0,0,640,360);};paint();const frame=setInterval(paint,100);
      const camera=canvas.captureStream(10).getVideoTracks()[0];stream.addTrack(camera);
      const sender=new RTCPeerConnection(),receiver=new RTCPeerConnection();
      sender.onicecandidate=event=>event.candidate&&receiver.addIceCandidate(event.candidate);
      receiver.onicecandidate=event=>event.candidate&&sender.addIceCandidate(event.candidate);
      let remote;receiver.ontrack=event=>{if(event.track.kind==='audio')remote=event.track;};
      const audioSender=sender.addTrack(old,stream),videoSender=sender.addTrack(camera,stream);
      await sender.setLocalDescription(await sender.createOffer());await receiver.setRemoteDescription(sender.localDescription);
      await receiver.setLocalDescription(await receiver.createAnswer());await sender.setRemoteDescription(receiver.localDescription);
      const encoding=videoSender.getParameters();encoding.encodings[0].scaleResolutionDownBy=2;await videoSender.setParameters(encoding);
      const wait=async predicate=>{const until=performance.now()+8000;while(!predicate()){if(performance.now()>until)throw Error('Generated media condition timed out');await new Promise(r=>setTimeout(r,50));}};
      let nudge=false,localLevel=0,active=true,moderated=false;
      const monitor=monitorLocalMicrophone(old,audio,()=>({muted:!old.enabled,active,moderated}),value=>{nudge=value.mutedSpeech;localLevel=value.level;});
      await wait(()=>nudge&&remote&&sender.connectionState==='connected');
      const remoteSource=audio.createMediaStreamSource(new MediaStream([remote])),analyser=audio.createAnalyser();remoteSource.connect(analyser);
      await new Promise(resolve=>setTimeout(resolve,300));
      const samples=new Float32Array(analyser.fftSize);analyser.getFloatTimeDomainData(samples);
      const remoteLevel=Math.sqrt(samples.reduce((sum,n)=>sum+n*n,0)/samples.length);
      moderated=true;monitor.update();const moderatedNudge=nudge;
      moderated=false;active=false;monitor.update();const inactiveNudge=nudge;
      const stats=new OutboundVideoStats();stats.sample(await sender.getStats());
      await new Promise(resolve=>setTimeout(resolve,200));stats.sample(await sender.getStats());
      const observedVideo=stats.rows.find(row=>row.width===320&&row.height===180);
      const streamId=stream.id,peerId=sender;
      monitor.stop();
      // Model device loss. Only a replacement source is captured; existing mute and camera survive.
      old.stop();old.dispatchEvent(new Event('ended'));
      const fallback=audio.createMediaStreamDestination(),replacement=fallback.stream.getAudioTracks()[0];gain.connect(fallback);
      const next=await replaceMicrophone({stream,track:old,capture:async()=>new MediaStream([replacement]),senders:()=>sender.getSenders(),valid:()=>true,enabled:()=>false});
      const replacementState={muted:!next.enabled,senderSame:audioSender.track===next,streamSame:stream.id===streamId,peerSame:sender===peerId,cameraSame:stream.getVideoTracks()[0]===camera,oldEnded:old.readyState==='ended'};
      const rejected=audio.createMediaStreamDestination().stream.getAudioTracks()[0];
      const failingPeer={track:next,replaceTrack:async()=>{throw Error('Peer departed while switching input');}};
      let rolledBack=false;
      try{await replaceMicrophone({stream,track:next,capture:async()=>new MediaStream([rejected]),senders:()=>[audioSender,failingPeer],valid:()=>true,enabled:()=>false});}
      catch{rolledBack=audioSender.track===next&&stream.getAudioTracks()[0]===next&&next.readyState==='live'&&rejected.readyState==='ended';}
      // A permission result delivered after leave is stopped and never attached to the peer.
      let release,valid=true;const late=audio.createMediaStreamDestination().stream.getAudioTracks()[0];
      const pending=replaceMicrophone({stream,track:next,capture:()=>new Promise(resolve=>release=()=>resolve(new MediaStream([late]))),senders:()=>sender.getSenders(),valid:()=>valid,enabled:()=>true});
      valid=false;release();let canceled=false;try{await pending;}catch(error){canceled=error.name==='AbortError';}
      const lateEnded=late.readyState==='ended',senderUnchanged=audioSender.track===next,cloneEnded=monitor.clone.readyState==='ended',previewHeight=camera.getSettings().height;
      sender.close();receiver.close();stream.getTracks().forEach(track=>track.stop());remoteSource.disconnect();analyser.disconnect();clearInterval(frame);oscillator.stop();await audio.close();
      return {localLevel,remoteLevel,moderatedNudge,inactiveNudge,observedVideo,previewHeight,replacementState,rolledBack,canceled,lateEnded,senderUnchanged,cloneEnded,captures};
    });
    assert.ok(result.localLevel>.025,'already-consented source produces a real local signal');
    assert.ok(result.remoteLevel<.001,'disabled sent track remains silent; analyser clone is never sent');
    assert.equal(result.moderatedNudge,false);assert.equal(result.inactiveNudge,false);
    assert.ok(result.observedVideo,'outbound statistics report actual encoded dimensions');
    assert.equal(result.previewHeight,360,'the local source remains larger than the 180p outgoing video');
    assert.ok(Number.isFinite(result.observedVideo.kbps));
    for(const [key,value] of Object.entries(result.replacementState))assert.equal(value,true,key);
    for(const key of ['rolledBack','canceled','lateEnded','senderUnchanged','cloneEnded'])assert.equal(result[key],true,key);
    assert.equal(result.captures,0,'analysis does not request microphone permission');
  } finally {await browser?.close();await new Promise(resolve=>server.close(resolve));}
});
