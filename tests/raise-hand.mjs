import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';

function mediaFixture(){
  window.__peers=[];window.__tones=[];window.__errors=[];
  window.addEventListener('error',e=>window.__errors.push(e.message));
  const Peer=RTCPeerConnection;window.RTCPeerConnection=class extends Peer{constructor(...args){super(...args);window.__peers.push(this);}};
  const create=AudioContext.prototype.createOscillator;
  AudioContext.prototype.createOscillator=function(){const oscillator=create.call(this),start=oscillator.start;oscillator.start=function(...args){window.__tones.push(oscillator.frequency.value);return start.apply(this,args);};return oscillator;};
  navigator.mediaDevices.getUserMedia=async()=>{
    const audio=new AudioContext(),tone=audio.createOscillator(),destination=audio.createMediaStreamDestination();
    tone.connect(destination);tone.start();await audio.resume();
    const stream=destination.stream,track=stream.getAudioTracks()[0],stop=track.stop.bind(track);
    track.stop=()=>{stop();tone.stop();audio.close();};window.__capture=stream;return stream;
  };
}
async function approve(page,id,label='Allow to speak'){
  const row=page.locator(`#group-people-content [data-member-id="${id}"]`);
  await row.locator('summary').click();await row.getByRole('button',{name:label,exact:true}).click();
}

test('optional speaking approval enforces audio blocks, chimes privately, and works for mobile guests',{timeout:120000},async()=>{
  const temp=await mkdtemp(join(tmpdir(),'pvp-speaking-'));let server,browser;
  try{
    await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
    const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
    server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
    for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
    browser=await chromium.launch({headless:true,args:['--autoplay-policy=no-user-gesture-required']});
    const peers=[];
    const request=async(i,path,data,status=200)=>{const response=await peers[i].context.request.fetch(base+'/api'+path,{method:data===undefined?'GET':'POST',headers:{Origin:base},...(data===undefined?{}:{data})});assert.equal(response.status(),status,`${path}: ${await response.text()}`);return response.json();};
    for(let i=0;i<3;i++){
      const context=await browser.newContext(i===2?{viewport:{width:375,height:760},isMobile:true,hasTouch:true}:{}),page=await context.newPage();peers.push({context,page});await page.addInitScript(mediaFixture);
      if(i<2)peers[i].user=await request(i,'/register',{username:`speaker${i}_${Date.now().toString().slice(-9)}`,display_name:i?'Member':'Host',password:'speaking-test-password-123'});
    }
    const meeting=await request(0,'/meetings',{name:'Speaking turns',open_invite:true}),id=meeting.meeting_id;
    assert.equal(meeting.raise_hand_enabled,false);
    const [host,member,guest]=peers.map(p=>p.page);
    await host.goto(meeting.url);await host.locator('#guest-manage').click();await host.locator('#meeting-raise-hand').check();
    await host.waitForFunction(async id=>(await fetch(`/api/meetings/${id}`).then(r=>r.json())).raise_hand_enabled,id);
    await request(1,`/meetings/${id}/speaking`,{enabled:false},403);
    await host.locator('#meeting-join').click();await host.locator('#guest-submit').click();await host.locator('#group-view').waitFor({state:'visible'});
    for(const page of [member,guest]){await page.goto(meeting.url);await page.locator('#guest-submit').waitFor();if(page===guest)await page.locator('#guest-name').fill('Mobile guest');await page.locator('#guest-submit').click();await page.locator('#group-view').waitFor({state:'visible'});await page.waitForFunction(()=>document.getElementById('group-mic').disabled&&window.__capture.getAudioTracks().every(t=>!t.enabled));}
    const guestIdentity=await request(2,'/me'),guestId=guestIdentity.id,memberId=peers[1].user.id;
    await request(2,`/meetings/${id}/speaking`,{enabled:false},401);
    await request(1,`/meetings/${id}/members/${memberId}/speak`,{allowed:true},403);
    await host.waitForFunction(()=>window.__peers.filter(p=>p.connectionState==='connected').length===2);
    await host.waitForFunction(id=>document.getElementById(`group-video-${id}`).srcObject.getAudioTracks().every(t=>!t.enabled),memberId);
    await member.evaluate(()=>window.__capture.getAudioTracks().forEach(t=>t.enabled=true));
    assert.equal(await host.evaluate(id=>document.getElementById(`group-video-${id}`).srcObject.getAudioTracks()[0].enabled,memberId),false,'receiver blocks a sender that ignores its own mute');
    await member.evaluate(()=>window.__capture.getAudioTracks().forEach(t=>t.enabled=false));
    await member.locator('#group-hand').click();await member.locator('#group-hand').filter({hasText:'Lower hand'}).waitFor();
    await member.locator('#group-hand').click();await member.locator('#group-hand').filter({hasText:'Raise hand'}).waitFor();
    assert.equal(await member.locator('#group-mic').isDisabled(),true,'lowering a hand does not grant permission');
    await guest.locator('#group-hand').click();await guest.locator('#group-hand').filter({hasText:'Lower hand'}).waitFor();
    await host.locator('#group-people').click();await host.locator(`[data-member-id="${guestId}"]`).filter({hasText:'Hand raised'}).waitFor();
    await approve(host,guestId);
    await guest.waitForFunction(()=>!document.getElementById('group-mic').disabled);
    assert.equal(await guest.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false,'approval keeps the microphone off');
    await guest.waitForFunction(()=>window.__tones.includes(523.25)&&window.__tones.some(f=>Math.abs(f-783.99)<0.01));
    assert.equal(await host.evaluate(()=>window.__tones.filter(f=>f===523.25).length),0,'host does not hear another participant’s chime');
    assert.equal(await member.evaluate(()=>window.__tones.filter(f=>f===523.25).length),0,'other participants do not hear the chime');
    await request(0,`/meetings/${id}/members/${guestId}/speak`,{allowed:true});
    await guest.waitForTimeout(150);assert.equal(await guest.evaluate(()=>window.__tones.filter(f=>f===523.25).length),1,'repeated approval does not replay the chime');
    for(const width of [320,360,375,390]){await guest.setViewportSize({width,height:760});assert.equal(await guest.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`no horizontal overflow at ${width}px`);const bounds=await guest.locator('#group-hand').boundingBox();assert.ok(bounds.x>=0&&bounds.x+bounds.width<=width,'hand control remains on screen');}
    await guest.locator('#group-mic').click();assert.equal(await guest.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),true);
    await host.waitForFunction(id=>document.getElementById(`group-video-${id}`).srcObject.getAudioTracks()[0].enabled,guestId);
    await approve(host,guestId,'End speaking turn');await guest.waitForFunction(()=>document.getElementById('group-mic').disabled&&window.__capture.getAudioTracks().every(t=>!t.enabled));
    await guest.locator('#group-hand').click();await approve(host,guestId);await guest.waitForFunction(()=>!document.getElementById('group-mic').disabled);
    await guest.locator('#group-hand').click();await guest.waitForFunction(()=>document.getElementById('group-mic').disabled);
    await member.locator('#group-hand').click();await approve(host,memberId);await member.waitForFunction(()=>!document.getElementById('group-mic').disabled);
    await member.locator('#group-leave').click();await member.locator('#guest-submit').click();await member.locator('#group-view').waitFor({state:'visible'});
    await member.waitForFunction(()=>document.getElementById('group-mic').disabled);assert.match(await member.locator('#group-hand').textContent(),/Raise hand/,'rejoin clears the earlier grant');
    await host.locator('#group-raise-hand').uncheck();
    for(const page of [member,guest]){await page.locator('#group-hand').waitFor({state:'hidden'});assert.equal(await page.locator('#group-mic').isDisabled(),false);assert.equal(await page.evaluate(()=>window.__capture.getAudioTracks()[0].enabled),false,'disabling the feature does not unmute anyone');}
    for(const {page} of peers)assert.deepEqual(await page.evaluate(()=>window.__errors),[]);
  }finally{await browser?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
});
