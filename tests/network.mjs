import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium,webkit} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
import {roomDistribution,sampledRooms,graphTopology,layoutRooms,intersects} from '../web/network.js';

test('the public graph accepts only bounded size counts and samples across sizes',()=>{
 const d=roomDistribution({version:1,connections:'illustrated',rooms:[{peers:2,count:10},{peers:16,count:1}]});
 assert.equal(d.total,11);assert.equal(d.peers,36);assert.deepEqual(sampledRooms(d,3),[2,16,2]);
 for(const rows of [[{peers:0,count:1}],[{peers:17,count:1}],[{peers:2,count:257}],[{peers:2,count:1},{peers:2,count:1}],[{peers:2,count:1.5}]])assert.throws(()=>roomDistribution({version:1,connections:'illustrated',rooms:rows}));
});
test('large-room video illustrates the four-child forwarding tree while keeping direct audio',()=>{
 assert.equal(graphTopology(5).forwarding,false);
 assert.deepEqual(graphTopology(6).routes,[[0,1],[0,2],[0,3],[0,4],[1,5]]);
 for(const n of [6,8,16]){const topology=graphTopology(n);assert.equal(topology.mesh.length,n*(n-1)/2);assert.equal(topology.routes.length,n-1);assert.ok(topology.forwarders.size>0);assert.ok(Math.max(...topology.depth)<=2);for(let node=0;node<n;node++)assert.ok(topology.routes.filter(([parent])=>parent===node).length<=4);}
});
test('responsive placement reserves text, controls, captions and the full drift envelope',()=>{
 for(const [width,height]of [[320,800],[390,775],[700,850],[701,850],[1440,904],[1920,1080]]){
  const exclusions=[{left:width*.16,right:width*.84,top:174,bottom:560},{left:15,right:width-15,top:height-64,bottom:height-16}];
  const plan=layoutRooms(width,height,exclusions,[2,6,3,8,4,5,6,3]);assert.ok(plan.length>0);
  for(const room of plan){assert.ok(room.bounds.left>=0&&room.bounds.right<=width&&room.bounds.top>=0&&room.bounds.bottom<=height);for(const rect of exclusions)assert.equal(intersects(room.bounds,rect),false);for(const other of plan.filter(p=>p!==room))assert.equal(intersects(room.bounds,other.bounds),false);}
 }
});
test('crowded layouts remove clusters instead of using text as graph space',()=>{
 const plan=layoutRooms(320,700,[{left:0,right:320,top:110,bottom:640}],[2,6,3,8,4,5]);assert.equal(plan.length,0);
});
async function assertClear(page,label){
 const collisions=await page.evaluate(()=>{
  const rects=[];for(const element of document.querySelectorAll('.network-eyebrow,#network-heading,.network-description,.network-fine')){const range=document.createRange();range.selectNodeContents(element);rects.push(...[...range.getClientRects()].filter(r=>r.width&&r.height));}
  rects.push(...[...document.querySelectorAll('.network-actions button,.network-footer,.network-focus-text')].map(n=>n.getBoundingClientRect()));
  const hits=[];for(const root of document.querySelectorAll('.room-cluster')){const b=root.getBoundingClientRect();for(const r of rects)if(b.left<r.right+2&&b.right>r.left-2&&b.top<r.bottom+2&&b.bottom>r.top-2)hits.push({slot:root.dataset.slot,graph:{x:b.x,y:b.y,w:b.width,h:b.height},copy:{x:r.x,y:r.y,w:r.width,h:r.height}});}return hits;
 });assert.deepEqual(collisions,[],label);
}
for(const [engineName,engine]of Object.entries({chromium,webkit}))test(`homepage room network: honest empty state, opt-in live peers, privacy and mobile entry (${engineName})`,{timeout:120000},async()=>{
 const temp=await mkdtemp(join(tmpdir(),'pvp-network-'));let service,browser;
 try{
  await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
  const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
  service=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'network.sqlite')},stdio:'ignore'});
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  browser=await engine.launch();const publicContext=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'}),home=await publicContext.newPage(),errors=[];
  home.on('pageerror',e=>errors.push(e.message));await home.goto(base);await home.locator('#network-count').filter({hasText:'No rooms sharing activity'}).waitFor();assert.equal(await home.locator('#room-network').getAttribute('data-source'),'example');assert.equal(await home.locator('#network-motion').isDisabled(),true);
  await home.locator('.room-cluster').first().focus();await home.keyboard.press('Enter');assert.match(await home.locator('.network-focus-text').textContent(),/An example, not a live room/);
  const large=home.locator('[data-topology=forwarding]').first();assert.equal(await large.locator('.video-source').count(),1);assert.ok(await large.locator('.forwarding-peer').count()>0);assert.equal(await large.locator('.room-shape').last().locator('.video-route').count(),Number(await large.getAttribute('data-peers'))-1);await large.focus();await home.keyboard.press('Enter');assert.match(await home.locator('.network-focus-text').textContent(),/Audio stays direct/);
  assert.equal(await home.locator('.node-halo').first().evaluate(n=>getComputedStyle(n).animationName),'none');
  await home.emulateMedia({reducedMotion:'no-preference'});await home.waitForFunction(()=>!document.getElementById('network-motion').disabled&&document.getElementById('room-network').getAnimations({subtree:true}).some(a=>a.playState==='running'));
  const pulse=await home.locator('.node-halo').first().evaluate(n=>getComputedStyle(n).transform);await home.waitForTimeout(220);assert.notEqual(await home.locator('.node-halo').first().evaluate(n=>getComputedStyle(n).transform),pulse,'peer halos breathe, not only the whole graph');
  assert.ok(await home.evaluate(()=>document.getElementById('room-network').getAnimations({subtree:true}).some(a=>a.effect.target.classList.contains('room-signal')&&a.playState==='running')),'illustrated video signals animate');
  const signalPosition=await home.evaluate(()=>{const a=document.getElementById('room-network').getAnimations({subtree:true}).find(a=>a.effect.target.classList.contains('room-signal'));a.currentTime=a.effect.getTiming().duration*.2;window.__testedSignal=a.effect.target;return getComputedStyle(window.__testedSignal).transform;});await home.waitForTimeout(160);assert.notEqual(await home.evaluate(()=>getComputedStyle(window.__testedSignal).transform),signalPosition,'signals travel along the peer links');
  await home.locator('#network-motion').click();await home.evaluate(()=>Promise.all(document.getElementById('room-network').getAnimations({subtree:true}).map(a=>a.ready)));const frozen=await home.evaluate(()=>document.getElementById('room-network').getAnimations({subtree:true}).map(a=>({time:a.currentTime,state:a.playState})));assert.ok(frozen.every(a=>a.state==='paused'));await home.waitForTimeout(180);assert.deepEqual(await home.evaluate(()=>document.getElementById('room-network').getAnimations({subtree:true}).map(a=>({time:a.currentTime,state:a.playState}))),frozen,'pause stops CSS and path animations');
  await home.locator('#network-motion').click();await home.emulateMedia({reducedMotion:'reduce'});

  for(const width of [320,390,700,701,768,1440]){await home.setViewportSize({width,height:900});await home.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await assertClear(home,`copy stays clear at ${width}px`);assert.equal(await home.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`no horizontal overflow at ${width}`);for(const id of ['network-create','network-join']){const r=await home.locator('#'+id).boundingBox();assert.ok(r.width>=44&&r.height>=44&&r.x>=0&&r.x+r.width<=width+1);}}
  await home.setViewportSize({width:700,height:784});await home.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await assertClear(home,'reported 700px layout');
  await home.locator('#network-heading').evaluate(n=>n.style.fontSize='82px');await home.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await assertClear(home,'larger text reflows safely');assert.equal(await home.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await home.locator('#network-heading').evaluate(n=>n.style.fontSize='');
  await home.setViewportSize({width:1440,height:1000});await home.evaluate(()=>document.documentElement.style.zoom='1.4');await home.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await assertClear(home,'zoomed document stays clear');await home.evaluate(()=>document.documentElement.style.zoom='');await home.emulateMedia({reducedMotion:'no-preference'});await home.waitForFunction(()=>!document.getElementById('network-motion').disabled);
  for(const fraction of [0,.25,.5,.75]){await home.evaluate(f=>{for(const a of document.getElementById('room-network').getAnimations({subtree:true}))if(a.effect.target.classList.contains('room-float')){a.pause();a.currentTime=a.effect.getTiming().duration*f;}},fraction);await assertClear(home,`moving graphs clear at phase ${fraction}`);}
  for(const width of [700,390,701,1440]){await home.setViewportSize({width,height:900});await home.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await assertClear(home,`animated resize keeps copy clear at ${width}`);await home.waitForTimeout(120);await assertClear(home,`no large fading shapes after resize at ${width}`);}
  const beforeExample=await home.getAttribute('#room-network','data-example-step');await home.waitForFunction(before=>document.getElementById('room-network').dataset.exampleStep!==before,beforeExample||undefined,{timeout:12000});
  await home.locator('#network-motion').click();const stoppedStep=await home.getAttribute('#room-network','data-example-step');await home.waitForTimeout(200);assert.equal(await home.getAttribute('#room-network','data-example-step'),stoppedStep);await home.locator('#network-motion').click();await home.emulateMedia({reducedMotion:'reduce'});
  await home.setViewportSize({width:390,height:844});await home.locator('#network-create').click();assert.equal(await home.evaluate(()=>document.activeElement.id),'home-guest-name');await home.locator('#network-join').click();assert.equal(await home.evaluate(()=>document.activeElement.id),'home-meeting-link');
  const owners=[];
  for(let i=0;i<2;i++){const context=await browser.newContext(),response=await context.request.post(base+'/api/register',{headers:{Origin:base},data:{username:`network_${i}_${Date.now()}`,display_name:`Private Person ${i}`,password:'network-test-password-123'}});assert.equal(response.status(),200);owners.push({context,page:await context.newPage()});}
  const owner=owners[0],other=owners[1];const api=async(path,data,expected=200)=>{const r=await owner.context.request.post(base+'/api'+path,{headers:{Origin:base},data});assert.equal(r.status(),expected);return r.json();};
  const meeting=await api('/meetings',{name:'Private room name never published',open_invite:true,peer_ids:[]});assert.equal(meeting.network_visible,false);
  await owner.page.goto(base+`/#meeting=${meeting.meeting_id}`);await owner.page.locator('#guest-listen').click();await owner.page.locator('#group-view').waitFor();
  await other.page.goto(base+`/#meeting=${meeting.meeting_id}`);await other.page.locator('#guest-listen').click();await other.page.locator('#group-view').waitFor();
  assert.deepEqual((await (await fetch(base+'/api/network')).json()).rooms,[],'live private-by-default rooms stay off the homepage');
  const forbidden=await other.context.request.post(base+`/api/meetings/${meeting.meeting_id}/network`,{headers:{Origin:base},data:{visible:true}});assert.equal(forbidden.status(),403);
  await owner.page.locator('#group-back').click();await owner.page.locator('#meeting-links-nav').click();await owner.page.locator('.meeting-list-item').first().click();await owner.page.locator('.meeting-network-setting > summary').click();await owner.page.locator('#meeting-network-visible').check();
  await owner.page.waitForFunction(async id=>(await (await fetch(`/api/meetings/${id}`)).json()).network_visible,meeting.meeting_id);

  const publicResponse=await fetch(base+'/api/network'),payload=await publicResponse.json();assert.match(publicResponse.headers.get('cache-control'),/no-store/);assert.deepEqual(payload.rooms,[{peers:2,count:1}]);
  const encoded=JSON.stringify(payload);for(const secret of [meeting.meeting_id,meeting.name,'Private Person','127.0.0.1','localhost','username','address','candidate','fingerprint'])assert.equal(encoded.includes(secret),false);
  await home.reload();await home.locator('#room-network[data-source=live]').waitFor();assert.equal(await home.locator('.room-node').count(),2,'two peers on the same local IP remain two nodes');await home.locator('#network-count').filter({hasText:'1 opt-in room · 2 peers'}).waitFor();assert.equal(await home.locator('.room-edge').count(),1);
  await home.locator('.network-key summary').click();assert.match(await home.locator('.network-key').textContent(),/not measurements of live media/);await home.locator('.network-key summary').click();
  await home.setViewportSize({width:1440,height:1000});await home.locator('#network-mode').click();await home.locator('#room-network[data-source=example]').waitFor();await home.locator('#network-mode').click();
  await home.locator('#room-network[data-source=live]').waitFor();
  await api(`/meetings/${meeting.meeting_id}/network`,{visible:false});await home.reload();await home.locator('#network-count').filter({hasText:'No rooms sharing activity'}).waitFor();
  await home.route('**/api/network',route=>route.fulfill({status:503,body:'unavailable'}));await home.reload();await home.locator('#network-count').filter({hasText:'Live activity unavailable'}).waitFor();assert.equal(await home.locator('#room-network').getAttribute('data-source'),'example');await home.unroute('**/api/network');await home.reload();
  await mkdir('.build/network-evidence',{recursive:true});await home.evaluate(()=>document.fonts.ready);await home.screenshot({path:`.build/network-evidence/${engineName}-desktop.png`});await home.setViewportSize({width:390,height:844});await home.screenshot({path:`.build/network-evidence/${engineName}-mobile.png`});
  assert.deepEqual(errors,[]);
 }finally{await browser?.close();if(service){service.kill();await new Promise(r=>service.once('exit',r));}await rm(temp,{recursive:true,force:true});}
});
