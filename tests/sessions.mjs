import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
test('persistent browser login survives browser restart and startup outage; cookie renews and logout revokes it',{timeout:90000},async()=>{
 const temp=await mkdtemp(join(tmpdir(),'pvp-sessions-'));let server,context;
 try {
  await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
  const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
  server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  const launch=()=>chromium.launchPersistentContext(join(temp,'profile'),{headless:true});
  context=await launch();let page=await context.newPage();await page.goto(base);
  await page.locator('#show-account').click(); await page.locator('#register-tab').click();await page.locator('#display-name').fill('Session Test');await page.locator('#username').fill(`session_${Date.now().toString().slice(-9)}`);await page.locator('#password').fill('session-test-password-123');await page.locator('#auth-submit').click();await page.locator('#connection-dot.online').waitFor();
  let cookie=(await context.cookies()).find(c=>c.name==='pvp_session');assert.ok(cookie.httpOnly);assert.equal(cookie.sameSite,'Strict');assert.ok(cookie.expires>Date.now()/1000+29*86400);assert.ok(!(await page.evaluate(()=>document.cookie)).includes('pvp_session'));
  await context.close();context=await launch();page=await context.newPage();let attempts=0;
  await page.route('**/api/me',route=>++attempts===1?route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'Temporary outage'})}):route.continue());
  await page.clock.install();await page.goto(base);await page.locator('#auth-error').filter({hasText:'Reconnecting'}).waitFor();await page.locator('#connection-dot.online').waitFor({timeout:15000});assert.ok(attempts>=2);assert.equal(await page.locator('#my-name').textContent(),'Session Test');
  await context.addCookies([{...cookie,expires:Date.now()/1000+60}]);await page.clock.fastForward(3600000);await page.waitForFunction(()=>document.getElementById('app-view').hidden===false);
  for(let i=0;i<50;i++){cookie=(await context.cookies()).find(c=>c.name==='pvp_session');if(cookie.expires>Date.now()/1000+29*86400)break;await new Promise(r=>setTimeout(r,100));}assert.ok(cookie.expires>Date.now()/1000+29*86400,'open browser refreshes its persistent cookie');
  await page.locator('#logout').click();await page.locator('#auth-view').waitFor({state:'visible'});await context.addCookies([cookie]);assert.equal((await context.request.get(base+'/api/me')).status(),401,'a revoked saved token cannot restore login');
  await context.clearCookies();await context.close();context=await launch();page=await context.newPage();await page.goto(base);await page.locator('#auth-view').waitFor({state:'visible'});assert.equal(await page.locator('#app-view').isVisible(),false);
 } finally {await context?.close();if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
});
