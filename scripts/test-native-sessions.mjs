import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
const temp=await mkdtemp(join(tmpdir(),'pvp-native-sessions-')),username=`persist_${Date.now().toString().slice(-9)}`;let server;
try {
 await promisify(execFile)('cargo',['build','--quiet','--manifest-path','signaling/Cargo.toml']);
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));const base=`http://localhost:${port}`;
 server=spawn('signaling/target/debug/pvp-signaling',[],{env:{...process.env,PVP_BIND:`127.0.0.1:${port}`,PVP_ORIGIN:base,PVP_DATABASE:join(temp,'pvp.sqlite')},stdio:'ignore'});
 for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 const response=await fetch(base+'/api/register',{method:'POST',headers:{Origin:base,'Content-Type':'application/json'},body:JSON.stringify({username,display_name:'Persistence Test',password:'session-test-password-123'})});if(!response.ok)throw Error('Test registration failed');
 const env={...process.env};if(env.PVP_TEST_SIGNING_IDENTITY){const signing=join(temp,'signing.xcconfig');await writeFile(signing,`CODE_SIGN_IDENTITY = ${env.PVP_TEST_SIGNING_IDENTITY}\nDEVELOPMENT_TEAM = ${env.PVP_TEST_TEAM}\nCODE_SIGN_STYLE = Manual\n`);env.XCODE_XCCONFIG_FILE=signing;}
 for(const phase of ['save','restore']) {
  console.log(`Native persistence phase: ${phase}`);
  const child=spawn(process.env.PVP_FLUTTER||resolve('.build/flutter-security-sdk/bin/flutter'),['test','-d','macos','integration_test/session_persistence_test.dart',`--dart-define=PVP_SERVICE=${base}`,`--dart-define=PVP_NATIVE_USER=${username}`,`--dart-define=PVP_SESSION_PHASE=${phase}`],{cwd:'desktop',stdio:'inherit',env});const exit=await new Promise(r=>child.once('exit',r));if(exit!==0)throw Error(`Native ${phase} phase failed`);
 }
}finally{if(server){server.kill();await new Promise(r=>server.once('exit',r));}await rm(temp,{recursive:true,force:true});}
