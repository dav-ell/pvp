import { chromium } from 'playwright';
import { createServer } from 'node:http';
const server=createServer((req,res)=>res.end('<!doctype html><title>PVP forwarding experiment</title>'));
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage(); await page.goto(`http://localhost:${server.address().port}`);
 console.log(JSON.stringify(await page.evaluate(async()=> {
 const supported=await VideoEncoder.isConfigSupported({codec:'vp8',width:320,height:180,bitrate:200000,framerate:15,latencyMode:'realtime'});
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
 const signing=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 async function pair(){const a=new RTCPeerConnection({iceServers:[]}),b=new RTCPeerConnection({iceServers:[]});a.onicecandidate=e=>e.candidate&&b.addIceCandidate(e.candidate);b.onicecandidate=e=>e.candidate&&a.addIceCandidate(e.candidate);const out=a.createDataChannel('video',{ordered:false,maxRetransmits:0});const incoming=new Promise(r=>b.ondatachannel=e=>r(e.channel));await a.setLocalDescription(await a.createOffer());await b.setRemoteDescription(a.localDescription);await b.setLocalDescription(await b.createAnswer());await a.setRemoteDescription(b.localDescription);const input=await incoming;await new Promise(r=>out.readyState==='open'?r():out.onopen=r);input.binaryType='arraybuffer';return {a,b,out,input};}
 const one=await pair(),two=await pair();let received=0,forwarded=0,encoded=0,lastPixel,latencies=[];
 const canvas=new OffscreenCanvas(320,180),ctx=canvas.getContext('2d');
 const decoder=new VideoDecoder({output:frame=>{ctx.drawImage(frame,0,0);lastPixel=[...ctx.getImageData(10,10,1,1).data];received++;frame.close();},error:e=>{throw e;}});decoder.configure({codec:'vp8',optimizeForLatency:true});
 one.input.onmessage=e=>{forwarded++;two.out.send(e.data);};
 two.input.onmessage=async e=>{const raw=new Uint8Array(e.data),iv=raw.slice(0,12),sig=raw.slice(12,76),ct=raw.slice(76);if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},signing.publicKey,sig,ct))throw Error('Signature failed');const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);decoder.decode(new EncodedVideoChunk({type:'key',timestamp:received*66667,data:plain}));latencies.push(performance.now()-Number(new DataView(iv.buffer).getFloat64(0)));};
 const encoder=new VideoEncoder({output:async chunk=>{const data=new Uint8Array(chunk.byteLength);chunk.copyTo(data);const iv=crypto.getRandomValues(new Uint8Array(12));new DataView(iv.buffer).setFloat64(0,performance.now());const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,data)),sig=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signing.privateKey,ct));const packet=new Uint8Array(76+ct.length);packet.set(iv);packet.set(sig,12);packet.set(ct,76);one.out.send(packet);encoded++;},error:e=>{throw e;}});encoder.configure(supported.config);
 for(let i=0;i<12;i++){ctx.fillStyle='#ff0088';ctx.fillRect(0,0,320,180);const frame=new VideoFrame(canvas,{timestamp:i*66667});encoder.encode(frame,{keyFrame:true});frame.close();await new Promise(r=>setTimeout(r,70));}
 await encoder.flush();await new Promise(r=>setTimeout(r,500));
 const result={supported:supported.supported,encoded,forwarded,received,lastPixel,meanHopTransportMs:latencies.reduce((a,b)=>a+b,0)/latencies.length};encoder.close();decoder.close();[one,two].forEach(p=>{p.a.close();p.b.close();});return result;
 }),null,2));
} finally {await browser.close();await new Promise(r=>server.close(r));}
