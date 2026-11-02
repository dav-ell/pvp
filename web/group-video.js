import { saverLimit } from './bandwidth.js';
import { cameraQuality, groupVideoKbps, forwardingEnabled } from './group-quality.js';
import { EncodedVideoStats } from './media-health.js';
// Encoded participant forwarding. Media keys never leave encrypted peer channels.
// WebRTC remains the audio transport and the compatibility video fallback.
const te = new TextEncoder(), td = new TextDecoder();
const b64 = bytes => btoa(String.fromCharCode(...bytes));
const un64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const concat = (...items) => { const out = new Uint8Array(items.reduce((n,i)=>n+i.length,0)); let at=0; for(const item of items){out.set(item,at);at+=item.length;}return out; };
export function treeFor(ids, source) {
  const sorted=[...ids].sort(), start=sorted.indexOf(source);
  if(start<0)return [];return sorted.slice(start).concat(sorted.slice(0,start));
}
export function treeParent(ids, source, id) { const tree=treeFor(ids,source),index=tree.indexOf(id);return index>0?tree[Math.floor((index-1)/4)]:null; }
export function treeChildren(ids, source, id) {const tree=treeFor(ids,source),index=tree.indexOf(id);return index<0?[]:tree.slice(index*4+1,index*4+5);}
export class VideoOverlay {
  constructor(group) {this.g=group;this.keys=new Map();this.assemblies=new Map();this.decoders=new Map();this.seen=new Map();this.closed=false;this.revision=0;this.seq=0;this.pending=0;this.sending=Promise.resolve();this.high=false;this.lastCapture=0;this.frameCount=0;this.wantKey=true;this.outputConfig=0;this.outputFrames=new Map();this.outputStats=new EncodedVideoStats();}
  async initialize() {
    this.supported=false;
    try {
      if(!globalThis.VideoEncoder||!globalThis.VideoDecoder)return;
      const config={codec:'vp8',width:160,height:90,bitrate:30000,framerate:5,latencyMode:'realtime'};
      if(!(await VideoEncoder.isConfigSupported(config)).supported||!(await VideoDecoder.isConfigSupported({codec:'vp8'})).supported)return;
      this.signing=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
      this.publicKey=await crypto.subtle.exportKey('jwk',this.signing.publicKey);
      if(this.closed)return;
      this.supported=true;this.canvas=document.createElement('canvas');this.ctx=this.canvas.getContext('2d');
      this.encoder=new VideoEncoder({output:(chunk,metadata)=>this.encoded(chunk,metadata),error:()=>this.disable()});
      this.captureTimer=setInterval(()=>this.capture(),40);
    } catch {this.supported=false;}
  }
  ids(){return this.g.members.map(m=>m.id);}
  parent(source){return treeParent(this.ids(),source,this.g.o.user()?.id);}
  children(source){return treeChildren(this.ids(),source,this.g.o.user()?.id);}
  membershipChanged(){this.rotate().catch(()=>this.disable());}
  async rotate(){
    if(this.closed)return;
    const rev=this.g.room?.revision;if(!rev||rev===this.revision)return;
    this.revision=rev;this.seq=0;this.secret=null;this.rawKey=null;this.noncePrefix=null;this.keys.clear();this.assemblies.clear();this.seen.clear();this.resetOutput();
    for(const decoder of this.decoders.values())try{decoder.close();}catch{}this.decoders.clear();
    for(const link of this.g.links.values()){link.useOverlay=false;link.receivingOverlay=false;link.overlayReady=false;link.lastOverlay=0;const canvas=document.getElementById(`group-canvas-${link.id}`);if(canvas)canvas.hidden=true;}
    if(this.supported){const secret=crypto.getRandomValues(new Uint8Array(32));const imported=await crypto.subtle.importKey('raw',secret,{name:'AES-GCM'},false,['encrypt']);if(this.closed||this.revision!==rev)return;this.rawKey=b64(secret);this.secret=imported;this.noncePrefix=crypto.getRandomValues(new Uint8Array(4));}
    if(this.closed||this.revision!==rev)return;
    this.wantKey=true;for(const link of this.g.links.values())this.peerOpened(link);
    await this.g.limits();
  }
  peerOpened(link){
    this.g.control(link,{type:'overlay-hello',relay:true,receive:this.supported,codec:'vp8'});
    if(this.supported&&this.rawKey)this.g.control(link,{type:'overlay-key',revision:this.revision,key:this.rawKey,publicKey:this.publicKey,codec:'vp8'});
  }
  async control(link,msg){
    if(this.closed)return;
    if(msg.type==='overlay-hello'){link.overlayRelay=msg.relay===true;link.overlayReceive=msg.receive===true&&msg.codec==='vp8';if(this.rawKey)this.g.control(link,{type:'overlay-key',revision:this.revision,key:this.rawKey,publicKey:this.publicKey,codec:'vp8'});}
    if(msg.type==='overlay-key'&&this.supported&&msg.revision===this.g.room?.revision&&msg.codec==='vp8'&&typeof msg.key==='string'&&msg.key.length===44){
      if(this.keys.get(link.id)?.raw===msg.key&&this.keys.get(link.id)?.revision===msg.revision){this.g.control(link,{type:'overlay-ready',revision:msg.revision});return;}
      if(link.importingKey)return;link.importingKey=true;
      try {
      const raw=un64(msg.key),pub=msg.publicKey;if(raw.length!==32||pub?.kty!=='EC'||pub.crv!=='P-256'||pub.d||typeof pub.x!=='string'||typeof pub.y!=='string'||pub.x.length!==43||pub.y.length!==43)return;
      const [key,verify]=await Promise.all([crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']),crypto.subtle.importKey('jwk',pub,{name:'ECDSA',namedCurve:'P-256'},false,['verify'])]);
      if(this.closed||this.g.links.get(link.id)!==link||msg.revision!==this.g.room?.revision)return;
      this.keys.set(link.id,{key,verify,raw:msg.key,revision:msg.revision,lastSeq:0,pending:0,chain:Promise.resolve()});this.g.control(link,{type:'overlay-ready',revision:msg.revision});
      } finally {link.importingKey=false;}
    }
    if(msg.type==='overlay-ready'&&msg.revision===this.revision){link.overlayReady=link.overlayReceive===true;this.wantKey=true;}
    if(msg.type==='overlay-playing'&&msg.revision===this.revision&&link.overlayReady&&!link.useOverlay){link.useOverlay=this.ready();await this.g.limits();}
    if(msg.type==='overlay-fallback'&&link.useOverlay){link.useOverlay=false;await this.g.limits();}
    if(msg.type==='overlay-want'){link.wantHigh=msg.high===true;link.focusedScreen=msg.screen===true;await this.g.limits();}
    if(msg.type==='overlay-keyframe'){if(performance.now()-(this.lastKeyRequest||0)>300){this.lastKeyRequest=performance.now();this.wantKey=true;}}
  }
  ready(){return saverLimit(this.g.o.preferences().dataSend)===null&&saverLimit(this.g.o.preferences().dataReceive)===null&&![...this.g.links.values()].some(l=>Object.values(l.caps.receive).some(v=>v!==null)||Object.values(l.caps.send).some(v=>v!==null)||Object.values(l.requested).some(v=>v!==null))&&this.supported&&!!this.secret&&!this.closed&&this.g.joined&&forwardingEnabled(this.g.members.length)&&!this.g.display&&this.revision===this.g.room.revision&&this.g.members.every(m=>m.id===this.g.o.user().id||(this.g.links.get(m.id)?.overlayRelay&&this.g.links.get(m.id)?.video?.readyState==='open'));}
  async refresh(){
    if(this.closed)return;
    if(this.revision!==this.g.room?.revision)await this.rotate();
    if(performance.now()-(this.lastHello||0)>2000){this.lastHello=performance.now();for(const link of this.g.links.values())this.peerOpened(link);}
    const ready=this.ready();
    for(const link of this.g.links.values()){
      if(!ready){link.useOverlay=false;if(link.receivingOverlay)this.fallback(link);}
      this.g.control(link,{type:'overlay-want',high:this.g.maximized?this.g.maximized===link.id:this.g.pinned===link.id||this.g.activeSpeakers().includes(link.id),screen:this.g.maximized==='self'?!!this.g.display:!!this.g.maximized&&!!this.g.links.get(this.g.maximized)?.state.sharing});
      if(link.receivingOverlay&&performance.now()-link.lastOverlay>2000&&!link.state.paused){this.fallback(link);}
    }
    // A bounded assembly lifetime protects against missing chunks and flooding.
    for(const [id,a] of this.assemblies)if(performance.now()-a.at>700)this.assemblies.delete(id);
  }
  configure(high){
    const p=this.g.o.preferences(),attendees=this.g.members.length;
    const captureHeight=document.getElementById('group-self-video')?.videoHeight||p.resolution;
    const quality=cameraQuality(p,attendees,high,captureHeight);
    const height=quality.small?quality.height:Math.min(captureHeight,high?360:90),width=Math.round(height*16/9/2)*2,fps=quality.small?quality.fps:high?15:3;
    const mixed=[...this.g.links.values()].some(l=>!l.useOverlay);
    const budget=groupVideoKbps(p,attendees)*(quality.small&&!mixed?1000:500);
    const bitrate=quality.small
      ? Math.max(24000,Math.min(800000,Math.floor(budget*.85/Math.max(1,attendees-1))))
      : Math.max(24000,Math.min(high?450000:20000,Math.floor(p.video*1000/16)));
    const mode=`${width}/${height}/${fps}/${bitrate}`;if(this.mode===mode)return;
    this.canvas.width=width;this.canvas.height=height;this.encoder.configure({codec:'vp8',width,height,bitrate,framerate:fps,latencyMode:'realtime'});this.resetOutput();this.mode=mode;this.fps=fps;this.wantKey=true;
  }
  capture(){
    if(!this.ready()||this.g.paused||this.g.shareBusy||this.pending>2)return;
    const video=document.getElementById('group-self-video');if(!video?.videoWidth||video.readyState<2)return;
    const high=!!this.g.display||this.g.activeSpeakers().includes(this.g.o.user().id)||[...this.g.links.values()].some(l=>l.wantHigh);
    try{
      this.configure(high);const now=performance.now();if(now-this.lastCapture<1000/this.fps||this.encoder.encodeQueueSize>2)return;this.lastCapture=now;
      this.ctx.fillStyle='#122a21';this.ctx.fillRect(0,0,this.canvas.width,this.canvas.height);const scale=Math.min(this.canvas.width/video.videoWidth,this.canvas.height/video.videoHeight),w=video.videoWidth*scale,h=video.videoHeight*scale;this.ctx.drawImage(video,(this.canvas.width-w)/2,(this.canvas.height-h)/2,w,h);
      const frame=new VideoFrame(this.canvas,{timestamp:Math.round(now*1000)}),keyFrame=this.wantKey||(++this.frameCount%Math.max(1,this.fps)===0);this.wantKey=false;
      this.outputFrames.set(frame.timestamp,{config:this.outputConfig,revision:this.revision});
      while(this.outputFrames.size>120)this.outputFrames.delete(this.outputFrames.keys().next().value);
      this.encoder.encode(frame,{keyFrame});frame.close();
    }catch{this.disable();}
  }
  resetOutput(){this.outputConfig++;this.outputFrames.clear();this.outputStats.reset(this.outputConfig);}
  observedOutput(now=Date.now()){return this.closed?[]:this.outputStats.fresh(now);}
  encoded(chunk,metadata){
    const output=this.outputFrames.get(chunk.timestamp);this.outputFrames.delete(chunk.timestamp);
    if(this.closed||!this.ready()||chunk.byteLength>250000||this.pending>2)return;
    const data=new Uint8Array(chunk.byteLength);chunk.copyTo(data);const rev=this.revision,seq=++this.seq,secret=this.secret,noncePrefix=this.noncePrefix;
    if(output?.config===this.outputConfig&&output.revision===rev)this.outputStats.observe(chunk,metadata,output.config,data);
    const meta=JSON.stringify({room:this.g.room.room_id,revision:rev,source:this.g.o.user().id,seq,timestamp:chunk.timestamp,type:chunk.type,codec:'vp8'});
    this.pending++;
    this.sending=this.sending.then(async()=>{
      if(this.closed||rev!==this.revision)return;
      const iv=new Uint8Array(12);iv.set(noncePrefix);new DataView(iv.buffer).setBigUint64(4,BigInt(seq));const aad=te.encode(meta);
      const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},secret,data));
      const signature=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},this.signing.privateKey,concat(aad,iv,cipher)));
      if(this.closed||rev!==this.revision)return;
      const total=Math.ceil(cipher.length/6000);
      for(let part=0;part<total;part++){
        const header=te.encode(JSON.stringify({m:meta,iv:b64(iv),sig:b64(signature),part,total,len:cipher.length}));const packet=new Uint8Array(2+header.length+Math.min(6000,cipher.length-part*6000));new DataView(packet.buffer).setUint16(0,header.length);packet.set(header,2);packet.set(cipher.subarray(part*6000,(part+1)*6000),2+header.length);
        this.forward(this.g.o.user().id,packet.buffer,false);
      }
    }).catch(()=>this.disable()).finally(()=>this.pending--);
  }
  forward(source,buffer,relaying){
    if(!this.ready())return;
    for(const id of this.children(source)){
      const link=this.g.links.get(id),dc=link?.video;if(!dc||dc.readyState!=='open'||dc.bufferedAmount>65536)continue;
      // Aggregate send budget, including streams this participant forwards.
      const now=performance.now();if(!this.budgetAt||now-this.budgetAt>=1000){this.budgetAt=now;this.budgetBytes=0;this.backgroundBytes=0;}
      const p=this.g.o.preferences(),attendees=this.g.members.length;const mixed=[...this.g.links.values()].some(l=>!l.useOverlay);const budget=groupVideoKbps(p,attendees)*1000/(cameraQuality(p,attendees,false).small&&!mixed?8:16);
      const sharing=source===this.g.o.user().id?!!this.g.display:!!this.g.links.get(source)?.state.sharing;
      if(this.budgetBytes+buffer.byteLength>budget||(!sharing&&this.g.members.some(m=>m.id===this.g.o.user().id?!!this.g.display:!!this.g.links.get(m.id)?.state.sharing)&&this.backgroundBytes+buffer.byteLength>budget/10))continue;
      try{dc.send(buffer);this.budgetBytes+=buffer.byteLength;if(!sharing)this.backgroundBytes+=buffer.byteLength;link.sentBytes+=buffer.byteLength;if(relaying)link.forwardedBytes+=buffer.byteLength;}catch{}
    }
  }
  packet(link,buffer){
    if(this.closed||!this.g.joined||!forwardingEnabled(this.g.members.length))return;
    let h,m,payload;
    try{
      const data=new Uint8Array(buffer),length=new DataView(buffer).getUint16(0);if(length>1200||length+2>=data.length)return;
      h=JSON.parse(td.decode(data.subarray(2,2+length)));if(typeof h.m!=='string'||h.m.length>600)return;m=JSON.parse(h.m);payload=data.subarray(2+length);
      if(m.room!==this.g.room.room_id||m.revision!==this.g.room.revision||m.codec!=='vp8'||!['key','delta'].includes(m.type)||!Number.isSafeInteger(m.seq)||m.seq<1||!Number.isSafeInteger(m.timestamp)||m.timestamp<0||!this.ids().includes(m.source)||m.source===this.g.o.user().id||this.g.links.get(m.source)?.state.sharing||this.parent(m.source)!==link.id||!Number.isInteger(h.total)||h.total<1||h.total>42||!Number.isInteger(h.part)||h.part<0||h.part>=h.total||!Number.isInteger(h.len)||h.len<17||h.len>250016||h.total!==Math.ceil(h.len/6000)||payload.length!==Math.min(6000,h.len-h.part*6000)||typeof h.iv!=='string'||h.iv.length!==16||typeof h.sig!=='string'||h.sig.length!==88)return;
    }catch{return;}
    link.receivedBytes+=buffer.byteLength;
    const packetId=`${m.source}/${m.revision}/${m.seq}/${h.part}`;
    if(this.seen.has(packetId))return;this.seen.set(packetId,performance.now());while(this.seen.size>2048)this.seen.delete(this.seen.keys().next().value);
    this.forward(m.source,buffer,true);
    const source=this.g.links.get(m.source),key=this.keys.get(m.source);if(!this.supported||!source||!key||key.revision!==m.revision)return;
    const id=`${m.source}/${m.seq}`;let assembly=this.assemblies.get(id);
    if(!assembly){if(this.assemblies.size>=64)return;assembly={h,m,parts:new Map(),at:performance.now()};this.assemblies.set(id,assembly);}
    if(assembly.h.m!==h.m||assembly.h.iv!==h.iv||assembly.h.sig!==h.sig)return;
    assembly.parts.set(h.part,payload.slice());if(assembly.parts.size!==h.total)return;this.assemblies.delete(id);
    const cipher=concat(...Array.from({length:h.total},(_,i)=>assembly.parts.get(i)));
    if(key.pending>=4){this.requestKey(source);return;}key.pending++;
    key.chain=key.chain.then(async()=>{
      if(this.closed||key!==this.keys.get(m.source)||m.seq<=key.lastSeq)return;
      const iv=un64(h.iv),sig=un64(h.sig),aad=te.encode(h.m);
      if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key.verify,sig,concat(aad,iv,cipher)))return;
      const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad},key.key,cipher);
      if(this.closed||key!==this.keys.get(m.source)||source.state.sharing)return;
      key.lastSeq=m.seq;
      let decoder=this.decoders.get(m.source);
      if(!decoder||decoder.state==='closed'){
        if(m.type!=='key'){this.requestKey(source);return;}
        decoder=new VideoDecoder({output:frame=>{
          if(this.closed||key!==this.keys.get(m.source)||m.revision!==this.g.room?.revision){frame.close();return;}
          const canvas=document.getElementById(`group-canvas-${m.source}`);if(canvas){canvas.width=frame.displayWidth;canvas.height=frame.displayHeight;const ctx=canvas.getContext('2d');if(source.state.paused){ctx.fillStyle='#122a21';ctx.fillRect(0,0,canvas.width,canvas.height);}else ctx.drawImage(frame,0,0);canvas.hidden=false;if(!source.state.paused)canvas.closest('.group-tile').dataset.video='on';}
          source.frames++;source.lastOverlay=performance.now();if(!source.receivingOverlay){source.receivingOverlay=true;this.g.control(source,{type:'overlay-playing',revision:this.revision});}frame.close();
        },error:()=>{this.fallback(source);this.requestKey(source);}});decoder.configure({codec:'vp8',optimizeForLatency:true});this.decoders.set(m.source,decoder);
      }
      if(decoder.decodeQueueSize>3){this.requestKey(source);return;}
      decoder.decode(new EncodedVideoChunk({type:m.type,timestamp:m.timestamp,data:plaintext}));
    }).catch(()=>{this.fallback(source);this.requestKey(source);}).finally(()=>{key.pending--;});
  }
  requestKey(link){if(performance.now()-(link.keyRequestAt||0)>500){link.keyRequestAt=performance.now();this.g.control(link,{type:'overlay-keyframe'});}}
  fallback(link){link.receivingOverlay=false;document.getElementById(`group-canvas-${link.id}`)?.setAttribute('hidden','');this.g.control(link,{type:'overlay-fallback'});}
  removePeer(id){this.keys.delete(id);const decoder=this.decoders.get(id);if(decoder&&decoder.state!=='closed')decoder.close();this.decoders.delete(id);}
  remoteSourceChanged(link){
    const decoder=this.decoders.get(link.id);if(decoder&&decoder.state!=='closed')decoder.close();this.decoders.delete(link.id);
    if(link.receivingOverlay)this.fallback(link);
  }
  sourceChanged(){this.wantKey=true;this.mode=null;this.resetOutput();}
  disable(){this.supported=false;this.resetOutput();clearInterval(this.captureTimer);for(const link of this.g.links.values()){link.useOverlay=false;this.fallback(link);this.g.control(link,{type:'overlay-hello',relay:true,receive:false,codec:'vp8'});}this.g.limits().catch(()=>{});}
  close(){this.closed=true;this.resetOutput();clearInterval(this.captureTimer);try{this.encoder?.close();}catch{}for(const d of this.decoders.values())try{d.close();}catch{}this.decoders.clear();this.keys.clear();this.secret=null;this.rawKey=null;this.signing=null;this.assemblies.clear();this.seen.clear();}
}
