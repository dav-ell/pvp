import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BandwidthMeter, bandwidthLabel, validCaps, videoCap} from '../web/bandwidth.js';
const report=(sent,received,id='t')=>new Map([[id,{id,type:'transport',bytesSent:sent,bytesReceived:received}],['pair',{id:'pair',type:'candidate-pair',state:'succeeded',nominated:true,bytesSent:sent,bytesReceived:received}],['rtp',{type:'outbound-rtp',bytesSent:sent}]]);
test('live bandwidth counts transport once and sums both directions across peers',()=>{
 const a=new BandwidthMeter(),b=new BandwidthMeter();assert.equal(a.sample(report(100,200),1000),null);
 a.sample(report(1100,2200),2000);b.sample(report(0,0),1000);b.sample(report(1000,2000),2000);
 assert.equal(a.rate.up,8);assert.equal(a.rate.down,16);
 assert.match(bandwidthLabel([a.rate,b.rate],2000),/↓ 32 Kbps · ↑ 16 Kbps · ~0.4 MB\/min/);
 assert.match(bandwidthLabel([a.rate],6000),/measuring/);
});
test('missing counters, reset, path changes and long sampling gaps need a new baseline',()=>{
 const m=new BandwidthMeter();m.sample(report(100,100),1000);assert.equal(m.sample(report(0,0),2000),null);
 assert.equal(m.sample(report(100,100,'new'),3000),null);assert.equal(m.sample(report(200,200,'new'),8000),null);
 assert.equal(m.sample(new Map(),9000),null);
 const pair=new Map([['p',{id:'p',type:'candidate-pair',state:'succeeded',selected:true,bytesSent:0,bytesReceived:0}]]);
 m.sample(pair,10000);pair.get('p').bytesReceived=1000;m.sample(pair,11000);assert.equal(m.rate.down,8);
});
test('connection limits validate remote input and isolate camera from screen share',()=>{
 assert.equal(validCaps({camera:-1,screen:null}),null);assert.equal(validCaps({camera:'64',screen:null}),null);assert.equal(validCaps({camera:Infinity,screen:null}),null);assert.equal(validCaps({camera:64}),null);
 const caps=validCaps({camera:64,screen:8000});assert.deepEqual(caps,{camera:64,screen:8000});
 assert.equal(videoCap(1800,caps,{camera:400,screen:4000},false),64);
 assert.equal(videoCap(1800,caps,{camera:400,screen:4000},true),4000);
 assert.equal(videoCap(1800,{camera:null,screen:null},{camera:null,screen:null},false),1800);
 assert.equal(videoCap(1800,{camera:null,screen:null},{camera:64,screen:null},false),64);
 assert.equal(videoCap(1800,{camera:null,screen:null},{camera:8000,screen:null},false),8000);
});

test('data saver recognizes cellular and metered hints and keeps manual limits independent', async()=>{
 const {connectionIsMetered,saverLimit,saverCaps}=await import('../web/bandwidth.js');
 for(const connection of [{type:'cellular',effectiveType:'4g'},{metered:true},{saveData:true},{effectiveType:'2g'}]) {
  assert.equal(connectionIsMetered(connection),true);
  assert.equal(saverLimit('auto',connection),128);
 }
 assert.equal(saverLimit('auto',{}),null);
 assert.equal(saverLimit('off',{type:'cellular'}),null);
 for(const [mode,limit] of [['low',400],['verylow',128],['minimal',64],['none',0]]) {
  assert.equal(saverLimit(mode,{}),limit);
  assert.deepEqual(saverCaps({camera:null,screen:null},mode,{}),{camera:limit,screen:limit});
 }
 assert.deepEqual(saverCaps({camera:64,screen:400},'verylow',{}),{camera:64,screen:128});
 assert.deepEqual(validCaps({camera:0,screen:0}),{camera:0,screen:0});
 assert.equal(videoCap(1800,{camera:null,screen:null},{camera:0,screen:0},false),0);
});
