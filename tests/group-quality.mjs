import {test} from 'node:test';
import assert from 'node:assert/strict';
import {cameraQuality,groupVideoKbps,screenVideoKbps,forwardingEnabled} from '../web/group-quality.js';
const balanced={preset:'balanced',resolution:720,fps:30,video:1800};
test('small groups retain 480p for quiet participants, respecting input resolution',()=>{
 for(const attendees of [2,6,8])for(const speaking of [true,false]){const q=cameraQuality(balanced,attendees,speaking);assert.equal(q.height,480);assert.equal(q.fps,24);assert.equal(q.scale,1.5);}
 assert.equal(cameraQuality(balanced,8,false,480).scale,1);
 assert.equal(cameraQuality(balanced,8,false,360).height,360,'cannot create camera detail absent from capture');
 assert.equal(cameraQuality(balanced,9,false).height,90);
 assert.equal(cameraQuality(balanced,9,true).height,360);
 assert.equal(cameraQuality(balanced,8,false).height,480,'quality recovers when ninth participant leaves');
});
test('balanced bandwidth scales with group size; saver and custom remain explicit',()=>{
 assert.equal(groupVideoKbps(balanced,8),4200);assert.equal(groupVideoKbps(balanced,2),1800);assert.equal(groupVideoKbps(balanced,9),1800);
 const custom={...balanced,preset:'custom',video:128};assert.equal(groupVideoKbps(custom,8),128);
 const saver={...balanced,preset:'saver',resolution:360,video:400};assert.equal(groupVideoKbps(saver,8),400);assert.equal(cameraQuality(saver,8,false).height,90);
 const studio={...balanced,preset:'studio',resolution:1080,video:4000};assert.equal(cameraQuality(studio,8,false).height,720);
});

test('forwarding starts at six attendees and stops when the sixth leaves',()=>{
 for(const n of [1,2,3,4,5])assert.equal(forwardingEnabled(n),false);
 for(const n of [6,7,16])assert.equal(forwardingEnabled(n),true);
});
test('maximized screens outrank thumbnails while explicit budgets remain respected',()=>{
 assert.equal(screenVideoKbps(balanced,false,false),2000);
 assert.equal(screenVideoKbps(balanced,true,true),6000);
 assert.equal(screenVideoKbps(balanced,false,true),400);
 assert.equal(screenVideoKbps({...balanced,preset:'custom',video:128},true,true),128);
 assert.equal(screenVideoKbps({...balanced,preset:'custom',video:128},true,true,4),32);
});
