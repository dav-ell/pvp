// Local microphone analysis never connects to a playback or WebRTC destination.
// A clone keeps analysing an already-consented source while the sent track is muted.
export class MutedSpeechDetector {
  update(level, { muted = false, active = false, moderated = false } = {}, now = performance.now()) {
    if (!muted || !active || moderated) { this.started = null; this.lastSound = null; return false; }
    if (level > .025) { this.started ??= now; this.lastSound = now; }
    else if (this.lastSound == null || now - this.lastSound > 1200) this.started = null;
    return this.started != null && now - this.started >= 600 && now - this.lastSound <= 1200;
  }
}

export function monitorLocalMicrophone(track, audio, state, sample, { interval = 150, ended = () => {} } = {}) {
  if (!track || track.readyState !== 'live' || !audio) return null;
  const clone = track.clone(); clone.enabled = true;
  let source, analyser, timer, stopped = false;
  const detector = new MutedSpeechDetector();
  const stop = () => {
    if (stopped) return; stopped = true; clearInterval(timer);
    track.removeEventListener('ended', ended);
    source?.disconnect(); analyser?.disconnect(); clone.stop();
  };
  try {
    source = audio.createMediaStreamSource(new MediaStream([clone]));
    analyser = audio.createAnalyser(); analyser.fftSize = 1024; source.connect(analyser);
    const samples = new Float32Array(analyser.fftSize);
    const update = () => {
      if (stopped) return;
      analyser.getFloatTimeDomainData(samples);
      const level = audio.state === 'running' && track.readyState === 'live'
        ? Math.sqrt(samples.reduce((sum, n) => sum + n * n, 0) / samples.length) : 0;
      const status = state();
      sample({ level, mutedSpeech: detector.update(level, status), ...status });
    };
    track.addEventListener('ended', ended); timer = setInterval(update, interval); update();
    return { stop, update, track, clone };
  } catch (error) { stop(); throw error; }
}

const canceled = () => new DOMException('Microphone change canceled', 'AbortError');
// Change only the audio track. Keep stream, peer connections, camera and consent state.
export async function replaceMicrophone({ stream, track, capture, senders, valid, enabled }) {
  let captured, next, installed = false; const replaced = [];
  try {
    captured = await capture(); next = captured.getAudioTracks()[0];
    if (!valid()) throw canceled();
    if (!next || next.readyState !== 'live') throw Error('No microphone was opened.');
    next.enabled = enabled();
    // Include peers that join while capture or replaceTrack is pending.
    for (;;) {
      const pending = senders().filter(sender => sender.track === track && !replaced.includes(sender));
      if (!pending.length) break;
      for (const sender of pending) {
        next.enabled = enabled(); await sender.replaceTrack(next); replaced.push(sender);
        if (!valid()) throw canceled();
      }
    }
    next.enabled = enabled();
    stream.removeTrack(track); stream.addTrack(next); captured.removeTrack(next); installed = true;
    track.stop(); return next;
  } catch (error) {
    // A canceled/ended call must never have an old track reattached to its senders.
    if (valid()) for (const sender of replaced.reverse()) {
      try { await sender.replaceTrack(track.readyState === 'live' ? track : null); } catch { /* Peer departed. */ }
    }
    throw error;
  } finally {
    captured?.getTracks().forEach(t => t.stop());
    if (!installed) next?.stop();
  }
}

// RTP output is one media path. Encoded forwarding has its own observations below.
export class OutboundVideoStats {
  constructor() { this.previous = new Map(); this.rows = []; }
  sample(report, now = Date.now()) {
    const previous = this.previous; this.previous = new Map();
    this.rows = [...report.values()].filter(row => row.type === 'outbound-rtp' && !row.isRemote && (row.kind || row.mediaType) === 'video').map(row => {
      const before = previous.get(row.id);
      const elapsed = before && row.timestamp - before.timestamp;
      const kbps = elapsed > 0 && elapsed < 4000 && Number.isFinite(row.bytesSent) && row.bytesSent >= before.bytesSent
        ? (row.bytesSent - before.bytesSent) * 8 / elapsed : null;
      this.previous.set(row.id, { timestamp: row.timestamp, bytesSent: row.bytesSent });
      const positive = n => Number.isFinite(n) && n > 0 ? n : null;
      return { id: row.id, width: positive(row.frameWidth), height: positive(row.frameHeight), fps: Number.isFinite(row.framesPerSecond) ? row.framesPerSecond : null, kbps, limitation: row.qualityLimitationReason || null, at: now };
    });
    return this.rows;
  }
  fresh(now = Date.now()) { return this.rows.filter(row => now - row.at < 4000); }
}

// These are encoder payload observations, not proof of transmission or playback.
// VP8 keyframes carry their coded dimensions; configured targets are never used.
export class EncodedVideoStats {
  constructor() { this.reset(null); }
  reset(identity) { this.identity=identity;this.samples=[];this.dimensions=null;this.rows=[]; }
  observe(chunk, metadata, identity, payload, now = Date.now()) {
    if(identity!==this.identity||!Number.isFinite(chunk?.byteLength)||chunk.byteLength<=0)return;
    const bytes=payload instanceof Uint8Array?payload:new Uint8Array(payload||0);
    const size=n=>Number.isInteger(n)&&n>0&&n<=16383?n:null;
    if(chunk.type==='key') {
      this.dimensions=null;
      if(bytes.length>=10&&(bytes[0]&1)===0&&bytes[3]===0x9d&&bytes[4]===0x01&&bytes[5]===0x2a) {
        const width=size((bytes[6]|bytes[7]<<8)&0x3fff),height=size((bytes[8]|bytes[9]<<8)&0x3fff);
        if(width&&height)this.dimensions={width,height};
      }
    }
    const config=metadata?.decoderConfig;
    if(!this.dimensions&&config?.codec==='vp8'&&size(config.codedWidth)&&size(config.codedHeight))this.dimensions={width:config.codedWidth,height:config.codedHeight};
    // Keep one baseline before the two-second window for low-frame-rate output.
    const last=this.samples.at(-1);if(last&&(now-last.at>=4000||now<last.at))this.samples=[];
    this.samples.push({at:now,bytes:chunk.byteLength});
    while(this.samples.length>2&&this.samples[1].at<now-2000)this.samples.shift();
    const first=this.samples[0],elapsed=now-first.at,measured=elapsed>=100;
    const fps=measured?(this.samples.length-1)*1000/elapsed:null;
    const kbps=measured?this.samples.slice(1).reduce((sum,sample)=>sum+sample.bytes,0)*8/elapsed:null;
    this.rows=[{id:`encoded-${identity}`,path:'encoded-forwarding',source:'VideoEncoder VP8 output',width:this.dimensions?.width??null,height:this.dimensions?.height??null,fps,kbps,at:now,delivery:'unverified'}];
    return this.rows;
  }
  fresh(now = Date.now()) { return this.rows.filter(row=>now-row.at<4000); }
}

export function selectedQuality(preferences) {
  if (!preferences) return null;
  const names = { saver: 'Data saver', balanced: 'Balanced', studio: 'High quality', custom: 'Custom' };
  return { preset: preferences.preset, label: names[preferences.preset] || 'Custom', resolution: preferences.resolution, fps: preferences.fps, kbps: preferences.video, dataSend: preferences.dataSend, dataReceive: preferences.dataReceive };
}

export function sentVideoLabel(peers, { camera = false, sharing = false } = {}) {
  if (!camera && !sharing) return 'Camera off';
  const range = values => Math.min(...values) === Math.max(...values) ? String(Math.round(values[0])) : `${Math.round(Math.min(...values))}–${Math.round(Math.max(...values))}`;
  const summarize=(rows,prefix,rateSuffix)=>{
    if(!rows.length)return prefix==='Encoded forwarding'?'Encoded forwarding · quality unavailable':prefix==='RTP sending'?'RTP quality unavailable':'Sent quality unavailable';
    const dimensions=[...new Set(rows.filter(row=>row.width&&row.height).map(row=>`${row.width} × ${row.height}`))];
    const frames=rows.map(row=>row.fps).filter(Number.isFinite),rates=rows.map(row=>row.kbps).filter(Number.isFinite);
    return [`${prefix} ${dimensions.length?dimensions.join(' / '):'resolution unavailable'}`,frames.length?`${range(frames)} fps`:'fps unavailable',rates.length?`${range(rates)} Kbps${rateSuffix}`:'bitrate measuring…'].join(' · ');
  };
  const encoded=peers.filter(peer=>peer.path==='encoded-forwarding'),rtp=peers.filter(peer=>peer.path!=='encoded-forwarding');
  const labels=[];
  if(encoded.length){const rows=[...new Map(encoded.flatMap(peer=>peer.rows||[]).map(row=>[row.id,row])).values()];labels.push(summarize(rows,'Encoded forwarding',' encoder payload')+' · delivery unverified');}
  if(rtp.length||!encoded.length)labels.push(summarize(rtp.flatMap(peer=>peer.rows||[]),encoded.length?'RTP sending':'Sending',rtp.length>1?' per connection':''));
  return labels.join(' / ');
}
