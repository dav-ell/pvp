// Per-connection transport counters include audio, video and data channels once.
export class BandwidthMeter {
  sample(report, now = Date.now()) {
    const rows = [...report.values()];
    const transports = rows.filter(r => r.type === 'transport' && Number.isFinite(r.bytesSent) && Number.isFinite(r.bytesReceived));
    const pairs = rows.filter(r => r.type === 'candidate-pair' && Number.isFinite(r.bytesSent) && Number.isFinite(r.bytesReceived) && r.state === 'succeeded' && (r.selected || r.nominated));
    const counters = transports.length ? transports : pairs;
    const snapshot = counters.length ? {key: counters.map(r => r.id).sort().join('/'), sent: counters.reduce((n,r)=>n+r.bytesSent,0), received: counters.reduce((n,r)=>n+r.bytesReceived,0), now} : null;
    const prev = this.previous; this.previous = snapshot;
    this.rate = snapshot && prev && snapshot.key === prev.key && now > prev.now && now-prev.now < 4000 && snapshot.sent >= prev.sent && snapshot.received >= prev.received
      ? {up: (snapshot.sent-prev.sent)*8/(now-prev.now), down: (snapshot.received-prev.received)*8/(now-prev.now), at: now} : null;
    return this.rate;
  }
}
export function bandwidthLabel(rates, now = Date.now()) {
  if (!rates.length || rates.some(r=>!r || now-r.at >= 4000)) return 'Your bandwidth · measuring…';
  const up=rates.reduce((n,r)=>n+r.up,0), down=rates.reduce((n,r)=>n+r.down,0);
  const fmt=n=>n>=1000?`${(n/1000).toFixed(2)} Mbps`:`${Math.round(n)} Kbps`;
  return `You · ↓ ${fmt(down)} · ↑ ${fmt(up)} · ~${((up+down)*60/8000).toFixed(1)} MB/min`;
}
export function validCaps(value) {
  if (!value || typeof value !== 'object') return null;
  const out={};
  for (const key of ['camera','screen']) {
    const n=value[key]; if (n === null) out[key]=null;
    else if (Number.isInteger(n) && (n===0 || n>=32) && n<=8000) out[key]=n;
    else return null;
  }
  return out;
}
export function videoCap(defaultKbps, sent, requested, sharing) {
  const key=sharing?'screen':'camera';
  return Math.min(sent?.[key] ?? requested?.[key] ?? defaultKbps, requested?.[key] ?? Infinity);
}
export function bandwidthControls(root, caps, change) {
  root.replaceChildren();
  const note=document.createElement('p'); note.className='settings-note';
  note.textContent='Video limits apply only to this participant, for this call. Receive limits require an updated sender. Audio and network overhead are additional. High limits do not guarantee higher quality.';root.append(note);
  for(const direction of ['receive','send'])for(const source of ['camera','screen']) {
    const label=document.createElement('label');label.textContent=`${direction==='receive'?'Receive their':'Send your'} ${source==='screen'?'screen share':'camera'}`;
    const select=document.createElement('select');select.dataset.direction=direction;select.dataset.source=source;
    for(const [value,text] of [['','Automatic'],['0','None · no video'],['64','Super low · 64 Kbps'],['400','Low · 400 Kbps'],['1800','Balanced · 1.8 Mbps'],['4000','High · 4 Mbps'],['8000','Super high · 8 Mbps'],['custom','Custom…']]) {const option=document.createElement('option');option.value=value;option.textContent=text;select.append(option);}
    const input=document.createElement('input');input.type='number';input.min=32;input.max=8000;input.step=1;input.setAttribute('aria-label',`${label.textContent} custom Kbps`);
    const value=caps[direction][source];const preset=[0,64,400,1800,4000,8000].includes(value);select.value=value==null?'':preset?String(value):'custom';input.hidden=select.value!=='custom';input.value=value??400;
    const commit=n=>{if(n!==null&&(!Number.isInteger(n)||(n!==0&&n<32)||n>8000)){input.setCustomValidity('Choose 0 (no video) or 32–8000 Kbps.');input.reportValidity();return;}input.setCustomValidity('');change(direction,source,n);};
    select.onchange=()=>{input.hidden=select.value!=='custom';if(!input.hidden)input.focus();else commit(select.value===''?null:Number(select.value));};input.onchange=()=>commit(Number(input.value));
    label.append(select,input);root.append(label);
  }
}

// Connection hints are optional; manual controls remain available on every browser.
export function connectionIsMetered(connection = globalThis.navigator?.connection) {
  return !!(connection && (connection.saveData || connection.metered || connection.type === 'cellular' || ['slow-2g', '2g', '3g'].includes(connection.effectiveType)));
}
export function saverLimit(mode, connection) {
  return ({off:null, auto:connectionIsMetered(connection)?128:null, low:400, verylow:128, minimal:64, none:0})[mode] ?? null;
}
export function saverCaps(caps, mode, connection) {
  const limit=saverLimit(mode,connection);
  return Object.fromEntries(['camera','screen'].map(key=>[key,limit===null?caps[key]:Math.min(caps[key]??Infinity,limit)]));
}
