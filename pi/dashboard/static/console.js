/* Local evidence only: never synthesize detections or replace offline data. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const text = (id, value) => { if ($(id)) $(id).textContent = value; };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const risks = {allow:'LOW',throttle:'MEDIUM',restrict:'HIGH',decoy:'CRITICAL'};
  const action = value => ({allow:'Allow',throttle:'Throttle',restrict:'Restrict',decoy:'Redirect to decoy'}[value] || value);
  const date = value => value ? new Date(Number(value)*1000).toLocaleString() : '—';
  const age = value => { const n=Math.max(0, Math.floor(Date.now()/1000-Number(value))); return n<60 ? `${n}s ago` : n<3600 ? `${Math.floor(n/60)}m ago` : `${Math.floor(n/3600)}h ago`; };
  const riskClass = value => Object.values(risks).includes(value) ? value : 'LOW';
  const score = (value, risk) => `<div class="score-meter"><span class="track"><span class="bar risk-bar ${riskClass(risk)}" style="width:${Math.min(100,Math.max(0,Number(value)||0))}%"></span></span><span>${Number(value).toFixed(1)}</span></div>`;
  const empty = (cols,message) => `<tr><td colspan="${cols}" class="empty">${esc(message)}</td></tr>`;
  const initial = id => $(id) ? JSON.parse($(id).textContent) : null;
  const get = window.soc.get;
  const intervalLabel = () => text('poll-seconds',window.socInterval()/1000);
  intervalLabel();
  const updateClock = () => text('console-clock',new Date().toLocaleTimeString()); updateClock(); setInterval(updateClock,1000);


  const samples = {};
  function renderStats(s) {
    text('tracked-clients',s.total_attackers);text('total-attackers',s.total_attackers);text('high-critical',s.high_critical);text('session-count',s.sessions);text('decoy-hits',s.decoy_hits);text('classified-events',s.classified_events);
    text('banner-high',s.high_critical);text('banner-decoy',s.decoy_sessions);text('snapshot-time',date(s.generated_at));text('risk-total',s.total_attackers);
    $('threat-banner')?.classList.toggle('elevated',s.high_critical>0);
    text('threat-label',`● THREAT LEVEL · ${s.high_critical?'ELEVATED':'NORMAL'}`);
    text('threat-description',s.high_critical?'High-risk clients detected — restrictions and decoy redirects are active.':'Monitoring MQTT traffic. No high-risk clients currently detected.');
    for(const [id,n] of Object.entries({'total-attackers':s.total_attackers,'high-critical':s.high_critical,'session-count':s.sessions,'decoy-hits':s.decoy_hits})) {
      const svg=document.querySelector(`[data-metric="${id}"]`); if(!svg) continue;
      const values=samples[id] ||= [];values.push(n);if(values.length>12)values.shift();
      const min=Math.min(...values),span=Math.max(1,Math.max(...values)-min);
      const points=values.length===1?'0,23 110,23':values.map((v,i)=>`${i*110/(values.length-1)},${23-(v-min)*20/span}`).join(' ');
      svg.querySelector('polyline').setAttribute('points',points);
    }
    if($('risk-donut')) {
      let angle=0;const stops=[];const total=s.total_attackers||1;
      $('risk-distribution').innerHTML=['LOW','MEDIUM','HIGH','CRITICAL'].map(risk=> { const n=s.risk_distribution[risk]||0;
        const end=angle+n/total*360;stops.push(`var(--${risk.toLowerCase()}) ${angle}deg ${end}deg`);angle=end;
        return `<div class="legend-row"><span class="${riskClass(risk)}"><span class="risk-dot"></span>${esc(risk)}</span><span>${n} &nbsp; ${Math.round(n/total*100)}%</span></div>`;
      }).join('');
      $('risk-donut').style.background=s.total_attackers?`conic-gradient(${stops.join(',')})`:'var(--surface-raised)';
      $('risk-donut').setAttribute('aria-label',Object.entries(s.risk_distribution).map(([k,v])=>`${k}: ${v}`).join(', '));
      const labels={'Flooding/DoS':'Flood','Brute Force':'Brute force','Reconnaissance':'Recon','MQTT Enumeration':'Enumeration','Unauthorized/Suspicious Publish':'Command spoof','Command/Protocol Abuse':'Protocol abuse'};
      const entries=Object.entries(labels).map(([name,label])=>[label,s.attack_event_distribution[name]||0]);const max=Math.max(1,...entries.map(([,n])=>n));
      const colors=['low','high','medium','low','critical','low'];
      $('attack-event-distribution').innerHTML=entries.map(([label,n],i)=>`<div class="chart-column"><b>${n}</b><div class="chart-bar" style="height:${n/max*85}%;background:var(--${colors[i]})"></div><small>${esc(label)}</small></div>`).join('');
    }
    for(const q of ['p50','p95'])text(`latency-${q}`,s.first_high_critical_latency_ms[q]===null?'—':`${s.first_high_critical_latency_ms[q].toFixed(1)} ms`);
    const device=s.device_state; $('device-led')?.classList.toggle('on',Boolean(device?.led_on));
    $('device-led')?.setAttribute('aria-label',device?`External LED ${device.led_on?'on':'off'}`:'External LED state unknown');
    text('device-lock',device?(device.locked?'LOCKED':'UNLOCKED'):'WAITING FOR DEVICE');text('device-detail',device?`LED ${device.led_on?'ON':'OFF'} · ${device.source} · ${s.device_online?'live real path':`last known state · no status for ${Math.floor(s.device_age_seconds)} s`}`:'No trusted status received yet.');
    const cloud=s.thingspeak_status;text('thingspeak-state',!s.thingspeak_enabled?'disabled':cloud?.error?`error: ${cloud.error}`:cloud?.entry_id?`stored entry ${cloud.entry_id}`:'enabled · waiting for first upload');
  }
  if(initial('initial-stats'))renderStats(initial('initial-stats'));
  window.socPoll(async()=>{intervalLabel();try {const s=await get('/api/stats');renderStats(s);text('last-updated',`Updated ${new Date(s.generated_at*1000).toLocaleTimeString()}`);}catch(_){}});

  if($('overview-events'))window.socPoll(async()=>{try{const events=await get('/api/events?limit=15');$('overview-events').innerHTML=events.map(e=>`<tr><td>${esc(new Date(e.time*1000).toLocaleTimeString())}</td><td><a href="/attacker/${encodeURIComponent(e.ip)}">${esc(e.ip)}</a></td><td><span class="type-tag">${esc(e.category||'Observation')}</span></td><td>${esc(e.signal||'session')}</td><td class="${riskClass(risks[e.action])}">+${Number(e.points).toFixed(1)}</td><td>${Number(e.score).toFixed(1)}</td><td>${esc(action(e.action))}</td></tr>`).join('')||empty(7,'No events recorded yet. Run a lab scenario to start collecting evidence.');}catch(_){}});

  Object.assign(window.soc, {text, esc, risks, action, date, age, riskClass, score, empty, initial});
})();
