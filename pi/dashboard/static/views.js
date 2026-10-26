/* Page controllers. Every visible value comes from a local evidence endpoint. */
(() => {
  'use strict';
  const {get, request, text, esc, risks, action, date, age, riskClass, score, empty, initial} = window.soc;
  const $ = id => document.getElementById(id);
  const watch = window.socPoll;
  const duration = s => s.end == null ? `${Math.max(0, Date.now()/1000-s.start).toFixed(0)} s · open` : `${Math.max(0,s.end-s.start).toFixed(1)} s`;
  const sourceLink = ip => `<a href="/attacker/${encodeURIComponent(ip)}">${esc(ip)}</a>`;
  const tags = value => String(value || '').split(',').filter(Boolean).map(t => `<span class="type-tag">${esc(t.trim())}</span>`).join('');
  const reSort = body => { const table=body.closest('table'), heading=table.querySelector('th[data-direction]'); window.soc.sortRows(table,heading,heading?.dataset.direction==='asc'); };
  const debounce = callback => { let timer; return () => { clearTimeout(timer); timer=setTimeout(callback,250); }; };
  function notify(title, message, critical = false) {
    const node=document.createElement('div');node.className='toast';
    const strong=document.createElement('strong');strong.textContent=title;
    const span=document.createElement('span');span.textContent=message;
    const close=document.createElement('button');close.className='toast-close';close.textContent='×';close.setAttribute('aria-label','Dismiss notification');close.onclick=()=>node.remove();
    node.append(close,strong,span);$('toast-stack').append(node);
    while ($('toast-stack').children.length>4) $('toast-stack').firstElementChild.remove();
    setTimeout(()=>node.remove(),critical?12000:6000);
  }
  // Downloads retain their normal links, with an actionable error if the server fails.
  document.addEventListener('click', async event => {
    const link=event.target.closest('a[href]');
    if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.button!==0) return;
    const url=new URL(link.href);
    if (url.origin!==location.origin || !['/api/events/export.csv','/api/evidence/export.zip'].includes(url.pathname)) return;
    event.preventDefault();if(link.getAttribute('aria-busy')==='true')return;
    link.setAttribute('aria-busy','true');
    try {
      const response=await request(url.href,{raw:true}), blob=await response.blob();
      const objectURL=URL.createObjectURL(blob), download=document.createElement('a');
      download.href=objectURL;download.download=url.pathname.endsWith('.csv')?'honeypot-attack-events.csv':'honeypot-evidence.zip';
      document.body.append(download);download.click();download.remove();setTimeout(()=>URL.revokeObjectURL(objectURL),10000);
    } catch(error) { notify('Export failed',error.message,true); }
    finally { link.removeAttribute('aria-busy'); }
  });
  const syncTheme = () => {
    text('theme-label',document.documentElement.dataset.theme);
    document.querySelectorAll('[data-theme-choice]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.themeChoice===document.documentElement.dataset.theme)));
  };
  $('theme-toggle').addEventListener('click',()=>window.soc.setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
  document.addEventListener('soc-theme',syncTheme);syncTheme();
  const collapse = value => {
    document.body.classList.toggle('collapsed',value);
    $('collapse-sidebar').setAttribute('aria-expanded',String(!value));
    $('collapse-sidebar').setAttribute('aria-label',value?'Expand sidebar':'Collapse sidebar');
  };
  try { collapse(localStorage.getItem('soc-collapsed')==='true'); } catch(_) {}
  $('collapse-sidebar').addEventListener('click',()=>{const value=!document.body.classList.contains('collapsed');collapse(value);try{localStorage.setItem('soc-collapsed',String(value));}catch(_){}});

  function notificationState() {
    const available='Notification' in window && window.isSecureContext;
    const permission=available?Notification.permission:'unavailable';
    const enabled=permission==='granted';
    text('desktop-alerts',enabled?'Desktop alerts: on':permission==='denied'?'Desktop alerts: blocked':available?'Desktop alerts: enable':'Desktop alerts: unavailable');
    text('notification-status',enabled?'Browser notifications are enabled.':permission==='denied'?'Notifications are blocked. Change this site’s browser permission to enable them.':available?'Enable browser notifications for new suspicious activity.':'System notifications require HTTPS or localhost. In-dashboard alerts remain available.');
  }
  async function enableNotifications() {
    try { if('Notification' in window && window.isSecureContext && Notification.permission==='default')await Notification.requestPermission(); }
    catch(error){notify('Notifications unavailable',error.message);}
    notificationState();
  }
  $('desktop-alerts').addEventListener('click',enableNotifications);
  $('enable-alerts')?.addEventListener('click',enableNotifications);notificationState();
  let cursor=null, generation=null;
  watch(async()=>{
    const params=cursor===null?'':`?${new URLSearchParams({after:String(cursor),generation:generation??''})}`;
    const data=await get(`/api/alerts${params}`);
    cursor=data.cursor;generation=data.generation;
    data.events.forEach(e=>{
      const title=`${action(e.action)} · ${e.ip}`, message=`Score ${Number(e.score).toFixed(1)} · ${e.detail}`;
      notify(title,message,true);
      if('Notification' in window && window.isSecureContext && Notification.permission==='granted') {
        try { new Notification(title,{body:message,tag:`honeypot-${generation}-${e.rowid}`}); } catch(_) {}
      }
    });
  });

  if($('attackers-body')) {
    let rows=initial('initial-attackers')||[], selectedRisk='';
    const render=()=>{
      const filtered=rows.filter(r=>r.ip.includes($('ip-filter').value.trim())&&(!selectedRisk||r.risk_level===selectedRisk)&&(!$('action-filter').value||r.current_action===$('action-filter').value));
      text('roster-count',`${filtered.length} of ${rows.length}`);
      $('attackers-body').innerHTML=filtered.map(r=>`<tr><td>${sourceLink(r.ip)}</td><td><span class="badge ${riskClass(r.risk_level)}">● ${esc(r.risk_level)}</span></td><td data-sort-value="${Number(r.current_score)}">${score(r.current_score,r.risk_level)}</td><td>${esc(action(r.current_action))}</td><td class="wrap">${tags(r.attack_types)}</td><td data-sort-value="${Number(r.attack_count)}">${Number(r.attack_count)}</td><td>${esc(r.fingerprint_label)}<div class="status-line">${esc(r.fingerprint)}</div></td><td data-sort-value="${Number(r.first_seen)}" title="${esc(date(r.first_seen))}">${age(r.first_seen)}</td><td data-sort-value="${Number(r.last_observed??r.last_seen)}" title="${esc(date(r.last_observed??r.last_seen))}">${age(r.last_observed??r.last_seen)}</td></tr>`).join('')||empty(9,rows.length?'No clients match these filters.':'No attacks recorded. Run a lab scenario to collect evidence.');
      reSort($('attackers-body'));
    };
    $('ip-filter').addEventListener('input',render);$('action-filter').addEventListener('change',render);
    document.querySelectorAll('.risk-buttons button').forEach(b=>b.addEventListener('click',()=>{selectedRisk=selectedRisk===b.dataset.risk?'':b.dataset.risk;document.querySelectorAll('.risk-buttons button').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.risk===selectedRisk)));render();}));
    render();watch(async()=>{rows=await get('/api/attackers');render();});
  }

  if($('events-body')) {
    let rows=initial('initial-events')||[], paused=false, nextBefore=null, revision=0, generation=null, busy=false;
    const category=$('category-filter');
    ['Reconnaissance','Brute Force','MQTT Enumeration','Unauthorized/Suspicious Publish','Command/Protocol Abuse','Flooding/DoS'].forEach(c=>{const o=document.createElement('option');o.value=c;o.textContent=c;category.append(o);});
    function parameters() {
      const p=new URLSearchParams();
      for(const [id,key] of [['ip-filter','ip'],['category-filter','category'],['action-filter','action'],['risk-filter','risk']])if($(id).value.trim())p.set(key,$(id).value.trim());
      if(Number($('time-filter').value))p.set('since',String(Date.now()/1000-Number($('time-filter').value)));
      return p;
    }
    const render=()=>{
      text('visible-count',rows.length);
      $('events-body').innerHTML=rows.map(r=>`<tr><td>${esc(date(r.time))}</td><td>${sourceLink(r.ip)}</td><td><span class="type-tag">${esc(r.category||'Observation')}</span></td><td>${esc(r.signal||'—')}</td><td class="${riskClass(risks[r.action])}">+${Number(r.points).toFixed(1)}</td><td>${score(r.score,risks[r.action])}</td><td>${esc(action(r.action))}</td><td class="wrap">${esc(r.detail)}</td></tr>`).join('')||empty(8,'No matching events. Change the filters or run a lab scenario.');
    };
    async function load(older=false) {
      if(older&&busy)return;
      const token=++revision, p=parameters();
      p.set('limit',String(older?100:Math.max(100,Math.min(500,rows.length))));
      if(older&&nextBefore)p.set('before',String(nextBefore));
      busy=true;$('load-more-events').disabled=true;text('event-load-status','Updating evidence…');
      try {
        const data=await get(`/api/event-feed?${p}`);
        if(token!==revision)return;
        if(older&&generation!==data.generation){rows=[];nextBefore=null;generation=data.generation;await load();return;}
        generation=data.generation;rows=older?[...rows,...data.events]:data.events;
        nextBefore=data.next_before;text('matching-count',data.total);
        $('load-more-events').hidden=!data.has_more;
        $('filtered-export').href=`/api/events/export.csv?${parameters()}`;
        text('event-load-status',paused?'Live stream paused. Filters and older evidence remain available.':'');render();
      } catch(error) { if(token===revision)text('event-load-status',`Update failed: ${error.message}`);throw error; }
      finally {if(token===revision){busy=false;$('load-more-events').disabled=false;}}
    }
    ['ip-filter','category-filter','action-filter','risk-filter','time-filter'].forEach(id=>$(id).addEventListener(id==='ip-filter'?'input':'change',debounce(()=>{rows=[];nextBefore=null;load().catch(()=>{});} )));
    $('pause-stream').addEventListener('click',()=>{paused=!paused;text('pause-stream',paused?'▶ Resume stream':'Ⅱ Pause stream');text('stream-state',paused?'paused':'streaming');text('stream-indicator',paused?'Ⅱ paused':'● live');$('pause-stream').setAttribute('aria-pressed',String(paused));if(!paused)load().catch(()=>{});});
    $('load-more-events').addEventListener('click',()=>{paused=true;text('pause-stream','▶ Resume stream');text('stream-state','paused');text('stream-indicator','Ⅱ paused');$('pause-stream').setAttribute('aria-pressed','true');load(true).catch(()=>{});});
    $('clear-logs').addEventListener('click',async()=>{
      if(!confirm('Clear all recorded events, sessions, attackers, decoy messages, alert logs, and live risk scores? Export evidence first. Trusted device state will be kept.'))return;
      const button=$('clear-logs');button.disabled=true;
      try { await request('/api/logs/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:'clear'})});revision++;rows=[];nextBefore=null;cursor=null;generation=null;render();await load();window.soc.refresh();notify('Evidence cleared','Live proxy scores reset when the proxy processes the request.'); }
      catch(error){notify('Clear failed',error.message,true);}finally{button.disabled=false;}
    });
    render();watch(()=>paused?Promise.resolve():load());
  }

  function sessionRows(rows,profiles={}) {
    return rows.map(s=>`<tr><td>${sourceLink(s.ip)}</td><td><span class="badge ${s.backend==='decoy'?'CRITICAL':'LOW'}">${esc(s.backend)}</span></td><td>${esc(profiles[s.profile]?.device_name||s.profile||'—')}</td><td data-sort-value="${Number(s.start)}">${esc(date(s.start))}</td><td data-sort-value="${Number(s.end)||0}">${s.end==null?'—':esc(date(s.end))}</td><td data-sort-value="${(s.end??Date.now()/1000)-s.start}">${duration(s)}</td></tr>`).join('')||empty(6,'No sessions recorded for these filters.');
  }
  if($('session-ledger')) {
    let revision=0;
    const render=rows=>{text('session-ledger-count',rows.length);$('session-ledger').innerHTML=sessionRows(rows);reSort($('session-ledger'));};
    render(initial('initial-sessions')||[]);
    const load=async()=>{const token=++revision,p=new URLSearchParams({limit:'500'});if($('session-ip-filter').value.trim())p.set('ip',$('session-ip-filter').value.trim());if($('backend-filter').value)p.set('backend',$('backend-filter').value);const rows=await get(`/api/sessions?${p}`);if(token===revision)render(rows);};
    $('session-ip-filter').addEventListener('input',debounce(()=>load().catch(()=>{})));$('backend-filter').addEventListener('change',()=>load().catch(()=>{}));watch(load);
  }
  if($('decoy-sessions')) {
    const render=d=>{
      const real=d.routing.real||0,decoy=d.routing.decoy||0,total=real+decoy;
      for(const [name,n] of [['real',real],['decoy',decoy]]){text(`${name}-routing-count`,n);text(`${name}-routing-percent`,`${total?Math.round(n/total*100):0}% of ${total} sessions`);$(`${name}-routing-bar`).style.width=`${total?n/total*100:0}%`;}
      $('decoy-sessions').innerHTML=sessionRows(d.sessions,d.profiles);
      $('decoy-feed').innerHTML=d.messages.map(m=>`<p><time>${esc(date(m.time))}</time> &nbsp; ${esc(m.ip)} → ${esc(m.topic)} &nbsp; ${esc(m.payload)}</p>`).join('')||'<p>No decoy messages recorded. Critical-risk clients reconnect to the decoy.</p>';
    };
    render(initial('initial-honeypot'));watch(async()=>render(await get('/api/honeypot')));
  }

  if($('detail-timeline')) {
    const first=initial('initial-attacker'), ip=first.ip, path=`/api/attacker/${encodeURIComponent(ip)}`;
    function render(a) {
      text('detail-risk',`${a.risk_level} · ${Number(a.current_score).toFixed(1)}`);$('detail-risk').className=riskClass(a.risk_level);
      text('detail-action',action(a.current_action));$('detail-action').className=riskClass(risks[a.current_action]);text('detail-count',a.attack_count);text('detail-highest',Number(a.highest_risk).toFixed(1));text('detail-label',a.fingerprint_label);text('detail-fingerprint',a.fingerprint);text('detail-types',a.attack_types||'—');text('detail-observed',`${date(a.first_seen)} → ${date(a.last_observed??a.last_seen)}`);
      $('detail-timeline').innerHTML=[...a.timeline].reverse().map(e=>`<tr><td>${esc(date(e.time))}</td><td>${esc(e.category||'Observation')}</td><td>${esc(e.signal||'—')}</td><td>+${Number(e.points).toFixed(1)}</td><td>${Number(e.score).toFixed(1)}</td><td>${esc(action(e.action))}</td><td class="wrap">${esc(e.detail)}</td></tr>`).join('')||empty(7,'No events for this source.');
      $('detail-sessions').innerHTML=[...a.sessions].reverse().map(s=>`<tr><td>${esc(s.backend)}</td><td>${esc(s.profile||'—')}</td><td>${esc(date(s.start))}</td><td>${esc(date(s.end))}</td><td>${duration(s)}</td></tr>`).join('')||empty(5,'No sessions recorded.');
      $('detail-similar').innerHTML=a.similar_attackers.map(r=>`<tr><td>${sourceLink(r.ip)}</td><td>${esc(r.fingerprint_label)}</td><td>${Number(r.highest_risk).toFixed(1)}</td></tr>`).join('')||empty(3,'No other sources share this fingerprint.');
      $('detail-messages').innerHTML=[...a.decoy_messages].reverse().map(m=>`<tr><td>${esc(date(m.time))}</td><td>${esc(m.topic)}</td><td class="wrap">${esc(m.payload)}</td></tr>`).join('')||empty(3,'No decoy messages recorded.');
    }
    render(first);
    watch(async()=>{
      try {
        const a=await get(`${path}?limit=100`);render(a);text('detail-status','Live evidence · newest 100 records per section');
        const group=await get(`/api/fingerprint/${encodeURIComponent(a.fingerprint_label)}`);
        $('detail-group').innerHTML=group.filter(r=>r.ip!==ip).map(r=>`<span class="type-tag">${sourceLink(r.ip)}</span>`).join('')||'<span class="muted">No other sources share this behavior label.</span>';
      }catch(error){if(error.status===404){text('detail-status','This source was cleared. Return to Attackers to see current records.');window.soc.forget(path);}throw error;}
    });
  }
  if($('alerts-body')) {
    const render=rows=>{
      text('alert-count',rows.length);
      $('alerts-body').innerHTML=rows.map(e=>`<tr><td>${esc(date(e.time))}</td><td>${sourceLink(e.ip)}</td><td><span class="badge ${riskClass(risks[e.action])}">${esc(risks[e.action]||'—')}</span></td><td>${esc(e.category||'Observation')}</td><td>${esc(e.signal||'—')}</td><td>${score(e.score,risks[e.action])}</td><td>${esc(action(e.action))}</td><td class="wrap">${esc(e.detail)}</td></tr>`).join('')||empty(8,'No recorded events have crossed the alert threshold.');
    };
    render(initial('initial-alerts')||[]);watch(async()=>render(await get('/api/alerts/history?limit=100')));
    watch(async()=>{const h=await get('/api/health');text('alert-threshold',`Configured alert threshold: ${action(h.alert_min_action)} and above`);});
  }
  if($('policy-content')) {
    watch(async()=>{
      const payload=await get('/api/policy'), c=payload.config;
      const tiers=[
        ['LOW',`Below ${c.MEDIUM}`,'Allow','Normal authenticated session on the real broker.','Behavioral inspection remains active.'],
        ['MEDIUM',`${c.MEDIUM} to below ${c.HIGH}`,'Throttle',`Connection delay: ${c.THROTTLE_DELAY_SEC} s.`,`Per-packet delay: ${c.THROTTLE_PACKET_DELAY_SEC} s.`],
        ['HIGH',`${c.HIGH} to below ${c.CRITICAL}`,'Restrict','Broad wildcard subscriptions are withheld.','Command publishes to home/door/lock are withheld.'],
        ['CRITICAL',`${c.CRITICAL}+`,'Redirect to decoy','Current connections are closed.','Reconnecting clients receive decoy state; publishes are recorded.']
      ];
      $('policy-content').innerHTML=`<section class="panel"><header class="panel-heading"><div><h2>Response tiers</h2><p>Configured policy · restart the proxy after editing config.env to apply changes</p></div></header><div class="policy-tiers">${tiers.map(([risk,range,label,first,second])=>`<article class="tier ${risk}"><div class="mono">${esc(range)}</div><h3>${risk} · ${esc(label)}</h3><p>${esc(first)}</p><ul><li>${esc(second)}</li></ul></article>`).join('')}</div></section><div class="grid decoy-grid"><section class="panel"><header class="panel-heading"><div><h2>Scoring signals</h2><p>Configured points for each behavioral signal</p></div></header><div class="table-wrap"><table><thead><tr><th>Signal</th><th>Weight</th><th>Description</th></tr></thead><tbody>${payload.signals.map(([signal,key,description])=>`<tr><td>${esc(signal)}</td><td class="HIGH">+${esc(c[key])}</td><td class="wrap">${esc(description)}</td></tr>`).join('')}</tbody></table></div></section><section class="panel"><header class="panel-heading"><div><h2>How scoring works</h2><p>Behavioral model overview</p></div></header><div class="detail-description"><p><strong>Additive signals.</strong> Configured weights accumulate per source. Scores are not globally capped at 100.</p><p><strong>Passive decay.</strong> Scores decrease by ${esc(c.DECAY_POINTS_PER_SEC)} points per second.</p><p><strong>Rolling windows.</strong> More than ${esc(c.CONNECTION_LIMIT)} connections in ${esc(c.CONNECTION_WINDOW_SEC)} s or ${esc(c.PUBLISH_LIMIT)} publishes in ${esc(c.PUBLISH_WINDOW_SEC)} s triggers a rate signal.</p><p><strong>Enumeration.</strong> More than ${esc(c.TOPIC_ENUMERATION_LIMIT)} unique topic filters triggers enumeration.</p><p><strong>Caps.</strong> Failed-auth points: ${esc(c.FAILED_AUTH_CAP)}. Short-session points: ${esc(c.SHORT_SESSION_CAP)} per proxy lifetime.</p><p><strong>Trusted clients.</strong> Ordinary scoring is ignored; malformed packets and blacklist matches can raise risk up to ${esc(c.WHITELIST_MAX_ANOMALY_SCORE)}.</p><p><strong>Fingerprints.</strong> Shared behavior helps correlate sources. It does not prove identity or transfer risk.</p></div></section></div>`;
    });
  }
  if($('api-base')) {
    $('api-base').value=location.origin;
    const interval=$('refresh-interval');interval.value=String(window.socInterval()/1000);
    interval.addEventListener('change',()=>{
      try{localStorage.setItem('soc-interval',interval.value);text('preferences-status','Refresh interval saved.');document.dispatchEvent(new Event('soc-preferences'));}
      catch(_){text('preferences-status','Browser storage is unavailable. Preferences cannot be saved.');}
    });
    document.querySelectorAll('[data-theme-choice]').forEach(b=>b.addEventListener('click',()=>window.soc.setTheme(b.dataset.themeChoice)));
    $('restore-preferences').addEventListener('click',()=>{
      try{localStorage.removeItem('soc-interval');}catch(_){}
      window.soc.setTheme('light');interval.value='3';text('preferences-status','Default appearance and interval restored.');document.dispatchEvent(new Event('soc-preferences'));
    });
    watch(async()=>{
      const h=await get('/api/health');
      $('health-summary').innerHTML=`<div><span class="eyebrow">Dashboard API</span><strong class="LOW">Online</strong></div><div><span class="eyebrow">Evidence database</span><strong class="LOW">Connected</strong></div><div><span class="eyebrow">Latest event</span><strong style="font-size:14px">${h.latest_event?esc(date(h.latest_event)):'No events yet'}</strong></div>`;
    });
    $('test-connection').addEventListener('click',async()=>{
      const button=$('test-connection');button.disabled=true;text('connection-result','Checking data endpoints…');text('endpoint-test-status','Running endpoint checks…');$('endpoint-tests').replaceChildren();
      const endpoints=['/api/health','/api/stats','/api/attackers','/api/events?limit=1','/api/event-feed?limit=1','/api/sessions?limit=1','/api/honeypot','/api/policy','/api/alerts','/api/alerts/history?limit=1'];
      try{
        const sources=await get('/api/attackers');
        if(sources.length){const a=sources[0],ip=encodeURIComponent(a.ip);endpoints.push(`/api/attacker/${ip}?limit=1`,`/api/risk/${ip}`,`/api/fingerprint/${encodeURIComponent(a.fingerprint_label)}`);}
      }catch(_){}
      const results=await Promise.all(endpoints.map(async endpoint=>{
        const start=performance.now();try{await get(endpoint);return {endpoint,ok:true,ms:performance.now()-start};}catch(error){return {endpoint,ok:false,error:error.message,ms:performance.now()-start};}
      }));
      $('endpoint-tests').innerHTML=results.map(r=>`<tr><td>${esc(r.endpoint)}</td><td class="${r.ok?'LOW':'CRITICAL'}">${r.ok?'Connected':esc(r.error)}</td><td>${r.ms.toFixed(0)} ms</td></tr>`).join('');
      const failed=results.filter(r=>!r.ok).length;
      text('connection-result',failed?`${failed} endpoint checks failed. See Connection health below.`:`Connected · all ${results.length} endpoint checks passed.`);
      text('endpoint-test-status',`${results.length-failed} of ${results.length} passed. ${endpoints.length===10?'Source-specific checks require a recorded attacker.':''} API health does not confirm that MQTT services are running.`);
      button.disabled=false;
    });
  }
})();
