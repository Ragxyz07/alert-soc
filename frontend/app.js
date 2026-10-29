const API = '';
const token = () => localStorage.getItem('soc_token');
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const seenAlertIds = new Set();
let dashboardFirstPaint = true;

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (token()) headers.Authorization = 'Bearer ' + token();
  if (options.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(API + path, {...options, headers});
  if (response.status === 401) {
    localStorage.removeItem('soc_token');
    if (!location.pathname.endsWith('login.html')) location.href = '/login.html';
    throw new Error('Please sign in');
  }
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || 'Request failed');
  return body;
}

function requireLogin() {
  if (!token() && !location.pathname.endsWith('login.html')) location.href = '/login.html';
}

function setupHeader() {
  const user = document.querySelector('#whoami');
  if (user) user.textContent = localStorage.getItem('soc_user') || 'Analyst';
  const logout = document.querySelector('#logout');
  if (logout) logout.onclick = () => { localStorage.clear(); location.href = '/login.html'; };
}

const loginForm = document.querySelector('#login-form');
if (loginForm) loginForm.onsubmit = async event => {
  event.preventDefault();
  const values = new FormData(loginForm);
  try {
    const result = await api('/login', {method:'POST', body:JSON.stringify({username:values.get('username'), password:values.get('password')})});
    localStorage.setItem('soc_token', result.token);
    localStorage.setItem('soc_user', result.username);
    location.href = '/';
  } catch (error) {
    document.querySelector('#login-error').textContent = error.message;
  }
};

function bandClass(band) { return 'band-' + String(band || 'Low'); }
function fmtDate(value) { return value ? new Date(value).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—'; }

function drawBars(canvas, entries, color) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d'), width = canvas.clientWidth, height = 180;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio; canvas.height = height * ratio; ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);
  const list = entries.slice(0, 6), max = Math.max(1, ...list.map(item => item[1]));
  const left = 95, right = 28, top = 8, gap = 27;
  ctx.font = '10px DM Sans';
  let progress = 0;
  function paint() {
    ctx.clearRect(0, 0, width, height);
    list.forEach(([name, value], index) => {
      const y = top + index * gap;
      ctx.fillStyle = '#bdcce2'; ctx.textAlign = 'right';
      ctx.fillText(name.length > 15 ? name.slice(0,14) + '…' : name, left - 10, y + 11);
      ctx.fillStyle = 'rgba(190,214,255,.10)'; ctx.fillRect(left, y, width-left-right, 12);
      ctx.fillStyle = color; const full = (width-left-right) * value / max, bar = full * progress; ctx.fillRect(left, y, bar, 12);
      if (progress >= 1) { ctx.fillStyle = '#d7e6fa'; ctx.textAlign = 'left'; ctx.fillText(value, left + bar + 6, y + 11); }
    });
    progress = Math.min(1, progress + .12);
    if (progress < 1) requestAnimationFrame(paint);
  }
  requestAnimationFrame(paint);
}

async function loadDashboard() {
  requireLogin(); setupHeader();
  async function refresh() {
    try {
      const [alerts, stats, config] = await Promise.all([api('/alerts'), api('/stats'), api('/config')]);
      const live = config.mode === 'live';
      const modeText = live ? (config.live_log_configured ? 'LIVE WINDOWS FIREWALL' : 'LIVE MODE · LOG NOT FOUND') : 'DATASET SIMULATION';
      document.querySelector('#live-mode-label').innerHTML = `<i></i> ${modeText}`;
      const simulate = document.querySelector('#simulate');
      simulate.classList.toggle('hidden', live);
      const bands = ['Critical','High','Medium','Low'];
      const colors = ['#fff0f1','#fff4e9','#fff9e5','#e9f7f2'];
      const ink = ['#bb3c4a','#b96b2a','#a47a20','#29836e'];
      const icons = ['⬆','◆','◈','✓'];
      document.querySelector('#summary').innerHTML = bands.map((band, i) =>
        `<article class="summary-card ${dashboardFirstPaint?'intro':''}" style="--card-index:${i}"><div><div class="label">${band} risk</div><div class="number">${stats.by_band[band]||0}</div></div><div class="sum-icon" style="color:${ink[i]};background:${colors[i]}">${icons[i]}</div></article>`).join('');

      let filtered = alerts;
      const risk = document.querySelector('#risk-filter').value, status = document.querySelector('#status-filter').value;
      if (risk) filtered = filtered.filter(alert => alert.risk_band === risk);
      if (status) filtered = filtered.filter(alert => alert.status === status);
      document.querySelector('#alert-rows').innerHTML = filtered.map((alert, index) => {
        const arrived = !seenAlertIds.has(alert.id);
        seenAlertIds.add(alert.id);
        return `<tr class="alert-row ${arrived?'arrive':''}" style="animation-delay:${Math.min(index,9)*38}ms"><td><a class="alert-id" href="/alert.html?id=${alert.id}">ALT-${String(alert.id).padStart(5,'0')}</a></td><td class="attack">${esc(alert.attack_type)}</td><td>${esc(alert.src_ip)}:${alert.src_port} → ${esc(alert.dst_ip)}:${alert.dst_port}</td><td class="confidence">${Math.round(alert.confidence*100)}%</td><td><span class="badge ${bandClass(alert.risk_band)}">${alert.risk_score} · ${esc(alert.risk_band)}</span></td><td><span class="badge status">${esc(alert.status)}</span></td><td>${fmtDate(alert.created_at)}</td></tr>`;
      }).join('');
      document.querySelector('#empty-state').classList.toggle('hidden', filtered.length > 0);
      drawBars(document.querySelector('#type-chart'), Object.entries(stats.by_type||{}).sort((a,b)=>b[1]-a[1]), '#80dfff');
      drawBars(document.querySelector('#band-chart'), bands.map(band=>[band,stats.by_band[band]||0]), '#71e1c5');
      dashboardFirstPaint = false;
    } catch (error) { console.error(error); }
  }
  document.querySelector('#risk-filter').onchange = refresh;
  document.querySelector('#status-filter').onchange = refresh;
  document.querySelector('#simulate').onclick = async () => {
    const kind = prompt('Attack type: DoS, PortScan, BruteForce, or WebAttack', 'DoS');
    if (!kind) return;
    try { await api('/simulate/burst', {method:'POST',body:JSON.stringify({attack_type:kind,n:5})}); await refresh(); }
    catch (error) { alert(error.message); }
  };
  await refresh(); setInterval(refresh, 5000);
}

function featureMarkup(features) {
  return (features||[]).map(feature => `<div class="feature-row"><span>${esc(feature.name)}</span><strong>${Number(feature.contribution||0).toFixed(3)}</strong></div>`).join('') || '<p class="muted">No feature details available.</p>';
}

async function loadCase() {
  requireLogin(); setupHeader();
  const id = new URLSearchParams(location.search).get('id');
  const root = document.querySelector('#case-content');
  if (!id) { root.innerHTML = '<div class="panel case-panel">No alert ID was provided.</div>'; return; }

  async function refresh() {
    const [alert, config] = await Promise.all([api('/alerts/'+encodeURIComponent(id)), api('/config')]);
    const liveAlert = alert.source === 'windows-firewall-log';
    const realBlock = config.real_blocking_available && liveAlert && config.role === 'admin';
    const hasRule = alert.history.some(event => event.action === 'block_ip' && event.details.includes('Windows Firewall'));
    const blockLabel = config.mode === 'live' ? (hasRule ? 'Already blocked' : realBlock ? 'Block IP · real' : 'Block IP unavailable') : 'Block IP · simulated';
    const blockDisabled = config.mode === 'live' && (!realBlock || hasRule);
    const actions = [['investigate','Investigate'],['block_ip',blockLabel],['isolate_host','Isolate Host'],['false_positive','False Positive'],['escalate','Escalate'],['close','Close case']];
    if (realBlock && hasRule) actions.splice(2,0,['unblock_ip','Remove firewall block']);
    const modeLabel = liveAlert ? 'REAL WINDOWS FIREWALL LOG' : 'DATASET SIMULATION';
    const responseNote = realBlock
      ? 'Block IP adds inbound and outbound rules to Windows Defender Firewall for this remote IP. This affects the whole PC.'
      : config.mode === 'live'
        ? (!config.live_log_configured ? `Live mode cannot read ${config.log_path}. Enable Windows Firewall logging and restart the app.` : config.real_blocking_enabled && config.role !== 'admin' ? 'Sign in as admin to add or remove real Windows Firewall rules.' : config.real_blocking_enabled ? 'Only live firewall alerts can be blocked. This case is not from the live log.' : 'Live log mode is on. Real blocking is off; enable it and run the app as Administrator to add firewall rules.')
        : 'These actions only update the case log. They do not change network devices.';
    root.innerHTML = `<div class="case-head"><div><div class="case-id">CASE ALT-${String(alert.id).padStart(5,'0')} · ${fmtDate(alert.created_at)}</div><h1>${esc(alert.attack_type)} alert</h1><p class="muted">${liveAlert?'Observed by the Windows Firewall log monitor':'Classified from the CIC-IDS2017 dataset'}</p></div><span class="badge ${bandClass(alert.risk_band)}">${esc(alert.risk_band)} risk</span></div><div class="case-layout"><div><section class="panel case-panel"><div class="panel-heading"><div><h2>Alert details</h2><p class="muted">${liveAlert?'Live firewall event and repeated-connection signals':'Flow attributes and model signals'}</p></div><span class="sim-label">${modeLabel}</span></div><div class="detail-grid"><div><div class="detail-label">Remote IP</div><div class="detail-value">${esc(alert.src_ip)}:${alert.src_port}</div></div><div><div class="detail-label">Local IP</div><div class="detail-value">${esc(alert.dst_ip)}:${alert.dst_port}</div></div><div><div class="detail-label">Protocol</div><div class="detail-value">${esc(alert.protocol)}</div></div><div><div class="detail-label">${liveAlert ? 'Signal confidence' : 'Classifier confidence'}</div><div class="detail-value">${(alert.confidence*100).toFixed(1)}%</div></div><div><div class="detail-label">Anomaly score</div><div class="detail-value">${Number(alert.anomaly_score).toFixed(3)}</div></div><div><div class="detail-label">Current status</div><div class="detail-value">${esc(alert.status)}</div></div></div><h2 class="section-title">${liveAlert?'Detection signals':'Top contributing features'}</h2><div class="feature-list">${featureMarkup(alert.top_features)}</div></section><section class="panel case-panel"><div class="panel-heading"><div><h2>Plain-English explanation</h2><p class="muted">On-demand analyst guidance · AI output is advisory</p></div><button id="explain" class="primary">✦ Explain this alert</button></div><div id="explanation" class="explain-box">${alert.explanation?esc(alert.explanation.text):'Select “Explain this alert” for a short summary and suggested next steps.'}</div>${alert.explanation?`<p class="muted">Source: ${esc(alert.explanation.source)}</p>`:''}</section><section class="panel case-panel"><h2>Response actions <span class="sim-label">${realBlock?'WINDOWS FIREWALL':'SIMULATED / CONFIGURATION REQUIRED'}</span></h2><p class="muted">${responseNote}</p><textarea id="note" class="note" placeholder="Optional case note…"></textarea><div class="actions">${actions.map(([value,label])=>`<button class="action-btn" data-action="${value}" ${value==='block_ip'&&blockDisabled?'disabled title="Enable real blocking in .env and restart as Administrator"':''}>${label}</button>`).join('')}</div></section></div><section class="panel case-panel"><div class="panel-heading"><div><h2>Case timeline</h2><p class="muted">Investigation history</p></div><span class="badge status">${esc(alert.status)}</span></div><div class="timeline">${alert.history.map(event=>`<div class="event"><div class="event-title">${esc(event.action)} <span class="muted">by ${esc(event.performed_by)}</span></div><div class="event-detail">${esc(event.details)}</div><div class="event-time">${fmtDate(event.created_at)}</div></div>`).join('')}</div></section></div>`;

    document.querySelector('#explain').onclick = async () => {
      const box = document.querySelector('#explanation'); box.textContent = 'Preparing explanation…';
      try { const result = await api(`/alerts/${id}/explain`, {method:'POST'}); box.textContent = result.text; await refresh(); }
      catch (error) { box.textContent = 'Explanation unavailable.'; }
    };
    document.querySelectorAll('[data-action]').forEach(button => button.onclick = async () => {
      const action = button.dataset.action;
      const prompts = {
        investigate:'Start investigation?', block_ip:realBlock?`Add real Windows Firewall rules for remote IP ${alert.src_ip}? This affects all matching traffic to and from this PC.`:`Record a simulated block for ${alert.src_ip}?`,
        unblock_ip:`Remove this app's Windows Firewall block rules for ${alert.src_ip}?`, isolate_host:`Record a simulated isolation for ${alert.dst_ip}?`,
        false_positive:'Mark this alert as a false positive?', escalate:'Escalate this case?', close:'Close this case?'
      };
      if (!confirm(prompts[action]+' Confirm to continue.')) return;
      try { await api(`/alerts/${id}/action`, {method:'POST',body:JSON.stringify({action,note:document.querySelector('#note').value})}); await refresh(); }
      catch (error) { alert(error.message); }
    });
  }
  try { await refresh(); } catch (error) { root.innerHTML = `<div class="panel case-panel">${esc(error.message)}</div>`; }
}

if (document.querySelector('#alert-rows')) loadDashboard();
if (document.querySelector('#case-content')) loadCase();
