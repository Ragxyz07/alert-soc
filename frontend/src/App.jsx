import React, { Suspense, lazy, useCallback, useEffect, useRef, useState } from 'react';
const DashboardCharts = lazy(() => import('./DashboardCharts.jsx'));

const API = '';
const TOKEN_KEY = 'soc_token';
const SEVERITY = {
  Critical: { color: '#e0231c', badge: 'risk-badge-critical' },
  High: { color: '#ff5a3c', badge: 'risk-badge-high' },
  Medium: { color: '#c9a24a', badge: 'risk-badge-medium' },
  Low: { color: '#7fa99b', badge: 'risk-badge-low' },
};

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${API}${path}`, { ...options, headers });
  if (response.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem('soc_user');
    if (!location.pathname.endsWith('login.html')) location.href = '/login.html';
    throw new Error('Please sign in again.');
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || 'The request could not be completed.');
  return body;
}

function Icon({ name, size = 17, className = '' }) {
  const shared = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round', className, 'aria-hidden': true };
  const paths = {
    mark: <><path d="M4 20 12 4l8 16"/><path d="M7 14h10M9 10h6"/></>,
    grid: <><rect x="3.5" y="3.5" width="7" height="7"/><rect x="13.5" y="3.5" width="7" height="7"/><rect x="3.5" y="13.5" width="7" height="7"/><rect x="13.5" y="13.5" width="7" height="7"/></>,
    pulse: <><path d="M3 12h4l2.3-6 4.4 12 2.3-6H21"/></>,
    nodes: <><circle cx="12" cy="12" r="2.5"/><circle cx="5" cy="5" r="1.5"/><circle cx="19" cy="5" r="1.5"/><circle cx="5" cy="19" r="1.5"/><circle cx="19" cy="19" r="1.5"/><path d="m10.2 10.2-4-4m7.6 4 4-4m-7.6 7.6-4 4m7.6-4 4 4"/></>,
    log: <><path d="M5 4.5h14M5 9.5h14M5 14.5h9M5 19.5h14"/><circle cx="18" cy="14.5" r="2"/></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9A7 7 0 0 1 18 6l2 2M4 16l2 2a7 7 0 0 0 12.4-3"/></>,
    shield: <><path d="M12 3 20 6v5c0 5-3.4 8.1-8 10-4.6-1.9-8-5-8-10V6l8-3Z"/><path d="m9 12 2 2 4-4"/></>,
    exit: <><path d="M10 17l5-5-5-5M15 12H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    chevron: <path d="m8 10 4 4 4-4"/>,
  };
  return <svg {...shared}>{paths[name] || paths.mark}</svg>;
}

function Brand({ compact = false }) {
  return <a href="/" className="flex items-center gap-3 text-bone no-underline" aria-label="Kage Security Operations home">
    <span className="grid h-9 w-9 place-items-center border border-line bg-white/[.025] text-bone-dim"><Icon name="mark" size={21}/></span>
    {!compact && <span><span className="block text-[12px] font-medium tracking-[.22em]">KAGE</span><span className="mt-1 block text-[9px] tracking-[.2em] text-muted">SECURITY OPERATIONS</span></span>}
  </a>;
}

function RiskBadge({ value, pulse = false }) {
  const tone = SEVERITY[value] || SEVERITY.Low;
  return <span className={`risk-badge ${tone.badge}${value === 'Critical' && pulse ? ' is-pulsing' : ''}`}><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tone.color }} />{value || 'Low'}</span>;
}

function formatDate(value, withSeconds = false) {
  if (!value) return '—';
  const options = withSeconds
    ? { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }
    : { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' };
  return new Date(value).toLocaleString([], options);
}

function useRequireLogin() {
  useEffect(() => {
    if (!localStorage.getItem(TOKEN_KEY)) location.replace('/login.html');
  }, []);
  return Boolean(localStorage.getItem(TOKEN_KEY));
}

function Header({ mode, username }) {
  return <header className="sticky top-0 z-10 border-b border-line-soft bg-ink/90 backdrop-blur-xl">
    <div className="mx-auto flex h-[68px] max-w-[1500px] items-center justify-between px-5 sm:px-8 xl:px-12">
      <div className="flex items-center gap-5"><Brand compact/><span className="hidden h-7 w-px bg-line md:block"/><span className="hidden text-[10px] uppercase tracking-[.18em] text-bone-dim md:block">Northstar Manufacturing <span className="mx-2 text-muted">/</span> SOC floor</span></div>
      <div className="flex items-center gap-4 sm:gap-6">
        <span className="inline-flex items-center gap-2 text-[9px] font-medium uppercase tracking-[.16em] text-bone-dim"><i className={`h-1.5 w-1.5 rounded-full ${mode === 'live' ? 'bg-sage shadow-[0_0_9px_#7fa99b]' : 'bg-ember shadow-[0_0_9px_#ff5a3c]'}`} />{mode === 'live' ? 'Firewall monitor' : 'Isolated simulation'}</span>
        <span className="hidden border-l border-line-soft pl-5 text-[10px] uppercase tracking-[.14em] text-muted sm:block">{username || 'Analyst'}</span>
        <button className="icon-button" onClick={() => { localStorage.clear(); location.href = '/login.html'; }} aria-label="Sign out"><Icon name="exit"/></button>
      </div>
    </div>
  </header>;
}

function Sidebar({ active = 'overview' }) {
  const items = [
    { key: 'overview', name: 'Overview', icon: 'grid', href: '/' },
    { key: 'alerts', name: 'Alert queue', icon: 'pulse', href: '#alert-queue' },
    { key: 'assets', name: 'Asset inventory', icon: 'nodes', href: '#asset-inventory' },
    { key: 'audit', name: 'Security log', icon: 'log', href: '#security-log' },
  ];
  return <aside className="hidden w-[228px] shrink-0 border-r border-line-soft px-5 py-8 lg:block">
    <div className="mb-9"><p className="eyebrow mb-3">Workspace</p><div className="border border-line-soft bg-white/[.02] p-3"><p className="text-[11px] font-normal text-bone">Northstar Manufacturing</p><p className="mt-2 text-[9px] uppercase tracking-[.14em] text-muted">Training environment</p></div></div>
    <p className="eyebrow mb-3 px-2">Operations</p>
    <nav className="space-y-1" aria-label="Dashboard sections">{items.map(item => <a key={item.key} href={item.href} className={`nav-link ${active === item.key ? 'nav-link-active' : ''}`}><Icon name={item.icon} size={16}/><span>{item.name}</span></a>)}</nav>
    <div className="mt-12 border-t border-line-soft pt-5"><p className="eyebrow mb-3">Environment</p><div className="flex items-center gap-2 px-2 text-[10px] text-sage"><span className="h-1.5 w-1.5 rounded-full bg-sage"/>Synthetic telemetry only</div></div>
  </aside>;
}

function SummaryCard({ label, value, note, tone = 'bone', delay = 0 }) {
  const colors = { red: 'text-[#ff7770]', ember: 'text-[#ff9a83]', gold: 'text-[#e6c56f]', sage: 'text-[#a4d2c2]', bone: 'text-bone' };
  return <article className="glass-panel section-enter min-h-[116px] p-4 sm:p-5" style={{ '--enter-delay': `${delay}ms` }}>
    <p className="data-label">{label}</p><p className={`mt-4 text-[28px] font-light leading-none ${colors[tone]}`}>{value}</p><p className="mt-3 text-[10px] text-muted">{note}</p>
  </article>;
}

function AssetCard({ asset, delay }) {
  const crit = asset.criticality === 'Critical' ? 'text-[#ff7770]' : asset.criticality === 'High' ? 'text-[#ff9a83]' : 'text-sage';
  return <article className="glass-panel section-enter p-4" style={{ '--enter-delay': `${delay}ms` }}>
    <div className="flex items-start justify-between gap-3"><div><p className="text-[9px] font-medium tracking-[.17em] text-bone-dim">{asset.id}</p><h3 className="mt-3 text-[13px] leading-tight text-bone">{asset.name}</h3></div><span className={`pt-0.5 text-[9px] uppercase tracking-[.13em] ${crit}`}>{asset.criticality}</span></div>
    <div className="mt-4 flex items-center justify-between gap-2 border-t border-line-soft pt-3 text-[9px] text-muted"><span>{asset.ip}</span><span className="truncate text-right">{asset.zone}</span></div>
  </article>;
}

function Dashboard() {
  const authenticated = useRequireLogin();
  const [data, setData] = useState({ alerts: [], stats: null, config: { mode: 'simulation' }, organization: null });
  const [loading, setLoading] = useState(true);
  const [scenario, setScenario] = useState('port_scan');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [error, setError] = useState('');
  const username = localStorage.getItem('soc_user') || 'Analyst';

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const [alerts, stats, config, organization] = await Promise.all([api('/alerts'), api('/stats'), api('/config'), api('/organization')]);
      setData({ alerts, stats, config, organization });
      setError('');
    } catch (cause) { setError(cause.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    if (!authenticated) return undefined;
    refresh();
    const timer = window.setInterval(() => refresh(true), 5000);
    return () => window.clearInterval(timer);
  }, [authenticated, refresh]);

  const runDrill = async () => {
    setBusy(true);
    setMessage('Generating isolated training events…');
    try {
      const result = await api('/organization/drill', { method: 'POST', body: JSON.stringify({ scenario }) });
      setMessage(`${result.created_events} synthetic events recorded · case ALT-${String(result.alert_id).padStart(5, '0')}`);
      await refresh(true);
    } catch (cause) { setMessage(cause.message); }
    finally { setBusy(false); }
  };

  if (!authenticated) return null;
  const organization = data.organization;
  const alerts = data.alerts || [];
  const events = organization?.recent_events || [];
  const filteredAlerts = alerts.filter(alert => (!riskFilter || alert.risk_band === riskFilter) && (!statusFilter || alert.status === statusFilter));
  const criticalCount = alerts.filter(alert => alert.risk_band === 'Critical' && !['Closed', 'False Positive'].includes(alert.status)).length;
  const openCount = alerts.filter(alert => !['Closed', 'False Positive'].includes(alert.status)).length;

  return <div className="min-h-screen">
    <Header mode={data.config?.mode} username={username}/>
    <div className="mx-auto flex min-h-[calc(100vh-68px)] max-w-[1500px]">
      <Sidebar/>
      <main className="min-w-0 flex-1 px-4 py-7 sm:px-7 sm:py-9 xl:px-10">
        <div className="mx-auto max-w-[1240px]">
          <section className="section-enter mb-7 flex flex-col justify-between gap-5 md:flex-row md:items-end" style={{ '--enter-delay': '0ms' }}>
            <div><p className="eyebrow mb-3 flex items-center gap-2"><span className="h-px w-7 bg-vermilion"/>Security observability <span className="text-muted">/</span> Northstar network</p><h1 className="max-w-3xl text-[27px] tracking-[.055em] sm:text-[34px]">Threat<br className="hidden sm:block"/> observability</h1><p className="mt-3 max-w-xl text-[12px] leading-6 text-bone-dim">A contained manufacturing network exercise. Every signal below is synthetic and kept in this local training environment.</p></div>
            <div className="flex flex-wrap items-center gap-2"><span className="mr-2 text-[9px] uppercase tracking-[.16em] text-muted">No live devices connected</span><button onClick={() => refresh()} className="control-button inline-flex items-center gap-2 px-3 text-[10px] uppercase tracking-[.12em]" aria-label="Refresh dashboard"><Icon name="refresh" size={15}/>Refresh</button></div>
          </section>

          {error && <div role="alert" className="mb-5 border border-ember/40 bg-ember/5 px-4 py-3 text-[11px] text-[#ff9a83]">{error}</div>}

          <section className="mb-7 grid grid-cols-2 gap-3 xl:grid-cols-4 xl:gap-4" aria-label="Security overview">
            <SummaryCard label="Critical open" value={criticalCount} note="Needs analyst review" tone="red" delay={65}/>
            <SummaryCard label="Open cases" value={openCount} note="Excludes closed and false positives" tone="ember" delay={135}/>
            <SummaryCard label="Network assets" value={organization?.assets?.length ?? '—'} note="Fictional company inventory" tone="gold" delay={205}/>
            <SummaryCard label="Recent event rows" value={events.length} note="Most recent local log entries" tone="sage" delay={275}/>
          </section>

          <section id="asset-inventory" className="mb-7 grid gap-6 xl:grid-cols-[1.18fr_.82fr]">
            <div className="glass-panel section-enter p-4 sm:p-5" style={{ '--enter-delay': '320ms' }}>
              <div className="mb-5 flex flex-wrap items-end justify-between gap-3"><div><p className="eyebrow mb-2">01 / Organization network</p><h2 className="text-[17px] tracking-[.09em]">{organization?.name || 'Northstar Manufacturing'}</h2><p className="mt-2 text-[10px] text-muted">{organization?.sector || 'Industrial manufacturing'} · fictional training network</p></div><span className="border border-line-soft px-2 py-1 text-[9px] uppercase tracking-[.15em] text-sage">Inventory only</span></div>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">{(organization?.assets || []).map((asset, index) => <AssetCard key={asset.id} asset={asset} delay={365 + index * 70}/>)}</div>
            </div>

            <div className="glass-panel section-enter flex flex-col p-4 sm:p-5" style={{ '--enter-delay': '390ms' }}>
              <div><p className="eyebrow mb-2">02 / Controlled exercise</p><h2 className="text-[17px] tracking-[.09em]">Run a security drill</h2><p className="mt-2 max-w-md text-[11px] leading-5 text-muted">Generate fictional network activity, correlate the signals, and create an incident for analyst practice.</p></div>
              <label htmlFor="scenario" className="data-label mt-7">Scenario</label>
              <div className="mt-2 flex flex-col gap-2 sm:flex-row"><div className="relative min-w-0 flex-1"><select id="scenario" value={scenario} onChange={event => setScenario(event.target.value)} className="h-[44px] w-full appearance-none border border-line bg-ink-2 px-3 pr-9 text-[11px] text-bone focus:border-bone/40">
                {(organization?.scenarios || []).map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
              </select><Icon name="chevron" size={15} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted"/></div><button onClick={runDrill} disabled={busy || !organization?.scenarios?.length} className="control-button control-button-primary inline-flex h-[44px] shrink-0 items-center justify-center gap-2 px-4 text-[10px] font-medium uppercase tracking-[.14em]"><Icon name="pulse" size={15}/>{busy ? 'Generating…' : 'Run drill'}</button></div>
              <p aria-live="polite" className="mt-4 min-h-9 border-l border-vermilion/60 pl-3 text-[10px] leading-5 text-bone-dim">{message || organization?.scenarios?.find(item => item.id === scenario)?.summary || 'Synthetic activity stays inside the demo.'}</p>
              <div className="mt-auto flex items-center gap-2 border-t border-line-soft pt-4 text-[9px] uppercase tracking-[.12em] text-muted"><Icon name="shield" size={14} className="text-sage"/>No packets sent · no devices changed</div>
            </div>
          </section>

          <section id="security-log" className="glass-panel section-enter mb-7 overflow-hidden" style={{ '--enter-delay': '460ms' }}>
            <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line-soft px-4 py-4 sm:px-5"><div><p className="eyebrow mb-2">03 / Local persistence</p><h2 className="text-[16px] tracking-[.08em]">Security event log</h2><p className="mt-2 text-[10px] text-muted">Saved to the local database · dashboard refreshes every 5 seconds</p></div><span className="inline-flex items-center gap-2 text-[9px] uppercase tracking-[.14em] text-bone-dim"><span className="h-1.5 w-1.5 rounded-full bg-sage"/>Demo telemetry</span></div>
            <div className="thin-scrollbar max-h-[360px] overflow-auto"><table className="w-full min-w-[700px] text-left"><thead className="sticky top-0 z-[1] bg-ink-2/95 text-[9px] uppercase tracking-[.15em] text-muted"><tr><th className="px-4 py-3 font-normal sm:px-5">Timestamp</th><th className="px-4 py-3 font-normal">Event signal</th><th className="px-4 py-3 font-normal">Asset / endpoint</th><th className="px-4 py-3 font-normal">Remote</th><th className="px-4 py-3 font-normal">Outcome</th><th className="px-4 py-3 font-normal">Case</th></tr></thead>
              <tbody>{events.map(event => <tr className="table-row" key={event.id}><td className="whitespace-nowrap px-4 py-3 text-[10px] text-bone-dim sm:px-5">{formatDate(event.created_at, true)}</td><td className="px-4 py-3"><span className="block text-[11px] text-bone">{event.event_type}</span><span className="mt-1 block max-w-[230px] text-[10px] leading-4 text-muted">{event.details}</span></td><td className="px-4 py-3"><span className="block text-[10px] text-bone">{event.asset_id}</span><span className="mt-1 block text-[10px] text-muted">{event.destination_ip}:{event.destination_port}</span></td><td className="px-4 py-3 font-mono text-[10px] text-bone-dim">{event.source_ip}</td><td className="px-4 py-3 text-[10px] text-bone-dim">{event.outcome}</td><td className="px-4 py-3"><a className="text-[10px] text-bone-dim underline decoration-line underline-offset-4 transition-colors hover:text-bone" href={`/alert.html?id=${event.alert_id}`}>ALT-{String(event.alert_id).padStart(5, '0')}</a></td></tr>)}</tbody></table>
              {events.length === 0 && <EmptyState>{loading ? 'Loading local events…' : 'No events yet. Choose a scenario above to create the first synthetic incident.'}</EmptyState>}
            </div>
          </section>

          <Suspense fallback={<section className="mb-7 grid h-56 place-items-center border border-line-soft text-[10px] uppercase tracking-[.16em] text-muted">Loading visualizations…</section>}><DashboardCharts stats={data.stats}/></Suspense>

          <section id="alert-queue" className="glass-panel section-enter overflow-hidden" style={{ '--enter-delay': '650ms' }}>
            <div className="flex flex-col gap-4 border-b border-line-soft px-4 py-4 sm:flex-row sm:items-end sm:justify-between sm:px-5"><div><p className="eyebrow mb-2">04 / Analyst workbench</p><h2 className="text-[16px] tracking-[.08em]">Alert queue</h2><p className="mt-2 text-[10px] text-muted">Risk ranked · updates every five seconds</p></div><div className="flex gap-2"><label className="sr-only" htmlFor="risk-filter">Filter by risk</label><select id="risk-filter" value={riskFilter} onChange={event => setRiskFilter(event.target.value)} className="h-9 border border-line bg-ink-2 px-3 text-[10px] text-bone"><option value="">All priorities</option>{Object.keys(SEVERITY).map(band => <option key={band}>{band}</option>)}</select><label className="sr-only" htmlFor="status-filter">Filter by case status</label><select id="status-filter" value={statusFilter} onChange={event => setStatusFilter(event.target.value)} className="h-9 border border-line bg-ink-2 px-3 text-[10px] text-bone"><option value="">All statuses</option>{['New','Investigating','Contained','False Positive','Escalated','Closed'].map(status => <option key={status}>{status}</option>)}</select></div></div>
            <div className="thin-scrollbar overflow-x-auto"><table className="w-full min-w-[800px] text-left"><thead className="bg-white/[.018] text-[9px] uppercase tracking-[.15em] text-muted"><tr><th className="px-4 py-3 font-normal sm:px-5">Case</th><th className="px-4 py-3 font-normal">Classification</th><th className="px-4 py-3 font-normal">Source → destination</th><th className="px-4 py-3 font-normal">Signal</th><th className="px-4 py-3 font-normal">Priority</th><th className="px-4 py-3 font-normal">Status</th><th className="px-4 py-3 font-normal">Created</th></tr></thead><tbody>{filteredAlerts.map((alert, index) => <tr key={alert.id} className={`table-row ${alert.risk_band === 'Critical' ? 'critical-edge' : ''}`}><td className="px-4 py-3 sm:px-5"><a href={`/alert.html?id=${alert.id}`} className="text-[10px] font-medium tracking-[.08em] text-bone underline decoration-line underline-offset-4 hover:decoration-bone">ALT-{String(alert.id).padStart(5, '0')}</a></td><td className="px-4 py-3 text-[11px] text-bone">{alert.attack_type}</td><td className="px-4 py-3 font-mono text-[10px] text-bone-dim">{alert.src_ip}:{alert.src_port}<span className="mx-2 text-muted">→</span>{alert.dst_ip}:{alert.dst_port}</td><td className="px-4 py-3 text-[10px] text-bone-dim">{Math.round(alert.confidence * 100)}%</td><td className="px-4 py-3"><RiskBadge value={alert.risk_band} pulse/><span className="ml-2 text-[10px] text-muted">{alert.risk_score}</span></td><td className="px-4 py-3 text-[10px] text-bone-dim">{alert.status}</td><td className="whitespace-nowrap px-4 py-3 text-[10px] text-bone-dim">{formatDate(alert.created_at)}</td></tr>)}</tbody></table>
              {!loading && filteredAlerts.length === 0 && <EmptyState>{alerts.length ? 'No cases match these filters.' : 'No alerts yet. Run a contained drill to create a case.'}</EmptyState>}
            </div>
          </section>
          <footer className="py-7 text-center text-[9px] uppercase tracking-[.16em] text-muted">Kage SOC · fictional training network · no live containment actions</footer>
        </div>
      </main>
    </div>
  </div>;
}

function EmberCanvas() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d', { alpha: true });
    if (!canvas || !context) return undefined;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let width = 0, height = 0, frame = 0, last = 0;
    const embers = Array.from({ length: 22 }, (_, index) => ({ x: Math.random(), y: Math.random(), radius: .6 + Math.random() * 1.5, speed: .000018 + Math.random() * .000034, drift: (Math.random() - .5) * .00007, phase: index * .71, alpha: .12 + Math.random() * .42 }));
    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      width = window.innerWidth; height = window.innerHeight;
      canvas.width = width * ratio; canvas.height = height * ratio;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    const draw = time => {
      if (time - last < 32) { frame = requestAnimationFrame(draw); return; }
      last = time;
      context.clearRect(0, 0, width, height);
      embers.forEach(particle => {
        const shimmer = .72 + Math.sin(time * .0007 + particle.phase) * .28;
        context.beginPath();
        context.fillStyle = `rgba(255, ${74 + Math.floor(particle.phase * 9) % 70}, 52, ${particle.alpha * shimmer})`;
        context.shadowColor = 'rgba(224,35,28,.36)';
        context.shadowBlur = 8;
        context.arc(particle.x * width, particle.y * height, particle.radius, 0, Math.PI * 2);
        context.fill();
        if (!reduced) {
          particle.y -= particle.speed * 32;
          particle.x += particle.drift * 32;
          if (particle.y < -.03) { particle.y = 1.03; particle.x = Math.random(); }
          if (particle.x < 0) particle.x = 1;
          if (particle.x > 1) particle.x = 0;
        }
      });
      context.shadowBlur = 0;
      if (!reduced) frame = requestAnimationFrame(draw);
    };
    resize();
    window.addEventListener('resize', resize, { passive: true });
    draw(0);
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', resize); };
  }, []);
  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 z-0 h-full w-full" aria-hidden="true"/>;
}

function Login() {
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async event => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const result = await api('/login', { method: 'POST', body: JSON.stringify({ username, password }) });
      localStorage.setItem(TOKEN_KEY, result.token);
      localStorage.setItem('soc_user', result.username);
      location.href = '/';
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  return <main className="relative grid min-h-screen place-items-center overflow-hidden px-5 py-10">
    <EmberCanvas/><div className="login-moon" aria-hidden="true"/>
    <section className="relative z-[1] w-full max-w-[440px] border border-line bg-ink/80 p-7 backdrop-blur-xl sm:p-10">
      <Brand/><p className="eyebrow mb-3 mt-10">Northstar Manufacturing · training access</p><h1 className="text-[28px] uppercase tracking-[.09em]">Enter the<br/> watch floor</h1><p className="mt-3 text-[12px] leading-5 text-bone-dim">Sign in to inspect simulated alerts and practice incident response.</p>
      <form className="mt-8 space-y-5" onSubmit={submit}>
        <label className="block"><span className="data-label">Username</span><input autoComplete="username" required value={username} onChange={event => setUsername(event.target.value)} className="mt-2 h-11 w-full border border-line bg-ink-2 px-3 text-[12px] text-bone placeholder:text-muted focus:border-bone/40"/></label>
        <label className="block"><span className="data-label">Password</span><input autoComplete="current-password" type="password" required value={password} onChange={event => setPassword(event.target.value)} placeholder="Enter password" className="mt-2 h-11 w-full border border-line bg-ink-2 px-3 text-[12px] text-bone placeholder:text-muted focus:border-bone/40"/></label>
        <button disabled={busy} className="control-button control-button-primary flex h-11 w-full items-center justify-center gap-2 text-[10px] font-medium uppercase tracking-[.19em]">{busy ? 'Checking access…' : 'Sign in'}<Icon name="arrow" size={15}/></button>
        <p role="alert" aria-live="polite" className="min-h-4 text-[11px] text-[#ff9a83]">{error}</p>
      </form>
      <div className="mt-5 border-t border-line-soft pt-4 text-[10px] text-muted">Demo access <span className="mx-2 text-line">/</span> analyst <span className="mx-1">·</span> analyst123</div>
      <p className="mt-5 text-[9px] uppercase tracking-[.14em] text-muted">Synthetic environment · no production connection</p>
    </section>
  </main>;
}

function CasePage() {
  const authenticated = useRequireLogin();
  const caseId = new URLSearchParams(location.search).get('id');
  const [alert, setAlert] = useState(null);
  const [config, setConfig] = useState({});
  const [error, setError] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  const refresh = useCallback(async () => {
    if (!caseId) { setError('No alert ID was provided.'); return; }
    try {
      const [result, settings] = await Promise.all([api(`/alerts/${encodeURIComponent(caseId)}`), api('/config')]);
      setAlert(result); setConfig(settings); setError('');
    } catch (cause) { setError(cause.message); }
  }, [caseId]);

  useEffect(() => { if (authenticated) refresh(); }, [authenticated, refresh]);
  if (!authenticated) return null;
  const liveAlert = alert?.source === 'windows-firewall-log';
  const organizationAlert = alert?.source === 'organization-simulation';
  const realBlock = Boolean(config.real_blocking_available && liveAlert && config.role === 'admin');
  const hasRule = alert?.history?.some(event => event.action === 'block_ip' && event.details.includes('Windows Firewall'));

  const act = async action => {
    const promptText = action === 'block_ip' && realBlock
      ? `Add real Windows Firewall rules for ${alert.src_ip}? This applies to this PC.`
      : action === 'block_ip' ? `Record a simulated block for ${alert.src_ip}?`
        : action === 'unblock_ip' ? `Remove this app's firewall rules for ${alert.src_ip}?`
          : action === 'isolate_host' ? `Record a simulated isolation for ${alert.dst_ip}?`
            : `${action.replaceAll('_', ' ')} this case?`;
    if (!window.confirm(`${promptText} Confirm to continue.`)) return;
    setBusy(true); setMessage('');
    try { await api(`/alerts/${caseId}/action`, { method: 'POST', body: JSON.stringify({ action, note }) }); setNote(''); await refresh(); }
    catch (cause) { setMessage(cause.message); }
    finally { setBusy(false); }
  };
  const explain = async () => {
    setBusy(true); setMessage('Preparing explanation…');
    try { await api(`/alerts/${caseId}/explain`, { method: 'POST' }); await refresh(); setMessage(''); }
    catch (cause) { setMessage(cause.message); }
    finally { setBusy(false); }
  };

  return <div className="min-h-screen"><Header mode={config.mode} username={localStorage.getItem('soc_user') || 'Analyst'}/><div className="mx-auto flex min-h-[calc(100vh-68px)] max-w-[1500px]"><Sidebar active="alerts"/><main className="min-w-0 flex-1 px-4 py-7 sm:px-7 sm:py-9 xl:px-10"><div className="mx-auto max-w-[1080px]">
    <a href="/" className="mb-6 inline-flex items-center gap-2 text-[10px] uppercase tracking-[.14em] text-bone-dim transition-colors hover:text-bone">← Back to operations</a>
    {error && !alert ? <div role="alert" className="glass-panel p-7 text-[12px] text-[#ff9a83]">{error}</div> : alert && <>
      <section className="section-enter mb-6 flex flex-col justify-between gap-4 border-b border-line-soft pb-5 sm:flex-row sm:items-end"><div><p className="eyebrow mb-3">Incident file <span className="mx-2 text-muted">/</span> ALT-{String(alert.id).padStart(5, '0')} <span className="mx-2 text-muted">/</span> {formatDate(alert.created_at)}</p><h1 className="text-[26px] tracking-[.08em] sm:text-[32px]">{alert.attack_type} alert</h1><p className="mt-3 text-[11px] text-bone-dim">{liveAlert ? 'Observed by the Windows Firewall log monitor' : organizationAlert ? 'Synthetic activity in the Northstar Manufacturing training network' : 'Classified from the CIC-IDS2017 dataset'}</p></div><RiskBadge value={alert.risk_band} pulse/></section>
      <div className="grid gap-4 xl:grid-cols-[1.15fr_.85fr]">
        <section className="glass-panel section-enter p-5 sm:p-6" style={{ '--enter-delay': '70ms' }}><div className="mb-5 flex items-center justify-between gap-3"><div><p className="eyebrow mb-2">Detection context</p><h2 className="text-[16px] tracking-[.09em]">Signal details</h2></div><span className="border border-line-soft px-2 py-1 text-[9px] uppercase tracking-[.12em] text-bone-dim">{liveAlert ? 'Live host log' : organizationAlert ? 'Synthetic org drill' : 'Dataset model'}</span></div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-5 sm:grid-cols-3">{[
            ['Remote address', `${alert.src_ip}:${alert.src_port}`], ['Local asset', `${alert.dst_ip}:${alert.dst_port}`], ['Protocol', alert.protocol], ['Signal confidence', `${(alert.confidence * 100).toFixed(1)}%`], ['Anomaly score', Number(alert.anomaly_score).toFixed(3)], ['Case status', alert.status],
          ].map(([label, value]) => <div key={label} className="border-t border-line-soft pt-3"><dt className="data-label">{label}</dt><dd className="mt-2 break-words font-mono text-[11px] text-bone">{value}</dd></div>)}</dl>
          <div className="mt-7"><p className="eyebrow mb-3">Observed indicators</p><div className="space-y-2">{(alert.top_features || []).map(feature => <div key={feature.name} className="flex items-center justify-between gap-3 border border-line-soft bg-white/[.018] px-3 py-2.5"><span className="text-[11px] text-bone-dim">{feature.name}</span><span className="font-mono text-[10px] text-bone">{Number(feature.contribution || 0).toFixed(3)}</span></div>)}</div></div>
        </section>
        <div className="space-y-4">
          <section className="glass-panel section-enter p-5 sm:p-6" style={{ '--enter-delay': '130ms' }}><div className="mb-4"><p className="eyebrow mb-2">Analyst guidance</p><h2 className="text-[16px] tracking-[.09em]">Case explanation</h2></div><p className="text-[11px] leading-6 text-bone-dim">{alert.explanation?.text || 'Request a short explanation with investigation steps for this alert.'}</p><button disabled={busy} onClick={explain} className="control-button mt-5 px-3 text-[9px] uppercase tracking-[.14em]">{alert.explanation ? 'Refresh explanation' : 'Explain this alert'}</button>{alert.explanation && <p className="mt-3 text-[9px] text-muted">Source: {alert.explanation.source}</p>}</section>
          <section className="glass-panel section-enter p-5 sm:p-6" style={{ '--enter-delay': '190ms' }}><p className="eyebrow mb-2">Response controls</p><h2 className="text-[16px] tracking-[.09em]">Analyst action</h2><p className="mt-2 text-[10px] leading-5 text-bone-dim">{realBlock ? 'A confirmed block changes Windows Firewall rules on this PC.' : 'Demo actions update this case history only. No network devices are changed.'}</p><label htmlFor="analyst-note" className="sr-only">Optional case note</label><textarea id="analyst-note" value={note} onChange={event => setNote(event.target.value)} placeholder="Add an analyst note…" className="mt-4 min-h-20 w-full resize-y border border-line bg-ink-2 p-3 text-[11px] text-bone placeholder:text-muted"/>
            <div className="mt-3 grid grid-cols-2 gap-2">{[['investigate','Investigate'],['block_ip', hasRule ? 'Already blocked' : realBlock ? 'Block IP · real' : 'Block IP · simulated'],['isolate_host','Isolate host'],['escalate','Escalate'],['false_positive','False positive'],['close','Close case']].map(([action, label]) => <button key={action} disabled={busy || (action === 'block_ip' && config.mode === 'live' && (!realBlock || hasRule))} onClick={() => act(action)} className="control-button px-2 text-[9px] uppercase tracking-[.08em]">{label}</button>)}</div>
            {realBlock && hasRule && <button disabled={busy} onClick={() => act('unblock_ip')} className="control-button mt-2 w-full px-2 text-[9px] uppercase tracking-[.1em]">Remove firewall block</button>}
            {message && <p role="status" aria-live="polite" className="mt-3 text-[10px] text-[#ff9a83]">{message}</p>}
          </section>
        </div>
        <section className="glass-panel section-enter p-5 sm:p-6 xl:col-span-2" style={{ '--enter-delay': '250ms' }}><div className="mb-5 flex items-end justify-between gap-4"><div><p className="eyebrow mb-2">Chain of custody</p><h2 className="text-[16px] tracking-[.09em]">Case timeline</h2></div><span className="text-[9px] uppercase tracking-[.13em] text-muted">{alert.history?.length || 0} entries</span></div><div className="case-timeline">{(alert.history || []).map(event => <article key={event.id} className="timeline-item"><span className="timeline-dot"/><p className="text-[10px] font-medium uppercase tracking-[.1em] text-bone">{event.action.replaceAll('_', ' ')} <span className="ml-2 font-light normal-case tracking-normal text-muted">by {event.performed_by}</span></p><p className="mt-1 text-[11px] leading-5 text-bone-dim">{event.details}</p><p className="mt-1 text-[9px] text-muted">{formatDate(event.created_at, true)}</p></article>)}</div></section>
      </div>
    </>}
  </div></main></div></div>;
}

export default function App() {
  const path = location.pathname;
  if (path.endsWith('/login.html')) return <Login/>;
  if (path.endsWith('/alert.html')) return <CasePage/>;
  return <Dashboard/>;
}
