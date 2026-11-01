import React from 'react';
import {
  Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts';

const SEVERITY = {
  Critical: '#e0231c',
  High: '#ff5a3c',
  Medium: '#c9a24a',
  Low: '#7fa99b',
};
const TYPE_COLOR = {
  DoS: '#e0231c',
  BruteForce: '#ff5a3c',
  PortScan: '#c9a24a',
  WebAttack: '#7fa99b',
  'Repeated Connection Attempts': '#ff5a3c',
  'Blocked Firewall Traffic': '#c9a24a',
};
const TOOLTIP = {
  contentStyle: { background: '#0a0e12', border: '1px solid rgba(223,231,224,.16)', borderRadius: 2, color: '#dfe7e0', fontSize: 11 },
  itemStyle: { color: '#dfe7e0' },
  labelStyle: { color: '#aab4ad', fontSize: 10, letterSpacing: '.12em' },
  cursor: { fill: 'rgba(223,231,224,.035)' },
};

function EmptyState({ children }) {
  return <div className="grid min-h-28 place-items-center px-4 text-center text-[11px] text-muted">{children}</div>;
}

export default function DashboardCharts({ stats }) {
  const byType = Object.entries(stats?.by_type || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 6);
  const byRisk = ['Critical', 'High', 'Medium', 'Low'].map(name => ({ name, value: stats?.by_band?.[name] || 0, color: SEVERITY[name] }));
  return <section className="mb-7 grid gap-4 xl:grid-cols-[1.15fr_.85fr]">
    <article className="glass-panel section-enter p-4 sm:p-5" style={{ '--enter-delay': '520ms' }}><div className="mb-4"><p className="eyebrow mb-2">Signal distribution</p><h2 className="text-[15px] tracking-[.08em]">Cases by classification</h2></div><div className="h-[220px] w-full">{byType.length ? <ResponsiveContainer width="100%" height="100%"><BarChart data={byType} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 4 }}><CartesianGrid horizontal={false} stroke="rgba(223,231,224,.07)"/><XAxis type="number" allowDecimals={false} tick={{ fill: '#aab4ad', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis type="category" dataKey="name" width={108} tick={{ fill: '#dfe7e0', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip {...TOOLTIP}/><Bar dataKey="value" name="Cases" radius={[0, 1, 1, 0]} maxBarSize={14} isAnimationActive animationDuration={650}>{byType.map(item => <Cell key={item.name} fill={TYPE_COLOR[item.name] || '#aab4ad'}/>)}</Bar></BarChart></ResponsiveContainer> : <EmptyState>No classified alerts yet.</EmptyState>}</div></article>
    <article className="glass-panel section-enter p-4 sm:p-5" style={{ '--enter-delay': '590ms' }}><div className="mb-2"><p className="eyebrow mb-2">Priority mix</p><h2 className="text-[15px] tracking-[.08em]">Risk distribution</h2></div><div className="flex h-[210px] items-center gap-2"><div className="h-full min-w-0 flex-1">{byRisk.some(item => item.value > 0) ? <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={byRisk} dataKey="value" nameKey="name" innerRadius="60%" outerRadius="82%" paddingAngle={2} stroke="none" isAnimationActive animationDuration={700}>{byRisk.map(item => <Cell key={item.name} fill={item.color} fillOpacity={item.value ? 1 : .18}/>)}</Pie><Tooltip {...TOOLTIP}/></PieChart></ResponsiveContainer> : <EmptyState>No cases to summarize.</EmptyState>}</div><div className="w-[104px] space-y-3">{byRisk.map(item => <div key={item.name} className="flex items-center justify-between gap-2"><span className="flex items-center gap-2 text-[9px] uppercase tracking-[.08em] text-bone-dim"><i className="h-1.5 w-1.5" style={{ background: item.color }}/>{item.name}</span><span className="text-[10px] text-bone">{item.value}</span></div>)}</div></div></article>
  </section>;
}
