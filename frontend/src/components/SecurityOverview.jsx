import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api.js';
import { button } from './AccessSession.jsx';

export default function SecurityOverview() {
  const [metrics, setMetrics] = useState(null);
  const [audits, setAudits] = useState([]);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState(null);
  const [loading, setLoading] = useState(false);
  const refresh = async () => {
    setLoading(true);
    const results = await Promise.allSettled([
      apiRequest('/api/v1/metrics/summary'), apiRequest('/api/audit/history?limit=25'), apiRequest('/api/v1/security/status'),
    ]);
    setMetrics(results[0].status === 'fulfilled' ? results[0].value : null);
    setAudits(results[1].status === 'fulfilled' && Array.isArray(results[1].value) ? results[1].value : []);
    setStatus(results[2].status === 'fulfilled' ? results[2].value : null);
    setError(results.some(item => item.status === 'rejected') ? 'Some telemetry could not be loaded. Missing values are shown as unavailable.' : '');
    setUpdated(new Date()); setLoading(false);
  };
  useEffect(() => { refresh(); const timer = setInterval(refresh, 10000); return () => clearInterval(timer); }, []);
  const available = metrics && metrics.available !== false && !['unavailable', 'error'].includes(metrics.status);
  const number = value => available && value != null ? value : '—';
  const cards = [
    ['Recorded inspections', number(metrics?.total_requests)],
    ['BLOCK decisions', number(metrics?.decisions?.BLOCK)],
    ['ALLOW decisions', number(metrics?.decisions?.ALLOW)],
    ['Average inspection latency', available && metrics?.total_requests > 0 && metrics?.average_latency_ms != null ? `${metrics.average_latency_ms} ms` : '—'],
  ];
  return <div style={{ display: 'grid', gap: '1.25rem' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
      <div><h2 style={{ margin: 0 }}>Security observations</h2><p style={{ color: 'var(--muted)', marginBottom: 0 }}>Gateway status: {status?.status || 'unknown'} · Updated: {updated ? updated.toLocaleTimeString() : 'not yet loaded'}</p></div>
      <button style={button} onClick={refresh} disabled={loading}>{loading ? 'Loading…' : 'Refresh telemetry'}</button>
    </div>
    {error && <p role="alert" style={{ color: 'var(--warning)' }}>{error}</p>}
    {!available && <p style={{ color: 'var(--warning)' }}>Inspection metrics are unavailable. No traffic counts or latency estimates have been substituted.</p>}
    <div className="stat-strip">
      {cards.map(([label, value]) => <div className="panel" key={label} style={{ padding: '1.25rem' }}><div style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>{label}</div><div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '8px' }}>{value}</div></div>)}
    </div>
    <p style={{ color: 'var(--muted)', fontSize: '0.8rem', margin: 0 }}>Decisions are detector outputs. ALLOW does not establish benign ground truth; BLOCK does not independently confirm an attack. Inspection latency excludes generation and tool execution.</p>
    <section className="panel" style={{ padding: '1.25rem' }}>
      <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Component readiness</h3>
      <p style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Readiness describes components available to the gateway. The protected assistant shows which checks were applied to each request.</p>
      <p style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Generation service: {status?.generation_backend?.id || 'unknown'} · {status?.generation_backend?.status || 'not checked'}. A configured service is verified when a protected request invokes it.</p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 250px), 1fr))', gap: '0.75rem' }}>
        {status?.active_layers?.map(item => <div key={item.layer} style={{ background: 'var(--surface)', border: '1px solid var(--surface-raised)', padding: '12px', borderRadius: '4px' }}>
          <strong style={{ fontSize: '0.85rem' }}>{item.name}</strong><div style={{ color: ['active', 'ready'].includes(item.status) ? 'var(--success)' : 'var(--warning)', marginTop: '6px', fontSize: '0.8rem' }}>{item.status || 'unknown'}</div>
          {item.model && <div style={{ color: 'var(--muted)', fontSize: '0.75rem', marginTop: '6px', overflowWrap: 'anywhere' }}>{item.model}</div>}
        </div>)}
      </div>
      {!status && <p style={{ color: 'var(--muted)' }}>Component status unavailable.</p>}
    </section>
    <section className="panel" style={{ padding: '1.25rem', overflowX: 'auto' }}>
      <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Recent recorded inspections</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
        <thead><tr>{['Request', 'Source', 'Decision', 'Risk', 'Evidence score', 'ML result', 'Latency'].map(label => <th key={label} style={{ padding: '8px', color: 'var(--muted)' }}>{label}</th>)}</tr></thead>
        <tbody>{audits.map((item, index) => <tr key={item.request_id || index} style={{ borderTop: '1px solid var(--surface-raised)' }}>
          <td style={{ padding: '8px' }}>{item.request_id || 'unknown'}</td><td>{item.source || 'unknown'}</td><td>{item.decision || 'unknown'}</td><td>{item.risk_level || 'unknown'}</td><td>{item.threat_score ?? '—'}</td><td>{item.ml_predicted_label || item.detectors?.ml?.predicted_label || 'not recorded'}</td><td>{item.latency_ms != null ? `${item.latency_ms} ms` : '—'}</td>
        </tr>)}</tbody>
      </table>
      {!audits.length && <p style={{ color: 'var(--muted)' }}>No inspection records were returned.</p>}
    </section>
  </div>;
}
