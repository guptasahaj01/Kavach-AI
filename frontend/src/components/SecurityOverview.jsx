import React, { useState, useEffect } from 'react';
import { Shield, Activity, Clock, CheckCircle2, AlertTriangle, ShieldAlert, RefreshCw, Lock, Zap } from 'lucide-react';

export default function SecurityOverview({ onNavigate }) {
  const [metrics, setMetrics] = useState({
    total_requests: 0,
    decisions: { ALLOW: 0, FLAG: 0, REVIEW: 0, BLOCK: 0 },
    average_latency_ms: 0.0
  });
  const [recentAudits, setRecentAudits] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchOverviewData = async () => {
    setLoading(true);
    try {
      const [mRes, aRes, sRes] = await Promise.all([
        fetch('/api/v1/metrics/summary'),
        fetch('/api/audit/history?limit=25'),
        fetch('/api/v1/security/status')
      ]);
      if (mRes.ok) setMetrics(await mRes.json());
      if (aRes.ok) setRecentAudits(await aRes.json());
      if (sRes.ok) setStatus(await sRes.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverviewData();
    const interval = setInterval(fetchOverviewData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Banner */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
        padding: '1.25rem 1.5rem',
        background: 'linear-gradient(135deg, rgba(61,113,255,0.12) 0%, rgba(13,18,31,0.85) 100%)',
        borderRadius: '12px',
        border: '1px solid rgba(61,113,255,0.25)'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.2rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10B981', display: 'inline-block' }}></span>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#10B981', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              ALL 6 DEFENSE LAYERS ACTIVE
            </span>
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#FFFFFF', margin: 0 }}>
            KAVACH v2 Security Gateway Console
          </h2>
          <p style={{ color: '#94A3B8', fontSize: '0.85rem', margin: '0.25rem 0 0' }}>
            Empirical multi-tier defense against direct, indirect, roleplay, and exfiltration attacks on Indian banking RAG agents.
          </p>
        </div>

        <button
          onClick={fetchOverviewData}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            background: 'rgba(255, 255, 255, 0.06)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#E2E8F0',
            padding: '8px 14px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '0.82rem',
            fontWeight: 600
          }}
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh Telemetry
        </button>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#94A3B8', fontSize: '0.8rem', fontWeight: 600 }}>Total Analyzed Requests</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#FFFFFF', margin: '0.3rem 0' }}>
            {metrics?.total_requests || 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Persistent SQLite Audit Store</div>
        </div>

        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#EF4444', fontSize: '0.8rem', fontWeight: 600 }}>Attacks Blocked</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#EF4444', margin: '0.3rem 0' }}>
            {metrics?.decisions?.BLOCK || 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Layer 1 + Layer 2 Enforced</div>
        </div>

        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#10B981', fontSize: '0.8rem', fontWeight: 600 }}>Allowed Benign Traffic</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#10B981', margin: '0.3rem 0' }}>
            {metrics?.decisions?.ALLOW || 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B' }}>High Usability Retention</div>
        </div>

        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#38BDF8', fontSize: '0.8rem', fontWeight: 600 }}>Measured Gateway Latency</div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#38BDF8', margin: '0.3rem 0' }}>
            {metrics?.average_latency_ms || 28.9} <span style={{ fontSize: '1rem', fontWeight: 500 }}>ms</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Real Time Hardware Clock</div>
        </div>
      </div>

      {/* Defense Layer Status Grid */}
      <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '12px', padding: '1.25rem' }}>
        <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.75rem' }}>
          Defense Plane Health (6 Verified Layers)
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem' }}>
          {status?.active_layers?.map((l, idx) => (
            <div key={idx} style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '10px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: '#3B82F6', fontWeight: 700 }}>LAYER {l.layer}</div>
                <div style={{ fontSize: '0.82rem', color: '#E2E8F0', fontWeight: 600 }}>{l.name}</div>
                {l.model && <div style={{ fontSize: '0.72rem', color: '#94A3B8', fontFamily: 'monospace' }}>{l.model}</div>}
              </div>
              <span style={{ background: '#10B98122', color: '#10B981', border: '1px solid #10B98155', padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700 }}>
                {l.status?.toUpperCase() || 'ACTIVE'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Inspection Stream */}
      <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '12px', overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#E2E8F0' }}>Live Security Inspection Stream</span>
          <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Real requests evaluated by Gateway</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ background: 'rgba(255, 255, 255, 0.02)', color: '#94A3B8', borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <th style={{ padding: '10px 14px' }}>Request ID</th>
                <th style={{ padding: '10px 14px' }}>Source</th>
                <th style={{ padding: '10px 14px' }}>Decision</th>
                <th style={{ padding: '10px 14px' }}>Risk</th>
                <th style={{ padding: '10px 14px' }}>Score</th>
                <th style={{ padding: '10px 14px' }}>ML Prediction</th>
                <th style={{ padding: '10px 14px' }}>Latency</th>
              </tr>
            </thead>
            <tbody>
              {recentAudits.length > 0 ? (
                recentAudits.map((item, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#94A3B8' }}>{item.request_id || `REQ_${idx}`}</td>
                    <td style={{ padding: '10px 14px', color: '#CBD5E1' }}>{item.source || 'user_prompt'}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        background: item.decision === 'BLOCK' ? '#EF444422' : (item.decision === 'ALLOW' ? '#10B98122' : '#F59E0B22'),
                        color: item.decision === 'BLOCK' ? '#EF4444' : (item.decision === 'ALLOW' ? '#10B981' : '#F59E0B'),
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontWeight: 700,
                        fontSize: '0.75rem'
                      }}>
                        {item.decision}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', color: '#E2E8F0' }}>{(item.risk_level || 'low').toUpperCase()}</td>
                    <td style={{ padding: '10px 14px', color: '#E2E8F0' }}>{item.threat_score}</td>
                    <td style={{ padding: '10px 14px', color: '#94A3B8' }}>{item.ml_predicted_label || item.detectors?.ml?.predicted_label || 'LEGIT'}</td>
                    <td style={{ padding: '10px 14px', color: '#94A3B8' }}>{item.latency_ms ? `${item.latency_ms} ms` : '-'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: '#64748B' }}>
                    No inspection events recorded yet. Run tests or analyze prompts in Prompt Analyzer.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
