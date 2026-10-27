import { apiFetch } from '../api.js';
import React, { useState, useEffect } from 'react';
import { Settings, Cpu, Shield, Wrench, Lock, CheckCircle, Database } from 'lucide-react';

export default function ConfigManager() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setLoading(true);
    apiFetch('/api/v1/config/public')
      .then(res => { if (!res.ok) throw new Error('Configuration unavailable'); return res.json(); })
      .then(data => setConfig(data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text)', margin: 0 }}>Gateway Configuration & Model Registry</h2>
        <p style={{ color: 'var(--muted)', fontSize: '0.85rem', margin: '0.25rem 0 0' }}>
          Inspect active defense layers, loaded transformer model backends, hardware acceleration, and tool authorization policies.
        </p>
      </div>

      {error && <p role="alert" style={{ color: 'var(--warning)' }}>{error}</p>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))', gap: '1.25rem' }}>
        {/* Model Card */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--accent)', fontWeight: 700, marginBottom: '1rem' }}>
            <Cpu size={18} /> Pretrained Transformer Model (Layer 2)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: 'var(--muted)' }}>Configured Primary Model:</span>
              <div style={{ color: 'var(--text)', fontWeight: 600, fontFamily: 'monospace', marginTop: '2px' }}>
                {config?.model_id || 'Unavailable'}
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--muted)' }}>Inference Device / Acceleration:</span>
              <div style={{ color: 'var(--success)', fontWeight: 700, marginTop: '2px' }}>
                {config?.model_device?.toUpperCase() || 'Unavailable'}
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--muted)' }}>Candidate models for separate evaluation:</span>
              <ul style={{ color: 'var(--text)', fontSize: '0.8rem', paddingLeft: '1.2rem', margin: '4px 0 0' }}>
                <li>meta-llama/Llama-Prompt-Guard-2-22M (Gated; requires HF_TOKEN)</li>
                <li>meta-llama/Prompt-Guard-86M (Gated; requires HF_TOKEN)</li>
                <li>protectai/deberta-v3-base-prompt-injection (Public)</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Tool Security Policy */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--accent)', fontWeight: 700, marginBottom: '1rem' }}>
            <Lock size={18} /> Deterministic Tool Policy (Layer 5)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: 'var(--muted)' }}>Read-Only Public Tools:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.read_only_tools?.map((t, i) => (
                  <span key={i} style={{ background: 'color-mix(in srgb, var(--accent) 15%, transparent)', color: 'var(--accent)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--muted)' }}>Restricted Privileged Tools:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.restricted_tools?.map((t, i) => (
                  <span key={i} style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--danger)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span style={{ color: 'var(--muted)' }}>Approved Export Destinations:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.approved_destinations?.map((d, i) => (
                  <span key={i} style={{ background: 'rgba(16, 185, 129, 0.15)', color: 'var(--success)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {d}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
