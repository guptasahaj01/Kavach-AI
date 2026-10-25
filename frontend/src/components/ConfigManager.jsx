import React, { useState, useEffect } from 'react';
import { Settings, Cpu, Shield, Wrench, Lock, CheckCircle, Database } from 'lucide-react';

export default function ConfigManager() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    fetch('/api/v1/config/public')
      .then(res => res.json())
      .then(data => setConfig(data))
      .catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>Gateway Configuration & Model Registry</h2>
        <p style={{ color: '#94A3B8', fontSize: '0.85rem', margin: '0.25rem 0 0' }}>
          Inspect active defense layers, loaded transformer model backends, hardware acceleration, and tool authorization policies.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
        {/* Model Card */}
        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#8B5CF6', fontWeight: 700, marginBottom: '1rem' }}>
            <Cpu size={18} /> Pretrained Transformer Model (Layer 2)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: '#94A3B8' }}>Active Primary Model:</span>
              <div style={{ color: '#FFFFFF', fontWeight: 600, fontFamily: 'monospace', marginTop: '2px' }}>
                {config?.model_id || 'deepset/deberta-v3-base-injection'}
              </div>
            </div>

            <div>
              <span style={{ color: '#94A3B8' }}>Inference Device / Acceleration:</span>
              <div style={{ color: '#10B981', fontWeight: 700, marginTop: '2px' }}>
                {config?.model_device?.toUpperCase() === 'MPS' ? 'Apple Silicon (MPS Hardware Accelerated)' : 'CPU / Generic'}
              </div>
            </div>

            <div>
              <span style={{ color: '#94A3B8' }}>Alternative Supported Models:</span>
              <ul style={{ color: '#CBD5E1', fontSize: '0.8rem', paddingLeft: '1.2rem', margin: '4px 0 0' }}>
                <li>meta-llama/Llama-Prompt-Guard-2-22M (Gated; requires HF_TOKEN)</li>
                <li>meta-llama/Prompt-Guard-86M (Gated; requires HF_TOKEN)</li>
                <li>protectai/deberta-v3-base-prompt-injection (Public)</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Tool Security Policy */}
        <div style={{ background: '#0F172A', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#3B82F6', fontWeight: 700, marginBottom: '1rem' }}>
            <Lock size={18} /> Deterministic Tool Policy (Layer 5)
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
            <div>
              <span style={{ color: '#94A3B8' }}>Read-Only Public Tools:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.read_only_tools?.map((t, i) => (
                  <span key={i} style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#60A5FA', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span style={{ color: '#94A3B8' }}>Restricted Privileged Tools:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.restricted_tools?.map((t, i) => (
                  <span key={i} style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#F87171', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span style={{ color: '#94A3B8' }}>Approved Export Destinations:</span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '4px' }}>
                {config?.approved_destinations?.map((d, i) => (
                  <span key={i} style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34D399', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
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
