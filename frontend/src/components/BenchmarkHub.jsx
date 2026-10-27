import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api.js';

export default function BenchmarkHub() {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => { apiRequest('/api/benchmark/table').then(setRows).catch(err => setError(err.message)); }, []);
  return <section className="panel" style={{ padding: '1.25rem', overflowX: 'auto' }}>
    <h3 style={{ marginTop: 0 }}>Historical 72-configuration simulation</h3>
    <p style={{ color: 'var(--warning)', lineHeight: 1.6 }}>These saved results use programmed model susceptibility and historical simulated guardrail behavior. They are retained for reference and do not measure real model robustness or production latency. All current documents fit within every tested chunk size.</p>
    {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
      <thead><tr>{['Configuration', 'k', 'Chunk words', 'Hardening', 'Guardrail', 'Simulated ASR', 'Simulated FPR'].map(label => <th key={label} style={{ padding: '8px', color: 'var(--muted)' }}>{label}</th>)}</tr></thead>
      <tbody>{rows.map(row => <tr key={row.Cfg} style={{ borderTop: '1px solid var(--surface-raised)' }}>
        <td style={{ padding: '8px' }}>{row.Cfg}</td><td>{row.k}</td><td>{row['Chunk (tokens)']}</td><td>{row.Hardening}</td><td>{row.Guardrail}</td><td>{row['ASR % [95% CI]']}</td><td>{row['Benign FPR % [95% CI]']}</td>
      </tr>)}</tbody>
    </table>
    {!rows.length && !error && <p style={{ color: 'var(--muted)' }}>No historical configurations returned.</p>}
  </section>;
}
