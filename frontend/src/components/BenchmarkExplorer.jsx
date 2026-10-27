import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api.js';
import { button } from './AccessSession.jsx';
import BenchmarkHub from './BenchmarkHub.jsx';

export default function BenchmarkExplorer() {
  const [runs, setRuns] = useState([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const load = async () => { setRuns(await apiRequest('/api/v1/benchmark/runs')); };
  useEffect(() => { load().catch(err => setError(err.message)); }, []);
  const run = async () => {
    setRunning(true); setError('');
    try { await apiRequest('/api/v1/benchmark/smoke', { method: 'POST' }); await load(); }
    catch (err) { setError(err.message); }
    finally { setRunning(false); }
  };
  return <div style={{ display: 'grid', gap: '1.25rem' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
      <div><h2 style={{ margin: 0 }}>Evaluation explorer</h2><p style={{ color: 'var(--muted)' }}>Detector diagnostics and historical simulations are separate result types.</p></div>
      <button style={button} disabled={running} onClick={run}>{running ? 'Running detector comparison…' : 'Run detector comparison'}</button>
    </div>
    {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
    <section className="panel" style={{ padding: '1.25rem', overflowX: 'auto' }}>
      <h3 style={{ marginTop: 0 }}>Prompt/document classification (B0–B6)</h3>
      <p style={{ color: 'var(--muted)', lineHeight: 1.6 }}>Miss rate is the proportion of labeled attacks that the detector did not reject. No downstream attack success is observed in this comparison. B6 evaluates inspection, excluding tool execution and output delivery. Historical results describe the code and dataset that produced them.</p>
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
        <thead><tr>{['Baseline', 'Labeled attacks / benign', 'Misses', 'Miss rate [95% CI]', 'False positives', 'FPR [95% CI]', 'F1', 'Median inspection time'].map(label => <th key={label} style={{ padding: '8px', color: 'var(--muted)' }}>{label}</th>)}</tr></thead>
        <tbody>{runs.map(row => <tr key={row.baseline_id} style={{ borderTop: '1px solid var(--surface-raised)' }}>
          <td style={{ padding: '8px', color: 'var(--accent)' }}>{row.baseline_id === 'B2' ? 'B2: Token Jaccard' : row.baseline_id === 'B6' ? 'B6: Gateway inspection' : row.baseline_name}</td>
          <td>{row.attack_samples} / {row.benign_samples}</td><td>{row.false_negatives}</td>
          <td>{((row.detector_miss_rate ?? row.asr) * 100).toFixed(1)}% [{row.asr_ci?.join('–')}]</td>
          <td>{row.false_positives}</td><td>{(row.fpr * 100).toFixed(1)}% [{row.fpr_ci?.join('–')}]</td><td>{row.f1_score.toFixed(3)}</td><td>{row.median_latency_ms.toFixed(2)} ms</td>
        </tr>)}</tbody>
      </table>
      {!runs.length && <p style={{ color: 'var(--muted)' }}>No saved detector comparison returned.</p>}
      <p style={{ color: 'var(--warning)', fontSize: '0.8rem', lineHeight: 1.6 }}>The original corpus contains only 17 attacks and six benign examples. Zero observed false positives on six examples does not establish a zero false-positive rate. Use independent held-out scenarios and task-success scoring before drawing broader conclusions.</p>
    </section>
    <BenchmarkHub />
  </div>;
}
