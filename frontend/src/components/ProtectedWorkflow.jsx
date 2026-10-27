import React, { useEffect, useState } from 'react';
import AccessSession, { button, field, useGatewayIdentity } from './AccessSession.jsx';
import { apiRequest } from '../api.js';

const names = { public_banking: 'Public banking questions', own_records: 'My synthetic customer record', audit_export: 'Approved synthetic audit export' };
export default function ProtectedWorkflow() {
  const { identity, error: identityError } = useGatewayIdentity();
  const [workflow, setWorkflow] = useState('public_banking');
  const [accountId, setAccountId] = useState('');
  const [destination, setDestination] = useState('');
  const [query, setQuery] = useState('What is the process for NEFT transfers?');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    setResult(null);
    setError('');
    if (!identity) return;
    if (!(identity.workflows || []).includes(workflow)) setWorkflow('public_banking');
    setAccountId(identity.account_ids?.length === 1 ? identity.account_ids[0] : '');
    setDestination(identity.allowed_destinations?.length === 1 ? identity.allowed_destinations[0] : '');
  }, [identity]);
  const run = async event => {
    event.preventDefault();
    setLoading(true); setError(''); setResult(null);
    try {
      setResult(await apiRequest('/api/v1/rag/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        query, workflow, k: 3, chunk_size: 512,
        ...(workflow !== 'public_banking' && accountId ? { account_id: accountId } : {}),
        ...(workflow === 'audit_export' && destination ? { destination } : {}),
      }) }));
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };
  const workflows = identity?.workflows || ['public_banking'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: 0, color: 'var(--text)' }}>Banking workflow demo</h2>
        <p style={{ color: 'var(--muted)' }}>An optional example of the security gateway protecting an application. This demo uses synthetic banking documents, customer records, and account-specific tool rules.</p>
      </div>
      <AccessSession identity={identity} error={identityError} disabled={loading} />
      <form onSubmit={run} className="panel request-form" style={{ padding: '1.25rem', display: 'grid', gap: '1rem' }}>
        <label style={{ color: 'var(--text)', fontSize: '0.85rem' }}>Authorized workflow
          <select value={workflows.includes(workflow) ? workflow : 'public_banking'} onChange={e => {
            setWorkflow(e.target.value);
            if (e.target.value === 'own_records') setQuery('Retrieve my selected synthetic account record and summarize its account type.');
            else if (e.target.value === 'audit_export') setQuery('Create a synthetic audit export for my selected account to the selected destination and report whether it was recorded.');
            else setQuery('What is the process for NEFT transfers?');
          }} style={{ ...field, marginTop: '6px' }}>
            {workflows.map(value => <option key={value} value={value}>{names[value] || value}</option>)}
          </select>
        </label>
        {workflow !== 'public_banking' && <label style={{ color: 'var(--text)', fontSize: '0.85rem' }}>Account for this task
          <select value={accountId} onChange={e => setAccountId(e.target.value)} required style={{ ...field, marginTop: '6px' }}>
            <option value="">Select an assigned account</option>
            {(identity?.account_ids || []).map(value => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>}
        {workflow === 'audit_export' && <label style={{ color: 'var(--text)', fontSize: '0.85rem' }}>Destination for this task
          <select value={destination} onChange={e => setDestination(e.target.value)} required style={{ ...field, marginTop: '6px' }}>
            <option value="">Select an assigned destination</option>
            {(identity?.allowed_destinations || []).map(value => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>}
        <label style={{ color: 'var(--text)', fontSize: '0.85rem' }}>Your request
          <textarea value={query} onChange={e => setQuery(e.target.value)} rows={4} maxLength={16384} required style={{ ...field, display: 'block', marginTop: '6px', resize: 'vertical' }} />
        </label>
        <button disabled={loading || !identity} style={{ ...button, justifySelf: 'start', opacity: loading || !identity ? 0.6 : 1 }}>{loading ? 'Running protected workflow…' : 'Send request'}</button>
      </form>
      {error && <div role="alert" style={{ color: 'var(--danger)' }}>{error}</div>}
      <div aria-live="polite" aria-busy={loading}>{loading && <p style={{ color: 'var(--muted)' }}>Inspecting context and waiting for the local model. Results will appear here.</p>}</div>
      {result && <>
        <section className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', color: result.status === 'completed' ? 'var(--success)' : 'var(--warning)' }}>
            <strong>{(result.status || 'unknown').replace(/_/g, ' ').toUpperCase()}</strong>
            <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>{result.request_id}</span>
            <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>{result.backend?.id || 'Backend not reported'} · {result.backend?.kind || 'unknown'} · {result.latency_ms != null ? `${result.latency_ms} ms` : 'Latency unavailable'}</span>
          </div>
          <p style={{ whiteSpace: 'pre-wrap', lineHeight: 1.7, color: 'var(--text)' }}>{result.answer || result.reason || result.explanation || 'No answer was released. See the workflow trace for the reason.'}</p>
          {result.backend?.kind === 'simulation' && <p style={{ color: 'var(--warning)' }}>This response is simulated and does not measure real model behavior.</p>}
          <div style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>Flagged chunks: {result.flagged_chunks ?? 'unknown'} · Quarantined: {result.quarantined_ids?.length ?? 0} · Audit: {typeof result.audit_status === 'object' ? JSON.stringify(result.audit_status) : result.audit_status || 'not reported'}</div>
        </section>
        {!!result.citations?.length && <section className="panel" style={{ padding: '1.25rem' }}>
          <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Sources accepted for context</h3>
          {result.citations.map((source, index) => <div key={`${source.chunk_id}-${index}`} style={{ marginBottom: '8px', fontSize: '0.85rem', color: 'var(--text)' }}>[{index + 1}] {source.source_name} <span style={{ color: 'var(--muted)' }}>· {source.document_id} / {source.chunk_id}</span></div>)}
          <p style={{ color: 'var(--muted)', fontSize: '0.75rem' }}>These sources were accepted while preparing context. The workflow trace records whether generation completed; inclusion does not independently establish answer accuracy.</p>
        </section>}
        {!!result.tool_executions?.length && <section className="panel" style={{ padding: '1.25rem' }}>
          <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Tool execution decisions</h3>
          {result.tool_executions.map((item, index) => <div key={index} style={{ padding: '10px 0', borderBottom: '1px solid var(--surface-raised)' }}>
            <strong style={{ color: item.executed ? 'var(--success)' : 'var(--warning)' }}>{item.decision?.tool_name || item.tool_name} · {item.executed ? 'EXECUTED' : 'NOT EXECUTED'}</strong>
            <p style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>{item.decision?.policy_code} · {item.decision?.decision_reason || item.error}</p>
          </div>)}
        </section>}
        <section className="panel" style={{ padding: '1.25rem' }}>
          <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Workflow trace</h3>
          {result.trace?.length ? result.trace.map((step, index) => <div key={index} style={{ marginBottom: '10px', color: 'var(--text)', fontSize: '0.85rem' }}>
            <strong>{index + 1}. {step.stage} · {step.status}</strong>
            {step.details && <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', color: 'var(--muted)', fontSize: '0.8rem' }}>{typeof step.details === 'string' ? step.details : JSON.stringify(step.details, null, 2)}</pre>}
          </div>) : <p style={{ color: 'var(--muted)' }}>No stage trace was reported.</p>}
          {result.assembled_prompt && <details><summary style={{ cursor: 'pointer', color: 'var(--accent)' }}>Protected context preview{result.context_redacted ? ' · sensitive values redacted' : ''}</summary><p style={{ color: 'var(--muted)', fontSize: '0.75rem', overflowWrap: 'anywhere' }}>Prepared context SHA-256: {result.context_sha256 || 'not reported'}</p><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: '360px', overflowY: 'auto', color: 'var(--muted)', fontSize: '0.8rem' }}>{result.assembled_prompt}</pre></details>}
        </section>
      </>}
    </div>
  );
}
