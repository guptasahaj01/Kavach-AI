import React, { useEffect, useState } from 'react';
import AccessSession, { button, field, useGatewayIdentity } from './AccessSession.jsx';
import { apiRequest } from '../api.js';

export default function ToolMonitor() {
  const { identity, error: identityError } = useGatewayIdentity();
  const [tool, setTool] = useState('retrieve_bank_rates');
  const [workflow, setWorkflow] = useState('public_banking');
  const [argumentsText, setArgumentsText] = useState('{"product":"savings"}');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  useEffect(() => { setResult(null); setError(''); }, [identity]);
  const run = async execute => {
    setLoading(true); setResult(null); setError('');
    try {
      const args = JSON.parse(argumentsText);
      setResult(await apiRequest(execute ? '/api/v1/tools/execute' : '/api/v1/security/authorize-tool', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tool_name: tool, arguments: args, workflow }),
      }));
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };
  const verdict = result?.decision || result;
  return <div style={{ display: 'grid', gap: '1.25rem' }}>
    <div><h2 style={{ margin: 0 }}>Tool policy and execution</h2><p style={{ color: 'var(--muted)' }}>Evaluate a proposal or execute it through the policy gate. All available tools operate on local synthetic data.</p></div>
    <AccessSession identity={identity} error={identityError} disabled={loading} />
    <section className="panel" style={{ padding: '1.25rem', display: 'grid', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <button style={button} onClick={() => { setTool('retrieve_bank_rates'); setWorkflow('public_banking'); setArgumentsText('{"product":"savings"}'); }}>Public rates</button>
        <button style={button} onClick={() => { setTool('simulated_customer_record_access'); setWorkflow('own_records'); setArgumentsText(JSON.stringify({ account_id: identity?.account_ids?.[0] || 'CUST_1001' }, null, 2)); }}>Own record</button>
        <button style={button} onClick={() => { setTool('simulated_external_export'); setWorkflow('audit_export'); setArgumentsText(JSON.stringify({ account_id: identity?.account_ids?.[0] || 'CUST_1001', destination: identity?.allowed_destinations?.[0] || 'internal://audit-vault', export_reason: 'Authorized audit' }, null, 2)); }}>Audit export</button>
      </div>
      <label style={{ color: 'var(--text)' }}>Workflow<select value={workflow} onChange={e => setWorkflow(e.target.value)} style={{ ...field, marginTop: '6px' }}>
        <option value="public_banking">Public banking</option><option value="own_records">Own records (requires account access)</option><option value="audit_export">Audit export (requires audit permission)</option>
      </select></label>
      <label style={{ color: 'var(--text)' }}>Proposed tool<select value={tool} onChange={e => setTool(e.target.value)} style={{ ...field, marginTop: '6px' }}>
        {['retrieve_bank_rates', 'search_public_documents', 'summarize_public_policy', 'simulated_customer_record_access', 'simulated_external_export', 'send_external_email', 'transfer_funds'].map(value => <option key={value}>{value}</option>)}
      </select></label>
      <label style={{ color: 'var(--text)' }}>Arguments (JSON)<textarea value={argumentsText} onChange={e => setArgumentsText(e.target.value)} rows={6} style={{ ...field, display: 'block', marginTop: '6px', fontFamily: 'monospace' }} /></label>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <button style={button} disabled={loading || !identity} onClick={() => run(false)}>Evaluate policy</button>
        <button style={{ ...button, background: 'var(--border)' }} disabled={loading || !identity} onClick={() => run(true)}>Execute synthetic tool</button>
      </div>
      <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--muted)' }}>Selecting a workflow requests that scope; the server decides whether your identity may use it. Money transfers and external email are unavailable.</p>
    </section>
    {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
    {verdict && <section className="panel" style={{ padding: '1.25rem' }}>
      <strong style={{ color: verdict.authorized ? 'var(--success)' : 'var(--danger)' }}>{verdict.authorized ? 'AUTHORIZED' : 'DENIED'} · {verdict.policy_code}</strong>
      <p style={{ color: 'var(--text)' }}>{verdict.decision_reason}</p>
      {'executed' in result && <p style={{ color: 'var(--muted)' }}>Execution: {result.executed ? 'Completed' : 'Did not run'}{result.error ? ` · ${result.error}` : ''}</p>}
      {result.result && <pre style={{ color: 'var(--muted)', whiteSpace: 'pre-wrap' }}>{JSON.stringify(result.result, null, 2)}</pre>}
    </section>}
  </div>;
}
