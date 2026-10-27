import React, { useCallback, useEffect, useState } from 'react';
import { apiRequest } from '../api.js';

export function useGatewayIdentity() {
  const [identity, setIdentity] = useState(null);
  const [error, setError] = useState('');
  const refresh = useCallback(async () => {
    setIdentity(null);
    try {
      setIdentity(await apiRequest('/api/v1/security/identity'));
      setError('');
    } catch (err) {
      setIdentity(null);
      setError(err.message);
    }
  }, []);
  useEffect(() => {
    refresh();
    window.addEventListener('kavach-auth-change', refresh);
    return () => window.removeEventListener('kavach-auth-change', refresh);
  }, [refresh]);
  return { identity, error, refresh };
}

export default function AccessSession({ identity, error, disabled = false }) {
  const [token, setToken] = useState(() => sessionStorage.getItem('kavach.accessToken') || '');
  const apply = () => {
    if (token.trim()) sessionStorage.setItem('kavach.accessToken', token.trim());
    else sessionStorage.removeItem('kavach.accessToken');
    window.dispatchEvent(new Event('kavach-auth-change'));
  };
  return (
    <section className="panel session-panel" style={{ padding: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.7rem', alignItems: 'end', flexWrap: 'wrap' }}>
        <label style={{ flex: 1, minWidth: '220px', color: 'var(--muted)', fontSize: '0.8rem' }}>
          Access token (optional for public questions)
          <input type="password" autoComplete="off" disabled={disabled} value={token} onChange={e => setToken(e.target.value)}
            style={{ ...field, display: 'block', marginTop: '6px' }} placeholder="Enter a token configured by the server administrator" />
        </label>
        <button type="button" disabled={disabled} onClick={apply} style={button}>Use this session</button>
      </div>
      <p style={{ color: 'var(--muted)', fontSize: '0.8rem', margin: '0.7rem 0 0' }}>
        {identity ? `Signed in as ${identity.principal_id} · ${identity.role} · Accounts: ${identity.account_ids?.join(', ') || 'public only'}` : error ? 'Identity unavailable' : 'Checking identity…'}
      </p>
      {error && <p role="alert" style={{ color: 'var(--danger)', marginBottom: 0 }}>{error}</p>}
      <p style={{ color: 'var(--muted)', fontSize: '0.75rem', marginBottom: 0 }}>Tokens are kept for this browser tab only. Permissions and account access are assigned by the server.</p>
    </section>
  );
}

export const field = { width: '100%', background: 'var(--surface)', color: 'var(--text)', padding: '10px 12px', border: '1px solid var(--surface-raised)', borderRadius: '4px', boxSizing: 'border-box' };
export const button = { background: 'var(--action)', color: 'var(--text)', border: 0, borderRadius: '4px', padding: '11px 16px', cursor: 'pointer', fontWeight: 600 };
