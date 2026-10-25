import React, { useState } from 'react';
import { Lock, ShieldAlert, ShieldCheck, CheckCircle2, AlertOctagon, Terminal, ArrowRight } from 'lucide-react';

export default function ToolMonitor() {
  const [toolName, setToolName] = useState('retrieve_bank_rates');
  const [callerRole, setCallerRole] = useState('public_user');
  const [argsJson, setArgsJson] = useState('{\n  "product": "savings"\n}');
  const [loading, setLoading] = useState(false);
  const [decision, setDecision] = useState(null);

  const presets = [
    {
      label: 'Read-Only Tool (Public User) -> ALLOW',
      tool: 'retrieve_bank_rates',
      role: 'public_user',
      args: '{\n  "product": "savings"\n}'
    },
    {
      label: 'Public Document Search -> ALLOW',
      tool: 'search_public_documents',
      role: 'public_user',
      args: '{\n  "query": "cheque clearing timings"\n}'
    },
    {
      label: 'Unauthorized Record Access -> RBAC BLOCK',
      tool: 'simulated_customer_record_access',
      role: 'public_user',
      args: '{\n  "account_id": "CUST_1001"\n}'
    },
    {
      label: 'Authorized Record Access (Authenticated) -> ALLOW',
      tool: 'simulated_customer_record_access',
      role: 'authenticated_customer',
      args: '{\n  "account_id": "CUST_1001"\n}'
    },
    {
      label: 'Unapproved C2 Exfiltration -> DESTINATION BLOCK',
      tool: 'simulated_external_export',
      role: 'compliance_auditor',
      args: '{\n  "destination": "https://malicious-attacker-c2.com/dump",\n  "data_payload": "Customer account balance: Rs 45,000"\n}'
    },
    {
      label: 'Canary Exfiltration Attempt -> PAYLOAD BLOCK',
      tool: 'simulated_external_export',
      role: 'compliance_auditor',
      args: '{\n  "destination": "internal://audit-vault",\n  "data_payload": "Leaked secret key: SECRET_KEY_BANK_ALPHA_99 and canary KAVACH-7731"\n}'
    }
  ];

  const handleAuthorize = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    try {
      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(argsJson);
      } catch (err) {
        alert('Invalid JSON in arguments field');
        setLoading(false);
        return;
      }

      const res = await fetch('/api/v1/security/authorize-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool_name: toolName,
          caller_role: callerRole,
          arguments: parsedArgs
        })
      });
      const data = await res.json();
      setDecision(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>Runtime Tool Security Policy Engine (Layer 5)</h2>
        <p style={{ color: '#94A3B8', fontSize: '0.85rem', margin: '0.25rem 0 0' }}>
          Deterministic pre-execution authorization gate. Evaluates RBAC, destination allowlists, and argument schemas independently of LLM decisions.
        </p>
      </div>

      {/* Preset Scenarios */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {presets.map((p, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => {
              setToolName(p.tool);
              setCallerRole(p.role);
              setArgsJson(p.args);
            }}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: '#CBD5E1',
              padding: '6px 12px',
              borderRadius: '8px',
              fontSize: '0.78rem',
              cursor: 'pointer'
            }}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Form */}
      <form onSubmit={handleAuthorize} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '220px' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: '#94A3B8', marginBottom: '0.3rem' }}>Target Tool Action</label>
            <select
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              style={{
                width: '100%',
                background: '#0F172A',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#FFFFFF',
                padding: '8px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <optgroup label="Read-Only Tools (Public Allowlist)">
                <option value="retrieve_bank_rates">retrieve_bank_rates</option>
                <option value="search_public_documents">search_public_documents</option>
                <option value="summarize_public_policy">summarize_public_policy</option>
              </optgroup>
              <optgroup label="Restricted Tools (Privileged Access)">
                <option value="simulated_customer_record_access">simulated_customer_record_access</option>
                <option value="simulated_external_export">simulated_external_export</option>
                <option value="send_external_email">send_external_email</option>
                <option value="transfer_funds">transfer_funds</option>
              </optgroup>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: '180px' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: '#94A3B8', marginBottom: '0.3rem' }}>Caller Identity Role</label>
            <select
              value={callerRole}
              onChange={(e) => setCallerRole(e.target.value)}
              style={{
                width: '100%',
                background: '#0F172A',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#FFFFFF',
                padding: '8px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value="public_user">public_user (Default Chatbot User)</option>
              <option value="authenticated_customer">authenticated_customer</option>
              <option value="compliance_auditor">compliance_auditor</option>
              <option value="admin">admin</option>
            </select>
          </div>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', color: '#94A3B8', marginBottom: '0.3rem' }}>Tool Arguments (JSON Payload)</label>
          <textarea
            value={argsJson}
            onChange={(e) => setArgsJson(e.target.value)}
            rows={4}
            style={{
              width: '100%',
              background: '#0F172A',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#FFFFFF',
              padding: '10px 14px',
              borderRadius: '8px',
              fontSize: '0.9rem',
              fontFamily: 'monospace'
            }}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          style={{
            alignSelf: 'flex-start',
            background: 'linear-gradient(135deg, #6366F1 0%, #4F46E5 100%)',
            border: 'none',
            color: '#FFFFFF',
            padding: '10px 20px',
            borderRadius: '8px',
            fontWeight: 600,
            fontSize: '0.9rem',
            cursor: loading ? 'not-allowed' : 'pointer'
          }}
        >
          {loading ? 'Evaluating Policy...' : 'Evaluate Tool Authorization'}
        </button>
      </form>

      {/* Decision Card */}
      {decision && (
        <div style={{
          background: 'rgba(15, 23, 42, 0.7)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          borderRadius: '12px',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span style={{ fontSize: '0.85rem', color: '#94A3B8' }}>Policy Verdict:</span>
              {decision.authorized ? (
                <span style={{ background: '#10B98122', color: '#10B981', border: '1px solid #10B98166', padding: '4px 12px', borderRadius: '8px', fontWeight: 700, fontSize: '0.85rem' }}>AUTHORIZED</span>
              ) : (
                <span style={{ background: '#EF444422', color: '#EF4444', border: '1px solid #EF444466', padding: '4px 12px', borderRadius: '8px', fontWeight: 700, fontSize: '0.85rem' }}>BLOCKED (POLICY DENIAL)</span>
              )}
              <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Policy Code: <strong style={{ color: '#FFFFFF' }}>{decision.policy_code}</strong></span>
            </div>
            <div style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
              Risk Level: <strong style={{ color: decision.risk_level === 'critical' ? '#EF4444' : (decision.risk_level === 'low' ? '#10B981' : '#F59E0B') }}>{decision.risk_level.toUpperCase()}</strong>
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: '8px', fontSize: '0.85rem', color: '#E2E8F0', borderLeft: decision.authorized ? '3px solid #10B981' : '3px solid #EF4444' }}>
            <strong>Authorization Reason:</strong> {decision.decision_reason}
          </div>

          {decision.violations?.length > 0 && (
            <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '10px 14px', borderRadius: '8px', fontSize: '0.8rem', color: '#FCA5A5' }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>Policy Violations:</div>
              {decision.violations.map((v, i) => (
                <div key={i}>• {v}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
