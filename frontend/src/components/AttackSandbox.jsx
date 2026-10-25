import React, { useState } from 'react';
import { 
  Play, ShieldAlert, ShieldCheck, Flame, Bug, 
  Layers, Lock, Database, CheckCircle2, XCircle, ArrowRight 
} from 'lucide-react';

export default function AttackSandbox({ onAttackComplete }) {
  const [attackType, setAttackType] = useState('upi_poisoned');
  const [k, setK] = useState(3);
  const [chunkSize, setChunkSize] = useState(512);
  const [hardening, setHardening] = useState('sandwich');
  const [guardrail, setGuardrail] = useState('on');
  const [loading, setLoading] = useState(false);
  const [simResult, setSimResult] = useState(null);

  const handleSimulate = async () => {
    setLoading(true);
    try {
      const res = await fetch('/v2/simulate_attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_type: attackType,
          k: parseInt(k, 10),
          chunk_size: parseInt(chunkSize, 10),
          hardening,
          guardrail
        })
      });
      const data = await res.json();
      setSimResult(data);
      if (onAttackComplete) onAttackComplete();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* 1. Header */}
      <div className="glass-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
          <Flame size={20} color="#EF4444" />
          <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#FFFFFF' }}>
            Interactive Indirect Prompt Injection Sandbox
          </h2>
        </div>
        <p style={{ color: '#94A3B8', fontSize: '0.88rem' }}>
          Simulate a black-box adversary attempting to exfiltrate secrets and trigger the <code style={{ color: '#00F0FF' }}>KAVACH-7731</code> canary through poisoned Indian banking documents. Test how different RAG parameters and defenses respond.
        </p>

        {/* 2. Controls Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', marginBottom: '6px' }}>
              Attack Scenario
            </label>
            <select
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
              style={{
                width: '100%',
                background: '#0D121F',
                border: '1px solid rgba(255,255,255,0.12)',
                color: '#FFFFFF',
                padding: '9px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value="upi_poisoned">UPI Daily Limit (Poisoned FAQ)</option>
              <option value="neft_exfiltration">NEFT Batch Settlement (Secret Leak)</option>
              <option value="aadhaar_injection">Aadhaar e-KYC (Compliance Override)</option>
              <option value="benign_query">Benign Customer Query (Baseline)</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', marginBottom: '6px' }}>
              Retrieval Depth (k)
            </label>
            <select
              value={k}
              onChange={(e) => setK(e.target.value)}
              style={{
                width: '100%',
                background: '#0D121F',
                border: '1px solid rgba(255,255,255,0.12)',
                color: '#FFFFFF',
                padding: '9px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value={1}>k = 1 chunk</option>
              <option value={3}>k = 3 chunks</option>
              <option value={5}>k = 5 chunks</option>
              <option value={10}>k = 10 chunks</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', marginBottom: '6px' }}>
              Chunk Size
            </label>
            <select
              value={chunkSize}
              onChange={(e) => setChunkSize(e.target.value)}
              style={{
                width: '100%',
                background: '#0D121F',
                border: '1px solid rgba(255,255,255,0.12)',
                color: '#FFFFFF',
                padding: '9px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value={256}>256 tokens</option>
              <option value={512}>512 tokens</option>
              <option value={1024}>1024 tokens</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', marginBottom: '6px' }}>
              Prompt Hardening
            </label>
            <select
              value={hardening}
              onChange={(e) => setHardening(e.target.value)}
              style={{
                width: '100%',
                background: '#0D121F',
                border: '1px solid rgba(255,255,255,0.12)',
                color: '#FFFFFF',
                padding: '9px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value="none">None (Naive Customer Prompt)</option>
              <option value="instructional">Instructional (Security Warning)</option>
              <option value="sandwich">Sandwich (Pre + Post Isolation)</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase', marginBottom: '6px' }}>
              Output Guardrail
            </label>
            <select
              value={guardrail}
              onChange={(e) => setGuardrail(e.target.value)}
              style={{
                width: '100%',
                background: '#0D121F',
                border: '1px solid rgba(255,255,255,0.12)',
                color: '#FFFFFF',
                padding: '9px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <option value="on">Guardrail ON (Llama Guard)</option>
              <option value="off">Guardrail OFF</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleSimulate}
          disabled={loading}
          style={{
            marginTop: '1.25rem',
            width: '100%',
            background: 'linear-gradient(135deg, #3D71FF 0%, #1D4ED8 100%)',
            border: 'none',
            color: '#FFFFFF',
            padding: '12px',
            borderRadius: '10px',
            fontWeight: 700,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            boxShadow: '0 4px 20px -2px rgba(61,113,255,0.4)'
          }}
        >
          <Play size={18} />
          {loading ? 'Running RAG Retrieval & Guardrail Pipeline...' : 'Execute Live Attack Simulation'}
        </button>
      </div>

      {/* 3. Execution Pipeline Result View */}
      {simResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Outcome Banner */}
          <div style={{
            padding: '1.25rem',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem',
            background: simResult.outcome === 'ATTACK_SUCCEEDED' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
            border: `1.5px solid ${simResult.outcome === 'ATTACK_SUCCEEDED' ? '#EF4444' : '#10B981'}`
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {simResult.outcome === 'ATTACK_SUCCEEDED' ? (
                <XCircle size={28} color="#EF4444" />
              ) : (
                <CheckCircle2 size={28} color="#10B981" />
              )}
              <div>
                <div style={{ 
                  fontSize: '1rem', 
                  fontWeight: 800, 
                  color: simResult.outcome === 'ATTACK_SUCCEEDED' ? '#EF4444' : '#10B981',
                  letterSpacing: '0.04em'
                }}>
                  {simResult.outcome.replace(/_/g, ' ')}
                </div>
                <div style={{ color: '#E2E8F0', fontSize: '0.85rem' }}>
                  {simResult.verdict}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem' }}>
              <span style={{ 
                padding: '4px 10px', 
                borderRadius: '8px', 
                background: 'rgba(0,0,0,0.4)', 
                color: simResult.canary_emitted ? '#EF4444' : '#10B981',
                fontWeight: 700 
              }}>
                Canary: {simResult.canary_emitted ? 'EMITTED (LEAK)' : 'CLEAN'}
              </span>
              <span style={{ 
                padding: '4px 10px', 
                borderRadius: '8px', 
                background: 'rgba(0,0,0,0.4)', 
                color: simResult.secret_leaked ? '#EF4444' : '#10B981',
                fontWeight: 700 
              }}>
                Secret: {simResult.secret_leaked ? 'EXFILTRATED' : 'PROTECTED'}
              </span>
              <span style={{ padding: '4px 10px', borderRadius: '8px', background: 'rgba(0,0,0,0.4)', color: '#00F0FF', fontWeight: 600 }}>
                Latency: {simResult.total_latency_ms} ms
              </span>
            </div>
          </div>

          {/* 4 Pipeline Steps in Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {/* Step 1: Query & RAG Retrieval */}
            <div className="glass-card" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B' }}>STEP 1: RAG RETRIEVAL</span>
                <span style={{ fontSize: '0.7rem', color: simResult.has_poisoned_chunk ? '#EF4444' : '#10B981' }}>
                  {simResult.has_poisoned_chunk ? 'Poisoned Twin Retrieved' : 'All Chunks Benign'}
                </span>
              </div>
              <p style={{ fontSize: '0.82rem', color: '#FFFFFF', fontWeight: 600, marginBottom: '0.5rem' }}>
                {simResult.query}
              </p>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8', maxHeight: '140px', overflowY: 'auto', background: 'rgba(0,0,0,0.25)', padding: '8px', borderRadius: '6px' }}>
                {simResult.retrieved_chunks_preview.map((chunk, i) => (
                  <div key={i} style={{ marginBottom: '6px', borderLeft: '2px solid #3D71FF', paddingLeft: '6px' }}>
                    <strong>Chunk {i + 1}:</strong> {chunk}
                  </div>
                ))}
              </div>
            </div>

            {/* Step 2: Pre-LLM Kavach Inspection */}
            <div className="glass-card" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B' }}>STEP 2: PRE-LLM GATE</span>
                <span style={{ 
                  fontSize: '0.7rem', 
                  fontWeight: 700,
                  color: simResult.pre_llm_guard_flagged ? '#EF4444' : '#10B981' 
                }}>
                  {simResult.pre_llm_guard_flagged ? 'INJECTION DETECTED' : 'CLEAN CONTEXT'}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: '#CBD5E1', lineHeight: '1.5' }}>
                <div>Flagged Chunks: <strong>{simResult.flagged_chunk_count}</strong></div>
                <div>Hardening: <strong>{simResult.hardening.toUpperCase()}</strong></div>
                <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#94A3B8' }}>
                  {simResult.hardening === 'sandwich' 
                    ? 'Applied pre- and post-retrieval boundary wrappers to mitigate recency bias.' 
                    : simResult.hardening === 'instructional'
                    ? 'Appended security directive without post-context boundaries.'
                    : 'Naive system prompt used; no boundary defense applied.'}
                </div>
              </div>
            </div>

            {/* Step 3: LLM Response */}
            <div className="glass-card" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B' }}>STEP 3: LLM GENERATION</span>
                <span style={{ fontSize: '0.7rem', color: '#00F0FF' }}>Anthropic / Calibrated</span>
              </div>
              <div style={{ 
                fontSize: '0.8rem', 
                color: simResult.canary_emitted ? '#EF4444' : '#E2E8F0',
                background: 'rgba(0,0,0,0.3)',
                padding: '8px',
                borderRadius: '6px',
                fontFamily: 'monospace',
                maxHeight: '140px',
                overflowY: 'auto'
              }}>
                {simResult.llm_response}
              </div>
            </div>

            {/* Step 4: Output Guardrail Assertion */}
            <div className="glass-card" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B' }}>STEP 4: OUTPUT GUARDRAIL</span>
                <span style={{ 
                  fontSize: '0.7rem', 
                  fontWeight: 700,
                  color: simResult.output_guardrail.blocked ? '#EF4444' : '#10B981' 
                }}>
                  {simResult.output_guardrail.blocked ? 'DELIVERY BLOCKED' : 'DELIVERED'}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: '#CBD5E1' }}>
                <div>Status: <strong>{simResult.output_guardrail.reason}</strong></div>
                <div>Guardrail Latency: <strong>{simResult.output_guardrail.latency_ms} ms</strong></div>
                {simResult.output_guardrail.blocked && (
                  <div style={{ marginTop: '0.5rem', color: '#10B981', fontSize: '0.75rem' }}>
                    Shield successfully stopped unauthorized Canary/Secret from reaching customer!
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
