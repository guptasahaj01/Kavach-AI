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
  const [error, setError] = useState('');
  const interpretations = {
    ATTACK_SUCCEEDED: 'The programmed response included a marker and the output filter was off. This is a simulated outcome.',
    BLOCKED_BY_GUARDRAIL: 'The deterministic output filter marked the simulated response for withholding.',
    NEUTRALIZED_BY_HARDENING: 'The programmed susceptibility rule did not emit a marker in this trial. This does not establish hardening effectiveness.',
    CLEAN_BENIGN_RESPONSE: 'The simulator returned its benign response template. Banking answer accuracy has not been evaluated.',
  };

  const handleSimulate = async () => {
    setLoading(true);
    setError('');
    setSimResult(null);
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
      if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Simulation request failed');
      setSimResult(data);
      if (onAttackComplete) onAttackComplete();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* 1. Header */}
      <div className="panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
          <Flame size={20} color="var(--danger)" />
          <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text)' }}>
            Research simulation sandbox
          </h2>
        </div>
        <p style={{ color: 'var(--muted)', fontSize: '0.88rem' }}>
          Explore a programmed susceptibility model using the <code style={{ color: 'var(--accent)' }}>KAVACH-7731</code> canary and poisoned banking documents. Outcomes are simulated; they do not establish real model vulnerability or defense effectiveness.
        </p>

        {/* 2. Controls Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 200px), 1fr))', gap: '1rem', marginTop: '1.25rem' }}>
          <div>
            <label htmlFor="attacksandbox-field-1" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Attack Scenario
            </label>
            <select id="attacksandbox-field-1"
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--canvas)',
                border: '1px solid var(--border)',
                color: 'var(--text)',
                padding: '9px 12px',
                borderRadius: '4px',
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
            <label htmlFor="attacksandbox-field-2" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Retrieval Depth (k)
            </label>
            <select id="attacksandbox-field-2"
              value={k}
              onChange={(e) => setK(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--canvas)',
                border: '1px solid var(--border)',
                color: 'var(--text)',
                padding: '9px 12px',
                borderRadius: '4px',
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
            <label htmlFor="attacksandbox-field-3" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Chunk Size
            </label>
            <select id="attacksandbox-field-3"
              value={chunkSize}
              onChange={(e) => setChunkSize(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--canvas)',
                border: '1px solid var(--border)',
                color: 'var(--text)',
                padding: '9px 12px',
                borderRadius: '4px',
                fontSize: '0.85rem'
              }}
            >
              <option value={256}>256 words</option>
              <option value={512}>512 words</option>
              <option value={1024}>1024 words</option>
            </select>
          </div>

          <div>
            <label htmlFor="attacksandbox-field-4" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Prompt Hardening
            </label>
            <select id="attacksandbox-field-4"
              value={hardening}
              onChange={(e) => setHardening(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--canvas)',
                border: '1px solid var(--border)',
                color: 'var(--text)',
                padding: '9px 12px',
                borderRadius: '4px',
                fontSize: '0.85rem'
              }}
            >
              <option value="none">None (Naive Customer Prompt)</option>
              <option value="instructional">Instructional (Security Warning)</option>
              <option value="sandwich">Sandwich (Pre + Post Isolation)</option>
            </select>
          </div>

          <div>
            <label htmlFor="attacksandbox-field-5" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Output Guardrail
            </label>
            <select id="attacksandbox-field-5"
              value={guardrail}
              onChange={(e) => setGuardrail(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--canvas)',
                border: '1px solid var(--border)',
                color: 'var(--text)',
                padding: '9px 12px',
                borderRadius: '4px',
                fontSize: '0.85rem'
              }}
            >
              <option value="on">Guardrail ON (deterministic output patterns)</option>
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
            background: 'var(--action)',
            border: 'none',
            color: 'var(--text)',
            padding: '12px',
            borderRadius: '4px',
            fontWeight: 700,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            boxShadow: 'none'
          }}
        >
          <Play size={18} />
          {loading ? 'Running RAG Retrieval & Guardrail Pipeline...' : 'Run research simulation'}
        </button>
      </div>

      {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
      {/* 3. Execution Pipeline Result View */}
      {simResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Outcome Banner */}
          <div style={{
            padding: '1.25rem',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem',
            background: simResult.outcome === 'ATTACK_SUCCEEDED' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
            border: `1.5px solid ${simResult.outcome === 'ATTACK_SUCCEEDED' ? 'var(--danger)' : 'var(--success)'}`
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {simResult.outcome === 'ATTACK_SUCCEEDED' ? (
                <XCircle size={28} color="var(--danger)" />
              ) : (
                <CheckCircle2 size={28} color="var(--success)" />
              )}
              <div>
                <div style={{
                  fontSize: '1rem',
                  fontWeight: 800,
                  color: simResult.outcome === 'ATTACK_SUCCEEDED' ? 'var(--danger)' : 'var(--success)',
                  letterSpacing: '0.04em'
                }}>
                  SIMULATED: {(simResult.outcome || 'unknown').replace(/_/g, ' ')}
                </div>
                <div style={{ color: 'var(--text)', fontSize: '0.85rem' }}>
                  {interpretations[simResult.outcome] || 'No interpretation is available for this simulation result.'}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem' }}>
              <span style={{
                padding: '4px 10px',
                borderRadius: '4px',
                background: 'rgba(0,0,0,0.4)',
                color: simResult.canary_emitted ? 'var(--danger)' : 'var(--success)',
                fontWeight: 700
              }}>
                Canary: {simResult.canary_emitted ? 'EMITTED (LEAK)' : 'CLEAN'}
              </span>
              <span style={{
                padding: '4px 10px',
                borderRadius: '4px',
                background: 'rgba(0,0,0,0.4)',
                color: simResult.secret_leaked ? 'var(--danger)' : 'var(--success)',
                fontWeight: 700
              }}>
                Secret: {simResult.secret_leaked ? 'PRESENT IN SIMULATED OUTPUT' : 'NOT OBSERVED'}
              </span>
              <span style={{ padding: '4px 10px', borderRadius: '4px', background: 'rgba(0,0,0,0.4)', color: 'var(--accent)', fontWeight: 600 }}>
                Simulation runtime: {simResult.total_latency_ms} ms
              </span>
            </div>
          </div>

          {/* 4 Pipeline Steps in Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '1rem' }}>
            {/* Step 1: Query & RAG Retrieval */}
            <div className="panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)' }}>STEP 1: RAG RETRIEVAL</span>
                <span style={{ fontSize: '0.7rem', color: simResult.has_poisoned_chunk ? 'var(--danger)' : 'var(--success)' }}>
                  {simResult.has_poisoned_chunk ? 'Poisoned Twin Retrieved' : 'No poisoned candidate retrieved'}
                </span>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text)', fontWeight: 600, marginBottom: '0.5rem' }}>
                {simResult.query}
              </p>
              <div style={{ fontSize: '0.75rem', color: 'var(--muted)', maxHeight: '140px', overflowY: 'auto', background: 'rgba(0,0,0,0.25)', padding: '8px', borderRadius: '6px' }}>
                {(simResult.retrieved_chunks_preview || []).map((chunk, i) => (
                  <div key={i} style={{ marginBottom: '6px', borderLeft: '2px solid var(--accent)', paddingLeft: '6px' }}>
                    <strong>Chunk {i + 1}:</strong> {chunk}
                  </div>
                ))}
              </div>
            </div>

            {/* Step 2: Pre-LLM Kavach Inspection */}
            <div className="panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)' }}>STEP 2: CONTEXT OBSERVATION</span>
                <span style={{
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  color: simResult.flagged_chunk_count ? 'var(--danger)' : 'var(--success)'
                }}>
                  {simResult.flagged_chunk_count ? 'INJECTION DETECTED' : 'NO CHUNKS FLAGGED'}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text)', lineHeight: '1.5' }}>
                <div>Flagged Chunks: <strong>{simResult.flagged_chunk_count}</strong></div>
                <div>Hardening: <strong>{(simResult.hardening || 'unknown').toUpperCase()}</strong></div>
                <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--muted)' }}>
                  {simResult.hardening === 'sandwich'
                    ? 'Applied pre- and post-retrieval boundary wrappers to mitigate recency bias.'
                    : simResult.hardening === 'instructional'
                    ? 'Appended security directive without post-context boundaries.'
                    : 'Naive system prompt used; no boundary defense applied.'}
                </div>
              </div>
            </div>

            {/* Step 3: LLM Response */}
            <div className="panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)' }}>STEP 3: SIMULATED GENERATION</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--accent)' }}>Programmed simulation</span>
              </div>
              <div style={{
                fontSize: '0.8rem',
                color: simResult.canary_emitted ? 'var(--danger)' : 'var(--text)',
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
            <div className="panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)' }}>STEP 4: OUTPUT GUARDRAIL</span>
                <span style={{
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  color: simResult.output_guardrail.blocked ? 'var(--danger)' : 'var(--success)'
                }}>
                  {simResult.output_guardrail.blocked ? 'WOULD BE WITHHELD' : 'WOULD BE RELEASED'}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text)' }}>
                <div>Status: <strong>{simResult.output_guardrail.reason}</strong></div>
                <div>Guardrail Latency: <strong>{simResult.output_guardrail.latency_ms} ms</strong></div>
                {simResult.output_guardrail.blocked && (
                  <div style={{ marginTop: '0.5rem', color: 'var(--success)', fontSize: '0.75rem' }}>
                    The simulated response matched an output-blocking rule.
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
