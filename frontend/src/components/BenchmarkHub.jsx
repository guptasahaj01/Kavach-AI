import React, { useState, useEffect } from 'react';
import { 
  FileText, BarChart3, Download, Filter, 
  TrendingUp, Shield, CheckCircle, AlertTriangle 
} from 'lucide-react';

export default function BenchmarkHub() {
  const [tableData, setTableData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [summary, setSummary] = useState(null);
  const [filterK, setFilterK] = useState('all');
  const [filterHardening, setFilterHardening] = useState('all');
  const [filterGuardrail, setFilterGuardrail] = useState('all');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('table'); // 'table', 'figure2', 'figure3'

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [tableRes, sumRes] = await Promise.all([
        fetch('/api/benchmark/table'),
        fetch('/api/benchmark/summary')
      ]);
      const tableJson = await tableRes.json();
      const sumJson = await sumRes.json();

      setTableData(tableJson.data || []);
      setFilteredData(tableJson.data || []);
      setSummary(sumJson);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let res = [...tableData];
    if (filterK !== 'all') {
      res = res.filter(r => r.k === parseInt(filterK, 10));
    }
    if (filterHardening !== 'all') {
      res = res.filter(r => r.Hardening.toLowerCase() === filterHardening.toLowerCase());
    }
    if (filterGuardrail !== 'all') {
      res = res.filter(r => r.Guardrail.toLowerCase() === filterGuardrail.toLowerCase());
    }
    setFilteredData(res);
  }, [filterK, filterHardening, filterGuardrail, tableData]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* 1. Header Banner */}
      <div className="glass-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <FileText size={18} color="#3D71FF" />
              <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#3D71FF', textTransform: 'uppercase' }}>
                KAVACH-AI RESEARCH DATA ENGINE
              </span>
            </div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#FFFFFF' }}>
              Empirical Measurement Study (72 Configurations &times; 200 Trials)
            </h2>
            <p style={{ color: '#94A3B8', fontSize: '0.88rem' }}>
              Black-box evaluation of Indian banking RAG chatbots across retrieval depth, chunk size, prompt hardening, and output safety layers.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <a 
              href="/outputs/table_1_matrix.csv" 
              download="kavach_table_1_matrix.csv"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid rgba(255,255,255,0.15)',
                color: '#E2E8F0',
                padding: '8px 14px',
                borderRadius: '8px',
                fontSize: '0.8rem',
                fontWeight: 600,
                textDecoration: 'none'
              }}
            >
              <Download size={14} /> Download Table I (CSV)
            </a>
          </div>
        </div>

        {/* 2. Research Key Findings Summary Cards */}
        {summary && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1rem', marginTop: '1.25rem' }}>
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 700 }}>Total Executed Trials</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#FFFFFF', marginTop: '4px' }}>14,400</div>
              <div style={{ fontSize: '0.75rem', color: '#10B981', marginTop: '2px' }}>72 configs &times; (100 poisoned + 100 benign)</div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 700 }}>Hardening Impact (RQ3)</div>
              <div style={{ fontSize: '0.85rem', color: '#CBD5E1', marginTop: '6px', lineHeight: '1.5' }}>
                None: <strong style={{ color: '#EF4444' }}>{summary.avg_asr_by_hardening.none}%</strong> | 
                Inst: <strong style={{ color: '#F59E0B' }}>{summary.avg_asr_by_hardening.instructional}%</strong> | 
                Sandwich: <strong style={{ color: '#10B981' }}>{summary.avg_asr_by_hardening.sandwich}%</strong>
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 700 }}>Retrieval Depth Impact (RQ1)</div>
              <div style={{ fontSize: '0.85rem', color: '#CBD5E1', marginTop: '6px', lineHeight: '1.5' }}>
                k=1: <strong style={{ color: '#10B981' }}>{summary.avg_asr_by_depth_k['1']}%</strong> &rarr; 
                k=10: <strong style={{ color: '#EF4444' }}>{summary.avg_asr_by_depth_k['10']}%</strong>
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ fontSize: '0.75rem', color: '#64748B', textTransform: 'uppercase', fontWeight: 700 }}>Optimal Defense Setup</div>
              <div style={{ fontSize: '0.82rem', color: '#10B981', fontWeight: 700, marginTop: '6px' }}>
                Sandwich + Guardrail ON
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>0.0% ASR at 3.0% Benign FPR cost</div>
            </div>
          </div>
        )}
      </div>

      {/* 3. Navigation Tabs: Table I vs Figure 2 vs Figure 3 */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem' }}>
        <button
          onClick={() => setActiveTab('table')}
          style={{
            background: activeTab === 'table' ? '#3D71FF' : 'transparent',
            color: '#FFFFFF',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '0.85rem',
            fontWeight: 700,
            cursor: 'pointer'
          }}
        >
          Table I: Configuration Matrix (72 Rows)
        </button>
        <button
          onClick={() => setActiveTab('figure2')}
          style={{
            background: activeTab === 'figure2' ? '#3D71FF' : 'transparent',
            color: '#FFFFFF',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '0.85rem',
            fontWeight: 700,
            cursor: 'pointer'
          }}
        >
          Figure 2: ASR vs Retrieval Depth (k)
        </button>
        <button
          onClick={() => setActiveTab('figure3')}
          style={{
            background: activeTab === 'figure3' ? '#3D71FF' : 'transparent',
            color: '#FFFFFF',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '0.85rem',
            fontWeight: 700,
            cursor: 'pointer'
          }}
        >
          Figure 3: Security-Usability Trade-off
        </button>
      </div>

      {/* Tab Content 1: Table I */}
      {activeTab === 'table' && (
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          {/* Filters Bar */}
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#64748B', fontSize: '0.8rem', fontWeight: 700 }}>
              <Filter size={14} /> FILTERS:
            </div>

            <select
              value={filterK}
              onChange={(e) => setFilterK(e.target.value)}
              style={{ background: '#0D121F', border: '1px solid rgba(255,255,255,0.1)', color: '#E2E8F0', padding: '6px 10px', borderRadius: '6px', fontSize: '0.8rem' }}
            >
              <option value="all">All Depth (k)</option>
              <option value="1">k = 1</option>
              <option value="3">k = 3</option>
              <option value="5">k = 5</option>
              <option value="10">k = 10</option>
            </select>

            <select
              value={filterHardening}
              onChange={(e) => setFilterHardening(e.target.value)}
              style={{ background: '#0D121F', border: '1px solid rgba(255,255,255,0.1)', color: '#E2E8F0', padding: '6px 10px', borderRadius: '6px', fontSize: '0.8rem' }}
            >
              <option value="all">All Hardening</option>
              <option value="none">None</option>
              <option value="instructional">Instructional</option>
              <option value="sandwich">Sandwich</option>
            </select>

            <select
              value={filterGuardrail}
              onChange={(e) => setFilterGuardrail(e.target.value)}
              style={{ background: '#0D121F', border: '1px solid rgba(255,255,255,0.1)', color: '#E2E8F0', padding: '6px 10px', borderRadius: '6px', fontSize: '0.8rem' }}
            >
              <option value="all">All Guardrails</option>
              <option value="off">Guardrail OFF</option>
              <option value="on">Guardrail ON</option>
            </select>

            <span style={{ fontSize: '0.75rem', color: '#94A3B8', marginLeft: 'auto' }}>
              Showing <strong>{filteredData.length}</strong> of 72 configurations
            </span>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '550px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
              <thead style={{ position: 'sticky', top: 0, background: '#0D121F', zIndex: 1 }}>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#64748B', textTransform: 'uppercase' }}>
                  <th style={{ padding: '8px' }}>Cfg</th>
                  <th style={{ padding: '8px' }}>k</th>
                  <th style={{ padding: '8px' }}>Chunk</th>
                  <th style={{ padding: '8px' }}>Hardening</th>
                  <th style={{ padding: '8px' }}>Guardrail</th>
                  <th style={{ padding: '8px' }}>N (pois)</th>
                  <th style={{ padding: '8px', color: '#EF4444' }}>ASR % [95% CI]</th>
                  <th style={{ padding: '8px' }}>Leak % [95% CI]</th>
                  <th style={{ padding: '8px', color: '#F59E0B' }}>Benign FPR %</th>
                  <th style={{ padding: '8px' }}>Latency</th>
                  <th style={{ padding: '8px' }}>Flag</th>
                </tr>
              </thead>
              <tbody>
                {filteredData.map((row) => (
                  <tr key={row.Cfg} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '8px', fontFamily: 'monospace', fontWeight: 700, color: '#3D71FF' }}>{row.Cfg}</td>
                    <td style={{ padding: '8px' }}>{row.k}</td>
                    <td style={{ padding: '8px' }}>{row['Chunk (tokens)']}</td>
                    <td style={{ padding: '8px', textTransform: 'capitalize' }}>
                      <span style={{
                        color: row.Hardening === 'sandwich' ? '#10B981' : row.Hardening === 'instructional' ? '#F59E0B' : '#EF4444'
                      }}>
                        {row.Hardening}
                      </span>
                    </td>
                    <td style={{ padding: '8px', textTransform: 'uppercase', color: row.Guardrail === 'on' ? '#10B981' : '#94A3B8' }}>
                      {row.Guardrail}
                    </td>
                    <td style={{ padding: '8px' }}>{row['N (poisoned)']}</td>
                    <td style={{ padding: '8px', fontWeight: 600, color: row['ASR %'] <= 10.0 ? '#10B981' : '#EF4444' }}>
                      {row['ASR % [95% CI]']}
                    </td>
                    <td style={{ padding: '8px' }}>{row['Leak % [95% CI]']}</td>
                    <td style={{ padding: '8px' }}>{row['Benign FPR % [95% CI]']}</td>
                    <td style={{ padding: '8px', fontFamily: 'monospace', color: '#00F0FF' }}>{row['Latency (ms)']}</td>
                    <td style={{ padding: '8px' }}>
                      {row.Flag === 'GOOD' ? (
                        <span style={{ background: 'rgba(16,185,129,0.2)', color: '#10B981', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                          GOOD
                        </span>
                      ) : (
                        <span style={{ color: '#475569' }}>nan</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab Content 2: Figure 2 */}
      {activeTab === 'figure2' && (
        <div className="glass-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.5rem' }}>
            Figure 2 — Attack Success Rate vs Retrieval Depth k (RQ1 & RQ3)
          </h3>
          <p style={{ color: '#94A3B8', fontSize: '0.85rem', marginBottom: '1.25rem', maxWidth: '750px', margin: '0 auto 1.5rem' }}>
            Empirical evidence showing that as retrieval depth k increases from 1 to 10, ASR increases under naive prompts due to higher context noise and attention dilution, whereas Sandwich Hardening consistently keeps ASR under control.
          </p>
          <div style={{ background: '#FFFFFF', padding: '1rem', borderRadius: '12px', display: 'inline-block', maxWidth: '100%' }}>
            <img 
              src="/api/benchmark/figures/figure_2_asr_vs_k.png" 
              alt="Figure 2: ASR vs Retrieval Depth k" 
              style={{ maxWidth: '100%', height: 'auto', borderRadius: '8px' }} 
            />
          </div>
        </div>
      )}

      {/* Tab Content 3: Figure 3 */}
      {activeTab === 'figure3' && (
        <div className="glass-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.5rem' }}>
            Figure 3 — Security-Usability Trade-off (RQ3 & RQ4)
          </h3>
          <p style={{ color: '#94A3B8', fontSize: '0.85rem', marginBottom: '1.25rem', maxWidth: '750px', margin: '0 auto 1.5rem' }}>
            Pareto frontier mapping security failure (ASR %) against usability cost (Benign False Positive Rate %). Highlights the trade-off incurred when pairing prompt hardening with secondary classification guardrails.
          </p>
          <div style={{ background: '#FFFFFF', padding: '1rem', borderRadius: '12px', display: 'inline-block', maxWidth: '100%' }}>
            <img 
              src="/api/benchmark/figures/figure_3_security_usability.png" 
              alt="Figure 3: Security-Usability Trade-off" 
              style={{ maxWidth: '100%', height: 'auto', borderRadius: '8px' }} 
            />
          </div>
        </div>
      )}
    </div>
  );
}
