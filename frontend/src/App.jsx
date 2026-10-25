import React, { useState } from 'react';
import { 
  Shield, Activity, Terminal, Database, Lock, 
  BarChart2, Settings, Play, RefreshCw, Cpu 
} from 'lucide-react';

import SecurityOverview from './components/SecurityOverview.jsx';
import PromptAnalyzer from './components/PromptAnalyzer.jsx';
import RAGInspector from './components/RAGInspector.jsx';
import ToolMonitor from './components/ToolMonitor.jsx';
import BenchmarkExplorer from './components/BenchmarkExplorer.jsx';
import ConfigManager from './components/ConfigManager.jsx';
import AttackSandbox from './components/AttackSandbox.jsx';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');

  const navItems = [
    { id: 'overview', label: 'Security Overview', icon: Activity },
    { id: 'analyzer', label: 'Prompt Analyzer', icon: Terminal },
    { id: 'rag', label: 'RAG Inspector', icon: Database },
    { id: 'tool', label: 'Tool Security', icon: Lock },
    { id: 'benchmark', label: 'Benchmark Explorer', icon: BarChart2 },
    { id: 'sandbox', label: 'RAG Attack Sandbox', icon: Play },
    { id: 'config', label: 'Configuration', icon: Settings },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#090D16', color: '#F8FAFC', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <nav style={{
        background: 'rgba(15, 23, 42, 0.95)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        padding: '0.75rem 2rem'
      }}>
        <div style={{ maxWidth: '1440px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          {/* Logo & Brand */}
          <div 
            style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}
            onClick={() => setActiveTab('overview')}
          >
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #3B82F6 0%, #1D4ED8 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(59, 130, 246, 0.4)'
            }}>
              <Shield size={20} color="#FFFFFF" />
            </div>
            <div>
              <div style={{ fontSize: '1.05rem', fontWeight: 800, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span>KAVACH</span>
                <span style={{ fontSize: '0.7rem', background: 'rgba(59, 130, 246, 0.2)', color: '#60A5FA', border: '1px solid rgba(59, 130, 246, 0.3)', padding: '1px 6px', borderRadius: '4px' }}>
                  v2.0
                </span>
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94A3B8' }}>
                Context-Aware, Provenance-Driven AI Security Gateway
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '0.3rem', background: 'rgba(0,0,0,0.3)', padding: '3px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    background: isActive ? '#1E293B' : 'transparent',
                    color: isActive ? '#FFFFFF' : '#94A3B8',
                    border: 'none',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    fontWeight: isActive ? 600 : 500,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <Icon size={14} color={isActive ? '#38BDF8' : '#64748B'} />
                  {item.label}
                </button>
              );
            })}
          </div>

          {/* Status Indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: '#10B981', fontWeight: 600 }}>
            <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10B981' }}></span>
            <span>Gateway Online</span>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '1.75rem 2rem', flex: 1 }}>
        {activeTab === 'overview' && <SecurityOverview onNavigate={(tab) => setActiveTab(tab)} />}
        {activeTab === 'analyzer' && <PromptAnalyzer onAnalyzed={() => {}} />}
        {activeTab === 'rag' && <RAGInspector />}
        {activeTab === 'tool' && <ToolMonitor />}
        {activeTab === 'benchmark' && <BenchmarkExplorer />}
        {activeTab === 'sandbox' && <AttackSandbox />}
        {activeTab === 'config' && <ConfigManager />}
      </main>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid rgba(255, 255, 255, 0.06)', padding: '1.25rem 2rem', textAlign: 'center', fontSize: '0.75rem', color: '#64748B' }}>
        <div>KAVACH v2 — Context-Aware, Provenance-Driven AI Security Gateway for Indian Retail Banking RAG Systems.</div>
        <div style={{ marginTop: '4px' }}>Real Transformer Latency & Empirical Verification | No Fabricated Data</div>
      </footer>
    </div>
  );
}
