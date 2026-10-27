import { backendMissing } from './api.js';
import React, { useState, useRef, useEffect } from 'react';
import SecurityOverview from './components/SecurityOverview.jsx';
import PromptAnalyzer from './components/PromptAnalyzer.jsx';
import RAGInspector from './components/RAGInspector.jsx';
import ToolMonitor from './components/ToolMonitor.jsx';
import BenchmarkExplorer from './components/BenchmarkExplorer.jsx';
import ConfigManager from './components/ConfigManager.jsx';
import AttackSandbox from './components/AttackSandbox.jsx';
import ProtectedWorkflow from './components/ProtectedWorkflow.jsx';

const groups = [
  ['Workspace', [['overview', 'Security overview']]],
  ['Inspect', [['analyzer', 'Prompt analyzer'], ['rag', 'Retrieved documents'], ['tool', 'Tool permissions']]],
  ['Research', [['benchmark', 'Evaluation results'], ['sandbox', 'Attack simulation'], ['config', 'Configuration']]],
  ['Examples', [['assistant', 'Banking workflow demo']]],
];
export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [menuOpen, setMenuOpen] = useState(false);
  const main = useRef(null);
  const firstRender = useRef(true);
  useEffect(() => { if (firstRender.current) firstRender.current = false; else main.current?.focus(); }, [activeTab]);
  const navigate = id => { setActiveTab(id); setMenuOpen(false); };
  const label = groups.flatMap(([, items]) => items).find(([id]) => id === activeTab)[1];
  return <div className="app-shell">
    <a className="skip-link" href="#workspace">Skip to workspace</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark" aria-hidden="true">K</span><div><strong>KAVACH</strong><small>Prompt-injection research</small></div></div>
      <button className="menu-toggle" aria-expanded={menuOpen} aria-controls="workspace-nav" onClick={() => setMenuOpen(!menuOpen)}>Navigation {menuOpen ? '−' : '+'}</button>
      <nav id="workspace-nav" aria-label="Workspace" className={menuOpen ? 'nav-groups is-open' : 'nav-groups'}>
        {groups.map(([title, items]) => <div className="nav-group" key={title}><p>{title}</p>{items.map(([id, name]) => <button key={id} aria-current={activeTab === id ? 'page' : undefined} onClick={() => navigate(id)}>{name}</button>)}</div>)}
      </nav>
      <div className="sidebar-note"><span>RESEARCH ENVIRONMENT</span><p>Banking examples and tool actions use synthetic data.</p></div>
    </aside>
    <div className="workspace-shell">
      <header className="workspace-header"><span>Security console / <strong>{label}</strong></span><span className="environment-label">Local console</span></header>
      <main id="workspace" ref={main} tabIndex={-1} className="workspace">
        <div hidden={!backendMissing} role="status" className="deployment-notice">Public interface preview. Connect the hosted backend to enable inspections, model generation, and tools.</div>
        <h1 className="sr-only">{label}</h1>
        {activeTab === 'assistant' && <ProtectedWorkflow />}
        {activeTab === 'overview' && <SecurityOverview onNavigate={navigate} />}
        {activeTab === 'analyzer' && <PromptAnalyzer onAnalyzed={() => {}} />}
        {activeTab === 'rag' && <RAGInspector />}
        {activeTab === 'tool' && <ToolMonitor />}
        {activeTab === 'benchmark' && <BenchmarkExplorer />}
        {activeTab === 'sandbox' && <AttackSandbox />}
        {activeTab === 'config' && <ConfigManager />}
      </main>
      <footer className="workspace-footer">KAVACH <span>Inspection decisions are evidence, not a guarantee of safety.</span></footer>
    </div>
  </div>;
}
