import React from 'react';
import { ShieldAlert, Search, FileText, Bot, Terminal, Zap, Radar } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, ollamaOnline }) {
  const tabs = [
    { id: 'swarm', label: 'Swarm Orchestrator', icon: Zap },
    { id: 'nmap', label: 'Network Recon', icon: Radar },
    { id: 'search', label: 'Unrestricted Search', icon: Search },
    { id: 'rag', label: 'Document RAG', icon: FileText },
    { id: 'agents', label: 'Agent Playground', icon: Bot },
  ];


  return (
    <header style={{ borderBottom: '1px solid var(--border-dim)', background: 'rgba(7, 9, 14, 0.85)', backdropFilter: 'blur(12px)', position: 'sticky', top: 0, zIndex: 50 }}>
      <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Brand Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'linear-gradient(135deg, var(--neon-cyan), var(--neon-green))', padding: '8px', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldAlert size={22} color="#07090e" strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: '800', letterSpacing: '1px', background: 'linear-gradient(90deg, #00e5ff, #00ff88)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                CYBERAGENT X
              </span>
              <span className="badge-neon badge-purple" style={{ fontSize: '0.65rem' }}>OFFLINE GPU</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Unrestricted Multi-Agent Intelligence Platform
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-secondary)', padding: '4px', borderRadius: '10px', border: '1px solid var(--border-dim)' }}>
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: 'none',
                  background: isActive ? 'linear-gradient(135deg, rgba(0, 229, 255, 0.2), rgba(0, 255, 136, 0.15))' : 'transparent',
                  color: isActive ? 'var(--neon-cyan)' : 'var(--text-secondary)',
                  fontWeight: isActive ? '600' : '500',
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  borderBottom: isActive ? '2px solid var(--neon-cyan)' : '2px solid transparent',
                }}
              >
                <Icon size={16} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Status Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="badge-neon badge-green">
            <span className="pulse-dot" />
            <span>CUDA ENGINE ONLINE</span>
          </div>
        </div>

      </div>
    </header>
  );
}
