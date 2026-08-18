import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import GpuMeter from './components/GpuMeter';
import SwarmVisualizer from './components/SwarmVisualizer';
import SearchHub from './components/SearchHub';
import RagIngestor from './components/RagIngestor';
import AgentPlayground from './components/AgentPlayground';
import NmapScannerHub from './components/NmapScannerHub';

export default function App() {
  const [activeTab, setActiveTab] = useState('swarm');
  const [gpuStats, setGpuStats] = useState(null);
  const [ollamaOnline, setOllamaOnline] = useState(true);

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/status');
      if (res.ok) {
        const data = await res.json();
        setGpuStats(data.gpu);
        setOllamaOnline(data.ollama_online);
      }
    } catch (e) {
      console.error('Status fetch failed:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleSendToSwarm = (result) => {
    setActiveTab('swarm');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} ollamaOnline={ollamaOnline} />

      {/* Main Content Area */}
      <main style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px', flex: 1 }}>
        
        {/* GPU HUD Bar */}
        <GpuMeter gpu={gpuStats} onRefresh={fetchStatus} />

        {/* View Routing */}
        {activeTab === 'swarm' && <SwarmVisualizer />}
        {activeTab === 'nmap' && <NmapScannerHub onSendToSwarm={handleSendToSwarm} />}
        {activeTab === 'search' && <SearchHub />}
        {activeTab === 'rag' && <RagIngestor />}
        {activeTab === 'agents' && <AgentPlayground />}

      </main>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid var(--border-dim)', padding: '16px 24px', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        CyberAgent X — 100% Offline Multi-Agent System on NVIDIA RTX 3050 (6GB VRAM) • Zero Telemetry • Zero Restrictions
      </footer>

    </div>
  );
}
