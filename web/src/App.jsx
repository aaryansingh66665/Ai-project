import React, { useState, useEffect } from 'react';
import CanvasBackground from './components/CanvasBackground';
import Navbar from './components/Navbar';
import GpuDashboard from './components/GpuDashboard';
import SwarmVisualizer from './components/SwarmVisualizer';
import SearchHub from './components/SearchHub';
import RagIngestor from './components/RagIngestor';
import AgentPlayground from './components/AgentPlayground';
import NmapScannerHub from './components/NmapScannerHub';
import ThreatIntelHub from './components/ThreatIntelHub';

export default function App() {
  const [activeTab, setActiveTab]           = useState('swarm');
  const [gpuStats, setGpuStats]             = useState(null);
  const [ollamaOnline, setOllamaOnline]     = useState(true);
  const [swarmInitQuery, setSwarmInitQuery] = useState('');

  const fetchStatus = async () => {
    try {
      const res  = await fetch('/api/status');
      if (res.ok) { const d = await res.json(); setGpuStats(d.gpu); setOllamaOnline(d.ollama_online); }
    } catch(e) {}
  };

  useEffect(() => { fetchStatus(); const id = setInterval(fetchStatus, 4000); return () => clearInterval(id); }, []);

  return (
    <>
      {/* Animated canvas — deep void + hex grid + matrix rain + particles */}
      <CanvasBackground />

      <div style={{ minHeight:'100vh', display:'flex', flexDirection:'column', position:'relative', zIndex:1 }}>
        <Navbar activeTab={activeTab} setActiveTab={setActiveTab} ollamaOnline={ollamaOnline} />

        <main style={{ maxWidth:1700, width:'100%', margin:'0 auto', padding:'18px 24px 36px', display:'flex', flexDirection:'column', gap:16, flex:1 }}>
          <GpuDashboard gpu={gpuStats} ollamaOnline={ollamaOnline} onRefresh={fetchStatus} />
          {activeTab === 'swarm'  && <SwarmVisualizer initialQuery={swarmInitQuery} />}
          {activeTab === 'threat' && <ThreatIntelHub onSendToSwarm={q => { setSwarmInitQuery(q); setActiveTab('swarm'); }} />}
          {activeTab === 'nmap'   && <NmapScannerHub onSendToSwarm={() => setActiveTab('swarm')} />}
          {activeTab === 'search' && <SearchHub />}
          {activeTab === 'rag'    && <RagIngestor />}
          {activeTab === 'agents' && <AgentPlayground />}
        </main>

        <footer style={{ borderTop:'1px solid rgba(0,200,248,0.08)', padding:'12px 24px', textAlign:'center', fontFamily:'Share Tech Mono,monospace', fontSize:'0.62rem', color:'rgba(0,200,248,0.2)', letterSpacing:'0.5px' }}>
          CYBERAGENT X · OFFLINE · RTX 3050 6GB VRAM · CUDA 13.2 · ZERO TELEMETRY · 100% LOCAL
        </footer>
      </div>
    </>
  );
}
