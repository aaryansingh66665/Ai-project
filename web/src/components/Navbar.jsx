import React, { useState, useEffect } from 'react';
import { ShieldAlert, Shield, Search, FileText, Bot, Zap, Radar, Wifi, WifiOff, Lock } from 'lucide-react';

const TABS = [
  { id: 'swarm',  label: 'SWARM',   icon: Zap    },
  { id: 'threat', label: 'THREAT',  icon: Shield  },
  { id: 'nmap',   label: 'NETWORK', icon: Radar   },
  { id: 'search', label: 'SEARCH',  icon: Search  },
  { id: 'rag',    label: 'DOCS',    icon: FileText },
  { id: 'agents', label: 'AGENTS',  icon: Bot     },
];

function LiveClock() {
  const [time, setTime] = useState({ h:'00', m:'00', s:'00', ms:'000' });
  useEffect(() => {
    const id = setInterval(() => {
      const d = new Date();
      setTime({
        h:  String(d.getHours()).padStart(2,'0'),
        m:  String(d.getMinutes()).padStart(2,'0'),
        s:  String(d.getSeconds()).padStart(2,'0'),
        ms: String(d.getMilliseconds()).padStart(3,'0'),
      });
    }, 50);
    return () => clearInterval(id);
  }, []);
  return (
    <div style={{ fontFamily:'Share Tech Mono,monospace', letterSpacing:2, display:'flex', alignItems:'baseline', gap:1 }}>
      <span style={{ fontSize:'0.95rem', color:'var(--p-blue)', textShadow:'0 0 10px rgba(0,200,248,0.7)' }}>
        {time.h}:{time.m}:{time.s}
      </span>
      <span style={{ fontSize:'0.6rem', color:'rgba(0,200,248,0.35)', marginLeft:2 }}>.{time.ms}</span>
    </div>
  );
}

/* Random flicker char for "boot" label */
function GlitchLabel({ children, color = 'var(--p-blue)' }) {
  return (
    <span className="glitch" style={{ fontFamily:'Orbitron,monospace', color, fontWeight:700, fontSize:'1.05rem', letterSpacing:'3px', textShadow:`0 0 14px ${color}80, 0 0 28px ${color}40` }}>
      {children}
    </span>
  );
}

export default function Navbar({ activeTab, setActiveTab, ollamaOnline }) {
  const [bootText, setBootText] = useState('INITIALIZING');
  useEffect(() => {
    const msgs = ['INITIALIZING','LOADING AGENTS','CUDA ACTIVE','SYSTEM READY'];
    let i = 0;
    const id = setInterval(() => { i = (i + 1) % msgs.length; setBootText(msgs[i]); }, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <header style={{
      position:'sticky', top:0, zIndex:100,
      background:'rgba(0,2,6,0.97)',
      backdropFilter:'blur(24px)',
      borderBottom:'1px solid rgba(0,200,248,0.14)',
      boxShadow:'0 0 40px rgba(0,200,248,0.07)',
    }}>
      {/* ── Top accent ── */}
      <div style={{ height:2, background:'linear-gradient(90deg,transparent 0%,var(--p-purple) 15%,var(--p-blue) 30%,var(--p-cyan) 50%,var(--p-blue) 70%,var(--p-purple) 85%,transparent 100%)', opacity:0.7 }} />

      <div style={{ maxWidth:1800, margin:'0 auto', padding:'0 24px', display:'flex', alignItems:'stretch', height:58 }}>

        {/* ── Brand ── */}
        <div style={{ display:'flex', alignItems:'center', gap:14, paddingRight:24, borderRight:'1px solid rgba(0,200,248,0.08)' }}>
          {/* Multi-ring logo */}
          <div style={{ position:'relative', width:44, height:44, flexShrink:0 }}>
            <svg width="44" height="44" style={{ position:'absolute', inset:0, animation:'spin-s 12s linear infinite' }}>
              <circle cx="22" cy="22" r="20" fill="none" stroke="rgba(0,200,248,0.2)" strokeWidth="1" strokeDasharray="3 5" />
            </svg>
            <svg width="44" height="44" style={{ position:'absolute', inset:0, animation:'spin-r 7s linear infinite' }}>
              <circle cx="22" cy="22" r="15" fill="none" stroke="rgba(0,255,148,0.2)" strokeWidth="1" strokeDasharray="2 6" />
            </svg>
            <svg width="44" height="44" style={{ position:'absolute', inset:0, animation:'spin-s 4s linear infinite' }}>
              <circle cx="22" cy="22" r="10" fill="none" stroke="rgba(191,64,255,0.3)" strokeWidth="1" strokeDasharray="1 4" />
            </svg>
            <div style={{ position:'absolute', top:10, left:10, right:10, bottom:10, background:'rgba(0,200,248,0.08)', border:'1px solid var(--p-blue)', display:'flex', alignItems:'center', justifyContent:'center', boxShadow:'0 0 16px rgba(0,200,248,0.5), inset 0 0 8px rgba(0,200,248,0.15)' }}>
              <ShieldAlert size={13} color="var(--p-blue)" strokeWidth={2.5} style={{ filter:'drop-shadow(0 0 4px var(--p-blue))' }} />
            </div>
          </div>

          <div>
            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
              <GlitchLabel color="var(--p-blue)">CYBERAGENT X</GlitchLabel>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.58rem', color:'var(--p-purple)', border:'1px solid rgba(191,64,255,0.35)', padding:'1px 6px', letterSpacing:'1px' }}>v2.0</span>
            </div>
            <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.6rem', color:'rgba(0,200,248,0.55)', letterSpacing:'1.5px', marginTop:1 }}>
              {bootText}
              <span style={{ animation:'blink 0.7s step-end infinite', color:'var(--p-blue)' }}>_</span>
            </div>
          </div>
        </div>

        {/* ── Tabs ── */}
        <nav style={{ display:'flex', alignItems:'stretch', flex:1 }}>
          {TABS.map(({ id, label, icon:Icon }) => {
            const active = activeTab === id;
            return (
              <button key={id} onClick={() => setActiveTab(id)}
                style={{
                  display:'flex', alignItems:'center', gap:7,
                  padding:'0 20px',
                  border:'none',
                  borderBottom: active ? '2px solid var(--p-blue)' : '2px solid transparent',
                  background: active ? 'rgba(0,200,248,0.07)' : 'transparent',
                  color: active ? 'var(--p-blue)' : 'rgba(0,200,248,0.55)',
                  fontFamily:'Orbitron,monospace', fontWeight:600,
                  fontSize:'0.62rem', letterSpacing:'2px',
                  textTransform:'uppercase', cursor:'pointer',
                  transition:'all 0.2s ease',
                  textShadow: active ? '0 0 10px rgba(0,200,248,0.6)' : 'none',
                  boxShadow: active ? 'inset 0 -4px 12px rgba(0,200,248,0.1)' : 'none',
                  position:'relative',
                }}
                onMouseEnter={e => { if (!active) { e.currentTarget.style.color='rgba(0,200,248,0.85)'; e.currentTarget.style.background='rgba(0,200,248,0.04)'; } }}
                onMouseLeave={e => { if (!active) { e.currentTarget.style.color='rgba(0,200,248,0.55)'; e.currentTarget.style.background='transparent'; } }}
              >
                <Icon size={12} style={{ filter: active ? 'drop-shadow(0 0 4px var(--p-blue))' : 'none' }} />
                <span>{label}</span>
                {active && <span style={{ position:'absolute', bottom:0, left:'25%', right:'25%', height:2, background:'var(--p-blue)', boxShadow:'0 0 10px var(--p-blue), 0 0 20px rgba(0,200,248,0.5)' }} />}
              </button>
            );
          })}
        </nav>

        {/* ── Status Right ── */}
        <div style={{ display:'flex', alignItems:'center', gap:18, paddingLeft:20, borderLeft:'1px solid rgba(0,200,248,0.08)' }}>
          <LiveClock />

          {/* System vitals */}
          {[
            { label:'CUDA', color:'var(--p-green)', on:true },
            { label:'VRAM', color:'var(--p-blue)',  on:true },
            { label:'GPU', color:'var(--p-amber)',  on:true },
          ].map(v => (
            <div key={v.label} style={{ display:'flex', alignItems:'center', gap:5 }}>
              <span style={{ width:5, height:5, borderRadius:'50%', background:v.on ? v.color:'var(--p-red)', boxShadow:`0 0 8px ${v.on ? v.color:'var(--p-red)'}`, display:'inline-block', animation:'phud 1.5s infinite' }} />
              <span style={{ fontFamily:'Orbitron,monospace', fontSize:'0.52rem', letterSpacing:'1px', color:v.on ? v.color:'var(--p-red)' }}>{v.label}</span>
            </div>
          ))}

          <div style={{ display:'flex', alignItems:'center', gap:6, padding:'4px 12px', border:`1px solid ${ollamaOnline ? 'rgba(0,255,148,0.3)' : 'rgba(255,30,60,0.3)'}`, background:ollamaOnline ? 'rgba(0,255,148,0.05)' : 'rgba(255,30,60,0.05)' }}>
            {ollamaOnline ? <Wifi size={10} color="var(--p-green)" /> : <WifiOff size={10} color="var(--p-red)" />}
            <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.6rem', color:ollamaOnline ? 'var(--p-green)':'var(--p-red)', letterSpacing:'0.5px' }}>
              {ollamaOnline ? ':11434' : 'OFFLINE'}
            </span>
          </div>

          <Lock size={13} color="rgba(0,200,248,0.3)" />
        </div>
      </div>

      {/* ── Bottom accent ── */}
      <div style={{ height:1, background:'linear-gradient(90deg,transparent,rgba(0,200,248,0.25) 30%,rgba(0,200,248,0.25) 70%,transparent)' }} />
    </header>
  );
}
