import React, { useEffect, useRef } from 'react';
import { Cpu, Thermometer, Trash2, RefreshCw, Wifi, WifiOff, Zap, HardDrive, Activity } from 'lucide-react';

/* ── Radar Sweep SVG ─────────────────────────────── */
function RadarSweep({ pct, color, size = 110 }) {
  const sweepRef = useRef(null);
  useEffect(() => {
    if (!sweepRef.current) return;
    let angle = 0;
    const id = setInterval(() => {
      angle = (angle + 2) % 360;
      sweepRef.current.setAttribute('transform', `rotate(${angle} ${size/2} ${size/2})`);
    }, 16);
    return () => clearInterval(id);
  }, [size]);

  const r = size / 2 - 8;
  const cx = size / 2, cy = size / 2;
  const rings = [r * 0.35, r * 0.6, r * 0.85, r];
  const ticks = Array.from({ length: 36 }, (_, i) => {
    const a = (i / 36) * Math.PI * 2 - Math.PI / 2;
    const outerR = r + 2;
    const innerR = r - (i % 3 === 0 ? 8 : 4);
    return {
      x1: cx + outerR * Math.cos(a), y1: cy + outerR * Math.sin(a),
      x2: cx + innerR * Math.cos(a), y2: cy + innerR * Math.sin(a),
      bold: i % 9 === 0,
    };
  });
  const fillPct = Math.min(pct, 100) / 100;
  const fillAngle = fillPct * Math.PI * 2 - Math.PI / 2;
  const arcX = cx + r * Math.cos(fillAngle);
  const arcY = cy + r * Math.sin(fillAngle);
  const largeArc = fillPct > 0.5 ? 1 : 0;

  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      {/* Rings */}
      {rings.map((rv, i) => (
        <circle key={i} cx={cx} cy={cy} r={rv} fill="none"
          stroke={`rgba(0,200,248,${0.06 + i * 0.02})`} strokeWidth={i === rings.length - 1 ? 1 : 0.5} />
      ))}
      {/* Cross hairs */}
      <line x1={cx - r - 5} y1={cy} x2={cx + r + 5} y2={cy} stroke="rgba(0,200,248,0.07)" strokeWidth="0.5" />
      <line x1={cx} y1={cy - r - 5} x2={cx} y2={cy + r + 5} stroke="rgba(0,200,248,0.07)" strokeWidth="0.5" />
      {/* Tick marks */}
      {ticks.map((t, i) => (
        <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2}
          stroke={t.bold ? 'rgba(0,200,248,0.35)' : 'rgba(0,200,248,0.12)'}
          strokeWidth={t.bold ? 1.2 : 0.6} />
      ))}
      {/* Fill arc */}
      {fillPct > 0 && fillPct < 1 && (
        <path d={`M ${cx} ${cy - r} A ${r} ${r} 0 ${largeArc} 1 ${arcX} ${arcY}`}
          fill="none" stroke={color} strokeWidth="5" strokeLinecap="butt"
          style={{ filter: `drop-shadow(0 0 4px ${color})`, transition: 'all 0.8s ease' }} />
      )}
      {fillPct === 1 && (
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="5"
          style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
      )}
      {/* Radar sweep */}
      <g ref={sweepRef}>
        <path d={`M ${cx} ${cy} L ${cx} ${cy - r} A ${r} ${r} 0 0 1 ${cx + r * Math.sin(Math.PI / 8)} ${cy - r * Math.cos(Math.PI / 8)} Z`}
          fill={`rgba(0,200,248,0.06)`} />
        <line x1={cx} y1={cy} x2={cx} y2={cy - r}
          stroke="rgba(0,200,248,0.45)" strokeWidth="1.5"
          style={{ filter: 'drop-shadow(0 0 3px rgba(0,200,248,0.8))' }} />
      </g>
      {/* Blip dots */}
      {[0.4, 0.65, 0.82].map((rv, i) => {
        const a = [1.2, 2.8, 0.7][i];
        return <circle key={i} cx={cx + rv * r * Math.cos(a)} cy={cy + rv * r * Math.sin(a)} r={2}
          fill={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />;
      })}
      {/* Center */}
      <circle cx={cx} cy={cy} r={2.5} fill={color} style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
      {/* Center value */}
      <text x={cx} y={cy - 6} textAnchor="middle" style={{ fill: color, fontSize: 16, fontFamily: 'Orbitron,monospace', fontWeight: 800 }}>{Math.round(pct)}</text>
      <text x={cx} y={cy + 10} textAnchor="middle" style={{ fill: 'rgba(0,200,248,0.35)', fontSize: 7, fontFamily: 'Share Tech Mono,monospace', letterSpacing: 1 }}>PCT</text>
    </svg>
  );
}

/* ── Waveform bar chart ─────────────────────────── */
function WaveBar({ value = 0, max = 100, color }) {
  const bars = 24;
  const filled = Math.round((value / max) * bars);
  return (
    <div style={{ display:'flex', gap:2, alignItems:'flex-end', height:28 }}>
      {Array.from({ length: bars }, (_, i) => {
        const h = 4 + Math.abs(Math.sin(i * 0.4 + Date.now() * 0.001)) * 20;
        const on = i < filled;
        return (
          <div key={i} style={{
            width: 3,
            height: on ? Math.max(4, h) : 4,
            background: on ? color : 'rgba(0,200,248,0.06)',
            boxShadow: on ? `0 0 4px ${color}` : 'none',
            transition: 'height 0.3s ease',
          }} />
        );
      })}
    </div>
  );
}

/* ── Stat column ─────────────────────────────────── */
function StatCol({ label, value, unit, color, sub }) {
  return (
    <div style={{ textAlign:'center', minWidth:70 }}>
      <div style={{ fontFamily:'Orbitron,monospace', fontSize:'0.48rem', letterSpacing:'1.5px', color:'rgba(0,200,248,0.3)', textTransform:'uppercase', marginBottom:4 }}>{label}</div>
      <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'1.3rem', fontWeight:700, color, textShadow:`0 0 14px ${color}80`, lineHeight:1 }}>
        {value}<span style={{ fontSize:'0.6rem', marginLeft:2 }}>{unit}</span>
      </div>
      {sub && <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.55rem', color:'rgba(0,200,248,0.25)', marginTop:3 }}>{sub}</div>}
    </div>
  );
}

/* ══════════════════════════════════════════════════
   GpuDashboard
══════════════════════════════════════════════════ */
export default function GpuDashboard({ gpu, ollamaOnline, onRefresh }) {
  const [unloading, setUnloading] = React.useState(false);
  const [tick, setTick] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 100);
    return () => clearInterval(id);
  }, []);

  const handleUnload = async () => {
    setUnloading(true);
    try { await fetch('/api/gpu/unload', { method:'POST' }); if (onRefresh) onRefresh(); }
    catch(e){ console.error(e); }
    finally { setUnloading(false); }
  };

  const usedPct = gpu?.used_pct  ?? 0;
  const temp    = gpu?.temp_c    ?? 0;
  const tempPct = Math.min((temp / 95) * 100, 100);
  const freeMb  = (gpu?.total_mb ?? 6144) - (gpu?.used_mb ?? 0);
  const vc = usedPct > 85 ? 'var(--p-red)' : usedPct > 65 ? 'var(--p-amber)' : 'var(--p-cyan)';
  const tc = temp    > 80 ? 'var(--p-red)' : temp    > 65 ? 'var(--p-amber)' : 'var(--p-green)';

  return (
    <div className="glass-panel" style={{ padding:'20px 26px' }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:18 }}>
        <div style={{ display:'flex', alignItems:'center', gap:14 }}>
          {/* Triple-ring CPU icon */}
          <div style={{ position:'relative', width:52, height:52 }}>
            <svg width="52" height="52" style={{ position:'absolute', inset:0, animation:'spin-s 15s linear infinite' }}>
              <circle cx="26" cy="26" r="24" fill="none" stroke="rgba(0,200,248,0.18)" strokeWidth="1" strokeDasharray="3 5" />
            </svg>
            <svg width="52" height="52" style={{ position:'absolute', inset:0, animation:'spin-r 9s linear infinite' }}>
              <circle cx="26" cy="26" r="18" fill="none" stroke="rgba(0,255,148,0.15)" strokeWidth="1" strokeDasharray="2 6" />
            </svg>
            <div style={{ position:'absolute', top:10, left:10, right:10, bottom:10, background:'rgba(0,200,248,0.08)', border:'1px solid var(--p-blue)', display:'flex', alignItems:'center', justifyContent:'center', boxShadow:'0 0 16px rgba(0,200,248,0.4), inset 0 0 10px rgba(0,200,248,0.1)' }}>
              <Cpu size={16} color="var(--p-blue)" style={{ filter:'drop-shadow(0 0 4px var(--p-blue))' }} />
            </div>
          </div>
          <div>
            <div style={{ fontFamily:'Orbitron,monospace', fontWeight:800, fontSize:'0.65rem', letterSpacing:'3px', color:'var(--p-blue)', textShadow:'0 0 12px rgba(0,200,248,0.6)', textTransform:'uppercase' }}>
              GPU ACCELERATION MATRIX
            </div>
            <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.8rem', color:'var(--p-white)', marginTop:3 }}>
              {gpu?.name ?? 'NVIDIA GeForce RTX 3050 · 6GB VRAM · CUDA 13.2'}
            </div>
          </div>
        </div>

        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          <div style={{ padding:'5px 12px', border:`1px solid ${ollamaOnline ? 'rgba(0,255,148,0.3)' : 'rgba(255,30,60,0.3)'}`, background:ollamaOnline ? 'rgba(0,255,148,0.05)':'rgba(255,30,60,0.05)', display:'flex', gap:7, alignItems:'center' }}>
            {ollamaOnline ? <Wifi size={11} color="var(--p-green)" /> : <WifiOff size={11} color="var(--p-red)" />}
            <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.65rem', color:ollamaOnline ? 'var(--p-green)':'var(--p-red)' }}>
              {ollamaOnline ? 'OLLAMA // ONLINE' : 'OLLAMA // OFFLINE'}
            </span>
          </div>
          <button onClick={onRefresh} className="cyber-btn cyber-btn-secondary" style={{ padding:'5px 11px' }}><RefreshCw size={11} /></button>
          <button onClick={handleUnload} disabled={unloading} className="cyber-btn cyber-btn-danger" style={{ padding:'5px 13px' }}>
            <Trash2 size={11} /> {unloading ? 'FLUSHING...' : 'FLUSH VRAM'}
          </button>
        </div>
      </div>

      {/* Main metrics */}
      <div style={{ display:'flex', alignItems:'center', gap:28, flexWrap:'wrap' }}>
        {/* Radar gauges */}
        <div style={{ display:'flex', gap:20 }}>
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
            <RadarSweep pct={usedPct} color={vc} size={110} />
            <div style={{ fontFamily:'Orbitron,monospace', fontSize:'0.52rem', letterSpacing:'1.5px', color:'rgba(0,200,248,0.4)', textTransform:'uppercase' }}>VRAM USAGE</div>
          </div>
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
            <RadarSweep pct={tempPct} color={tc} size={110} />
            <div style={{ fontFamily:'Orbitron,monospace', fontSize:'0.52rem', letterSpacing:'1.5px', color:'rgba(0,200,248,0.4)', textTransform:'uppercase' }}>TEMPERATURE</div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ width:1, height:100, background:'linear-gradient(to bottom,transparent,rgba(0,200,248,0.2),transparent)', flexShrink:0 }} />

        {/* Right stats panel */}
        <div style={{ flex:1, minWidth:220, display:'flex', flexDirection:'column', gap:14 }}>
          {/* VRAM bar with waveform */}
          <div>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:5 }}>
              <span style={{ fontFamily:'Orbitron,monospace', fontSize:'0.5rem', letterSpacing:'1.5px', color:'rgba(0,200,248,0.4)' }}>VRAM ALLOCATION</span>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.72rem', color:vc, textShadow:`0 0 8px ${vc}80` }}>{usedPct}%</span>
            </div>
            {/* Waveform visualization */}
            <WaveBar value={usedPct} max={100} color={vc} />
            <div className="progress-bar-track" style={{ height:3, marginTop:4 }}>
              <div className="progress-bar-fill" style={{ width:`${usedPct}%`, background:`linear-gradient(90deg,rgba(0,200,248,0.6),${vc})`, boxShadow:`0 0 10px ${vc}80` }} />
            </div>
            <div style={{ display:'flex', justifyContent:'space-between', marginTop:4 }}>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.58rem', color:'rgba(255,30,60,0.7)' }}>USED: {gpu?.used_mb ?? 0} MB</span>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.58rem', color:'var(--p-green)' }}>FREE: {freeMb} MB</span>
            </div>
          </div>

          {/* Stats row */}
          <div style={{ display:'flex', gap:0, justifyContent:'space-around', background:'rgba(0,200,248,0.03)', border:'1px solid rgba(0,200,248,0.08)', padding:'10px 0' }}>
            <StatCol label="Core Temp"  value={temp}     unit="°C" color={tc} sub="GPU Die" />
            <div style={{ width:1, background:'rgba(0,200,248,0.08)' }} />
            <StatCol label="Free VRAM"  value={freeMb}   unit="MB" color="var(--p-green)"  sub="Available" />
            <div style={{ width:1, background:'rgba(0,200,248,0.08)' }} />
            <StatCol label="Capacity"   value={gpu?.total_mb ?? 6144} unit="MB" color="var(--p-blue)"  sub="Total" />
            <div style={{ width:1, background:'rgba(0,200,248,0.08)' }} />
            <StatCol label="CUDA"       value="13.2"     unit=""   color="var(--p-purple)" sub="Driver" />
          </div>
        </div>
      </div>
    </div>
  );
}
