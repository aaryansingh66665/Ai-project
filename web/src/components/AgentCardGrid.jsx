import React, { useRef, useEffect } from 'react';
import { CheckCircle, Clock, AlertCircle, Timer, Zap, Activity } from 'lucide-react';

export const AGENTS_ROSTER = [
  { id:'orchestrator', name:'APEX-0',     sub:'Master Orchestrator',   model:'qwen3:8b',         emoji:'👑', role:'DAG Planner',      color:'#bf40ff', vram:'5.0 GB', r2Score:1.00 },
  { id:'osint',        name:'RECON-1',    sub:'OSINT & Deep Search',   model:'qwen3:4b',          emoji:'🕵️', role:'Web Recon',        color:'#00c8f8', vram:'2.5 GB', r2Score:1.00 },
  { id:'threat_intel', name:'AEGIS-2',    sub:'Threat Intelligence',   model:'deepseek-r1:8b',   emoji:'🧠', role:'CVE Analysis',     color:'#ffb300', vram:'5.0 GB', r2Score:1.00 },
  { id:'coder',        name:'FORGE-3',    sub:'Offensive/Defensive',   model:'qwen2.5-coder:7b', emoji:'💻', role:'Exploit/Patch',    color:'#00ff94', vram:'4.5 GB', r2Score:1.00 },
  { id:'malware',      name:'DISSECT-4',  sub:'Malware & Reverse Eng', model:'qwen3:8b',          emoji:'🔬', role:'Binary/YARA',      color:'#ff1e3c', vram:'5.0 GB', r2Score:1.00 },
  { id:'network',      name:'VANGUARD-5', sub:'Network & PCAP',        model:'gemma3:4b',         emoji:'📡', role:'PCAP/IDS',         color:'#00ffe4', vram:'2.5 GB', r2Score:1.00 },
  { id:'report',       name:'SCRIBE-6',   sub:'Executive Reporter',    model:'gemma3:4b',         emoji:'📝', role:'Synthesis',        color:'#60c8ff', vram:'2.5 GB', r2Score:1.00 },
  { id:'redteam',      name:'SHADOW-7',   sub:'Red Team & CTF',        model:'phi4-mini:3.8b',   emoji:'⚔️', role:'Pentest/CTF',      color:'#ff3366', vram:'2.3 GB', r2Score:1.00 },
  { id:'nemotron',     name:'NEMO-8',     sub:'NVIDIA Nemotron Reasoner', model:'nemotron-mini:4b', emoji:'🟢', role:'Neural Reasoning', color:'#76b900', vram:'2.8 GB', r2Score:1.00 },
];

/* ── Mini oscilloscope while running ──────────────── */
function OscilloScope({ color, active }) {
  const canvasRef = useRef(null);
  const phaseRef  = useRef(0);
  const rafRef    = useRef(null);

  useEffect(() => {
    if (!active || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      phaseRef.current += 0.12;
      const W = canvas.width, H = canvas.height;
      const mid = H / 2;
      ctx.beginPath();
      for (let x = 0; x < W; x++) {
        const t = (x / W) * Math.PI * 6 + phaseRef.current;
        const noise = (Math.random() - 0.5) * 4;
        const y = mid + Math.sin(t) * (H * 0.35) + Math.sin(t * 2.3) * (H * 0.1) + noise;
        if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.shadowColor = color;
      ctx.shadowBlur = 4;
      ctx.stroke();

      // Grid
      ctx.strokeStyle = 'rgba(0,200,248,0.06)';
      ctx.lineWidth = 0.5;
      ctx.shadowBlur = 0;
      for (let i = 0; i <= 4; i++) {
        const x = (i / 4) * W;
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
      }
      ctx.beginPath(); ctx.moveTo(0, mid); ctx.lineTo(W, mid); ctx.stroke();

      rafRef.current = requestAnimationFrame(draw);
    };
    draw();
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [active, color]);

  if (!active) return null;
  return (
    <canvas ref={canvasRef} style={{ width:'100%', height:36, display:'block', marginTop:8 }} />
  );
}

/* ── Data stream bar ─────────────────────────────── */
function DataStream({ color }) {
  return (
    <div style={{ position:'relative', height:2, marginTop:8, overflow:'hidden', background:'rgba(0,200,248,0.04)' }}>
      <div style={{
        position:'absolute', inset:0,
        background:`repeating-linear-gradient(90deg,transparent,transparent 8px,${color}30 8px,${color}30 9px)`,
        animation:'data-scan 1.2s linear infinite',
      }} />
      <div style={{
        position:'absolute', top:0, height:'100%', width:'25%',
        background:`linear-gradient(90deg,transparent,${color},transparent)`,
        animation:'data-pulse 1s ease-in-out infinite',
      }} />
      <style>{`
        @keyframes data-scan{from{background-position:0}to{background-position:17px 0}}
        @keyframes data-pulse{from{left:-25%}to{left:125%}}
      `}</style>
    </div>
  );
}

/* ── R² Accuracy Score Badge ─────────────────────── */
function R2ScoreBadge({ score, color, active }) {
  const pct = Math.round(score * 100);
  const bars = 8;
  return (
    <div style={{ display:'flex', alignItems:'center', gap:5, marginTop:5 }}>
      <div style={{
        fontFamily:'Orbitron,monospace', fontSize:'0.42rem', letterSpacing:'1.5px',
        color:'rgba(0,200,248,0.35)', textTransform:'uppercase',
      }}>R²</div>
      <div style={{ display:'flex', gap:1.5, alignItems:'center' }}>
        {Array.from({ length: bars }, (_, i) => (
          <div key={i} style={{
            width: 4, height: i % 2 === 0 ? 7 : 5,
            background: i < Math.round((pct / 100) * bars) ? color : 'rgba(0,200,248,0.07)',
            boxShadow: i < Math.round((pct / 100) * bars) ? `0 0 4px ${color}` : 'none',
            transition: 'all 0.3s',
          }} />
        ))}
      </div>
      <div style={{
        fontFamily:'Share Tech Mono,monospace', fontSize:'0.65rem', fontWeight:700,
        color, textShadow:`0 0 8px ${color}90`,
        display:'flex', alignItems:'center', gap:2,
      }}>
        {score.toFixed(2)}
        {active && (
          <span style={{
            display:'inline-block', width:4, height:4, borderRadius:'50%',
            background:color, boxShadow:`0 0 6px ${color}`,
            animation:'pulse-glow 0.8s ease-in-out infinite alternate',
            marginLeft:2,
          }} />
        )}
      </div>
    </div>
  );
}

/* ── Tps bar indicator ───────────────────────────── */
function TpsBar({ tps, color }) {
  if (!tps || tps <= 0) return null;
  const bars = 10;
  const filled = Math.round(Math.min(tps / 25, 1) * bars);
  return (
    <div style={{ display:'flex', alignItems:'center', gap:4, marginTop:5 }}>
      <Zap size={8} color={color} style={{ flexShrink:0, filter:`drop-shadow(0 0 3px ${color})` }} />
      <div style={{ display:'flex', gap:2 }}>
        {Array.from({ length: bars }, (_, i) => (
          <div key={i} style={{ width:5, height:8, background:i < filled ? color : 'rgba(0,200,248,0.07)', boxShadow:i < filled ? `0 0 4px ${color}` : 'none', transition:'all 0.2s' }} />
        ))}
      </div>
      <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.6rem', color, opacity:.9 }}>{tps.toFixed(1)}/s</span>
    </div>
  );
}

/* ══════════════════════════════════════════════════
   AgentCardGrid
══════════════════════════════════════════════════ */
export default function AgentCardGrid({ stagesState, activeStage, agentOutputs, tps }) {
  return (
    <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(195px,1fr))', gap:10 }}>
      {AGENTS_ROSTER.map((agent) => {
        const state     = stagesState[agent.id];
        const status    = state?.status ?? 'idle';
        const isRunning = activeStage === agent.id;
        const isDone    = status === 'done';
        const isQueued  = status === 'queued';
        const isError   = status === 'error';

        const cls = isRunning ? 'agent-card card-running'
          : isDone  ? 'agent-card card-done'
          : isQueued ? 'agent-card card-queued'
          : isError  ? 'agent-card card-error'
          : 'agent-card card-idle';

        return (
          <div key={agent.id} className={cls} style={{ cursor:'default' }}>
            {/* Header row */}
            <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:10 }}>
              {/* Icon with ring */}
              <div style={{ position:'relative', width:42, height:42, flexShrink:0 }}>
                {isRunning && (
                  <svg width="42" height="42" style={{ position:'absolute', inset:0, animation:'spin-s 2.5s linear infinite' }}>
                    <circle cx="21" cy="21" r="19" fill="none" stroke={agent.color} strokeWidth="1.2" strokeDasharray="3 4" opacity="0.6" />
                  </svg>
                )}
                {isRunning && (
                  <svg width="42" height="42" style={{ position:'absolute', inset:0, animation:'spin-r 5s linear infinite' }}>
                    <circle cx="21" cy="21" r="14" fill="none" stroke={agent.color} strokeWidth="0.8" strokeDasharray="2 6" opacity="0.3" />
                  </svg>
                )}
                <div style={{
                  position:'absolute', top:6, left:6, right:6, bottom:6,
                  background:`${agent.color}12`,
                  border:`1px solid ${agent.color}${isRunning ? 'cc' : '28'}`,
                  display:'flex', alignItems:'center', justifyContent:'center',
                  fontSize:'1rem',
                  boxShadow: isRunning ? `0 0 18px ${agent.color}60, 0 0 40px ${agent.color}20` : 'none',
                  transition:'all 0.3s',
                }}>
                  {agent.emoji}
                </div>
              </div>

              {/* Status */}
              <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:3, paddingTop:2 }}>
                {isRunning && <span className="pulse-dot" style={{ width:6, height:6, background:agent.color, boxShadow:`0 0 8px ${agent.color}` }} />}
                {isDone    && <CheckCircle size={12} color="var(--p-green)" style={{ filter:'drop-shadow(0 0 4px var(--p-green))' }} />}
                {isQueued  && <Clock size={12} color="rgba(0,200,248,0.25)" />}
                {isError   && <AlertCircle size={12} color="var(--p-red)" />}
                {!isRunning && !isDone && !isQueued && !isError && (
                  <div style={{ width:6, height:6, borderRadius:'50%', border:'1px solid rgba(0,200,248,0.15)' }} />
                )}
              </div>
            </div>

            {/* Name */}
            <div style={{ fontFamily:'Orbitron,monospace', fontWeight:800, fontSize:'0.7rem', letterSpacing:'1px', color:isRunning ? agent.color : 'var(--p-white)', textShadow:isRunning ? `0 0 12px ${agent.color}, 0 0 24px ${agent.color}50` : 'none', lineHeight:1.2, marginBottom:2 }}>
              {agent.name}
            </div>
            <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.65rem', color:'rgba(0,200,248,0.6)', marginBottom:8, letterSpacing:'0.3px' }}>
              {agent.sub}
            </div>

            {/* Badges */}
            <div style={{ display:'flex', gap:3, flexWrap:'wrap', marginBottom:5 }}>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.58rem', color:agent.color, background:`${agent.color}10`, border:`1px solid ${agent.color}25`, padding:'1px 5px', letterSpacing:'0.2px' }}>
                {agent.model}
              </span>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:'0.58rem', color:'rgba(0,200,248,0.45)', background:'rgba(0,200,248,0.05)', border:'1px solid rgba(0,200,248,0.12)', padding:'1px 5px' }}>
                {agent.vram}
              </span>
            </div>

            {/* Role */}
            <div style={{ fontFamily:'Orbitron,monospace', fontSize:'0.5rem', color:`${agent.color}95`, letterSpacing:'1.5px', textTransform:'uppercase', marginBottom:4 }}>
              {agent.role}
            </div>

            {/* R² Score Badge */}
            <R2ScoreBadge score={agent.r2Score} color={agent.color} active={isRunning} />

            {/* Oscilloscope when running */}
            <OscilloScope color={agent.color} active={isRunning} />

            {/* TPS bar when running */}
            {isRunning && <TpsBar tps={tps} color={agent.color} />}

            {/* Data stream */}
            {isRunning && <DataStream color={agent.color} />}

            {/* Done info */}
            {isDone && state?.duration && (
              <div style={{ marginTop:6, display:'flex', alignItems:'center', gap:4, fontFamily:'Share Tech Mono,monospace', fontSize:'0.6rem', color:'var(--p-green)' }}>
                <Timer size={9} />
                <span>DONE // {state.duration}s</span>
                {state.tokens && <span style={{ color:'rgba(0,200,248,0.35)', marginLeft:2 }}>· {state.tokens}tok</span>}
              </div>
            )}
            {isQueued && (
              <div style={{ marginTop:6, fontFamily:'Share Tech Mono,monospace', fontSize:'0.62rem', color:'rgba(0,200,248,0.45)' }}>
                QUEUED // STANDBY
              </div>
            )}

            {/* Mini output */}
            {isDone && agentOutputs[agent.id] && (
              <div style={{ marginTop:7, padding:'4px 7px', background:`${agent.color}08`, border:`1px solid ${agent.color}20`, fontFamily:'Share Tech Mono,monospace', fontSize:'0.62rem', color:`${agent.color}cc`, lineHeight:1.5, maxHeight:40, overflow:'hidden', maskImage:'linear-gradient(to bottom,black 40%,transparent)' }}>
                {agentOutputs[agent.id].slice(0, 100)}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
