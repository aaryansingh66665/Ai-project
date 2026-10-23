import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Play, Square, RotateCcw, Copy, Download, Brain, Code,
  CheckCircle, Sparkles, Wrench, Activity, Cpu,
  Zap, Timer, ArrowRight, Target, Layers, Terminal, FolderTree, Folder, File, ChevronRight, ChevronDown, ShieldCheck, Flame
} from 'lucide-react';
import AgentCardGrid, { AGENTS_ROSTER } from './AgentCardGrid';

const PRESETS = [
  "Full exploit PoC, patch & detection for Log4j CVE-2021-44228",
  "Active Directory Kerberoasting & Token Impersonation CTF playbook",
  "Disassemble x64 XOR-encoded shellcode & generate YARA rule",
  "Analyze DNS tunneling PCAP, write Suricata IDS rule set",
  "Deep recon + CVE audit on 192.168.1.50 via Nmap + threat intel",
];

const MISSION_NODES = [
  { key: 'target', label: 'target', desc: 'Target identifier / domain / IP' },
  { key: 'scope', label: 'scope', desc: 'Authorized boundaries & rules' },
  { key: 'discovered_assets', label: 'discovered_assets', desc: 'Discovered hosts, IPs & OS fingerprints' },
  { key: 'services', label: 'services', desc: 'Open ports, banners & protocols' },
  { key: 'vulnerabilities', label: 'vulnerabilities', desc: '8-step enriched CVEs, CVSS & exploits' },
  { key: 'evidence', label: 'evidence', desc: 'Artifacts, outputs & raw logs' },
  { key: 'agent_results', label: 'agent_results', desc: 'Specialist agent outputs' },
  { key: 'confidence', label: 'confidence', desc: 'Overall mission rating & factor breakdown' },
  { key: 'decisions', label: 'decisions', desc: 'Tactical pivots & triage decisions' },
  { key: 'final_report', label: 'final_report', desc: 'Executive intelligence deliverable' },
];

/* ── Neural network canvas ── shows agent connections ─── */
function NeuralCanvas({ stagesState, activeStage }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width = canvas.offsetWidth;
    const H = canvas.height = canvas.offsetHeight;

    const N = AGENTS_ROSTER.length;
    const cols = Math.ceil(N / 2);
    const nodes = AGENTS_ROSTER.map((a, i) => ({
      x: ((i % cols) + 0.5) / cols * W,
      y: (Math.floor(i / cols) + 0.5) / 2 * H,
      agent: a,
    }));

    let t = 0;
    let animId;
    const draw = () => {
      t++;
      ctx.clearRect(0, 0, W, H);

      // Draw background grid lines connecting all neural nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const na = nodes[i], nb = nodes[j];
          const dist = Math.hypot(na.x - nb.x, na.y - nb.y);
          if (dist > W * 0.65) continue;

          const aDone = stagesState[na.agent.id]?.status === 'done';
          const bDone = stagesState[nb.agent.id]?.status === 'done';
          const isActive = activeStage === na.agent.id || activeStage === nb.agent.id;

          const baseAlpha = (aDone && bDone) ? 0.45 : (aDone || bDone) ? 0.30 : 0.15;
          const alpha = isActive ? 0.85 : baseAlpha;
          const color = isActive
            ? (na.agent.id === activeStage ? na.agent.color : nb.agent.color)
            : (aDone && bDone) ? 'rgba(0,255,148,1)' : 'rgba(0,200,248,1)';

          ctx.beginPath();
          ctx.moveTo(na.x, na.y);
          ctx.lineTo(nb.x, nb.y);
          ctx.strokeStyle = isActive ? color : color.replace('1)', `${alpha})`);
          ctx.lineWidth = isActive ? 2.4 : 1.0;
          if (isActive) {
            ctx.shadowColor = color;
            ctx.shadowBlur = 12;
          }
          ctx.stroke();
          ctx.shadowBlur = 0;

          if (isActive || (aDone && bDone && (i + j) % 2 === 0)) {
            const speed = isActive ? 2.5 : 1.0;
            const progress = ((t * speed + (i * 20)) % 100) / 100;
            const px = na.x + (nb.x - na.x) * progress;
            const py = na.y + (nb.y - na.y) * progress;
            ctx.beginPath();
            ctx.arc(px, py, isActive ? 3.5 : 2.0, 0, Math.PI * 2);
            ctx.fillStyle = isActive ? '#ffffff' : color;
            ctx.shadowColor = color;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }
      }

      // Draw neural nodes
      for (const node of nodes) {
        const st = stagesState[node.agent.id]?.status ?? 'idle';
        const isRunning = activeStage === node.agent.id;
        const isDone = st === 'done';
        const r = isRunning ? 18 : 14;

        const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * (isRunning ? 3.5 : 2.5));
        const c = node.agent.color;
        grad.addColorStop(0, isRunning ? `${c}70` : isDone ? 'rgba(0,255,148,0.4)' : `${c}30`);
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * (isRunning ? 3.5 : 2.5), 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = isRunning ? `${c}33` : isDone ? 'rgba(0,255,148,0.15)' : 'rgba(0,10,25,0.85)';
        ctx.strokeStyle = isRunning ? c : isDone ? 'var(--p-green)' : 'rgba(0,200,248,0.3)';
        ctx.lineWidth = isRunning ? 2.5 : 1.2;
        ctx.stroke();

        ctx.font = `${isRunning ? '12px' : '10px'} sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.agent.emoji, node.x, node.y);

        ctx.font = '8px "Share Tech Mono", monospace';
        ctx.fillStyle = isRunning ? c : isDone ? 'var(--p-green)' : 'rgba(0,200,248,0.7)';
        ctx.fillText(node.agent.name.toUpperCase(), node.x, node.y + r + 11);
      }

      animId = requestAnimationFrame(draw);
    };

    animId = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animId);
  }, [stagesState, activeStage]);

  return <canvas ref={canvasRef} style={{ width: '100%', height: 180, display: 'block' }} />;
}

/* ── Animated waveform indicator ── */
function OutputWaveform({ active, color }) {
  if (!active) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 3, padding: '4px 0 8px' }}>
      {[0.4, 0.9, 0.6, 1.0, 0.5, 0.8, 0.3, 0.95, 0.7].map((h, i) => (
        <span
          key={i}
          style={{
            display: 'inline-block',
            width: 3,
            height: Math.max(4, Math.round(14 * h)),
            background: color || 'var(--p-blue)',
            boxShadow: `0 0 6px ${color || 'var(--p-blue)'}`,
            animation: `phud ${0.6 + (i % 4) * 0.2}s ease-in-out infinite alternate`,
          }}
        />
      ))}
    </div>
  );
}

function HudHeader({ icon: Icon, label, color = 'var(--p-blue)', right, sub }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 2, height: 20, background: color, boxShadow: `0 0 10px ${color}, 0 0 20px ${color}40` }} />
        <Icon size={13} color={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
        <div>
          <div style={{ fontFamily: 'Orbitron,monospace', fontWeight: 800, fontSize: '0.63rem', letterSpacing: '2.5px', color, textShadow: `0 0 10px ${color}60`, textTransform: 'uppercase' }}>
            {label}
          </div>
          {sub && <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.62rem', color: 'rgba(0,200,248,0.6)', marginTop: 1 }}>{sub}</div>}
        </div>
      </div>
      {right}
    </div>
  );
}

/* ── Pipeline chip ───────────────────────────────── */
function PipelineChip({ agent, state, isActive }) {
  const done   = state?.status === 'done';
  return (
    <div style={{
      background: isActive ? `${agent.color}10` : done ? 'rgba(0,255,148,0.05)' : 'rgba(0,200,248,0.03)',
      border: `1px solid ${isActive ? agent.color : done ? 'rgba(0,255,148,0.3)' : 'rgba(0,200,248,0.1)'}`,
      padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 7, minWidth: 130, transition: 'all 0.3s',
      boxShadow: isActive ? `0 0 20px ${agent.color}40` : 'none',
      clipPath: 'polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,0 100%)',
    }}>
      <span style={{ fontSize: '0.85rem' }}>{agent.emoji}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.62rem', fontWeight: 700, color: isActive ? agent.color : done ? 'var(--p-green)' : 'rgba(0,200,248,0.7)', letterSpacing: '0.5px', textShadow: isActive ? `0 0 8px ${agent.color}` : 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {agent.name}
        </div>
        <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.58rem', color: 'rgba(0,200,248,0.5)' }}>{agent.model}</div>
      </div>
      {isActive && <span className="pulse-dot" style={{ width: 5, height: 5, background: agent.color, boxShadow: `0 0 6px ${agent.color}` }} />}
      {done      && <CheckCircle size={10} color="var(--p-green)" />}
    </div>
  );
}

/* ── Metric box ──────────────────────────────────── */
function MetricBox({ label, value, color }) {
  return (
    <div style={{ padding: '8px 14px', background: 'rgba(0,200,248,0.04)', border: '1px solid rgba(0,200,248,0.15)', clipPath: 'polygon(0 0,calc(100% - 6px) 0,100% 6px,100% 100%,6px 100%,0 calc(100% - 6px))', textAlign: 'center' }}>
      <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.5rem', letterSpacing: '1.5px', color: 'rgba(0,200,248,0.6)', textTransform: 'uppercase', marginBottom: 3 }}>{label}</div>
      <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '1.05rem', fontWeight: 700, color, textShadow: `0 0 14px ${color}80`, lineHeight: 1 }}>{value}</div>
    </div>
  );
}

/* ── Tool call row ───────────────────────────────── */
function ToolCallRow({ tc }) {
  const agent = AGENTS_ROSTER.find(a => a.id === tc.agentId);
  return (
    <div className="fade-in" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px', background: 'rgba(0,255,148,0.04)', border: '1px solid rgba(0,255,148,0.12)' }}>
      <span style={{ fontSize: '0.8rem', flexShrink: 0 }}>{agent?.emoji ?? '🤖'}</span>
      <span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.55rem', letterSpacing: '0.8px', color: 'var(--p-cyan)', border: '1px solid rgba(0,200,248,0.25)', padding: '1px 5px', flexShrink: 0 }}>
        {String(tc.tool ?? '').toUpperCase()}
      </span>
      <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.68rem', color: 'rgba(0,200,248,0.8)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {tc.payload?.query ?? tc.payload?.target ?? tc.payload?.preview ?? JSON.stringify(tc.payload).slice(0, 80)}
      </span>
      <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.58rem', color: 'rgba(0,200,248,0.45)', flexShrink: 0 }}>{tc.timestamp}</span>
    </div>
  );
}

/* ══════════════════════════════════════════════════════
   SwarmVisualizer
══════════════════════════════════════════════════════ */
export default function SwarmVisualizer({ initialQuery }) {
  const [query, setQuery]                   = useState(initialQuery || '');
  const [selectedAgents, setSelectedAgents] = useState([]);
  const [isRunning, setIsRunning]           = useState(false);
  const [isStopping, setIsStopping]         = useState(false);
  const [activeStage, setActiveStage]       = useState(null);
  const [activeAgentName, setActiveAgentName] = useState('');
  const [activeModel, setActiveModel]       = useState('');
  const [stagesState, setStagesState]       = useState({});
  const [agentOutputs, setAgentOutputs]     = useState({});
  const [toolCalls, setToolCalls]           = useState([]);
  const [thinkingStream, setThinkingStream] = useState('');
  const [outputStream, setOutputStream]     = useState('');
  const [finalReport, setFinalReport]       = useState('');
  const [missionData, setMissionData]       = useState(null);
  const [missionTree, setMissionTree]       = useState(null);
  const [activeTreeNode, setActiveTreeNode] = useState('vulnerabilities');
  const [tokenCount, setTokenCount]         = useState(0);
  const [elapsed, setElapsed]               = useState(0);
  const [activeView, setActiveView]         = useState('split');
  const [copied, setCopied]                 = useState(false);
  const [agentPlan, setAgentPlan]           = useState([]);
  const [showNeural, setShowNeural]         = useState(true);

  const socketRef    = useRef(null);
  const outputEndRef = useRef(null);
  const timerRef     = useRef(null);
  const abortRef     = useRef(null);

  // Fetch active mission on mount
  const fetchActiveMission = async () => {
    try {
      const res = await fetch('/api/mission/current');
      if (res.ok) {
        const d = await res.json();
        setMissionData(d.mission);
        setMissionTree(d.summary);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchActiveMission();
  }, []);

  useEffect(() => {
    if (isRunning) {
      const start = Date.now();
      timerRef.current = setInterval(() => setElapsed(((Date.now() - start) / 1000).toFixed(1)), 100);
    } else { clearInterval(timerRef.current); }
    return () => clearInterval(timerRef.current);
  }, [isRunning]);

  useEffect(() => { outputEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [outputStream]);

  useEffect(() => {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/ws/pipeline`);
    socketRef.current = ws;
    ws.onmessage = ev => { try { handleEvent(JSON.parse(ev.data)); } catch (e) {} };
    return () => ws.close();
  }, []);

  const handleEvent = useCallback(data => {
    if (data.type === 'pipeline_start') {
      setIsRunning(true); setAgentPlan(data.payload.plan || []);
      const init = {}; (data.payload.plan || []).forEach(id => { init[id] = { status: 'queued' }; });
      setStagesState(init); setAgentOutputs({}); setToolCalls([]);
      setThinkingStream(''); setOutputStream(''); setFinalReport(''); setTokenCount(0);
      if (data.payload.mission_summary) setMissionTree(data.payload.mission_summary);
    } else if (data.type === 'start') {
      setActiveStage(data.agent_id); setActiveAgentName(data.agent_name ?? data.agent_id); setActiveModel(data.payload?.model ?? '');
      setStagesState(p => ({ ...p, [data.agent_id]: { ...p[data.agent_id], status: 'running', model: data.payload?.model } }));
    } else if (data.type === 'thinking') {
      const c = data.payload?.chunk ?? ''; setThinkingStream(p => p + c); setTokenCount(p => p + Math.max(1, c.length >> 2));
    } else if (data.type === 'stream') {
      const c = data.payload?.chunk ?? ''; setOutputStream(p => p + c); setTokenCount(p => p + Math.max(1, c.length >> 2));
      if (data.agent_id) setAgentOutputs(p => ({ ...p, [data.agent_id]: (p[data.agent_id] ?? '') + c }));
    } else if (data.type === 'tool_call') {
      setToolCalls(p => [{ agentId: data.agent_id, agentName: data.agent_name, tool: data.payload?.tool, payload: data.payload, timestamp: new Date().toLocaleTimeString() }, ...p]);
    } else if (data.type === 'complete') {
      setStagesState(p => ({ ...p, [data.agent_id]: { ...p[data.agent_id], status: 'done', duration: data.payload?.duration_s, tokens: data.payload?.tokens_approx } }));
    } else if (data.type === 'mission_update') {
      if (data.payload?.mission_summary) setMissionTree(data.payload.mission_summary);
      if (data.payload?.mission) setMissionData(data.payload.mission);
    } else if (data.type === 'pipeline_complete' || data.type === 'pipeline_stopped') {
      setIsRunning(false); setIsStopping(false); setActiveStage(null); setActiveAgentName(''); setActiveModel('');
      fetchActiveMission();
    }
  }, []);

  const runSwarm = async e => {
    if (e) e.preventDefault();
    if (!query.trim() || isRunning) return;
    setIsRunning(true); setIsStopping(false);
    setThinkingStream(''); setOutputStream(''); setFinalReport('');
    setToolCalls([]); setAgentOutputs({}); setTokenCount(0); setAgentPlan([]);
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const r = await fetch('/api/query', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query.trim(), custom_agents: selectedAgents.length ? selectedAgents : null }),
        signal: ctrl.signal,
      });
      const d = await r.json(); 
      setFinalReport(d.final_report ?? outputStream);
      if (d.mission) setMissionData(d.mission);
      if (d.mission_summary) setMissionTree(d.mission_summary);
    } catch (e) { if (e.name !== 'AbortError') console.error(e); }
    finally { setIsRunning(false); setIsStopping(false); abortRef.current = null; }
  };

  const stopSwarm = async () => {
    if (!isRunning) return;
    setIsStopping(true);
    try { await fetch('/api/pipeline/stop', { method: 'POST' }); } catch (e) { console.error(e); }
    setTimeout(() => { abortRef.current?.abort(); }, 1200);
  };

  const toggleAgent = id => setSelectedAgents(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);
  const copy   = () => { navigator.clipboard.writeText(outputStream || finalReport); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const export_ = () => { const b = new Blob([outputStream || finalReport], { type: 'text/markdown' }); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `CyberAgent_Report_${Date.now()}.md`; a.click(); };
  const clear  = () => { setOutputStream(''); setFinalReport(''); setAgentPlan([]); setStagesState({}); setThinkingStream(''); setToolCalls([]); setQuery(''); };

  const tps = elapsed > 0 ? tokenCount / elapsed : 0;
  const doneCount = Object.values(stagesState).filter(s => s.status === 'done').length;
  const totalPlanned = agentPlan.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Mission Input ─────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '22px 26px' }}>
        <HudHeader icon={Target} label="Mission Objective Input"
          sub="AUTONOMOUS SWARM EXECUTION // 10-NODE MISSION STATE // ZERO RESTRICTIONS"
          color="var(--p-blue)"
          right={<span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.52rem', letterSpacing: '1.5px', color: 'var(--p-red)', border: '1px solid rgba(255,30,60,0.35)', padding: '2px 8px', boxShadow: '0 0 8px rgba(255,30,60,0.2)' }}>UNRESTRICTED</span>}
        />

        <form onSubmit={runSwarm}>
          <div style={{ position: 'relative', marginBottom: 12 }}>
            {[['top:0','left:0','borderTop','borderLeft'],['top:0','right:0','borderTop','borderRight'],['bottom:0','left:0','borderBottom','borderLeft'],['bottom:0','right:0','borderBottom','borderRight']].map(([pos1,pos2,b1,b2],i) => (
              <div key={i} style={{ position: 'absolute', ...Object.fromEntries([[pos1.split(':')[0],pos1.split(':')[1]],[pos2.split(':')[0],pos2.split(':')[1]]]), width: 16, height: 16, [b1]: '2px solid var(--p-blue)', [b2]: '2px solid var(--p-blue)', zIndex: 5 }} />
            ))}
            <textarea
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="[ ENTER MISSION PARAMETERS ] — Target CVE / exploit / PCAP / CTF / threat intel / Nmap recon..."
              rows={4}
              style={{ width: '100%', background: 'rgba(0,200,248,0.03)', border: '1px solid rgba(0,200,248,0.15)', borderRadius: 0, padding: '16px 20px', color: 'var(--p-white)', fontFamily: 'Share Tech Mono,monospace', fontSize: '0.82rem', resize: 'vertical', outline: 'none', lineHeight: 1.75, caretColor: 'var(--p-blue)' }}
              onFocus={e => e.target.style.borderColor = 'rgba(0,200,248,0.4)'}
              onBlur={e => e.target.style.borderColor = 'rgba(0,200,248,0.15)'}
            />
          </div>

          {/* Quick presets */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.52rem', letterSpacing: '1.5px', color: 'rgba(0,200,248,0.6)', textTransform: 'uppercase', marginBottom: 7 }}>
              TACTICAL SCENARIOS
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {PRESETS.map((p, i) => (
                <button key={i} type="button" onClick={() => setQuery(p)}
                  className="cyber-btn cyber-btn-secondary"
                  style={{ fontSize: '0.65rem', padding: '4px 10px', textTransform: 'none', letterSpacing: '0.2px' }}>
                  {p}
                </button>
              ))}
            </div>
          </div>

          {/* Custom agent selection chips */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.52rem', letterSpacing: '1.5px', color: 'rgba(0,200,248,0.6)', textTransform: 'uppercase', marginBottom: 7 }}>
              AGENT ROSTER // {selectedAgents.length === 0 ? 'ALL 8 ACTIVE (CANONICAL DAG)' : `${selectedAgents.length} SELECTED`}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {AGENTS_ROSTER.map(a => {
                const isSel = selectedAgents.includes(a.id);
                return (
                  <button key={a.id} type="button" onClick={() => toggleAgent(a.id)}
                    style={{
                      background: isSel ? `${a.color}20` : 'rgba(0,200,248,0.03)',
                      border: `1px solid ${isSel ? a.color : 'rgba(0,200,248,0.12)'}`,
                      padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6,
                      cursor: 'pointer', fontFamily: 'Share Tech Mono,monospace', fontSize: '0.68rem',
                      color: isSel ? a.color : 'rgba(0,200,248,0.6)',
                      boxShadow: isSel ? `0 0 10px ${a.color}30` : 'none',
                    }}>
                    <span>{a.emoji}</span>
                    <span>{a.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
            {(outputStream || finalReport) && <button type="button" onClick={clear} className="cyber-btn cyber-btn-secondary"><RotateCcw size={11} /> CLEAR</button>}
            {isRunning && (
              <button type="button" onClick={stopSwarm} disabled={isStopping}
                className="cyber-btn cyber-btn-danger"
                style={{ animation: isStopping ? 'none' : 'pulse-hud 1.2s ease-in-out infinite',
                  boxShadow: '0 0 20px rgba(255,30,60,0.5)', opacity: isStopping ? 0.6 : 1 }}>
                <Square size={12} fill="currentColor" />
                {isStopping ? 'STOPPING...' : 'STOP SWARM'}
              </button>
            )}
            <button type="submit" disabled={isRunning || !query.trim()} className="cyber-btn"
              style={{ opacity: isRunning || !query.trim() ? 0.3 : 1, boxShadow: !isRunning && query.trim() ? '0 0 20px rgba(0,200,248,0.4)' : 'none' }}>
              <Play size={12} /> {isRunning ? 'SWARM ACTIVE...' : 'INITIATE AUTONOMOUS SWARM'}
            </button>
          </div>
        </form>
      </div>

      {/* ── Live execution HUD ───────────────────────── */}
      {isRunning && (
        <div className="glass-panel fade-in" style={{ padding: '14px 22px', background: 'rgba(0,200,248,0.04)', borderColor: 'var(--p-blue)', boxShadow: '0 0 30px rgba(0,200,248,0.1)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className="pulse-dot" />
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ fontFamily: 'Orbitron,monospace', fontWeight: 800, fontSize: '0.75rem', color: 'var(--p-blue)', letterSpacing: '1px', textShadow: '0 0 16px rgba(0,200,248,0.7)' }}>
                    ACTIVE UNIT: {activeAgentName || 'STANDBY'}
                  </div>
                  {activeModel && <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.65rem', color: 'var(--p-purple)', border: '1px solid rgba(191,64,255,0.35)', padding: '0 6px' }}>{activeModel}</span>}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.65rem', color: 'rgba(0,200,248,0.6)', marginTop: 2 }}>
                  NEURAL INFERENCE ACTIVE // CUDA STREAM OPEN // RTX 3050 TENSOR CORES
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <MetricBox label="Tokens"   value={`~${tokenCount}`} color="var(--p-green)" />
              <MetricBox label="Elapsed"  value={`${elapsed}s`}   color="var(--p-amber)" />
              <MetricBox label="T/Sec"    value={tps > 0 ? tps.toFixed(1) : '0.0'} color="var(--p-blue)" />
              <MetricBox label="Progress" value={`${doneCount}/${totalPlanned}`} color="var(--p-cyan)" />
              <button type="button" onClick={stopSwarm} disabled={isStopping}
                className="cyber-btn cyber-btn-danger"
                style={{ padding: '7px 16px', animation: isStopping ? 'none' : 'pulse-hud 1.2s infinite',
                  boxShadow: '0 0 18px rgba(255,30,60,0.4)', opacity: isStopping ? 0.5 : 1, height: 'fit-content', alignSelf: 'center' }}>
                <Square size={11} fill="currentColor" />
                {isStopping ? 'STOPPING...' : 'ABORT'}
              </button>
            </div>
          </div>
          {totalPlanned > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="progress-bar-track" style={{ height: 3 }}>
                <div className="progress-bar-fill" style={{ width: `${(doneCount/totalPlanned)*100}%`, background: 'linear-gradient(90deg,var(--p-blue),var(--p-cyan))', boxShadow: '0 0 10px var(--p-blue), 0 0 20px rgba(0,200,248,0.3)' }} />
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── 10-NODE MISSION STATE TREE VIEWER ────────────────────────── */}
      <div className="glass-panel" style={{ padding: '20px 24px', borderColor: 'var(--p-cyan)' }}>
        <HudHeader icon={FolderTree} label="Mission State Architecture // mission/ Tree"
          sub="STRUCTURED CONTEXT & THREAT STATE // 10 CORE DIRECTORIES"
          color="var(--p-cyan)"
          right={
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {missionData?.confidence && (
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.62rem', color: 'var(--p-green)', fontWeight: 800, background: 'rgba(0,255,148,0.1)', padding: '2px 8px', border: '1px solid rgba(0,255,148,0.3)' }}>
                  CONFIDENCE: {missionData.confidence.overall_score || 0}% ({missionData.confidence.risk_rating || 'MEDIUM'})
                </span>
              )}
            </div>
          }
        />

        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14, background: '#000510', border: '1px solid rgba(0,200,248,0.15)', padding: 12 }}>
          
          {/* Left: Directory Tree Listing */}
          <div style={{ borderRight: '1px solid rgba(0,200,248,0.1)', paddingRight: 10 }}>
            <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.68rem', fontWeight: 800, color: 'var(--p-cyan)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Folder size={13} color="var(--p-cyan)" />
              <span>mission/</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {MISSION_NODES.map((node, i) => {
                const isSelected = activeTreeNode === node.key;
                const nodeSummary = missionTree?.nodes?.find(n => n.name === node.key);
                const count = nodeSummary?.count ?? (Array.isArray(missionData?.[node.key]) ? missionData[node.key].length : missionData?.[node.key] ? 1 : 0);

                return (
                  <button
                    key={node.key}
                    onClick={() => setActiveTreeNode(node.key)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '5px 8px',
                      background: isSelected ? 'rgba(0,200,248,0.12)' : 'transparent',
                      border: `1px solid ${isSelected ? 'var(--p-cyan)' : 'transparent'}`,
                      color: isSelected ? '#fff' : 'rgba(0,200,248,0.7)',
                      fontFamily: 'Share Tech Mono,monospace',
                      fontSize: '0.72rem',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: 'rgba(0,200,248,0.4)' }}>{i === MISSION_NODES.length - 1 ? '└──' : '├──'}</span>
                      <span>{node.label}</span>
                    </div>
                    <span style={{
                      fontFamily: 'Orbitron,monospace',
                      fontSize: '0.55rem',
                      color: count > 0 ? 'var(--p-green)' : 'rgba(255,255,255,0.2)',
                      background: count > 0 ? 'rgba(0,255,148,0.1)' : 'transparent',
                      padding: '1px 5px',
                    }}>
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right: Node Content Inspector */}
          <div style={{ maxHeight: 280, overflowY: 'auto', padding: '6px 10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(0,200,248,0.1)', paddingBottom: 6, marginBottom: 10 }}>
              <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.65rem', fontWeight: 800, color: 'var(--p-cyan)' }}>
                INSPECTING: mission/{activeTreeNode}
              </div>
              <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.62rem', color: 'rgba(0,200,248,0.5)' }}>
                {MISSION_NODES.find(n => n.key === activeTreeNode)?.desc}
              </span>
            </div>

            {/* Custom renders per tree node */}
            {activeTreeNode === 'vulnerabilities' && (
              <div>
                {missionData?.vulnerabilities && missionData.vulnerabilities.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {missionData.vulnerabilities.map((v, idx) => (
                      <div key={idx} style={{ background: 'rgba(0,10,25,0.7)', border: '1px solid rgba(0,200,248,0.2)', padding: '6px 10px', fontSize: '0.72rem', fontFamily: 'Share Tech Mono,monospace' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--p-cyan)', fontWeight: 700 }}>
                          <span>{v.cve_id} (Port {v.port})</span>
                          <span style={{ color: v.cvss_score >= 9.0 ? 'var(--p-red)' : 'var(--p-amber)' }}>CVSS {v.cvss_score}</span>
                        </div>
                        <div style={{ color: '#fff', marginTop: 2 }}>{v.title}</div>
                        <div style={{ color: 'rgba(0,200,248,0.6)', fontSize: '0.65rem', marginTop: 2 }}>
                          CPE: {v.cpe} • Confidence: {v.confidence_score}% ({v.confidence_level})
                          {v.is_cisa_kev && <span style={{ color: '#ff0055', marginLeft: 6, fontWeight: 700 }}>● CISA KEV ACTIVE</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'rgba(0,200,248,0.4)', fontSize: '0.72rem', fontFamily: 'Share Tech Mono,monospace' }}>
                    No vulnerabilities currently correlated in mission state.
                  </div>
                )}
              </div>
            )}

            {activeTreeNode === 'services' && (
              <div>
                {missionData?.services && missionData.services.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {missionData.services.map((s, idx) => (
                      <div key={idx} style={{ background: 'rgba(0,10,25,0.7)', border: '1px solid rgba(0,200,248,0.2)', padding: '6px 10px', fontSize: '0.72rem', fontFamily: 'Share Tech Mono,monospace' }}>
                        <span style={{ color: 'var(--p-cyan)', fontWeight: 700 }}>Port {s.port}/{s.protocol}</span> — {s.service} ({s.product} {s.version})
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'rgba(0,200,248,0.4)', fontSize: '0.72rem', fontFamily: 'Share Tech Mono,monospace' }}>
                    No services currently populated.
                  </div>
                )}
              </div>
            )}

            {activeTreeNode === 'confidence' && (
              <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.75rem', color: '#fff' }}>
                <div style={{ display: 'flex', gap: 14, marginBottom: 8 }}>
                  <div>Score: <strong style={{ color: 'var(--p-green)' }}>{missionData?.confidence?.overall_score || 0}%</strong></div>
                  <div>Rating: <strong style={{ color: 'var(--p-amber)' }}>{missionData?.confidence?.risk_rating || 'MEDIUM'}</strong></div>
                  <div>Level: <strong style={{ color: 'var(--p-cyan)' }}>{missionData?.confidence?.confidence_level || 'PROBABLE'}</strong></div>
                </div>
                {missionData?.confidence?.validated_checks && (
                  <ul style={{ paddingLeft: 16, margin: 0, color: 'rgba(0,200,248,0.8)', fontSize: '0.7rem' }}>
                    {missionData.confidence.validated_checks.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* Fallback JSON view for other nodes */}
            {activeTreeNode !== 'vulnerabilities' && activeTreeNode !== 'services' && activeTreeNode !== 'confidence' && (
              <pre style={{ margin: 0, fontFamily: 'Share Tech Mono,monospace', fontSize: '0.7rem', color: 'rgba(0,200,248,0.8)', whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(missionData?.[activeTreeNode] ?? '// Node empty or awaiting swarm execution', null, 2)}
              </pre>
            )}

          </div>
        </div>
      </div>

      {/* ── Neural network + Agent grid ──────────────── */}
      <div className="glass-panel" style={{ padding: '18px 22px' }}>
        <HudHeader icon={Cpu} label="Multi-Agent Swarm Matrix // 8 Specialized Neural Units"
          sub="DYNAMIC VRAM LIFECYCLE SWAP // RTX 3050 6GB // ONE AGENT LOADED AT A TIME"
          color="var(--p-blue)"
          right={
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setShowNeural(n => !n)} className="cyber-btn cyber-btn-secondary" style={{ padding: '4px 10px', fontSize: '0.58rem' }}>
                <Activity size={10} /> {showNeural ? 'HIDE' : 'SHOW'} NEURAL
              </button>
              {isRunning && <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.68rem', color: 'var(--p-green)', border: '1px solid rgba(0,255,148,0.4)', padding: '3px 10px', animation: 'phud 1.5s infinite', fontWeight: 700 }}>● SWARM ACTIVE</span>}
            </div>
          }
        />

        {showNeural && (
          <div style={{ marginBottom: 14, border: '1px solid rgba(0,200,248,0.2)', background: 'radial-gradient(ellipse at center, rgba(0,20,40,0.6) 0%, rgba(0,5,15,0.9) 100%)', boxShadow: '0 0 25px rgba(0,200,248,0.08)' }}>
            <NeuralCanvas stagesState={stagesState} activeStage={activeStage} />
          </div>
        )}

        <AgentCardGrid stagesState={stagesState} activeStage={activeStage} agentOutputs={agentOutputs} tps={tps} />
      </div>

      {/* ── Pipeline DAG ─────────────────────────────── */}
      {agentPlan.length > 0 && (
        <div className="glass-panel fade-in" style={{ padding: '14px 22px' }}>
          <HudHeader icon={Layers} label="Execution DAG // Sequential Pipeline" color="var(--p-cyan)" />
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflowX: 'auto', paddingBottom: 4 }}>
            {agentPlan.map((id, idx) => {
              const agent = AGENTS_ROSTER.find(a => a.id === id) ?? { id, name: id, emoji: '🤖', model: 'local', color: 'var(--p-blue)' };
              const isActive = activeStage === id;
              return (
                <React.Fragment key={id}>
                  <PipelineChip agent={agent} state={stagesState[id]} isActive={isActive} />
                  {idx < agentPlan.length - 1 && (
                    <div className={isActive ? 'flow-arrow' : ''} style={{ color: isActive ? 'var(--p-blue)' : 'rgba(0,200,248,0.15)', flexShrink: 0 }}>
                      <ArrowRight size={13} />
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Tool calls ───────────────────────────────── */}
      {toolCalls.length > 0 && (
        <div className="glass-panel" style={{ padding: '14px 20px', borderColor: 'rgba(0,255,148,0.18)' }}>
          <HudHeader icon={Wrench} label={`Autonomous Tool Executions // ${toolCalls.length} Calls`} color="var(--p-green)" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, maxHeight: 140, overflowY: 'auto' }}>
            {toolCalls.map((tc, i) => <ToolCallRow key={i} tc={tc} />)}
          </div>
        </div>
      )}

      {/* ── Output terminal ──────────────────────────── */}
      <div className="glass-panel" style={{ padding: '18px 22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', gap: 4 }}>
            {[{ k: 'split', i: Activity, l: 'Split View' }, { k: 'output', i: Code, l: 'Intelligence' }, { k: 'thinking', i: Brain, l: 'CoT Trace' }].map(({ k, i: I, l }) => (
              <button key={k} onClick={() => setActiveView(k)} className={activeView === k ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'} style={{ padding: '5px 12px' }}>
                <I size={11} /> {l}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button onClick={copy}    className="cyber-btn cyber-btn-secondary" style={{ padding: '5px 10px' }}><Copy size={10} /> {copied ? 'COPIED' : 'COPY'}</button>
            <button onClick={export_} className="cyber-btn cyber-btn-secondary" style={{ padding: '5px 10px' }}><Download size={10} /> EXPORT .MD</button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: activeView === 'split' ? '1fr 1fr' : '1fr', gap: 12 }}>
          {(activeView === 'thinking' || activeView === 'split') && (
            <div style={{ background: '#000510', border: '1px solid rgba(255,179,0,0.12)', padding: '14px 16px', maxHeight: 520, overflowY: 'auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
                <Brain size={11} color="var(--p-amber)" />
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.58rem', letterSpacing: '1.5px', color: 'var(--p-amber)', textTransform: 'uppercase' }}>Chain-of-Thought // &lt;think&gt; Trace</span>
                {isRunning && <span className="pulse-dot pulse-dot-amber" style={{ marginLeft: 'auto', width: 5, height: 5 }} />}
              </div>
              <OutputWaveform active={isRunning && !thinkingStream} color="rgba(255,179,0,0.4)" />
              <pre className={!thinkingStream && isRunning ? 'blink-cursor' : ''} style={{ color: 'rgba(255,179,0,0.7)', fontSize: '0.76rem', fontFamily: 'Share Tech Mono,monospace', whiteSpace: 'pre-wrap', lineHeight: 1.75, margin: 0 }}>
                {thinkingStream || '// AWAITING REASONING STREAM...'}
              </pre>
            </div>
          )}
          {(activeView === 'output' || activeView === 'split') && (
            <div style={{ background: '#000510', border: '1px solid rgba(0,200,248,0.1)', padding: '14px 16px', maxHeight: 520, overflowY: 'auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
                <Terminal size={11} color="var(--p-blue)" />
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.58rem', letterSpacing: '1.5px', color: 'var(--p-blue)', textTransform: 'uppercase' }}>Live Intelligence Feed // Agent Deliverables</span>
                {isRunning && <span className="pulse-dot pulse-dot-sky" style={{ marginLeft: 'auto', width: 5, height: 5 }} />}
              </div>
              <OutputWaveform active={isRunning} color="rgba(0,200,248,0.5)" />
              <pre className={isRunning && !outputStream ? 'blink-cursor' : ''} style={{ color: 'var(--p-white)', fontSize: '0.78rem', fontFamily: 'Share Tech Mono,monospace', whiteSpace: 'pre-wrap', lineHeight: 1.75, margin: 0 }}>
                {outputStream || finalReport || '// STANDING BY // ENTER MISSION OBJECTIVE TO BEGIN...'}
              </pre>
              <div ref={outputEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
