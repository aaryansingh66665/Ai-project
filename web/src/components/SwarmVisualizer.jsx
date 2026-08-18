import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  RotateCcw, 
  Copy, 
  Download, 
  Brain, 
  Code, 
  CheckCircle, 
  Clock, 
  Sparkles, 
  Shield, 
  ChevronRight, 
  Wrench, 
  Activity, 
  Terminal, 
  Search, 
  Radar, 
  Layers,
  Database,
  Cpu
} from 'lucide-react';

const QUICK_PROMPTS = [
  "Comprehensive root-cause exploit PoC & patch for Log4j (CVE-2021-44228)",
  "Active Directory Kerberoasting & Token Impersonation tactical CTF playbook",
  "Disassemble x64 XOR-encoded shellcode, extract payload & craft YARA rule",
  "Analyze malicious DNS tunneling PCAP traffic and generate Suricata IDS rules",
  "Nmap scan reconnaissance on 192.168.1.50 with service CVE auditing",
];

const AGENTS_ROSTER = [
  { id: 'osint', name: 'OSINT & Search', model: 'qwen3:4b', emoji: '🕵️' },
  { id: 'threat_intel', name: 'Threat Intel', model: 'deepseek-r1:8b', emoji: '🧠' },
  { id: 'coder', name: 'Offensive/Defensive Coder', model: 'qwen2.5-coder:7b', emoji: '💻' },
  { id: 'malware', name: 'Malware & Reverse Eng', model: 'qwen3:8b', emoji: '🔬' },
  { id: 'network', name: 'Network & PCAP Analyst', model: 'gemma3:4b', emoji: '📡' },
  { id: 'redteam', name: 'Red Team & CTF', model: 'phi4-mini:3.8b', emoji: '⚔️' },
  { id: 'report', name: 'Executive Report', model: 'gemma3:4b', emoji: '📝' },
];

export default function SwarmVisualizer() {
  const [query, setQuery] = useState('');
  const [selectedAgents, setSelectedAgents] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [activeStage, setActiveStage] = useState(null);
  const [activeAgentName, setActiveAgentName] = useState('');
  const [activeModel, setActiveModel] = useState('');
  const [stagesState, setStagesState] = useState({});
  const [agentOutputs, setAgentOutputs] = useState({});
  const [toolCalls, setToolCalls] = useState([]);
  const [thinkingStream, setThinkingStream] = useState('');
  const [outputStream, setOutputStream] = useState('');
  const [finalReport, setFinalReport] = useState('');
  const [tokenCount, setTokenCount] = useState(0);
  const [startTime, setStartTime] = useState(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [activeView, setActiveView] = useState('split'); // 'output' | 'thinking' | 'split' | 'tools'
  const [copied, setCopied] = useState(false);

  const socketRef = useRef(null);
  const outputEndRef = useRef(null);
  const timerRef = useRef(null);

  // Live timer during execution
  useEffect(() => {
    if (isRunning) {
      const start = Date.now();
      setStartTime(start);
      timerRef.current = setInterval(() => {
        setElapsedSeconds(((Date.now() - start) / 1000).toFixed(1));
      }, 100);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning]);

  useEffect(() => {
    // Setup WebSocket connection for live streaming
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/pipeline`;
    const ws = new WebSocket(wsUrl);
    socketRef.current = ws;

    ws.onopen = () => console.log('Connected to pipeline WebSocket');
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleStreamEvent(data);
      } catch (e) {
        console.error('WebSocket parse error:', e);
      }
    };
    ws.onclose = () => console.log('WebSocket disconnected');

    return () => {
      if (ws) ws.close();
    };
  }, []);

  const handleStreamEvent = (data) => {
    if (data.type === 'pipeline_start') {
      setIsRunning(true);
      const initialStages = {};
      data.payload.plan.forEach((agentId, idx) => {
        initialStages[agentId] = { status: 'queued', index: idx + 1, total: data.payload.total_steps };
      });
      setStagesState(initialStages);
      setAgentOutputs({});
      setToolCalls([]);
      setThinkingStream('');
      setOutputStream('');
      setFinalReport('');
      setTokenCount(0);
    } else if (data.type === 'start') {
      setActiveStage(data.agent_id);
      setActiveAgentName(data.agent_name || data.agent_id);
      setActiveModel(data.payload?.model || '');
      setStagesState((prev) => ({
        ...prev,
        [data.agent_id]: { 
          ...prev[data.agent_id], 
          status: 'running', 
          model: data.payload?.model,
          promptPreview: data.payload?.prompt 
        },
      }));
    } else if (data.type === 'thinking') {
      const chunk = data.payload?.chunk || '';
      setThinkingStream((prev) => prev + chunk);
      setTokenCount((prev) => prev + Math.max(1, Math.round(chunk.length / 4)));
    } else if (data.type === 'stream') {
      const chunk = data.payload?.chunk || '';
      setOutputStream((prev) => prev + chunk);
      setTokenCount((prev) => prev + Math.max(1, Math.round(chunk.length / 4)));
      if (data.agent_id) {
        setAgentOutputs((prev) => ({
          ...prev,
          [data.agent_id]: (prev[data.agent_id] || '') + chunk
        }));
      }
    } else if (data.type === 'tool_call') {
      const toolEvent = {
        agentId: data.agent_id,
        agentName: data.agent_name,
        tool: data.payload?.tool,
        payload: data.payload,
        timestamp: new Date().toLocaleTimeString(),
      };
      setToolCalls((prev) => [toolEvent, ...prev]);
    } else if (data.type === 'complete') {
      setStagesState((prev) => ({
        ...prev,
        [data.agent_id]: { 
          ...prev[data.agent_id], 
          status: 'done', 
          duration: data.payload?.duration_s,
          tokens: data.payload?.tokens_approx
        },
      }));
    } else if (data.type === 'pipeline_complete') {
      setIsRunning(false);
      setActiveStage(null);
      setActiveAgentName('');
      setActiveModel('');
    }
  };

  const handleRunSwarm = async (e) => {
    if (e) e.preventDefault();
    if (!query.trim() || isRunning) return;

    setIsRunning(true);
    setThinkingStream('');
    setOutputStream('');
    setFinalReport('');
    setToolCalls([]);
    setAgentOutputs({});
    setTokenCount(0);

    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: query.trim(),
          custom_agents: selectedAgents.length > 0 ? selectedAgents : null,
        }),
      });
      const data = await res.json();
      setFinalReport(data.final_report || outputStream);
    } catch (err) {
      console.error('Execution error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const toggleAgent = (agentId) => {
    if (selectedAgents.includes(agentId)) {
      setSelectedAgents(selectedAgents.filter((id) => id !== agentId));
    } else {
      setSelectedAgents([...selectedAgents, agentId]);
    }
  };

  const handleCopy = () => {
    const textToCopy = outputStream || finalReport;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportMarkdown = () => {
    const text = outputStream || finalReport;
    const blob = new Blob([text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberAgent_Report_${Date.now()}.md`;
    a.click();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Query Input Section */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sparkles size={18} color="var(--neon-cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: '700', letterSpacing: '0.5px' }}>
              AUTONOMOUS CYBERSECURITY SWARM OBJECTIVE
            </h2>
          </div>
          <span className="badge-neon badge-cyan">ZERO RESTRICTIONS</span>
        </div>

        <form onSubmit={handleRunSwarm}>
          <div style={{ position: 'relative' }}>
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Describe your security research target, Nmap reconnaissance analysis, exploit requirement, or CTF problem..."
              rows={3}
              style={{
                width: '100%',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-dim)',
                borderRadius: '10px',
                padding: '14px 16px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-main)',
                fontSize: '0.95rem',
                resize: 'vertical',
                outline: 'none',
                lineHeight: '1.5',
              }}
            />
          </div>

          {/* Quick Prompts */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Quick Objectives:</span>
            {QUICK_PROMPTS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setQuery(p)}
                className="badge-neon badge-purple"
                style={{ cursor: 'pointer', border: '1px solid rgba(181, 23, 158, 0.4)', background: 'rgba(181, 23, 158, 0.08)' }}
              >
                {p.slice(0, 42)}...
              </button>
            ))}
          </div>

          {/* Agent Custom Selector */}
          <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-dim)', paddingTop: '14px' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
              Target Agents (Leave unselected for Auto-Orchestrator Planning):
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {AGENTS_ROSTER.map((agent) => {
                const isSel = selectedAgents.includes(agent.id);
                return (
                  <button
                    key={agent.id}
                    type="button"
                    onClick={() => toggleAgent(agent.id)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: '8px',
                      background: isSel ? 'rgba(0, 229, 255, 0.15)' : 'var(--bg-secondary)',
                      border: isSel ? '1px solid var(--neon-cyan)' : '1px solid var(--border-dim)',
                      color: isSel ? 'var(--neon-cyan)' : 'var(--text-secondary)',
                      fontSize: '0.8rem',
                      fontWeight: '600',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <span>{agent.emoji}</span>
                    <span>{agent.name}</span>
                    <span style={{ fontSize: '0.7rem', opacity: 0.6 }}>({agent.model})</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Action Bar */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '16px' }}>
            <button
              type="submit"
              disabled={isRunning || !query.trim()}
              className="cyber-btn"
              style={{ opacity: isRunning || !query.trim() ? 0.5 : 1 }}
            >
              <Play size={16} />
              {isRunning ? 'Swarm Executing...' : 'Launch GPU Swarm'}
            </button>
          </div>
        </form>
      </div>

      {/* Real-time AI Processing Telemetry & Live HUD */}
      {isRunning && (
        <div className="glass-panel" style={{ padding: '16px 20px', background: 'linear-gradient(90deg, rgba(0, 229, 255, 0.08), rgba(181, 23, 158, 0.08))', border: '1px solid var(--border-glow)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div className="pulse-dot" style={{ width: '12px', height: '12px' }} />
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--neon-cyan)' }}>
                  ACTIVE AGENT: {activeAgentName}
                </span>
                <span className="badge-neon badge-purple" style={{ fontSize: '0.7rem' }}>
                  {activeModel}
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Streaming neural reasoning & generating technical intelligence...
              </div>
            </div>
          </div>

          {/* Real-time Metrics */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>GENERATED TOKENS</div>
              <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--neon-green)', fontFamily: 'var(--font-code)' }}>
                ~{tokenCount} tokens
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ELAPSED TIME</div>
              <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--neon-amber)', fontFamily: 'var(--font-code)' }}>
                {elapsedSeconds}s
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>EST. SPEED</div>
              <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--neon-cyan)', fontFamily: 'var(--font-code)' }}>
                {elapsedSeconds > 0 ? (tokenCount / elapsedSeconds).toFixed(1) : '0'} t/s
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Dynamic DAG Pipeline Visualizer */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={18} color="var(--neon-green)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: '700', letterSpacing: '0.5px' }}>
              EXECUTION PIPELINE DAG & MULTI-STAGE COGNITIVE FLOW
            </h3>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-code)' }}>
            Sequential Dynamic VRAM Offloading (RTX 3050 6GB Bound)
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', overflowX: 'auto', paddingBottom: '8px' }}>
          {Object.keys(stagesState).length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '12px 0' }}>
              Pipeline idle. Enter an objective above to trigger the autonomous execution DAG.
            </div>
          ) : (
            Object.entries(stagesState).map(([agentId, state], index, arr) => {
              const agentInfo = AGENTS_ROSTER.find((a) => a.id === agentId) || { name: agentId, emoji: '🤖', model: 'local' };
              const isCurrent = activeStage === agentId;
              const isDone = state.status === 'done';

              return (
                <React.Fragment key={agentId}>
                  <div
                    style={{
                      background: isCurrent ? 'rgba(0, 229, 255, 0.15)' : 'var(--bg-secondary)',
                      border: isCurrent ? '1px solid var(--neon-cyan)' : isDone ? '1px solid var(--neon-green)' : '1px solid var(--border-dim)',
                      boxShadow: isCurrent ? '0 0 15px rgba(0, 229, 255, 0.3)' : 'none',
                      borderRadius: '10px',
                      padding: '12px 16px',
                      minWidth: '180px',
                      transition: 'all 0.3s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <span style={{ fontSize: '1.2rem' }}>{agentInfo.emoji}</span>
                      {isDone ? (
                        <CheckCircle size={15} color="var(--neon-green)" />
                      ) : isCurrent ? (
                        <span className="pulse-dot" />
                      ) : (
                        <Clock size={15} color="var(--text-muted)" />
                      )}
                    </div>
                    <div style={{ fontWeight: '700', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                      {agentInfo.name}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--neon-cyan)', fontFamily: 'var(--font-code)', marginTop: '2px' }}>
                      {agentInfo.model}
                    </div>
                    {state.duration && (
                      <div style={{ fontSize: '0.7rem', color: 'var(--neon-green)', marginTop: '4px' }}>
                        ✔ {state.duration}s
                      </div>
                    )}
                  </div>

                  {index < arr.length - 1 && (
                    <ChevronRight size={20} color="var(--text-muted)" style={{ opacity: 0.5, flexShrink: 0 }} />
                  )}
                </React.Fragment>
              );
            })
          )}
        </div>
      </div>

      {/* Live Tool Execution Stream & Activity Feed */}
      {toolCalls.length > 0 && (
        <div className="glass-panel" style={{ padding: '16px 20px', border: '1px solid rgba(0, 255, 136, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Wrench size={16} color="var(--neon-green)" />
            <h4 style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)', textTransform: 'uppercase' }}>
              Real-Time Autonomous Tool Calls ({toolCalls.length})
            </h4>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '160px', overflowY: 'auto' }}>
            {toolCalls.map((tc, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="badge-neon badge-green" style={{ fontSize: '0.7rem' }}>
                    {tc.tool}
                  </span>
                  <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                    {tc.agentName}:
                  </span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-code)', fontSize: '0.75rem' }}>
                    {tc.payload?.query || tc.payload?.target || tc.payload?.preview || JSON.stringify(tc.payload).slice(0, 80)}
                  </span>
                </div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                  {tc.timestamp}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dual Stream / Output Viewer */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setActiveView('split')}
              className={activeView === 'split' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '6px 14px', fontSize: '0.8rem' }}
            >
              <Activity size={14} /> Split CoT + Output
            </button>
            <button
              onClick={() => setActiveView('output')}
              className={activeView === 'output' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '6px 14px', fontSize: '0.8rem' }}
            >
              <Code size={14} /> Intelligence Output
            </button>
            <button
              onClick={() => setActiveView('thinking')}
              className={activeView === 'thinking' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '6px 14px', fontSize: '0.8rem' }}
            >
              <Brain size={14} /> Deep CoT &lt;think&gt; Trace
            </button>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={handleCopy} className="cyber-btn cyber-btn-secondary" style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
              <Copy size={13} /> {copied ? 'Copied!' : 'Copy Code'}
            </button>
            <button onClick={handleExportMarkdown} className="cyber-btn cyber-btn-secondary" style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
              <Download size={13} /> Export Report (.md)
            </button>
          </div>
        </div>

        {/* Live Output Containers */}
        <div style={{ display: 'grid', gridTemplateColumns: activeView === 'split' ? '1fr 1fr' : '1fr', gap: '16px' }}>
          
          {/* Thinking Stream */}
          {(activeView === 'thinking' || activeView === 'split') && (
            <div style={{ background: '#05070a', border: '1px solid rgba(255, 183, 3, 0.25)', borderRadius: '8px', padding: '16px', maxHeight: '550px', overflowY: 'auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--neon-amber)', fontSize: '0.8rem', fontWeight: '700' }}>
                  <Brain size={15} /> DEEPSEEK-R1 & QWEN3 CHAIN-OF-THOUGHT TRACE
                </div>
                {isRunning && <span className="pulse-dot" style={{ backgroundColor: 'var(--neon-amber)' }} />}
              </div>
              <pre style={{ color: '#fbbf24', fontSize: '0.85rem', fontFamily: 'var(--font-code)', whiteSpace: 'pre-wrap', lineHeight: '1.5' }}>
                {thinkingStream || '// Waiting for thinking tokens & reasoning steps...'}
              </pre>
            </div>
          )}

          {/* Deliverables Stream */}
          {(activeView === 'output' || activeView === 'split') && (
            <div style={{ background: '#05070a', border: '1px solid rgba(0, 229, 255, 0.25)', borderRadius: '8px', padding: '16px', maxHeight: '550px', overflowY: 'auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--neon-cyan)', fontSize: '0.8rem', fontWeight: '700' }}>
                  <Code size={15} /> LIVE AGENT DELIVERABLES & TECHNICAL SYNTHESIS
                </div>
                {isRunning && <span className="pulse-dot" />}
              </div>
              <pre style={{ color: '#e2e8f0', fontSize: '0.88rem', fontFamily: 'var(--font-code)', whiteSpace: 'pre-wrap', lineHeight: '1.6' }}>
                {outputStream || finalReport || '// Execution output will stream live here...'}
              </pre>
              <div ref={outputEndRef} />
            </div>
          )}

        </div>
      </div>

    </div>
  );
}
