import React, { useState } from 'react';
import { Bot, Send, User, Cpu, Sparkles, Terminal, Code } from 'lucide-react';

const AGENTS = [
  { id: 'orchestrator', name: 'Master Orchestrator', model: 'qwen3:8b', emoji: '👑', desc: 'Autonomous task decomposition & swarm planning' },
  { id: 'nemotron', name: 'NVIDIA Nemotron Reasoner', model: 'nemotron-mini:4b', emoji: '🟢', desc: 'Hardware-accelerated deep threat modeling & reasoning' },
  { id: 'threat_intel', name: 'Threat Intelligence', model: 'deepseek-r1:8b', emoji: '🧠', desc: 'Deep chain-of-thought CVE analysis & MITRE TTPs' },
  { id: 'coder', name: 'Offensive & Defensive Coder', model: 'qwen2.5-coder:7b', emoji: '💻', desc: 'Full-scale exploit PoCs, patches & automation' },
  { id: 'malware', name: 'Malware & Reverse Eng', model: 'qwen3:8b', emoji: '🔬', desc: 'Binary disassembly, shellcode & YARA rules' },
  { id: 'network', name: 'Network & Packet Analyst', model: 'gemma3:4b', emoji: '📡', desc: 'PCAP dissection & Suricata IDS signatures' },
  { id: 'osint', name: 'OSINT & Deep Search', model: 'qwen3:4b', emoji: '🕵️', desc: 'Unrestricted multi-source web recon' },
  { id: 'report', name: 'Executive Report Generator', model: 'gemma3:4b', emoji: '📝', desc: 'Technical deliverable & remediation synthesis' },
  { id: 'redteam', name: 'Red Team & CTF Simulator', model: 'phi4-mini:3.8b', emoji: '⚔️', desc: 'Privilege escalation & tactical attack playbooks' },
];

export default function AgentPlayground() {
  const [selectedAgent, setSelectedAgent] = useState(AGENTS[1]); // Default to Threat Intel (deepseek-r1:8b)
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [isGenerating, setIsGenerating] = useState(false);

  const handleSendMessage = async (e) => {
    if (e) e.preventDefault();
    if (!input.trim() || isGenerating) return;

    const userMsg = { role: 'user', content: input.trim() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsGenerating(true);

    const botMsg = { role: 'assistant', agent: selectedAgent.name, model: selectedAgent.model, content: '', thinking: '' };
    setMessages((prev) => [...prev, botMsg]);

    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: userMsg.content,
          custom_agents: [selectedAgent.id],
        }),
      });
      const data = await res.json();
      const stage = data.stages?.[0] || {};

      setMessages((prev) => {
        const next = [...prev];
        next[next.length - 1] = {
          role: 'assistant',
          agent: selectedAgent.name,
          model: selectedAgent.model,
          content: stage.output || 'No response generated.',
          thinking: stage.thinking || '',
          duration: stage.duration_s,
        };
        return next;
      });
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '20px' }}>
      
      {/* Agent Picker Sidebar */}
      <div className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        <div style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          SELECT ACTIVE AGENT
        </div>
        {AGENTS.map((agent) => {
          const isSel = selectedAgent.id === agent.id;
          return (
            <button
              key={agent.id}
              onClick={() => setSelectedAgent(agent)}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '10px',
                padding: '10px 12px',
                borderRadius: '8px',
                border: isSel ? '1px solid var(--neon-cyan)' : '1px solid transparent',
                background: isSel ? 'rgba(0, 229, 255, 0.12)' : 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <span style={{ fontSize: '1.2rem', marginTop: '2px' }}>{agent.emoji}</span>
              <div>
                <div style={{ fontWeight: '700', fontSize: '0.85rem', color: isSel ? 'var(--neon-cyan)' : 'var(--text-primary)' }}>
                  {agent.name}
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--neon-green)', fontFamily: 'var(--font-code)' }}>
                  {agent.model}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Direct Interactive Chat Window */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', height: '700px' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '14px', borderBottom: '1px solid var(--border-dim)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.5rem' }}>{selectedAgent.emoji}</span>
            <div>
              <div style={{ fontWeight: '700', fontSize: '1rem' }}>{selectedAgent.name}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{selectedAgent.desc}</div>
            </div>
          </div>
          <span className="badge-neon badge-green">{selectedAgent.model}</span>
        </div>

        {/* Message Feed */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 0', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {messages.length === 0 ? (
            <div style={{ textAlign: 'center', margin: 'auto', color: 'var(--text-muted)' }}>
              <Bot size={36} color="var(--neon-cyan)" style={{ marginBottom: '12px', opacity: 0.5 }} />
              <div>Direct Playground active with <strong>{selectedAgent.name}</strong>.</div>
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>Ask targeted exploit analysis, code generation, or reverse engineering tasks.</div>
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div
                key={idx}
                style={{
                  alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                  background: msg.role === 'user' ? 'rgba(0, 229, 255, 0.12)' : 'var(--bg-secondary)',
                  border: msg.role === 'user' ? '1px solid rgba(0, 229, 255, 0.3)' : '1px solid var(--border-dim)',
                  borderRadius: '10px',
                  padding: '14px 16px',
                }}
              >
                <div style={{ fontSize: '0.75rem', color: msg.role === 'user' ? 'var(--neon-cyan)' : 'var(--neon-green)', fontWeight: '700', marginBottom: '6px' }}>
                  {msg.role === 'user' ? 'YOU' : `${msg.agent} (${msg.model})`}
                </div>
                
                {msg.thinking && (
                  <div style={{ background: 'rgba(0,0,0,0.5)', borderLeft: '3px solid var(--neon-amber)', padding: '8px 12px', marginBottom: '10px', fontSize: '0.8rem', color: '#fbbf24', fontFamily: 'var(--font-code)' }}>
                    <strong>Thinking Trace:</strong>
                    <p style={{ marginTop: '4px', whiteSpace: 'pre-wrap' }}>{msg.thinking}</p>
                  </div>
                )}

                <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', lineHeight: '1.5', fontFamily: msg.role === 'assistant' ? 'var(--font-code)' : 'var(--font-main)' }}>
                  {msg.content || (isGenerating && idx === messages.length - 1 ? 'Generating response on NVIDIA GPU...' : '')}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Input Footer */}
        <form onSubmit={handleSendMessage} style={{ display: 'flex', gap: '10px', paddingTop: '14px', borderTop: '1px solid var(--border-dim)' }}>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`Ask ${selectedAgent.name}...`}
            style={{
              flex: 1,
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-dim)',
              borderRadius: '8px',
              padding: '12px 16px',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-main)',
              fontSize: '0.95rem',
              outline: 'none',
            }}
          />
          <button type="submit" disabled={isGenerating || !input.trim()} className="cyber-btn">
            <Send size={16} />
            Send
          </button>
        </form>

      </div>

    </div>
  );
}
