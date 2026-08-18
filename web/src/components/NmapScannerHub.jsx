import React, { useState, useEffect } from 'react';
import { 
  Radar, 
  Terminal, 
  UploadCloud, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Play, 
  FileText, 
  Cpu, 
  Layers, 
  Zap, 
  RefreshCw,
  Server,
  Lock,
  ChevronDown,
  ChevronRight
} from 'lucide-react';

export default function NmapScannerHub({ onSendToSwarm }) {
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('standard');
  const [customArgs, setCustomArgs] = useState('-sV -sC -T4');
  const [isScanning, setIsScanning] = useState(false);
  const [statusInfo, setStatusInfo] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [expandedScripts, setExpandedScripts] = useState({});
  const [swarmTriggering, setSwarmTriggering] = useState(false);

  // Fetch Nmap binary status
  const checkNmapStatus = async () => {
    try {
      const res = await fetch('/api/tools/nmap/status');
      if (res.ok) {
        const data = await res.json();
        setStatusInfo(data);
      }
    } catch (e) {
      console.error('Failed to get Nmap status:', e);
    }
  };

  useEffect(() => {
    checkNmapStatus();
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!target) return;

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);

    try {
      const res = await fetch('/api/tools/nmap/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          profile,
          custom_args: profile === 'custom' ? customArgs : undefined,
          timeout_seconds: 180,
        }),
      });

      const data = await res.json();
      if (data.success) {
        setScanResult(data);
      } else {
        setErrorMessage(data.error || 'Nmap scan encountered an issue.');
      }
    } catch (err) {
      setErrorMessage(`Scan failed: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadStatus('Parsing Nmap scan file...');
    setErrorMessage(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/tools/nmap/upload', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();
      if (data.success) {
        setScanResult(data);
        setUploadStatus(`✔ Successfully parsed '${data.filename}' (${data.open_ports_count} open ports found)`);
      } else {
        setErrorMessage(`Upload parsing failed: ${data.error}`);
        setUploadStatus(null);
      }
    } catch (err) {
      setErrorMessage(`Upload error: ${err.message}`);
      setUploadStatus(null);
    }
  };

  const toggleScriptExpand = (key) => {
    setExpandedScripts(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const triggerSwarmAudit = async () => {
    if (!scanResult) return;
    setSwarmTriggering(true);
    try {
      const res = await fetch('/api/tools/nmap/analyze-with-swarm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: scanResult.target || target,
          scan_data: scanResult,
          custom_agents: ['network', 'threat_intel', 'coder', 'redteam', 'report']
        })
      });
      const data = await res.json();
      if (onSendToSwarm) {
        onSendToSwarm(data);
      }
    } catch (err) {
      console.error('Swarm audit trigger failed:', err);
    } finally {
      setSwarmTriggering(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header Banner & Status Bar */}
      <div className="glass-panel" style={{ padding: '20px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.2), rgba(0, 255, 136, 0.2))', padding: '10px', borderRadius: '10px', border: '1px solid var(--border-glow)' }}>
            <Radar size={28} color="var(--neon-cyan)" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: '800', background: 'linear-gradient(90deg, #00e5ff, #00ff88)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              NMAP NETWORK RECONNAISSANCE HUB
            </h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Live host discovery, service versioning, NSE script auditing & multi-agent vulnerability assessment
            </p>
          </div>
        </div>

        {/* Nmap Status Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {statusInfo?.available ? (
            <div className="badge-neon badge-green" style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
              <CheckCircle size={14} />
              <span>NMAP BINARY DETECTED</span>
            </div>
          ) : (
            <div className="badge-neon badge-amber" style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
              <AlertTriangle size={14} />
              <span>OFFLINE LOG MODE ACTIVE</span>
            </div>
          )}
          <button 
            onClick={checkNmapStatus}
            style={{ background: 'transparent', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)', padding: '6px', borderRadius: '6px', cursor: 'pointer' }}
            title="Refresh Nmap binary status"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Main 2-Column Grid: Scanner Form & Offline Ingestion */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        
        {/* Live Scan Control Box */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px' }}>
            <Server size={18} color="var(--neon-cyan)" />
            <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Live Target Scanner</h3>
          </div>

          <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Target IP, Subnet or Hostname
              </label>
              <input
                type="text"
                className="cyber-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 192.168.1.1, 10.0.0.0/24, scanme.nmap.org"
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Scan Profile & Techniques
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                {[
                  { id: 'quick', label: '⚡ Fast Discovery (-F -sV)' },
                  { id: 'standard', label: '🛡️ Service Audit (-sV -sC)' },
                  { id: 'vuln', label: '🔥 Vuln NSE Scripts' },
                  { id: 'custom', label: '⚙️ Custom Flags' },
                ].map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => setProfile(p.id)}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      border: profile === p.id ? '1px solid var(--neon-cyan)' : '1px solid var(--border-dim)',
                      background: profile === p.id ? 'rgba(0, 229, 255, 0.15)' : 'var(--bg-secondary)',
                      color: profile === p.id ? 'var(--neon-cyan)' : 'var(--text-secondary)',
                      fontSize: '0.75rem',
                      fontWeight: profile === p.id ? '600' : '400',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            {profile === 'custom' && (
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Custom Command Arguments
                </label>
                <input
                  type="text"
                  className="cyber-input"
                  value={customArgs}
                  onChange={(e) => setCustomArgs(e.target.value)}
                  placeholder="-sS -p 1-1000 -T4 -O"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={isScanning}
              className="cyber-btn"
              style={{ width: '100%', justifyContent: 'center', marginTop: '4px' }}
            >
              {isScanning ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  <span>Scanning Network Target...</span>
                </>
              ) : (
                <>
                  <Play size={16} />
                  <span>Execute Nmap Recon</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Offline Log Ingestion & Host Installation Info */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px', marginBottom: '14px' }}>
              <UploadCloud size={18} color="var(--neon-green)" />
              <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Offline Scan Ingestor</h3>
            </div>
            
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Upload pre-existing Nmap scan logs (<code>.xml</code> or <code>.nmap</code> plaintext) for immediate agent extraction and CVE correlation.
            </p>

            <label style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '24px',
              border: '2px dashed var(--border-dim)',
              borderRadius: '10px',
              cursor: 'pointer',
              background: 'rgba(13, 18, 29, 0.5)',
              transition: 'all 0.2s ease',
            }}>
              <UploadCloud size={32} color="var(--neon-cyan)" style={{ marginBottom: '8px' }} />
              <span style={{ fontSize: '0.85rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                Drop Nmap .XML or .NMAP File Here
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                or click to browse local filesystem
              </span>
              <input
                type="file"
                accept=".xml,.nmap,.txt"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
            </label>
          </div>

          {/* Helper Tips */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-dim)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--neon-cyan)', marginBottom: '4px', fontWeight: '600' }}>
              <Terminal size={14} />
              <span>Windows CLI Tip:</span>
            </div>
            To enable live scanning on this machine, install Nmap via:
            <code style={{ display: 'block', background: 'var(--bg-primary)', padding: '4px 8px', borderRadius: '4px', color: 'var(--neon-green)', marginTop: '4px' }}>
              winget install Insecure.Nmap
            </code>
          </div>
        </div>

      </div>

      {/* Status Messages */}
      {uploadStatus && (
        <div style={{ background: 'rgba(0, 255, 136, 0.1)', border: '1px solid var(--neon-green)', color: 'var(--neon-green)', padding: '12px 16px', borderRadius: '8px', fontSize: '0.85rem' }}>
          {uploadStatus}
        </div>
      )}

      {errorMessage && (
        <div style={{ background: 'rgba(255, 0, 85, 0.1)', border: '1px solid var(--neon-red)', color: 'var(--neon-red)', padding: '12px 16px', borderRadius: '8px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <AlertTriangle size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Discovered Hosts & Ports Matrix */}
      {scanResult && (
        <div className="glass-panel" style={{ padding: '24px' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '20px', borderBottom: '1px solid var(--border-dim)', paddingBottom: '16px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={20} color="var(--neon-cyan)" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: '700' }}>
                  Reconnaissance Findings for: {scanResult.target || target}
                </h3>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Discovered <strong>{scanResult.total_hosts || scanResult.hosts?.length || 0}</strong> active hosts • <strong>{scanResult.open_ports_count || 0}</strong> open ports
              </p>
            </div>

            {/* Swarm Audit Trigger */}
            <button
              onClick={triggerSwarmAudit}
              disabled={swarmTriggering}
              className="cyber-btn"
              style={{ background: 'linear-gradient(135deg, rgba(181, 23, 158, 0.3), rgba(0, 229, 255, 0.2))', borderColor: 'var(--neon-purple)', color: '#fff' }}
            >
              <Zap size={16} color="var(--neon-cyan)" />
              <span>{swarmTriggering ? 'Disseminating to Swarm...' : 'Analyze with Multi-Agent Swarm'}</span>
            </button>
          </div>

          {/* Hosts and Ports Loop */}
          {scanResult.hosts && scanResult.hosts.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {scanResult.hosts.map((host, hIdx) => (
                <div key={hIdx} style={{ background: 'var(--bg-secondary)', borderRadius: '10px', border: '1px solid var(--border-dim)', overflow: 'hidden' }}>
                  
                  {/* Host Card Header */}
                  <div style={{ padding: '14px 18px', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{ background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border-dim)', fontFamily: 'var(--font-code)', fontSize: '0.9rem', color: 'var(--neon-cyan)', fontWeight: '700' }}>
                        {host.ip || 'Host'}
                      </div>
                      {host.hostnames && host.hostnames.length > 0 && (
                        <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          ({host.hostnames.join(', ')})
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {host.os_matches && host.os_matches.length > 0 && (
                        <span className="badge-neon badge-purple" style={{ fontSize: '0.75rem' }}>
                          OS: {host.os_matches[0].name} ({host.os_matches[0].accuracy}%)
                        </span>
                      )}
                      <span className="badge-neon badge-green" style={{ fontSize: '0.75rem' }}>
                        {host.ports?.length || 0} Open Ports
                      </span>
                    </div>
                  </div>

                  {/* Ports Table */}
                  {host.ports && host.ports.length > 0 ? (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-dim)', textAlign: 'left', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                            <th style={{ padding: '10px 16px' }}>Port</th>
                            <th style={{ padding: '10px 16px' }}>State</th>
                            <th style={{ padding: '10px 16px' }}>Service</th>
                            <th style={{ padding: '10px 16px' }}>Product & Version</th>
                            <th style={{ padding: '10px 16px' }}>Scripts / Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {host.ports.map((port, pIdx) => {
                            const scriptKeys = Object.keys(port.scripts || {});
                            const rowKey = `${hIdx}_${pIdx}`;
                            const isExpanded = expandedScripts[rowKey];

                            return (
                              <React.Fragment key={pIdx}>
                                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', transition: 'background 0.15s ease' }}>
                                  <td style={{ padding: '12px 16px', fontFamily: 'var(--font-code)', fontWeight: '700', color: 'var(--neon-cyan)' }}>
                                    {port.port}/{port.protocol}
                                  </td>
                                  <td style={{ padding: '12px 16px' }}>
                                    <span style={{ color: 'var(--neon-green)', fontWeight: '600' }}>
                                      ● {port.state}
                                    </span>
                                  </td>
                                  <td style={{ padding: '12px 16px', color: 'var(--text-primary)', fontWeight: '500' }}>
                                    {port.service || 'unknown'}
                                  </td>
                                  <td style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>
                                    {port.product} {port.version} {port.extrainfo ? `(${port.extrainfo})` : ''}
                                  </td>
                                  <td style={{ padding: '12px 16px' }}>
                                    {scriptKeys.length > 0 ? (
                                      <button
                                        onClick={() => toggleScriptExpand(rowKey)}
                                        style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '4px',
                                          background: 'rgba(0, 229, 255, 0.1)',
                                          border: '1px solid var(--border-dim)',
                                          color: 'var(--neon-cyan)',
                                          padding: '4px 8px',
                                          borderRadius: '4px',
                                          fontSize: '0.75rem',
                                          cursor: 'pointer',
                                        }}
                                      >
                                        {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                                        <span>{scriptKeys.length} NSE Scripts</span>
                                      </button>
                                    ) : (
                                      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>None</span>
                                    )}
                                  </td>
                                </tr>

                                {/* Expanded Script Details */}
                                {isExpanded && scriptKeys.length > 0 && (
                                  <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                                    <td colSpan={5} style={{ padding: '12px 16px' }}>
                                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                        {scriptKeys.map((sKey) => (
                                          <div key={sKey} style={{ background: 'var(--bg-primary)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-dim)' }}>
                                            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--neon-amber)', marginBottom: '4px' }}>
                                              NSE: {sKey}
                                            </div>
                                            <pre style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', fontFamily: 'var(--font-code)' }}>
                                              {port.scripts[sKey]}
                                            </pre>
                                          </div>
                                        ))}
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </React.Fragment>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                      No open ports identified on this host.
                    </div>
                  )}

                </div>
              ))}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
              No host or open port data discovered in this scan output.
            </div>
          )}

        </div>
      )}

    </div>
  );
}
