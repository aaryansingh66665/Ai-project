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
  ChevronRight,
  Shield,
  Flame,
  Bug,
  Crosshair,
  Award,
  Sparkles,
  ArrowRight
} from 'lucide-react';

const ENRICHMENT_STEPS = [
  { step: '1', name: 'Nmap Scan', desc: 'Port & Service Discovery', color: 'var(--p-blue)' },
  { step: '2', name: 'Product + Version', desc: 'Banner & String Normalization', color: 'var(--p-cyan)' },
  { step: '3', name: 'CPE 2.3', desc: 'Standard NIST Platform IDs', color: 'var(--p-purple)' },
  { step: '4', name: 'CVE Matching', desc: 'NVD, Vulners, GHSA Feeds', color: 'var(--p-amber)' },
  { step: '5', name: 'CVSS Scoring', desc: 'v3.1 Base Metric & Vectors', color: 'var(--p-red)' },
  { step: '6', name: 'CISA KEV', desc: 'Actively Exploited Catalog', color: '#ff0055' },
  { step: '7', name: 'Exploit Availability', desc: 'ExploitDB & Metasploit Modules', color: '#ff5500' },
  { step: '8', name: 'Confidence Score', desc: '0-100% Explainable Rating', color: 'var(--p-green)' },
];

export default function NmapScannerHub({ onSendToSwarm }) {
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('standard');
  const [customArgs, setCustomArgs] = useState('-sV -sC -T4');
  const [isScanning, setIsScanning] = useState(false);
  const [isEnriching, setIsEnriching] = useState(false);
  const [statusInfo, setStatusInfo] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [enrichmentResult, setEnrichmentResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [expandedScripts, setExpandedScripts] = useState({});
  const [expandedBreakdown, setExpandedBreakdown] = useState({});
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
    setEnrichmentResult(null);

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
        // Automatically trigger 8-step correlation
        run8StepEnrichment(data);
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
    setEnrichmentResult(null);

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
        // Trigger 8-step correlation
        run8StepEnrichment(data);
      } else {
        setErrorMessage(`Upload parsing failed: ${data.error}`);
        setUploadStatus(null);
      }
    } catch (err) {
      setErrorMessage(`Upload error: ${err.message}`);
      setUploadStatus(null);
    }
  };

  const run8StepEnrichment = async (scanDataToUse) => {
    const data = scanDataToUse || scanResult;
    if (!data) return;

    setIsEnriching(true);
    try {
      const res = await fetch('/api/mission/correlate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: data.target || target,
          scan_data: data,
        }),
      });

      if (res.ok) {
        const enriched = await res.json();
        setEnrichmentResult(enriched);
      }
    } catch (err) {
      console.error('8-step enrichment failed:', err);
    } finally {
      setIsEnriching(false);
    }
  };

  const toggleScriptExpand = (key) => {
    setExpandedScripts(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const toggleBreakdown = (cveId) => {
    setExpandedBreakdown(prev => ({
      ...prev,
      [cveId]: !prev[cveId]
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
        }),
      });

      if (onSendToSwarm) {
        onSendToSwarm();
      }
    } catch (err) {
      console.error('Failed to trigger swarm audit:', err);
    } finally {
      setSwarmTriggering(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* ── 8-STEP ENRICHMENT CHAIN BANNER ────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: '20px 24px', background: 'radial-gradient(ellipse at center, rgba(0,30,60,0.4) 0%, rgba(0,5,15,0.85) 100%)', borderColor: 'var(--p-blue)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Crosshair size={18} color="var(--p-cyan)" />
            <div>
              <div style={{ fontFamily: 'Orbitron,monospace', fontWeight: 800, fontSize: '0.82rem', letterSpacing: '2px', color: 'var(--p-cyan)', textTransform: 'uppercase' }}>
                8-Stage Vulnerability Risk & Enrichment Pipeline
              </div>
              <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.68rem', color: 'rgba(0,200,248,0.7)', marginTop: '2px' }}>
                Nmap Ingestion → CPE Normalization → Threat Intel Correlation → CISA KEV & Exploit Validation → Confidence Scoring
              </div>
            </div>
          </div>

          {scanResult && (
            <button
              onClick={() => run8StepEnrichment()}
              disabled={isEnriching}
              className="cyber-btn"
              style={{ padding: '6px 14px', fontSize: '0.72rem' }}
            >
              {isEnriching ? <RefreshCw size={12} className="animate-spin" /> : <Sparkles size={12} />}
              {isEnriching ? 'ENRICHING...' : 'RE-RUN 8-STEP ENRICHMENT'}
            </button>
          )}
        </div>

        {/* The 8 Step Flow Display */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px', marginTop: '10px' }}>
          {ENRICHMENT_STEPS.map((s, idx) => (
            <div key={s.step} style={{
              background: 'rgba(0,200,248,0.03)',
              border: `1px solid ${s.color}40`,
              padding: '10px 12px',
              position: 'relative',
              clipPath: 'polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 0 100%)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.6rem', color: s.color, fontWeight: 800 }}>STEP 0{s.step}</span>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, boxShadow: `0 0 8px ${s.color}` }} />
              </div>
              <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.68rem', fontWeight: 700, color: '#fff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {s.name}
              </div>
              <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.58rem', color: 'rgba(255,255,255,0.5)', marginTop: '2px', lineHeight: 1.2 }}>
                {s.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Control Grid: Scan Config & Offline Upload */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        
        {/* Live Network Scanner */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Radar size={20} color="var(--neon-cyan)" />
              <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Live Network Reconnaissance</h3>
            </div>
            {statusInfo && (
              <span className={`badge-neon ${statusInfo.available ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.7rem' }}>
                {statusInfo.available ? 'NMAP ONLINE' : 'NMAP OFFLINE'}
              </span>
            )}
          </div>

          <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                TARGET IP / CIDR / HOSTNAME
              </label>
              <input
                type="text"
                className="cyber-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.1 or 10.0.0.0/24 or example.com"
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                SCAN PROFILE PRESET
              </label>
              <select
                className="cyber-input"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                style={{ cursor: 'pointer' }}
              >
                <option value="quick">Quick Port Scan (-sV -T4 -F)</option>
                <option value="standard">Standard Service Recon (-sV -sC -T4)</option>
                <option value="vuln">Vulnerability Audit (-sV --script=vulners,vuln)</option>
                <option value="full">Full Port Sweep (-sV -sC -p- -T4)</option>
                <option value="custom">Custom Parameters</option>
              </select>
            </div>

            {profile === 'custom' && (
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  CUSTOM CLI ARGUMENTS
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
                  <span>Execute Nmap Recon & 8-Step Audit</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Offline Log Ingestion */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-dim)', paddingBottom: '12px', marginBottom: '14px' }}>
              <UploadCloud size={18} color="var(--neon-green)" />
              <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Offline Scan Ingestor</h3>
            </div>
            
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Upload pre-existing Nmap scan logs (<code>.xml</code> or <code>.nmap</code> plaintext) for immediate 8-step CVE correlation and AI swarm auditing.
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

      {/* ── 8-STEP CORRELATED VULNERABILITIES RESULT CARDS ────────────────────────── */}
      {enrichmentResult && enrichmentResult.vulnerabilities && enrichmentResult.vulnerabilities.length > 0 && (
        <div className="glass-panel" style={{ padding: '24px', borderColor: 'var(--p-purple)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Shield size={22} color="var(--p-purple)" />
              <div>
                <h3 style={{ fontFamily: 'Orbitron,monospace', fontSize: '1.05rem', fontWeight: 800, color: 'var(--p-purple)' }}>
                  Correlated Vulnerabilities ({enrichmentResult.vulnerabilities.length} Found)
                </h3>
                <p style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.72rem', color: 'rgba(0,200,248,0.7)', marginTop: '2px' }}>
                  Enrichment completed in {enrichmentResult.duration_s}s across {enrichmentResult.total_services} service(s)
                </p>
              </div>
            </div>

            <button
              onClick={triggerSwarmAudit}
              disabled={swarmTriggering}
              className="cyber-btn"
              style={{ background: 'linear-gradient(135deg, rgba(181, 23, 158, 0.4), rgba(0, 229, 255, 0.3))', borderColor: 'var(--neon-purple)', color: '#fff' }}
            >
              <Zap size={14} color="var(--neon-cyan)" />
              <span>{swarmTriggering ? 'Disseminating...' : 'Analyze with Multi-Agent Swarm'}</span>
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {enrichmentResult.vulnerabilities.map((v, idx) => {
              const isKev = v.is_cisa_kev;
              const hasExploit = v.exploit_available;
              const confPct = v.confidence_score || 0;
              const isExpanded = expandedBreakdown[v.cve_id];

              return (
                <div key={idx} style={{
                  background: 'rgba(0,10,25,0.6)',
                  border: `1px solid ${isKev ? '#ff0055' : v.cvss_score >= 9.0 ? 'var(--p-red)' : 'rgba(0,200,248,0.2)'}`,
                  padding: '16px 20px',
                  position: 'relative'
                }}>
                  {/* Top Bar */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontFamily: 'Orbitron,monospace', fontWeight: 800, fontSize: '0.9rem', color: 'var(--p-cyan)' }}>
                        {v.cve_id}
                      </span>
                      {v.port && (
                        <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.68rem', color: 'var(--p-blue)', background: 'rgba(0,200,248,0.1)', padding: '2px 6px', border: '1px solid rgba(0,200,248,0.3)' }}>
                          PORT {v.port}
                        </span>
                      )}
                      {v.cvss_score && (
                        <span style={{
                          fontFamily: 'Orbitron,monospace',
                          fontSize: '0.68rem',
                          fontWeight: 800,
                          padding: '2px 8px',
                          background: v.cvss_score >= 9.0 ? 'rgba(255,30,60,0.2)' : v.cvss_score >= 7.0 ? 'rgba(255,140,0,0.2)' : 'rgba(0,200,248,0.2)',
                          color: v.cvss_score >= 9.0 ? 'var(--p-red)' : v.cvss_score >= 7.0 ? 'var(--p-amber)' : 'var(--p-blue)',
                          border: `1px solid ${v.cvss_score >= 9.0 ? 'var(--p-red)' : v.cvss_score >= 7.0 ? 'var(--p-amber)' : 'var(--p-blue)'}`,
                        }}>
                          CVSS {v.cvss_score} // {v.cvss_severity}
                        </span>
                      )}
                      {isKev && (
                        <span style={{
                          fontFamily: 'Orbitron,monospace',
                          fontSize: '0.65rem',
                          fontWeight: 800,
                          background: 'rgba(255,0,85,0.25)',
                          color: '#ff0055',
                          border: '1px solid #ff0055',
                          padding: '2px 8px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          animation: 'phud 1.5s infinite'
                        }}>
                          <Flame size={10} /> CISA KEV ACTIVE THREAT
                        </span>
                      )}
                    </div>

                    {/* Confidence Meter */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.62rem', color: 'var(--p-green)', fontWeight: 700 }}>
                          {confPct}% CONFIDENCE ({v.confidence_level})
                        </div>
                        <div style={{ width: 100, height: 4, background: 'rgba(255,255,255,0.1)', marginTop: 3 }}>
                          <div style={{ width: `${confPct}%`, height: '100%', background: confPct >= 80 ? 'var(--p-green)' : confPct >= 50 ? 'var(--p-amber)' : 'var(--p-blue)' }} />
                        </div>
                      </div>
                      <button
                        onClick={() => toggleBreakdown(v.cve_id)}
                        className="cyber-btn cyber-btn-secondary"
                        style={{ padding: '3px 8px', fontSize: '0.58rem' }}
                      >
                        {isExpanded ? 'HIDE' : 'EXPLAIN'}
                      </button>
                    </div>
                  </div>

                  {/* Title & Product info */}
                  <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.82rem', color: '#fff', marginBottom: '6px' }}>
                    {v.title}
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', fontSize: '0.7rem', color: 'rgba(0,200,248,0.7)', marginBottom: '8px' }}>
                    <span>Product: <strong>{v.product} {v.version}</strong></span>
                    <span>•</span>
                    <span>CPE: <code style={{ color: 'var(--p-cyan)' }}>{v.cpe}</code></span>
                    {hasExploit && (
                      <>
                        <span>•</span>
                        <span style={{ color: '#ff5500', fontWeight: 700 }}>
                          Exploit Available ({v.exploit_sources?.join(', ')})
                        </span>
                      </>
                    )}
                  </div>

                  {/* Explainable Confidence Breakdown Dropdown */}
                  {isExpanded && v.confidence_breakdown && (
                    <div style={{ background: 'rgba(0,5,15,0.9)', border: '1px solid rgba(0,255,148,0.3)', padding: '10px 14px', marginTop: '8px', marginBottom: '8px' }}>
                      <div style={{ fontFamily: 'Orbitron,monospace', fontSize: '0.62rem', color: 'var(--p-green)', fontWeight: 800, marginBottom: '6px' }}>
                        CONFIDENCE FACTOR BREAKDOWN (TOTAL: {confPct}/100)
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '6px', fontSize: '0.68rem', fontFamily: 'Share Tech Mono,monospace' }}>
                        {Object.entries(v.confidence_breakdown).map(([k, item]) => (
                          <div key={k} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,0.02)', padding: '4px 8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span style={{ color: 'rgba(0,200,248,0.8)' }}>{item.reason}</span>
                            <span style={{ color: item.pts > 0 ? 'var(--p-green)' : 'rgba(255,255,255,0.3)', fontWeight: 700 }}>+{item.pts} pts</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Remediation */}
                  {v.remediation && (
                    <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.72rem', color: 'rgba(0,255,148,0.8)', marginTop: '4px' }}>
                      Remediation: {v.remediation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
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
