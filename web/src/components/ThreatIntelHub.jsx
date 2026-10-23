import React, { useState, useRef } from "react";
import { 
  Shield, Search, AlertTriangle, AlertCircle, Info, CheckCircle, 
  ExternalLink, Zap, Database, RefreshCw, ChevronDown, ChevronRight, 
  Send, Sparkles, Terminal, BookOpen, Layers, Flame, Package, Cpu, ArrowRight,
  Code2, Copy, Check, FileText, Download, Crosshair, Star, GitFork, Play
} from "lucide-react";

/* ── Severity badge ────────────────────────────────── */
const SEV_COLORS = {
  CRITICAL: { bg: "rgba(255,30,60,0.12)", border: "rgba(255,30,60,0.5)", text: "#ff1e3c", icon: AlertTriangle },
  HIGH:     { bg: "rgba(255,100,0,0.10)", border: "rgba(255,100,0,0.45)", text: "#ff6400", icon: AlertCircle },
  MEDIUM:   { bg: "rgba(255,179,0,0.10)", border: "rgba(255,179,0,0.4)",  text: "#ffb300", icon: Info },
  LOW:      { bg: "rgba(0,255,148,0.08)", border: "rgba(0,255,148,0.35)", text: "#00ff94", icon: CheckCircle },
  UNKNOWN:  { bg: "rgba(0,200,248,0.07)", border: "rgba(0,200,248,0.25)", text: "#00c8f8", icon: Info },
};

function SeverityBadge({ severity }) {
  const s = SEV_COLORS[severity] || SEV_COLORS.UNKNOWN;
  const Icon = s.icon;
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:4, padding:"2px 8px",
      background:s.bg, border:`1px solid ${s.border}`, color:s.text,
      fontFamily:"Orbitron,monospace", fontSize:"0.55rem", letterSpacing:"1px",
      textTransform:"uppercase", flexShrink:0 }}>
      <Icon size={9} />
      {severity}
    </span>
  );
}

/* ── Source chip ───────────────────────────────────── */
const SOURCE_COLORS = {
  NVD:              "#00c8f8",
  CISA_KEV:         "#ff1e3c",
  OSV:              "#00ff94",
  GitHub_Advisory:  "#bf40ff",
  ExploitDB:        "#ff6400",
  Vulners:          "#ffb300",
  Rapid7:           "#ff3366",
  Metasploit:       "#ff0055",
  GitHub_PoC:       "#a855f7",
  RedHat:           "#ff1e3c",
  Ubuntu:           "#ff6400",
};

function SourceChip({ source }) {
  const color = SOURCE_COLORS[source] || "#00c8f8";
  return (
    <span style={{ padding:"1px 6px", background:`${color}15`, border:`1px solid ${color}30`,
      color, fontFamily:"Share Tech Mono,monospace", fontSize:"0.58rem", letterSpacing:"0.3px", flexShrink:0 }}>
      {source.replace("_"," ")}
    </span>
  );
}

const QUICK_QUERIES = [
  "CVE-2021-44228", "MS17-010", "CVE-2024-3400", "CVE-2024-6387",
  "log4shell", "vsftpd", "eternalblue", "spring4shell", "proxylogon"
];

export default function ThreatIntelHub({ onSendToSwarm }) {
  // Modes: 'radar' (Unified Exploit & Vuln Search), 'metasploit', 'exploitdb', 'github_pocs', 'hybrid_kb', 'kb_synthesis', 'cisa_kev'
  const [activeMode, setActiveMode] = useState("radar");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Results State
  const [radarResults, setRadarResults] = useState(null);
  const [msfResults, setMsfResults] = useState(null);
  const [edbResults, setEdbResults] = useState(null);
  const [ghPocResults, setGhPocResults] = useState(null);
  const [kbResult, setKbResult] = useState(null);
  const [cisaFeed, setCisaFeed] = useState(null);

  // Dual-Engine Hybrid Search State
  const [hybridResults, setHybridResults] = useState(null);
  const [searchMode, setSearchMode] = useState("hybrid"); // "hybrid" | "bm25" | "semantic"
  const [alpha, setAlpha] = useState(0.5);

  // Neural Synthesis Model Selector (NVIDIA Nemotron / Qwen)
  const [synthesisModel, setSynthesisModel] = useState("nemotron-mini:4b");

  // Active Code Modal / Drawer
  const [selectedCode, setSelectedCode] = useState(null); // { title, language, code, filename }
  const [copied, setCopied] = useState(false);

  // 1. Unified Radar Search
  const handleRadarSearch = async (q) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/tools/exploits/find-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: targetQ }),
      });
      const data = await res.json();
      setRadarResults(data);
      if (q) setQuery(q);
    } catch (e) {
      setError(`Unified Exploit search failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 2. Metasploit Search
  const handleMsfSearch = async (q) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/tools/metasploit/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: targetQ, max_results: 10 }),
      });
      const data = await res.json();
      setMsfResults(data.modules || []);
      if (q) setQuery(q);
    } catch (e) {
      setError(`Metasploit search failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 3. Exploit-DB Search
  const handleEdbSearch = async (q) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/tools/exploitdb/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: targetQ, max_results: 12 }),
      });
      const data = await res.json();
      setEdbResults(data.entries || []);
      if (q) setQuery(q);
    } catch (e) {
      setError(`Exploit-DB search failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 4. GitHub PoCs Search
  const handleGhPocSearch = async (q) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/tools/github-pocs/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: targetQ, max_results: 12 }),
      });
      const data = await res.json();
      setGhPocResults(data.pocs || []);
      if (q) setQuery(q);
    } catch (e) {
      setError(`GitHub PoC search failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 5. Dual-Engine Hybrid KB Search
  const handleHybridSearch = async (q, customMode, customAlpha) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/security-kb/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: targetQ,
          top_k: 8,
          mode: customMode || searchMode,
          alpha: customAlpha !== undefined ? customAlpha : alpha,
        }),
      });
      const data = await res.json();
      setHybridResults(data);
      if (q) setQuery(q);
    } catch (e) {
      setError(`Hybrid KB search failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 6. Local Security KB Synthesis (NVIDIA Nemotron / Qwen)
  const handleKBSynthesis = async (q, customModel) => {
    const targetQ = q || query.trim();
    if (!targetQ) return;
    const targetModel = customModel || synthesisModel;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/security-kb/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: targetQ, model: targetModel }),
      });
      const data = await res.json();
      setKbResult(data);
      if (q) setQuery(q);
    } catch (e) {
      setError(`Neural Intelligence synthesis failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 7. CISA KEV Feed
  const handleFetchCisaKev = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/threat-intel/cisa-kev");
      const data = await res.json();
      setCisaFeed(data.vulnerabilities || []);
    } catch (e) {
      setError(`Failed to fetch CISA KEV: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Helper: Fetch raw Exploit-DB code
  const viewRawEdbCode = async (edbId, title) => {
    setLoading(true);
    try {
      const cleanId = edbId.replace(/[^\d]/g, "");
      const res = await fetch(`/api/tools/exploitdb/code/${cleanId}`);
      const data = await res.json();
      setSelectedCode({
        title: `Exploit-DB: EDB-${cleanId} (${title || "PoC Code"})`,
        language: "python",
        code: data.raw_code || "// No code available.",
        filename: `EDB_${cleanId}.py`,
      });
    } catch (e) {
      setError(`Failed to fetch raw EDB code: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Helper: Generate MSF RC Script
  const generateMsfRc = async (fullname, rhosts = "127.0.0.1", rport = null) => {
    try {
      const res = await fetch("/api/tools/metasploit/generate-rc", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ module_fullname: fullname, rhosts, rport }),
      });
      const data = await res.json();
      setSelectedCode({
        title: `Metasploit Resource Script (.rc) - ${fullname}`,
        language: "ruby",
        code: data.rc_script,
        filename: data.filename,
      });
    } catch (e) {
      setError(`Failed to generate MSF script: ${e.message}`);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const onSubmit = (e) => {
    if (e) e.preventDefault();
    if (activeMode === "radar") handleRadarSearch();
    else if (activeMode === "metasploit") handleMsfSearch();
    else if (activeMode === "exploitdb") handleEdbSearch();
    else if (activeMode === "github_pocs") handleGhPocSearch();
    else if (activeMode === "hybrid_kb") handleHybridSearch();
    else if (activeMode === "kb_synthesis") handleKBSynthesis();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      
      {/* ── HEADER & TOOL SELECTOR ────────────────────────────────────────── */}
      <div className="glass-panel" style={{ padding: "20px 24px", borderColor: "var(--p-cyan)", background: "radial-gradient(ellipse at center, rgba(0,25,50,0.5) 0%, rgba(0,5,15,0.9) 100%)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Crosshair size={22} color="var(--p-cyan)" />
            <div>
              <div style={{ fontFamily: "Orbitron,monospace", fontWeight: 800, fontSize: "0.9rem", letterSpacing: "2px", color: "var(--p-cyan)", textTransform: "uppercase" }}>
                EXPLOIT, CVE & METASPLOIT INTELLIGENCE RADAR
              </div>
              <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.68rem", color: "rgba(0,200,248,0.7)", marginTop: 2 }}>
                Metasploit Framework Modules · Exploit-DB Public Codes · GitHub CVE PoCs & Advisories · Local KB
              </div>
            </div>
          </div>

          {/* Sub-Tab Mode Switcher */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button
              onClick={() => { setActiveMode("radar"); if (query) handleRadarSearch(); }}
              className={activeMode === "radar" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem" }}
            >
              <Crosshair size={11} /> UNIFIED RADAR
            </button>
            <button
              onClick={() => { setActiveMode("metasploit"); if (query) handleMsfSearch(); }}
              className={activeMode === "metasploit" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem", borderColor: "#ff0055", color: activeMode === "metasploit" ? "#fff" : "#ff0055" }}
            >
              <Terminal size={11} /> METASPLOIT
            </button>
            <button
              onClick={() => { setActiveMode("exploitdb"); if (query) handleEdbSearch(); }}
              className={activeMode === "exploitdb" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem", borderColor: "#ff6400", color: activeMode === "exploitdb" ? "#fff" : "#ff6400" }}
            >
              <Code2 size={11} /> EXPLOIT-DB
            </button>
            <button
              onClick={() => { setActiveMode("github_pocs"); if (query) handleGhPocSearch(); }}
              className={activeMode === "github_pocs" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem", borderColor: "#bf40ff", color: activeMode === "github_pocs" ? "#fff" : "#bf40ff" }}
            >
              <GitFork size={11} /> GITHUB POCS
            </button>
            <button
              onClick={() => { setActiveMode("hybrid_kb"); if (query) handleHybridSearch(); }}
              className={activeMode === "hybrid_kb" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem", borderColor: "var(--p-cyan)", color: activeMode === "hybrid_kb" ? "#fff" : "var(--p-cyan)" }}
            >
              <Layers size={11} /> HYBRID KB SEARCH
            </button>
            <button
              onClick={() => { setActiveMode("kb_synthesis"); if (query) handleKBSynthesis(); }}
              className={activeMode === "kb_synthesis" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem", borderColor: "#76b900", color: activeMode === "kb_synthesis" ? "#fff" : "#76b900" }}
            >
              <Sparkles size={11} /> NEMOTRON / QWEN SYNTHESIS
            </button>
            <button
              onClick={() => { setActiveMode("cisa_kev"); handleFetchCisaKev(); }}
              className={activeMode === "cisa_kev" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
              style={{ padding: "5px 12px", fontSize: "0.65rem" }}
            >
              <Flame size={11} /> CISA KEV
            </button>
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={onSubmit} style={{ display: "flex", gap: 10, marginBottom: 12 }}>
          <div style={{ flex: 1, position: "relative" }}>
            <Search size={14} color="rgba(0,200,248,0.4)" style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search CVE, Metasploit module, Exploit-DB or GitHub PoC (e.g. CVE-2021-44228, ms17-010, log4shell, vsftpd)..."
              style={{
                width: "100%", padding: "12px 14px 12px 38px",
                background: "rgba(0,200,248,0.04)", border: "1px solid rgba(0,200,248,0.2)",
                color: "#fff", fontFamily: "Share Tech Mono,monospace", fontSize: "0.82rem",
                outline: "none", caretColor: "var(--p-cyan)"
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="cyber-btn"
            style={{ padding: "0 22px", opacity: loading || !query.trim() ? 0.4 : 1 }}
          >
            {loading ? <RefreshCw size={14} className="animate-spin" /> : <Crosshair size={14} />}
            <span>{loading ? "SEARCHING..." : "EXECUTE RADAR SCAN"}</span>
          </button>
        </form>

        {/* Quick query chips */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.55rem", color: "rgba(0,200,248,0.5)", letterSpacing: "1px" }}>
            TARGET RADAR:
          </span>
          {QUICK_QUERIES.map((q, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setQuery(q);
                if (activeMode === "radar") handleRadarSearch(q);
                else if (activeMode === "metasploit") handleMsfSearch(q);
                else if (activeMode === "exploitdb") handleEdbSearch(q);
                else if (activeMode === "github_pocs") handleGhPocSearch(q);
                else if (activeMode === "kb_synthesis") handleKBSynthesis(q);
              }}
              className="cyber-btn cyber-btn-secondary"
              style={{ padding: "3px 8px", fontSize: "0.62rem" }}
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ background: "rgba(255,30,60,0.1)", border: "1px solid var(--p-red)", color: "var(--p-red)", padding: "12px 16px", fontFamily: "Share Tech Mono,monospace", fontSize: "0.8rem" }}>
          {error}
        </div>
      )}

      {/* ── CODE / RC SCRIPT VIEWER MODAL ─────────────────────────────────── */}
      {selectedCode && (
        <div className="glass-panel" style={{ padding: "20px 24px", borderColor: "var(--p-cyan)", background: "#010814" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, borderBottom: "1px solid rgba(0,200,248,0.2)", paddingBottom: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Code2 size={16} color="var(--p-cyan)" />
              <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", color: "var(--p-cyan)", fontWeight: 800 }}>
                {selectedCode.title}
              </span>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                onClick={() => copyToClipboard(selectedCode.code)}
                className="cyber-btn"
                style={{ padding: "3px 10px", fontSize: "0.62rem" }}
              >
                {copied ? <Check size={11} color="var(--p-green)" /> : <Copy size={11} />}
                <span>{copied ? "COPIED!" : "COPY SCRIPT"}</span>
              </button>
              <button
                onClick={() => setSelectedCode(null)}
                className="cyber-btn cyber-btn-secondary"
                style={{ padding: "3px 8px", fontSize: "0.62rem" }}
              >
                CLOSE
              </button>
            </div>
          </div>

          <pre style={{
            margin: 0,
            maxHeight: 400,
            overflowY: "auto",
            fontFamily: "Share Tech Mono,monospace",
            fontSize: "0.75rem",
            lineHeight: 1.6,
            color: "var(--p-white)",
            background: "#00030a",
            padding: "14px 18px",
            border: "1px solid rgba(0,200,248,0.15)",
          }}>
            {selectedCode.code}
          </pre>
        </div>
      )}

      {/* ── 1. UNIFIED RADAR SEARCH RESULTS ──────────────────────────────── */}
      {activeMode === "radar" && radarResults && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          
          {/* Summary Badge Row */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
            <div style={{ background: "rgba(255,0,85,0.08)", border: "1px solid rgba(255,0,85,0.3)", padding: "10px 14px" }}>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.62rem", color: "#ff0055" }}>METASPLOIT MODULES</div>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "1.2rem", fontWeight: 800, color: "#fff" }}>
                {radarResults.metasploit_modules?.length || 0}
              </div>
            </div>
            <div style={{ background: "rgba(255,100,0,0.08)", border: "1px solid rgba(255,100,0,0.3)", padding: "10px 14px" }}>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.62rem", color: "#ff6400" }}>EXPLOIT-DB CODES</div>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "1.2rem", fontWeight: 800, color: "#fff" }}>
                {radarResults.exploit_db_entries?.length || 0}
              </div>
            </div>
            <div style={{ background: "rgba(191,64,255,0.08)", border: "1px solid rgba(191,64,255,0.3)", padding: "10px 14px" }}>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.62rem", color: "var(--p-purple)" }}>GITHUB POC REPOSITORIES</div>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "1.2rem", fontWeight: 800, color: "#fff" }}>
                {radarResults.github_pocs?.length || 0}
              </div>
            </div>
            <div style={{ background: "rgba(0,200,248,0.08)", border: "1px solid rgba(0,200,248,0.3)", padding: "10px 14px" }}>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.62rem", color: "var(--p-cyan)" }}>GITHUB ADVISORIES</div>
              <div style={{ fontFamily: "Orbitron,monospace", fontSize: "1.2rem", fontWeight: 800, color: "#fff" }}>
                {radarResults.github_advisories?.length || 0}
              </div>
            </div>
          </div>

          {/* Section 1: Metasploit Modules */}
          {radarResults.metasploit_modules?.length > 0 && (
            <div className="glass-panel" style={{ padding: "18px 22px", borderColor: "#ff0055" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <Terminal size={16} color="#ff0055" />
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", color: "#ff0055", fontWeight: 800 }}>
                  METASPLOIT FRAMEWORK MODULES ({radarResults.metasploit_modules.length})
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {radarResults.metasploit_modules.map((m, idx) => (
                  <div key={idx} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(255,0,85,0.25)", borderLeft: "3px solid #ff0055", padding: "12px 16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 6, marginBottom: 4 }}>
                      <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.78rem", color: "#fff", fontWeight: 700 }}>
                        {m.fullname}
                      </span>
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.55rem", color: "var(--p-amber)", border: "1px solid rgba(255,179,0,0.3)", padding: "1px 5px" }}>
                          RANK: {m.rank}
                        </span>
                        <button
                          onClick={() => generateMsfRc(m.fullname, "127.0.0.1", m.default_port)}
                          className="cyber-btn"
                          style={{ padding: "2px 8px", fontSize: "0.58rem" }}
                        >
                          <Terminal size={10} /> GENERATE .RC
                        </button>
                      </div>
                    </div>
                    <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.68rem", color: "rgba(0,200,248,0.75)", marginBottom: 6 }}>
                      {m.description}
                    </div>
                    {m.cves?.length > 0 && (
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {m.cves.map((c, i) => (
                          <span key={i} style={{ fontFamily: "Orbitron,monospace", fontSize: "0.55rem", color: "var(--p-cyan)", border: "1px solid rgba(0,200,248,0.2)", padding: "1px 5px" }}>
                            {c}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 2: Exploit-DB Entries */}
          {radarResults.exploit_db_entries?.length > 0 && (
            <div className="glass-panel" style={{ padding: "18px 22px", borderColor: "#ff6400" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <Code2 size={16} color="#ff6400" />
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", color: "#ff6400", fontWeight: 800 }}>
                  EXPLOIT-DB PUBLIC WEAPONIZED CODES ({radarResults.exploit_db_entries.length})
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {radarResults.exploit_db_entries.map((e, idx) => (
                  <div key={idx} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(255,100,0,0.25)", borderLeft: "3px solid #ff6400", padding: "12px 16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 6, marginBottom: 4 }}>
                      <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", color: "#ff6400", fontWeight: 800 }}>
                        {e.id} - {e.title}
                      </span>
                      <button
                        onClick={() => viewRawEdbCode(e.edb_id, e.title)}
                        className="cyber-btn"
                        style={{ padding: "2px 8px", fontSize: "0.58rem" }}
                      >
                        <FileText size={10} /> VIEW RAW CODE
                      </button>
                    </div>
                    <div style={{ display: "flex", gap: 10, fontFamily: "Share Tech Mono,monospace", fontSize: "0.62rem", color: "rgba(255,255,255,0.6)" }}>
                      <span>Platform: <strong>{e.platform}</strong></span>
                      <span>Type: <strong>{e.exploit_type}</strong></span>
                      <span>Date: <strong>{e.date_published}</strong></span>
                      {e.verified && <span style={{ color: "var(--p-green)", fontWeight: 700 }}>● VERIFIED</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 3: GitHub PoC Repositories */}
          {radarResults.github_pocs?.length > 0 && (
            <div className="glass-panel" style={{ padding: "18px 22px", borderColor: "var(--p-purple)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <GitFork size={16} color="var(--p-purple)" />
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", color: "var(--p-purple)", fontWeight: 800 }}>
                  GITHUB CVE POC REPOSITORIES ({radarResults.github_pocs.length})
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 10 }}>
                {radarResults.github_pocs.map((g, idx) => (
                  <div key={idx} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(191,64,255,0.25)", padding: "12px 14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                      <a href={g.html_url} target="_blank" rel="noreferrer" style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.75rem", color: "var(--p-cyan)", textDecoration: "none", fontWeight: 700 }}>
                        {g.full_name}
                      </a>
                      <div style={{ display: "flex", gap: 6, fontSize: "0.6rem", color: "var(--p-amber)" }}>
                        <span><Star size={10} style={{ display: "inline" }} /> {g.stars}</span>
                        <span><GitFork size={10} style={{ display: "inline" }} /> {g.forks}</span>
                      </div>
                    </div>
                    <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.65rem", color: "rgba(255,255,255,0.7)", marginBottom: 6 }}>
                      {g.description || "No description provided."}
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.58rem", color: "rgba(255,255,255,0.4)" }}>
                      <span>Lang: {g.language || "Multi"}</span>
                      <span>Updated: {g.updated_at}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

      {/* ── 2. DEDICATED METASPLOIT TAB ──────────────────────────────────── */}
      {activeMode === "metasploit" && msfResults && (
        <div className="glass-panel" style={{ padding: "20px 24px", borderColor: "#ff0055" }}>
          <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "#ff0055", marginBottom: 14 }}>
            METASPLOIT MODULES FOR: {query} ({msfResults.length} Found)
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {msfResults.map((m, i) => (
              <div key={i} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(255,0,85,0.3)", borderLeft: "4px solid #ff0055", padding: "14px 18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8, marginBottom: 6 }}>
                  <div>
                    <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.85rem", color: "#fff", fontWeight: 800 }}>
                      {m.fullname}
                    </div>
                    <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.68rem", color: "var(--p-cyan)", marginTop: 2 }}>
                      {m.name}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      onClick={() => generateMsfRc(m.fullname, "127.0.0.1", m.default_port)}
                      className="cyber-btn"
                      style={{ padding: "4px 10px", fontSize: "0.62rem" }}
                    >
                      <Terminal size={11} /> GENERATE .RC SCRIPT
                    </button>
                    {m.github_url && (
                      <a href={m.github_url} target="_blank" rel="noreferrer" className="cyber-btn cyber-btn-secondary" style={{ padding: "4px 8px", fontSize: "0.62rem", textDecoration: "none" }}>
                        <ExternalLink size={11} /> SOURCE
                      </a>
                    )}
                  </div>
                </div>
                <p style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.72rem", color: "rgba(0,200,248,0.8)", margin: "6px 0 10px 0", lineHeight: 1.5 }}>
                  {m.description}
                </p>
                <div style={{ display: "flex", gap: 12, fontSize: "0.62rem", fontFamily: "Share Tech Mono,monospace", color: "rgba(255,255,255,0.6)" }}>
                  <span>Rank: <strong style={{ color: "var(--p-amber)" }}>{m.rank}</strong></span>
                  <span>Port: <strong>{m.default_port || "Dynamic"}</strong></span>
                  <span>Author: <strong>{m.author?.join(", ") || "Rapid7"}</strong></span>
                  <span>Date: <strong>{m.disclosure_date || "N/A"}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 3. DEDICATED EXPLOIT-DB TAB ──────────────────────────────────── */}
      {activeMode === "exploitdb" && edbResults && (
        <div className="glass-panel" style={{ padding: "20px 24px", borderColor: "#ff6400" }}>
          <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "#ff6400", marginBottom: 14 }}>
            EXPLOIT-DB ENTRIES FOR: {query} ({edbResults.length} Found)
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {edbResults.map((e, i) => (
              <div key={i} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(255,100,0,0.3)", borderLeft: "3px solid #ff6400", padding: "12px 16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontFamily: "Orbitron,monospace", fontWeight: 800, fontSize: "0.8rem", color: "#ff6400" }}>
                    {e.id} - {e.title}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      onClick={() => viewRawEdbCode(e.edb_id, e.title)}
                      className="cyber-btn"
                      style={{ padding: "3px 8px", fontSize: "0.6rem" }}
                    >
                      <FileText size={10} /> VIEW RAW POC
                    </button>
                    <a href={e.url} target="_blank" rel="noreferrer" className="cyber-btn cyber-btn-secondary" style={{ padding: "3px 6px", fontSize: "0.6rem", textDecoration: "none" }}>
                      <ExternalLink size={10} />
                    </a>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 12, fontFamily: "Share Tech Mono,monospace", fontSize: "0.65rem", color: "rgba(255,255,255,0.6)", marginTop: 4 }}>
                  <span>Platform: <strong>{e.platform}</strong></span>
                  <span>Type: <strong>{e.exploit_type}</strong></span>
                  <span>Date: <strong>{e.date_published}</strong></span>
                  {e.verified && <span style={{ color: "var(--p-green)", fontWeight: 700 }}>● VERIFIED</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 4. DEDICATED GITHUB POCS TAB ─────────────────────────────────── */}
      {activeMode === "github_pocs" && ghPocResults && (
        <div className="glass-panel" style={{ padding: "20px 24px", borderColor: "var(--p-purple)" }}>
          <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "var(--p-purple)", marginBottom: 14 }}>
            GITHUB CVE POC REPOSITORIES FOR: {query} ({ghPocResults.length} Repositories)
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
            {ghPocResults.map((g, i) => (
              <div key={i} style={{ background: "rgba(0,10,25,0.8)", border: "1px solid rgba(191,64,255,0.3)", padding: "14px 16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <a href={g.html_url} target="_blank" rel="noreferrer" style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.82rem", color: "var(--p-cyan)", textDecoration: "none", fontWeight: 800 }}>
                    {g.full_name}
                  </a>
                  <div style={{ display: "flex", gap: 8, fontSize: "0.65rem", color: "var(--p-amber)" }}>
                    <span><Star size={11} style={{ display: "inline" }} /> {g.stars}</span>
                    <span><GitFork size={11} style={{ display: "inline" }} /> {g.forks}</span>
                  </div>
                </div>
                <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.7rem", color: "rgba(255,255,255,0.75)", marginBottom: 8, lineHeight: 1.4 }}>
                  {g.description || "Open-source CVE PoC implementation."}
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.62rem", color: "rgba(255,255,255,0.4)" }}>
                  <span>Language: {g.language || "Multi"}</span>
                  <span>Updated: {g.updated_at}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 5. DEDICATED HYBRID KB SEARCH (BM25 + SEMANTIC EMBEDDINGS) ─── */}
      {activeMode === "hybrid_kb" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Controls Panel */}
          <div className="glass-panel" style={{ padding: "16px 20px", borderColor: "var(--p-cyan)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Layers size={16} color="var(--p-cyan)" />
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "var(--p-cyan)" }}>
                  DUAL-ENGINE RETRIEVAL MODE:
                </span>
              </div>
              
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  onClick={() => { setSearchMode("hybrid"); handleHybridSearch(query, "hybrid", alpha); }}
                  className={searchMode === "hybrid" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem" }}
                >
                  ⚡ HYBRID (BM25 + SEMANTIC)
                </button>
                <button
                  onClick={() => { setSearchMode("bm25"); handleHybridSearch(query, "bm25", 1.0); }}
                  className={searchMode === "bm25" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem" }}
                >
                  🔤 BM25 KEYWORD ONLY
                </button>
                <button
                  onClick={() => { setSearchMode("semantic"); handleHybridSearch(query, "semantic", 0.0); }}
                  className={searchMode === "semantic" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem" }}
                >
                  🧠 DENSE SEMANTIC ONLY
                </button>
              </div>
            </div>

            {searchMode === "hybrid" && (
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(0,200,248,0.15)" }}>
                <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.65rem", color: "rgba(255,255,255,0.7)" }}>
                  Fusion Balance (α={alpha}):
                </span>
                <span style={{ fontSize: "0.6rem", color: "var(--p-cyan)" }}>Dense Semantic (0.0)</span>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={alpha}
                  onChange={(e) => {
                    const newAlpha = parseFloat(e.target.value);
                    setAlpha(newAlpha);
                    handleHybridSearch(query, "hybrid", newAlpha);
                  }}
                  style={{ flex: 1, accentColor: "var(--p-cyan)", cursor: "pointer" }}
                />
                <span style={{ fontSize: "0.6rem", color: "var(--p-cyan)" }}>BM25 Keyword (1.0)</span>
              </div>
            )}
          </div>

          {/* Results Display */}
          {hybridResults && (
            <div className="glass-panel" style={{ padding: "20px 24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "var(--p-cyan)" }}>
                  HYBRID RETRIEVAL MATCHES FOR: "{hybridResults.query}" ({hybridResults.total_matches} Records)
                </span>
                <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.62rem", color: "rgba(0,200,248,0.7)" }}>
                  Mode: {hybridResults.mode.toUpperCase()} · α={hybridResults.alpha}
                </span>
              </div>

              {hybridResults.matches.length === 0 ? (
                <div style={{ textAlign: "center", padding: "20px 0", color: "rgba(255,255,255,0.5)", fontFamily: "Share Tech Mono,monospace", fontSize: "0.75rem" }}>
                  No vector records matched. Ingest new CVEs or audit targets to populate the local vector store.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {hybridResults.matches.map((m, i) => {
                    const e = m.entry;
                    return (
                      <div key={i} style={{ background: "rgba(0,10,25,0.85)", border: "1px solid rgba(0,200,248,0.25)", borderLeft: "4px solid var(--p-cyan)", padding: "14px 18px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8, marginBottom: 6 }}>
                          <div>
                            <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.85rem", fontWeight: 800, color: "#fff" }}>
                              {e.cve_id ? `${e.cve_id} — ` : ""}{e.title}
                            </div>
                            <div style={{ display: "flex", gap: 8, marginTop: 4, alignItems: "center", flexWrap: "wrap" }}>
                              {e.cvss_severity && <SeverityBadge severity={e.cvss_severity} />}
                              {e.cvss_score && (
                                <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.65rem", color: "var(--p-amber)" }}>
                                  CVSS: {e.cvss_score}
                                </span>
                              )}
                              {e.is_cisa_kev && (
                                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.55rem", color: "#ff1e3c", border: "1px solid #ff1e3c", padding: "1px 5px", fontWeight: 800 }}>
                                  ● CISA KEV (ACTIVE WILD THREAT)
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Score Badges */}
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            <span style={{ background: "rgba(0,200,248,0.15)", border: "1px solid var(--p-cyan)", padding: "2px 8px", fontFamily: "Orbitron,monospace", fontSize: "0.62rem", color: "var(--p-cyan)", fontWeight: 800 }}>
                              ⚡ HYBRID: {m.score}
                            </span>
                            <span style={{ background: "rgba(255,179,0,0.1)", border: "1px solid var(--p-amber)", padding: "2px 8px", fontFamily: "Share Tech Mono,monospace", fontSize: "0.6rem", color: "var(--p-amber)" }}>
                              🔤 BM25: {m.bm25_score}
                            </span>
                            <span style={{ background: "rgba(0,255,148,0.1)", border: "1px solid var(--p-green)", padding: "2px 8px", fontFamily: "Share Tech Mono,monospace", fontSize: "0.6rem", color: "var(--p-green)" }}>
                              🧠 SEMANTIC: {m.semantic_score}
                            </span>
                          </div>
                        </div>

                        <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.72rem", color: "rgba(255,255,255,0.75)", lineHeight: 1.5, marginBottom: 8 }}>
                          {e.description || "No description provided."}
                        </div>

                        {e.cpe_list?.length > 0 && (
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                            {e.cpe_list.map((c, ci) => (
                              <span key={ci} style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.6rem", color: "var(--p-purple)", border: "1px solid rgba(191,64,255,0.3)", padding: "1px 6px", background: "rgba(191,64,255,0.05)" }}>
                                {c}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── 6. NEURAL SYNTHESIS (NVIDIA NEMOTRON / QWEN) ────────────────── */}
      {activeMode === "kb_synthesis" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* AI Engine Model Selector */}
          <div className="glass-panel" style={{ padding: "16px 20px", borderColor: "#76b900", background: "rgba(0,15,5,0.7)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Cpu size={16} color="#76b900" />
                <span style={{ fontFamily: "Orbitron,monospace", fontSize: "0.78rem", fontWeight: 800, color: "#76b900" }}>
                  NEURAL SYNTHESIS ENGINE:
                </span>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button
                  onClick={() => { setSynthesisModel("nemotron-mini:4b"); handleKBSynthesis(query, "nemotron-mini:4b"); }}
                  className={synthesisModel === "nemotron-mini:4b" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem", borderColor: "#76b900", color: synthesisModel === "nemotron-mini:4b" ? "#fff" : "#76b900" }}
                >
                  🟢 NVIDIA NEMOTRON (4B)
                </button>
                <button
                  onClick={() => { setSynthesisModel("nemotron:latest"); handleKBSynthesis(query, "nemotron:latest"); }}
                  className={synthesisModel === "nemotron:latest" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem", borderColor: "#76b900", color: synthesisModel === "nemotron:latest" ? "#fff" : "#76b900" }}
                >
                  🟢 NVIDIA NEMOTRON (LATEST)
                </button>
                <button
                  onClick={() => { setSynthesisModel("qwen3:8b"); handleKBSynthesis(query, "qwen3:8b"); }}
                  className={synthesisModel === "qwen3:8b" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem", borderColor: "var(--p-green)", color: synthesisModel === "qwen3:8b" ? "#fff" : "var(--p-green)" }}
                >
                  🧠 QWEN 3 (8B)
                </button>
                <button
                  onClick={() => { setSynthesisModel("deepseek-r1:8b"); handleKBSynthesis(query, "deepseek-r1:8b"); }}
                  className={synthesisModel === "deepseek-r1:8b" ? "cyber-btn" : "cyber-btn cyber-btn-secondary"}
                  style={{ padding: "4px 10px", fontSize: "0.62rem", borderColor: "var(--p-amber)", color: synthesisModel === "deepseek-r1:8b" ? "#fff" : "var(--p-amber)" }}
                >
                  ⚡ DEEPSEEK R1 (8B)
                </button>
              </div>
            </div>
          </div>

          {kbResult && (
            <div className="glass-panel" style={{ padding: "22px 26px", borderColor: kbResult.model?.includes("nemotron") ? "#76b900" : "var(--p-green)" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, borderBottom: `1px solid ${kbResult.model?.includes("nemotron") ? "rgba(118,185,0,0.3)" : "rgba(0,255,148,0.2)"}`, paddingBottom: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Cpu size={18} color={kbResult.model?.includes("nemotron") ? "#76b900" : "var(--p-green)"} />
                  <div style={{ fontFamily: "Orbitron,monospace", fontWeight: 800, fontSize: "0.85rem", color: kbResult.model?.includes("nemotron") ? "#76b900" : "var(--p-green)", letterSpacing: "1.5px" }}>
                    {kbResult.model?.includes("nemotron") ? "NVIDIA NEMOTRON AI TECHNICAL DELIVERABLE" : "OLLAMA + QWEN TECHNICAL INTELLIGENCE DELIVERABLE"}
                  </div>
                </div>
                <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.65rem", color: kbResult.model?.includes("nemotron") ? "#76b900" : "rgba(0,255,148,0.8)", border: `1px solid ${kbResult.model?.includes("nemotron") ? "rgba(118,185,0,0.4)" : "rgba(0,255,148,0.3)"}`, padding: "2px 8px" }}>
                  SYNTHESIS ENGINE: {kbResult.model} ({kbResult.duration_s}s)
                </span>
              </div>
              <pre style={{
                margin: 0,
                fontFamily: "Share Tech Mono,monospace",
                fontSize: "0.8rem",
                lineHeight: 1.7,
                color: "var(--p-white)",
                whiteSpace: "pre-wrap",
                background: "#000510",
                padding: "16px 20px",
                border: `1px solid ${kbResult.model?.includes("nemotron") ? "rgba(118,185,0,0.2)" : "rgba(0,255,148,0.15)"}`,
              }}>
                {kbResult.synthesis || kbResult.qwen_synthesis || "// Awaiting neural response..."}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* ── 6. CISA KEV CATALOG BROWSER ───────────────────────────────────── */}
      {activeMode === "cisa_kev" && cisaFeed && (
        <div className="glass-panel" style={{ padding: "20px 24px" }}>
          <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.75rem", fontWeight: 800, color: "#ff0055", marginBottom: 14 }}>
            CISA KNOWN EXPLOITED VULNERABILITIES CATALOG ({cisaFeed.length} Actively Exploited Threats)
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 600, overflowY: "auto" }}>
            {cisaFeed.slice(0, 50).map((v, i) => (
              <div key={i} style={{ background: "rgba(0,10,25,0.7)", border: "1px solid rgba(255,0,85,0.25)", borderLeft: "3px solid #ff0055", padding: "10px 14px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontFamily: "Orbitron,monospace", fontWeight: 800, fontSize: "0.75rem", color: "var(--p-cyan)" }}>{v.cveID}</span>
                  <span style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.62rem", color: "#ff0055" }}>Added: {v.dateAdded}</span>
                </div>
                <div style={{ fontFamily: "Orbitron,monospace", fontSize: "0.72rem", color: "#fff", fontWeight: 700 }}>{v.vulnerabilityName}</div>
                <div style={{ fontFamily: "Share Tech Mono,monospace", fontSize: "0.68rem", color: "rgba(0,200,248,0.7)", marginTop: 2 }}>{v.shortDescription}</div>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
