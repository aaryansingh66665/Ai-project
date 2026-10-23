import React, { useState, useEffect } from 'react';
import { UploadCloud, FileText, CheckCircle, Database, RefreshCw, Folder, Search, Layers, Zap } from 'lucide-react';

export default function RagIngestor() {
  const [documents, setDocuments] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);

  // Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [searchMode, setSearchMode] = useState('hybrid'); // 'hybrid' | 'bm25' | 'semantic'
  const [alpha, setAlpha] = useState(0.5);
  const [searchResults, setSearchResults] = useState(null);
  const [isSearching, setIsSearching] = useState(false);

  const fetchDocuments = async () => {
    try {
      const res = await fetch('/api/documents');
      const data = await res.json();
      setDocuments(data.documents || []);
    } catch (e) {
      console.error('Failed to load documents:', e);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadStatus(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/documents/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setUploadStatus(`✔ Successfully indexed '${data.filename}' into ${data.chunks} dense semantic chunks.`);
        fetchDocuments();
      } else {
        setUploadStatus(`❌ Upload failed: ${data.error}`);
      }
    } catch (err) {
      setUploadStatus(`❌ Error uploading: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    try {
      const res = await fetch('/api/documents/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: searchQuery.trim(),
          top_k: 6,
          mode: searchMode,
          alpha: alpha,
        }),
      });
      const data = await res.json();
      setSearchResults(data);
    } catch (err) {
      console.error('Search failed:', err);
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Upload Zone */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Database size={20} color="var(--neon-cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: '700' }}>
              OFFLINE LOCAL DOCUMENT RAG INGESTION & HYBRID VECTOR STORE
            </h2>
          </div>
          <span className="badge-neon badge-cyan">100% AIR-GAPPED & PRIVATE</span>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: '1.5' }}>
          Upload vulnerability writeups, source code files (.py, .c, .cpp), network dumps, or security PDFs.
          All files are tokenized into subwords, embedded into dense vector spaces, and made instantly searchable for all 8 autonomous agents.
        </p>

        <label
          style={{
            border: '2px dashed var(--border-dim)',
            borderRadius: '12px',
            padding: '36px 20px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '12px',
            cursor: 'pointer',
            background: 'var(--bg-secondary)',
            transition: 'all 0.2s ease',
          }}
        >
          <UploadCloud size={36} color="var(--neon-cyan)" />
          <div style={{ fontWeight: '600', fontSize: '0.95rem' }}>
            {isUploading ? 'Ingesting and Chunking Document with Dense Vectors...' : 'Click to Upload Security Document / Code'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Supports PDF, TXT, MD, JSON, PY, C, CPP, LOG, PCAP
          </div>
          <input
            type="file"
            onChange={handleFileUpload}
            disabled={isUploading}
            style={{ display: 'none' }}
          />
        </label>

        {uploadStatus && (
          <div style={{ marginTop: '14px', padding: '10px 14px', borderRadius: '8px', background: 'rgba(0, 255, 136, 0.1)', border: '1px solid rgba(0, 255, 136, 0.3)', color: 'var(--neon-green)', fontSize: '0.85rem' }}>
            {uploadStatus}
          </div>
        )}
      </div>

      {/* Dual-Engine Hybrid Document Search */}
      <div className="glass-panel" style={{ padding: '24px', borderColor: 'var(--p-cyan)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={18} color="var(--p-cyan)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--p-cyan)' }}>
              DUAL-ENGINE HYBRID DOCUMENT SEARCH
            </h3>
          </div>

          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              onClick={() => { setSearchMode('hybrid'); }}
              className={searchMode === 'hybrid' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '4px 8px', fontSize: '0.62rem' }}
            >
              ⚡ HYBRID
            </button>
            <button
              onClick={() => { setSearchMode('bm25'); }}
              className={searchMode === 'bm25' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '4px 8px', fontSize: '0.62rem' }}
            >
              🔤 BM25 KEYWORD
            </button>
            <button
              onClick={() => { setSearchMode('semantic'); }}
              className={searchMode === 'semantic' ? 'cyber-btn' : 'cyber-btn cyber-btn-secondary'}
              style={{ padding: '4px 8px', fontSize: '0.62rem' }}
            >
              🧠 DENSE SEMANTIC
            </button>
          </div>
        </div>

        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search ingested documents, writeups, source code (e.g. memory leak, privilege escalation, buffer overflow, jwt bypass)..."
            style={{
              flex: 1,
              padding: '10px 14px',
              background: 'rgba(0,200,248,0.04)',
              border: '1px solid rgba(0,200,248,0.25)',
              borderRadius: '6px',
              color: '#fff',
              fontFamily: 'Share Tech Mono,monospace',
              fontSize: '0.8rem',
              outline: 'none',
            }}
          />
          <button
            type="submit"
            disabled={isSearching || !searchQuery.trim()}
            className="cyber-btn"
            style={{ padding: '0 18px', fontSize: '0.75rem' }}
          >
            {isSearching ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
            <span>SEARCH</span>
          </button>
        </form>

        {searchResults && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '14px' }}>
            <div style={{ fontSize: '0.75rem', fontFamily: 'Share Tech Mono,monospace', color: 'rgba(0,200,248,0.8)' }}>
              Found {searchResults.total_matches} matching chunks (Mode: {searchResults.mode.toUpperCase()})
            </div>

            {searchResults.results.map((r, i) => (
              <div
                key={i}
                style={{
                  background: 'rgba(0,10,25,0.8)',
                  border: '1px solid rgba(0,200,248,0.2)',
                  borderLeft: '3px solid var(--p-cyan)',
                  padding: '12px 14px',
                  borderRadius: '4px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '6px' }}>
                  <span style={{ fontWeight: '700', fontSize: '0.8rem', color: '#fff', fontFamily: 'Share Tech Mono,monospace' }}>
                    📄 {r.filename} (Chunk #{r.chunk_index})
                  </span>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <span style={{ background: 'rgba(0,200,248,0.15)', border: '1px solid var(--p-cyan)', padding: '1px 6px', fontFamily: 'Orbitron,monospace', fontSize: '0.58rem', color: 'var(--p-cyan)' }}>
                      ⚡ HYBRID: {r.score}
                    </span>
                    <span style={{ background: 'rgba(255,179,0,0.1)', border: '1px solid var(--p-amber)', padding: '1px 6px', fontFamily: 'Share Tech Mono,monospace', fontSize: '0.58rem', color: 'var(--p-amber)' }}>
                      🔤 BM25: {r.bm25_score}
                    </span>
                    <span style={{ background: 'rgba(0,255,148,0.1)', border: '1px solid var(--p-green)', padding: '1px 6px', fontFamily: 'Share Tech Mono,monospace', fontSize: '0.58rem', color: 'var(--p-green)' }}>
                      🧠 SEMANTIC: {r.semantic_score}
                    </span>
                  </div>
                </div>
                <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: '0.72rem', color: 'rgba(255,255,255,0.8)', lineHeight: '1.5', whiteSpace: 'pre-wrap' }}>
                  {r.text.length > 300 ? `${r.text.substring(0, 300)}...` : r.text}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Document Library */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Folder size={18} color="var(--neon-amber)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: '700' }}>
              INDEXED KNOWLEDGE BASE ({documents.length} FILES)
            </h3>
          </div>
          <button onClick={fetchDocuments} className="cyber-btn cyber-btn-secondary" style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>

        {documents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text-muted)' }}>
            No documents indexed yet. Upload files above to build your private local knowledge repository.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '14px' }}>
            {documents.map((doc, idx) => (
              <div
                key={idx}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '8px',
                  padding: '16px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <FileText size={18} color="var(--neon-cyan)" />
                  <div style={{ fontWeight: '700', fontSize: '0.9rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {doc.filename}
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  <span>{doc.chunks} dense chunks</span>
                  <span className="badge-neon badge-green" style={{ fontSize: '0.65rem' }}>ACTIVE IN RAG</span>
                </div>
                {doc.preview && (
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '8px', opacity: 0.8 }}>
                    {doc.preview}...
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}

