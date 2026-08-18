import React, { useState, useEffect } from 'react';
import { UploadCloud, FileText, CheckCircle, Database, RefreshCw, Folder } from 'lucide-react';

export default function RagIngestor() {
  const [documents, setDocuments] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);

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
        setUploadStatus(`✔ Successfully indexed '${data.filename}' into ${data.chunks} semantic chunks.`);
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Upload Zone */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Database size={20} color="var(--neon-cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: '700' }}>
              OFFLINE LOCAL DOCUMENT RAG INGESTION
            </h2>
          </div>
          <span className="badge-neon badge-cyan">100% AIR-GAPPED & PRIVATE</span>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: '1.5' }}>
          Upload vulnerability writeups, source code files (.py, .c, .cpp), network dumps, or security PDFs.
          All files are tokenized, indexed, and made instantly searchable for all 8 autonomous agents.
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
            {isUploading ? 'Ingesting and Chunking Document...' : 'Click to Upload Security Document / Code'}
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
                  <span>{doc.chunks} semantic chunks</span>
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
