import React, { useState } from 'react';
import { Search, Globe, ExternalLink, ShieldCheck, Sparkles, Filter } from 'lucide-react';

export default function SearchHub() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [activeSource, setActiveSource] = useState('all');

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    if (!query.trim() || isSearching) return;

    setIsSearching(true);
    try {
      const res = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query.trim(), max_results: 8 }),
      });
      const data = await res.json();
      setResults(data.results || []);
    } catch (e) {
      console.error('Search failed:', e);
    } finally {
      setIsSearching(false);
    }
  };

  const filtered = activeSource === 'all' ? results : results.filter((r) => r.source === activeSource);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Search Bar */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Globe size={20} color="var(--neon-cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: '700' }}>
              UNRESTRICTED MULTI-SOURCE SEARCH ENGINE
            </h2>
          </div>
          <span className="badge-neon badge-green">ZERO API KEYS • NO LIMITS</span>
        </div>

        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '12px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search CVEs, exploit databases, technical documentation, or research papers..."
              style={{
                width: '100%',
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
          </div>
          <button type="submit" disabled={isSearching || !query.trim()} className="cyber-btn">
            <Search size={16} />
            {isSearching ? 'Searching...' : 'Deep Search'}
          </button>
        </form>

        {/* Source Filters */}
        <div style={{ display: 'flex', gap: '8px', marginTop: '14px' }}>
          {['all', 'duckduckgo', 'ddg_html', 'wikipedia'].map((src) => (
            <button
              key={src}
              onClick={() => setActiveSource(src)}
              className={activeSource === src ? 'badge-neon badge-cyan' : 'badge-neon'}
              style={{ cursor: 'pointer', border: '1px solid var(--border-dim)', background: activeSource === src ? 'rgba(0, 229, 255, 0.15)' : 'transparent' }}
            >
              {src.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Results Container */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-secondary)' }}>
            DISCOVERED INTELLIGENCE ({filtered.length} RESULTS)
          </h3>
        </div>

        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
            {isSearching ? 'Scraping and aggregating intelligence...' : 'No search performed yet. Enter a query above.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {filtered.map((item, idx) => (
              <div
                key={idx}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: '8px',
                  padding: '16px',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      fontSize: '1rem',
                      fontWeight: '700',
                      color: 'var(--neon-cyan)',
                      textDecoration: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    {item.title}
                    <ExternalLink size={14} />
                  </a>
                  <span className="badge-neon badge-purple" style={{ fontSize: '0.65rem' }}>
                    {item.source}
                  </span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--neon-green)', fontFamily: 'var(--font-code)', marginBottom: '8px' }}>
                  {item.url}
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                  {item.snippet}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
