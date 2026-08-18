import React, { useState } from 'react';
import { Cpu, Thermometer, Trash2, RefreshCw, Activity } from 'lucide-react';

export default function GpuMeter({ gpu, onRefresh }) {
  const [unloading, setUnloading] = useState(false);

  const handleUnload = async () => {
    setUnloading(true);
    try {
      await fetch('/api/gpu/unload', { method: 'POST' });
      if (onRefresh) onRefresh();
    } catch (e) {
      console.error(e);
    } finally {
      setUnloading(false);
    }
  };

  const usedPct = gpu?.used_pct || 0;
  const vramColor = usedPct > 85 ? 'var(--neon-red)' : usedPct > 60 ? 'var(--neon-amber)' : 'var(--neon-green)';

  return (
    <div className="glass-panel" style={{ padding: '14px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '20px', flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{ background: 'rgba(0, 229, 255, 0.1)', padding: '10px', borderRadius: '10px', border: '1px solid rgba(0, 229, 255, 0.2)' }}>
          <Cpu size={22} color="var(--neon-cyan)" />
        </div>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            GPU ACCELERATION (CUDA)
          </div>
          <div style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-primary)' }}>
            {gpu?.name || 'NVIDIA GeForce RTX 3050 (6GB)'}
          </div>
        </div>
      </div>

      <div style={{ flex: 1, minWidth: '220px', maxWidth: '380px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '6px' }}>
          <span style={{ color: 'var(--text-secondary)' }}>VRAM Memory</span>
          <span style={{ fontFamily: 'var(--font-code)', fontWeight: '600', color: vramColor }}>
            {gpu?.used_mb || 0} MB / {gpu?.total_mb || 6144} MB ({usedPct}%)
          </span>
        </div>
        <div style={{ height: '7px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '4px', overflow: 'hidden' }}>
          <div
            style={{
              width: `${Math.min(usedPct, 100)}%`,
              height: '100%',
              background: `linear-gradient(90deg, var(--neon-cyan), ${vramColor})`,
              transition: 'width 0.4s ease',
              boxShadow: `0 0 10px ${vramColor}`,
            }}
          />
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-code)' }}>
          <Thermometer size={16} color="var(--neon-amber)" />
          <span>{gpu?.temp_c || 45}°C</span>
        </div>

        <button
          onClick={handleUnload}
          disabled={unloading}
          className="cyber-btn cyber-btn-secondary"
          style={{ padding: '6px 12px', fontSize: '0.75rem' }}
          title="Unload models and release VRAM"
        >
          <Trash2 size={13} />
          {unloading ? 'Purging...' : 'Flush VRAM'}
        </button>
      </div>
    </div>
  );
}
