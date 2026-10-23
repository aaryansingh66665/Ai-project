import { useEffect, useRef } from 'react';

export default function CanvasBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let raf;

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    /* ── Shared palette ──────────────────────────── */
    const BLUE   = 'rgba(0,200,248,';
    const GREEN  = 'rgba(0,255,148,';
    const PURPLE = 'rgba(191,64,255,';
    const AMBER  = 'rgba(255,179,0,';

    /* ── Hex Grid ────────────────────────────────── */
    const HEX_R = 38;
    const hexPoints = (cx, cy, r) => {
      const pts = [];
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
      }
      return pts;
    };
    const drawHexGrid = (t) => {
      const cols = Math.ceil(canvas.width  / (HEX_R * Math.sqrt(3))) + 2;
      const rows = Math.ceil(canvas.height / (HEX_R * 1.5)) + 2;
      for (let row = -1; row < rows; row++) {
        for (let col = -1; col < cols; col++) {
          const x = col * HEX_R * Math.sqrt(3) + (row % 2 ? HEX_R * Math.sqrt(3) / 2 : 0);
          const y = row * HEX_R * 1.5;
          const pts = hexPoints(x, y, HEX_R - 2);
          const pulse = (Math.sin(t * 0.0008 + col * 0.3 + row * 0.2) + 1) / 2;
          const alpha = 0.018 + pulse * 0.015;
          ctx.beginPath();
          ctx.moveTo(pts[0][0], pts[0][1]);
          for (let i = 1; i < 6; i++) ctx.lineTo(pts[i][0], pts[i][1]);
          ctx.closePath();
          ctx.strokeStyle = `${BLUE}${alpha.toFixed(3)})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
          // Occasional bright hex
          if (Math.sin(t * 0.0005 + col * 1.7 + row * 2.3) > 0.96) {
            ctx.fillStyle = `${BLUE}0.03)`;
            ctx.fill();
          }
        }
      }
    };

    /* ── Matrix Rain ─────────────────────────────── */
    const CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨ!@#$%^&*<>[]{}';
    const FONT_SZ = 13;
    const cols_m = Math.floor(canvas.width / FONT_SZ);
    const drops = Array.from({ length: cols_m }, () => Math.random() * -100);
    const dropAlpha = Array.from({ length: cols_m }, () => 0.3 + Math.random() * 0.5);

    const drawMatrix = () => {
      ctx.font = `${FONT_SZ}px "Share Tech Mono"`;
      for (let i = 0; i < drops.length; i++) {
        const char = CHARS[Math.floor(Math.random() * CHARS.length)];
        const y = drops[i] * FONT_SZ;
        if (y > 0 && y < canvas.height) {
          // Head char — brighter
          ctx.fillStyle = `rgba(180,255,240,${dropAlpha[i]})`;
          ctx.fillText(char, i * FONT_SZ, y);
          // Trail
          ctx.fillStyle = `${GREEN}${(dropAlpha[i] * 0.3).toFixed(3)})`;
          ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], i * FONT_SZ, y - FONT_SZ);
        }
        if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.4;
      }
    };

    /* ── Particles & Neural Constellations ──────── */
    const N_PARTICLES = 110;
    const particles = Array.from({ length: N_PARTICLES }, (_, i) => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45 - 0.05,
      r: Math.random() * 2.2 + 0.8,
      color: i % 4 === 0 ? GREEN : i % 6 === 0 ? PURPLE : i % 9 === 0 ? AMBER : BLUE,
      alpha: Math.random() * 0.5 + 0.35,
      pulse: Math.random() * Math.PI * 2,
    }));

    const drawParticles = (t) => {
      for (const p of particles) {
        p.x  += p.vx;
        p.y  += p.vy;
        p.pulse += 0.025;
        const a = p.alpha * (0.7 + 0.3 * Math.sin(p.pulse));

        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color}${a.toFixed(3)})`;
        ctx.fill();

        // Glow halo
        const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 5);
        grad.addColorStop(0, `${p.color}${(a * 0.6).toFixed(3)})`);
        grad.addColorStop(1, `${p.color}0)`);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * 5, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();
      }

      // Synaptic connection lines between nearby neural particles
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 140) {
            const a = (1 - dist / 140) * 0.22;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `${BLUE}${a.toFixed(3)})`;
            ctx.lineWidth = 0.9;
            ctx.stroke();
          }
        }
      }
    };

    /* ── Horizon scan line ──────────────────────── */
    let scanY = 0;
    const drawScanLine = (t) => {
      scanY = (t * 0.06) % canvas.height;
      const grad = ctx.createLinearGradient(0, scanY - 30, 0, scanY + 30);
      grad.addColorStop(0, 'rgba(0,200,248,0)');
      grad.addColorStop(0.5, 'rgba(0,200,248,0.04)');
      grad.addColorStop(1, 'rgba(0,200,248,0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, scanY - 30, canvas.width, 60);
      ctx.strokeStyle = 'rgba(0,200,248,0.12)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, scanY);
      ctx.lineTo(canvas.width, scanY);
      ctx.stroke();
    };

    /* ── Main loop ──────────────────────────────── */
    let t = 0;
    const draw = () => {
      t++;
      // Clear with fade trail
      ctx.fillStyle = 'rgba(0,3,6,0.18)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      drawHexGrid(t);
      drawMatrix();
      drawParticles(t);
      drawScanLine(t);

      raf = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0, left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
        opacity: 0.85,
      }}
    />
  );
}
