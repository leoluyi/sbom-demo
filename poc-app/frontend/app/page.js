'use client';

import { useEffect } from 'react';
import axios from 'axios';
import { create } from 'zustand';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

// ---------------------------------------------------------------------------
// Zustand store -- centralises dashboard state so every section reacts to
// the same fetch cycle.
// ---------------------------------------------------------------------------
const useDashboardStore = create((set) => ({
  health: null,
  services: null,
  loading: false,
  error: null,

  fetchAll: async () => {
    set({ loading: true, error: null });
    try {
      const [healthRes, servicesRes] = await Promise.all([
        axios.get(`${API_BASE}/health`),
        axios.get(`${API_BASE}/services`),
      ]);
      set({
        health: healthRes.data,
        services: servicesRes.data,
        loading: false,
      });
    } catch (err) {
      set({
        error: err.message || 'Failed to reach backend',
        loading: false,
      });
    }
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${h}h ${m}m ${s}s`;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function HealthCard({ health }) {
  if (!health) return null;
  const isHealthy = health.status === 'ok';
  return (
    <div className="card">
      <h2>Backend Health</h2>
      <p>
        Status:{' '}
        <span className={`status-badge ${isHealthy ? 'healthy' : 'unhealthy'}`}>
          {health.status}
        </span>
      </p>
      <p>Uptime: {formatUptime(health.uptime)}</p>
    </div>
  );
}

function ServicesCard({ services }) {
  if (!services) return null;
  const languageGroups = Object.entries(services.byLanguage || {});
  return (
    <div className="card">
      <h2>Registered Services ({services.count})</h2>
      <ul className="service-list">
        {languageGroups.map(([lang, items]) =>
          items.map((svc) => (
            <li key={svc.name}>
              <span>{svc.name}</span>
              <span className="status-badge healthy">{lang}</span>
            </li>
          )),
        )}
      </ul>
      {services.goService && (
        <p style={{ marginTop: '0.75rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Go service URL: {services.goService}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function DashboardPage() {
  const { health, services, loading, error, fetchAll } = useDashboardStore();

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  return (
    <main className="container">
      <h1>SBOM PoC Dashboard</h1>

      {loading && <p className="loading">Loading...</p>}
      {error && <p className="error-message">Error: {error}</p>}

      <HealthCard health={health} />
      <ServicesCard services={services} />

      <button onClick={fetchAll} disabled={loading}>
        Refresh
      </button>
    </main>
  );
}
