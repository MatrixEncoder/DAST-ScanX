import { useEffect, useState, useCallback } from 'react'
import { getDashboard } from '../api/client'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import {
  Target, Scan, Bug, AlertTriangle, TrendingUp,
  Shield, Activity, Zap
} from 'lucide-react'

const SEV_COLORS = {
  Critical: '#f87171',
  High:     '#fb923c',
  Medium:   '#fbbf24',
  Low:      '#4ade80',
  Info:     '#60a5fa',
}

const STATUS_LABELS = {
  created:   'Created',
  queued:    'Queued',
  running:   'Running',
  completed: 'Completed',
  failed:    'Failed',
}

function RiskChip({ score }) {
  const cls = score >= 7 ? 'critical' : score >= 5 ? 'high' : score >= 3 ? 'medium' : 'low'
  return <span className={`risk-chip risk-${cls}`}>{score.toFixed(1)}</span>
}

function StatusBadge({ status }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABELS[status] || status}</span>
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    try {
      const res = await getDashboard()
      setData(res.data)
      setError(null)
    } catch (e) {
      setError('Could not connect to Scan-X backend. Make sure it is running on port 8000.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return (
    <div className="loading"><div className="spinner" /><span>Connecting to Scan-X backendâ€¦</span></div>
  )

  if (error) return (
    <div style={{ padding: 40 }}>
      <div className="card" style={{ borderColor: '#f87171', background: 'rgba(248,113,113,0.05)' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          <AlertTriangle color="#f87171" size={22} style={{ marginTop: 2 }} />
          <div>
            <div style={{ fontWeight: 700, color: '#f87171', marginBottom: 6 }}>Backend Offline</div>
            <div style={{ color: '#8b949e', fontSize: 14 }}>{error}</div>
            <div style={{ marginTop: 12, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#79c0ff', background: '#0d1117', padding: '8px 12px', borderRadius: 6, display: 'inline-block' }}>
              uvicorn backend.main:app --reload --port 8000
            </div>
          </div>
        </div>
      </div>
    </div>
  )

  const sevData = [
    { name: 'Critical', value: data.critical },
    { name: 'High',     value: data.high },
    { name: 'Medium',   value: data.medium },
    { name: 'Low',      value: data.low },
    { name: 'Info',     value: data.info },
  ].filter(d => d.value > 0)

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <Zap size={20} color="#00d4ff" />
          <h1>Security Dashboard</h1>
        </div>
        <p>Real-time overview of your application security posture</p>
      </div>

      {/* KPIs */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-icon"><Target size={48} /></div>
          <div className="kpi-label">Total Targets</div>
          <div className="kpi-value" style={{ color: '#00d4ff' }}>{data.total_targets}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><Activity size={48} /></div>
          <div className="kpi-label">Total Scans</div>
          <div className="kpi-value" style={{ color: '#7c3aed' }}>{data.total_scans}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><Bug size={48} /></div>
          <div className="kpi-label">Vulnerabilities</div>
          <div className="kpi-value" style={{ color: '#fb923c' }}>{data.total_vulnerabilities}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><AlertTriangle size={48} /></div>
          <div className="kpi-label">Critical</div>
          <div className="kpi-value" style={{ color: '#f87171' }}>{data.critical}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><Shield size={48} /></div>
          <div className="kpi-label">High</div>
          <div className="kpi-value" style={{ color: '#fb923c' }}>{data.high}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><TrendingUp size={48} /></div>
          <div className="kpi-label">Medium</div>
          <div className="kpi-value" style={{ color: '#fbbf24' }}>{data.medium}</div>
        </div>
      </div>

      {/* Charts + Recent Scans */}
      <div className="chart-grid">
        {/* Donut Chart */}
        <div className="card">
          <div style={{ fontWeight: 700, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Bug size={16} color="#00d4ff" />
            Severity Distribution
          </div>
          {sevData.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">ðŸ“Š</div>
              <p>No vulnerabilities found yet.<br />Run a scan to see data here.</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" innerRadius={60} outerRadius={90}
                     paddingAngle={4} dataKey="value" label={({ name, percent }) =>
                       `${name} ${(percent * 100).toFixed(0)}%`}
                     labelLine={false}>
                  {sevData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Recent Scans */}
        <div className="card">
          <div style={{ fontWeight: 700, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={16} color="#00d4ff" />
            Recent Scans
          </div>
          {data.recent_scans.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">ðŸ”</div>
              <p>No scans yet. Start your first scan!</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {data.recent_scans.map(s => (
                <div key={s.id} className="card-sm" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>Scan #{s.id}</div>
                    <div style={{ fontSize: 12, color: '#8b949e', marginTop: 2 }}>
                      {s.scanner} Â· {new Date(s.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <StatusBadge status={s.status} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Top Risk Vulnerabilities */}
      <div className="card">
        <div style={{ fontWeight: 700, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
          <TrendingUp size={16} color="#00d4ff" />
          Top 10 Highest Risk Vulnerabilities
        </div>
        {data.top_risks.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">ðŸ›¡ï¸</div>
            <h3>All Clear</h3>
            <p>No vulnerabilities found yet. Start scanning your applications.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Title</th>
                  <th>Endpoint</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>OWASP</th>
                  <th>Detected By</th>
                </tr>
              </thead>
              <tbody>
                {data.top_risks.map((v, i) => (
                  <tr key={v.id}>
                    <td style={{ color: '#8b949e', fontSize: 12, width: 40 }}>{i + 1}</td>
                    <td style={{ fontWeight: 600 }}>{v.title}</td>
                    <td><span className="mono">{v.endpoint.length > 40 ? v.endpoint.slice(0, 40) + 'â€¦' : v.endpoint}</span></td>
                    <td><span className={`badge badge-${v.severity}`}>{v.severity}</span></td>
                    <td><RiskChip score={v.risk_score} /></td>
                    <td><span className="owasp-tag" style={{ fontSize: 11 }}>{(v.owasp_category ?? '').split('â€“')[0]?.trim() || 'N/A'}</span></td>
                    <td style={{ fontSize: 12, color: '#8b949e' }}>{v.detected_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

