import { useEffect, useState, useCallback, useRef } from 'react'
import { getScans, getTargets, createScan, cancelScan } from '../api/client'
import { Play, XCircle, RefreshCw, Scan, Clock } from 'lucide-react'

function StatusBadge({ status }) {
  return (
    <span className={`badge badge-${status}`}>
      {status === 'running' && <span className="pulse" style={{ marginRight: 5 }} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  )
}

export default function Scans() {
  const [scans, setScans] = useState([])
  const [targets, setTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ target_id: '', scanner: 'wapiti+nuclei' })
  const [launching, setLaunching] = useState(false)
  const pollRef = useRef(null)

  const load = useCallback(async () => {
    try {
      const [scansRes, targetsRes] = await Promise.all([getScans(), getTargets()])
      setScans(scansRes.data)
      setTargets(targetsRes.data)
    } catch {}
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    load()
    pollRef.current = setInterval(load, 5000)   // poll every 5s for live status
    return () => clearInterval(pollRef.current)
  }, [load])

  const handleLaunch = async (e) => {
    e.preventDefault()
    if (!form.target_id) return
    setLaunching(true)
    try {
      await createScan({ target_id: parseInt(form.target_id), scanner: form.scanner })
      await load()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to launch scan.')
    } finally {
      setLaunching(false)
    }
  }

  const handleCancel = async (id) => {
    if (!window.confirm('Cancel this scan?')) return
    await cancelScan(id)
    await load()
  }

  const targetName = (tid) => targets.find(t => t.id === tid)?.name || `Target #${tid}`
  const targetUrl = (tid) => targets.find(t => t.id === tid)?.base_url || ''

  const fmtTime = (iso) => {
    if (!iso) return '—'
    // Treat naive datetime strings (no tz info) as UTC so browser converts to local IST
    const utc = iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z'
    return new Date(utc).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  }

  const duration = (s) => {
    if (!s.started_at || !s.completed_at) return s.started_at ? '⏳ Running…' : '—'
    const secs = Math.round((new Date(s.completed_at) - new Date(s.started_at)) / 1000)
    return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`
  }

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Scan size={20} color="#00d4ff" />
          <h1>Scan Management</h1>
        </div>
        <p>Launch DAST scans and monitor their status in real time</p>
      </div>

      {/* New scan form */}
      <div className="card" style={{ marginBottom: 28 }}>
        <div style={{ fontWeight: 700, marginBottom: 16, fontSize: 15 }}>
          🚀 Launch New Scan
        </div>
        <form onSubmit={handleLaunch} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 2, minWidth: 200, marginBottom: 0 }}>
            <label>Target Application</label>
            <select className="form-select" value={form.target_id}
              onChange={e => setForm(f => ({ ...f, target_id: e.target.value }))}>
              <option value="">— Select a target —</option>
              {targets.map(t => (
                <option key={t.id} value={t.id}>{t.name} ({t.base_url})</option>
              ))}
            </select>
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: 160, marginBottom: 0 }}>
            <label>Scanner Profile</label>
            <select className="form-select" value={form.scanner}
              onChange={e => setForm(f => ({ ...f, scanner: e.target.value }))}>
              <option value="wapiti+nuclei">Wapiti + Nuclei (Full)</option>
              <option value="wapiti">Wapiti Only</option>
              <option value="nuclei">Nuclei Only</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary" disabled={launching || !form.target_id}
            style={{ marginBottom: 0 }}>
            {launching ? <><div className="spinner" /> Launching…</> : <><Play size={15} /> Launch Scan</>}
          </button>
        </form>
        {targets.length === 0 && (
          <div style={{ marginTop: 12, fontSize: 13, color: '#fbbf24' }}>
            ⚠️ No targets found. <a href="/targets" style={{ color: '#00d4ff' }}>Add a target first →</a>
          </div>
        )}
      </div>

      {/* Scan history */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ fontWeight: 700, fontSize: 16 }}>Scan History</div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /><span>Loading scans…</span></div>
      ) : scans.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <h3>No Scans Yet</h3>
            <p>Launch your first scan using the form above.</p>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>URL</th>
                <th>Scanner</th>
                <th>Status</th>
                <th>Started</th>
                <th>Ended</th>
                <th>Duration</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id}>
                  <td style={{ color: '#8b949e', fontSize: 12 }}>#{s.id}</td>
                  <td style={{ fontWeight: 600 }}>{targetName(s.target_id)}</td>
                  <td><span className="mono">{(targetUrl(s.target_id) || '').slice(0, 30)}</span></td>
                  <td style={{ fontSize: 12, color: '#8b949e' }}>{s.scanner}</td>
                  <td><StatusBadge status={s.status} /></td>
                  <td style={{ fontSize: 12, color: '#8b949e' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Clock size={11} />
                      {fmtTime(s.started_at)}
                    </div>
                  </td>
                  <td style={{ fontSize: 12, color: s.completed_at ? '#4ade80' : '#fbbf24' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Clock size={11} />
                      {fmtTime(s.completed_at)}
                    </div>
                  </td>
                  <td style={{ fontSize: 12, color: '#8b949e' }}>{duration(s)}</td>
                  <td>
                    {(s.status === 'running' || s.status === 'queued') && (
                      <button className="btn btn-danger btn-sm" onClick={() => handleCancel(s.id)}>
                        <XCircle size={13} /> Cancel
                      </button>
                    )}
                    {s.status === 'failed' && s.error_message && (
                      <span style={{ fontSize: 11, color: '#f87171' }} title={s.error_message}>
                        ⚠ Error
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
