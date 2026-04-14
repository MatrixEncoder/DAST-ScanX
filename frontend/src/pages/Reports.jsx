import { useEffect, useState } from 'react'
import { getScans, getTargets, getReports, generateReport, downloadReport } from '../api/client'
import { FileText, Download, RefreshCw, Loader } from 'lucide-react'

function StatusBadge({ status }) {
  return <span className={`badge badge-${status}`}>{status.charAt(0).toUpperCase() + status.slice(1)}</span>
}

export default function Reports() {
  const [scans, setScans] = useState([])
  const [targets, setTargets] = useState([])
  const [reports, setReports] = useState({})   // { scanId: [reportObj, ...] }
  const [generating, setGenerating] = useState({})
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [scansRes, targetsRes] = await Promise.all([getScans(), getTargets()])
      const completedScans = scansRes.data.filter(s => s.status === 'completed')
      setScans(scansRes.data)
      setTargets(targetsRes.data)
      // Fetch existing reports for each completed scan
      const reportsMap = {}
      await Promise.all(completedScans.map(async s => {
        try {
          const r = await getReports(s.id)
          reportsMap[s.id] = r.data
        } catch {
          reportsMap[s.id] = []
        }
      }))
      setReports(reportsMap)
    } catch {}
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleGenerate = async (scanId) => {
    setGenerating(g => ({ ...g, [scanId]: true }))
    try {
      await generateReport(scanId)
      const r = await getReports(scanId)
      setReports(prev => ({ ...prev, [scanId]: r.data }))
    } catch (e) {
      alert(e?.response?.data?.detail || 'Report generation failed.')
    } finally {
      setGenerating(g => ({ ...g, [scanId]: false }))
    }
  }

  const targetName = (tid) => targets.find(t => t.id === tid)?.name || `Target #${tid}`
  const hasReport = (scanId, fmt) => (reports[scanId] || []).some(r => r.format === fmt)

  const completedScans = scans.filter(s => s.status === 'completed')

  return (
    <div>
      <div className="page-actions">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileText size={20} color="#00d4ff" />
            <h1>Security Reports</h1>
          </div>
          <p>Generate and download HTML & PDF vulnerability reports for completed scans</p>
        </div>
        <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /> Refresh</button>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /><span>Loading reports…</span></div>
      ) : completedScans.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">📄</div>
            <h3>No Completed Scans</h3>
            <p>Reports can be generated once a scan completes. Head to the Scans page to launch one.</p>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Scanner</th>
                <th>Completed</th>
                <th>Reports</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {completedScans.map(s => (
                <tr key={s.id}>
                  <td style={{ color: '#8b949e', fontSize: 12 }}>#{s.id}</td>
                  <td style={{ fontWeight: 600 }}>{targetName(s.target_id)}</td>
                  <td style={{ fontSize: 12, color: '#8b949e' }}>{s.scanner}</td>
                  <td style={{ fontSize: 12, color: '#8b949e' }}>
                    {s.completed_at ? new Date(s.completed_at).toLocaleString() : '—'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 8 }}>
                      {hasReport(s.id, 'html')
                        ? <span className="badge badge-completed">HTML ✓</span>
                        : <span className="badge badge-created">HTML</span>}
                      {hasReport(s.id, 'pdf')
                        ? <span className="badge badge-completed">PDF ✓</span>
                        : <span className="badge badge-created">PDF</span>}
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {/* Generate button */}
                      <button className="btn btn-primary btn-sm"
                        onClick={() => handleGenerate(s.id)}
                        disabled={generating[s.id]}>
                        {generating[s.id]
                          ? <><Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> Generating…</>
                          : <><RefreshCw size={13} /> {(reports[s.id]?.length > 0) ? 'Regenerate' : 'Generate'}</>
                        }
                      </button>
                      {/* Download HTML */}
                      {hasReport(s.id, 'html') && (
                        <a className="btn btn-ghost btn-sm"
                          href={downloadReport(s.id, 'html')} target="_blank" rel="noreferrer">
                          <Download size={13} /> HTML
                        </a>
                      )}
                      {/* Download PDF */}
                      {hasReport(s.id, 'pdf') && (
                        <a className="btn btn-ghost btn-sm"
                          href={downloadReport(s.id, 'pdf')} target="_blank" rel="noreferrer">
                          <Download size={13} /> PDF
                        </a>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* All scans reference */}
      {scans.some(s => s.status !== 'completed') && (
        <div className="card" style={{ marginTop: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 14 }}>Other Scans</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Note</th></tr>
              </thead>
              <tbody>
                {scans.filter(s => s.status !== 'completed').map(s => (
                  <tr key={s.id}>
                    <td style={{ color: '#8b949e', fontSize: 12 }}>#{s.id}</td>
                    <td>{targetName(s.target_id)}</td>
                    <td><StatusBadge status={s.status} /></td>
                    <td style={{ fontSize: 12, color: '#8b949e' }}>
                      {s.status === 'running' ? 'Scan in progress — reports available after completion' :
                       s.status === 'failed'  ? (s.error_message || 'Scan failed') :
                       'Awaiting completion'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
