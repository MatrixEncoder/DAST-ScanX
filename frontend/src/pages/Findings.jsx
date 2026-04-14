import { useEffect, useState } from 'react'
import { getFindings } from '../api/client'
import { Bug, ChevronDown, ChevronRight } from 'lucide-react'

function RiskChip({ score }) {
  const cls = score >= 7 ? 'critical' : score >= 5 ? 'high' : score >= 3 ? 'medium' : 'low'
  return <span className={`risk-chip risk-${cls}`}>{score?.toFixed(1)}</span>
}

function VulnDetail({ v }) {
  return (
    <div className="vuln-detail-panel" style={{ marginTop: 0, borderTopLeftRadius: 0, borderTopRightRadius: 0, borderTop: 'none' }}>
      <div style={{ marginBottom: 12 }}>
        <span className="owasp-tag">{v.owasp_category}</span>
      </div>
      <div className="detail-grid-2" style={{ marginBottom: 14 }}>
        <div className="detail-item"><label>Confidence</label><p>{v.confidence}</p></div>
        <div className="detail-item"><label>Detected By</label><p>{v.detected_by}</p></div>
        <div className="detail-item"><label>Risk Score</label><p>{v.risk_score?.toFixed(2)} / 10</p></div>
        <div className="detail-item"><label>Timestamp</label><p>{new Date(v.timestamp).toLocaleString()}</p></div>
      </div>
      <div className="detail-item" style={{ marginBottom: 10 }}>
        <label>Description</label>
        <p style={{ marginTop: 6, color: '#c9d1d9', lineHeight: 1.7 }}>{v.description || '—'}</p>
      </div>
      {v.evidence && (
        <div style={{ marginBottom: 10 }}>
          <label className="detail-item" style={{ display: 'block', fontSize: 11, color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1 }}>Evidence</label>
          <div className="evidence-box">{v.evidence}</div>
        </div>
      )}
      <div>
        <label style={{ display: 'block', fontSize: 11, color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>Remediation</label>
        <div className="remediation-box">{v.remediation}</div>
      </div>
    </div>
  )
}

export default function Findings() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    getFindings()
      .then(r => setVulns(r.data))
      .catch(() => setVulns([]))
      .finally(() => setLoading(false))
  }, [])

  const filtered = vulns.filter(v => {
    const matchSearch = !search || v.title.toLowerCase().includes(search.toLowerCase()) ||
                        v.endpoint.toLowerCase().includes(search.toLowerCase()) ||
                        v.vuln_type.toLowerCase().includes(search.toLowerCase())
    const matchSev = !sevFilter || v.severity === sevFilter
    return matchSearch && matchSev
  })

  const counts = {
    Critical: vulns.filter(v => v.severity === 'Critical').length,
    High:     vulns.filter(v => v.severity === 'High').length,
    Medium:   vulns.filter(v => v.severity === 'Medium').length,
    Low:      vulns.filter(v => v.severity === 'Low').length,
    Info:     vulns.filter(v => v.severity === 'Info').length,
  }

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Bug size={20} color="#00d4ff" />
          <h1>Findings</h1>
        </div>
        <p>Browse, filter, and investigate all discovered vulnerabilities</p>
      </div>

      {/* Severity quick filter pills */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        {['', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(sev => (
          <button key={sev} onClick={() => setSevFilter(sev)}
            className={`btn btn-sm ${sevFilter === sev ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: 12 }}>
            {sev === '' ? `All (${vulns.length})` : `${sev} (${counts[sev] || 0})`}
          </button>
        ))}
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input className="search-input" placeholder="Search by title, endpoint, or type…"
          value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /><span>Loading findings…</span></div>
      ) : filtered.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">🛡️</div>
            <h3>{vulns.length === 0 ? 'No Findings Yet' : 'No Matches'}</h3>
            <p>{vulns.length === 0
              ? 'Run a scan to discover vulnerabilities in your target applications.'
              : 'Try different search terms or filters.'}
            </p>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th style={{ width: 28 }}></th>
                <th>#</th>
                <th>Vulnerability</th>
                <th>Endpoint</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Risk Score</th>
                <th>Detected By</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v, i) => (
                <>
                  <tr key={v.id} onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                    style={{ cursor: 'pointer' }}>
                    <td style={{ textAlign: 'center', color: '#8b949e' }}>
                      {expanded === v.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </td>
                    <td style={{ color: '#8b949e', fontSize: 12 }}>{i + 1}</td>
                    <td style={{ fontWeight: 600 }}>{v.title}</td>
                    <td><span className="mono">{v.endpoint.length > 45 ? v.endpoint.slice(0,45) + '…' : v.endpoint}</span></td>
                    <td style={{ fontSize: 12, color: '#8b949e' }}>{v.vuln_type}</td>
                    <td><span className={`badge badge-${v.severity}`}>{v.severity}</span></td>
                    <td style={{ fontSize: 12, color: '#8b949e' }}>{v.confidence}</td>
                    <td><RiskChip score={v.risk_score} /></td>
                    <td style={{ fontSize: 12, color: '#8b949e' }}>{v.detected_by}</td>
                  </tr>
                  {expanded === v.id && (
                    <tr key={`detail-${v.id}`} style={{ background: '#0d1117' }}>
                      <td colSpan={9} style={{ padding: 0 }}>
                        <VulnDetail v={v} />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
