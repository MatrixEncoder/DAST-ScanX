import axios from 'axios'

const api = axios.create({
  baseURL: '',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Targets ────────────────────────────────────────────────
export const getTargets = () => api.get('/targets/')
export const getTarget = (id) => api.get(`/targets/${id}`)
export const createTarget = (data) => api.post('/targets/', data)
export const updateTarget = (id, data) => api.put(`/targets/${id}`, data)
export const deleteTarget = (id) => api.delete(`/targets/${id}`)

// ── Scans ──────────────────────────────────────────────────
export const getScans = () => api.get('/scans/')
export const getScan = (id) => api.get(`/scans/${id}`)
export const createScan = (data) => api.post('/scans/', data)
export const cancelScan = (id) => api.post(`/scans/${id}/cancel`)

// ── Findings ───────────────────────────────────────────────
export const getFindings = (params = {}) => api.get('/findings/', { params })
export const getFinding = (id) => api.get(`/findings/${id}`)
export const getDashboard = () => api.get('/findings/dashboard')
export const getVulnStats = (scanId) => api.get('/findings/stats', { params: { scan_id: scanId } })

// ── Reports ────────────────────────────────────────────────
export const generateReport = (scanId) => api.post(`/reports/${scanId}/generate`)
export const getReports = (scanId) => api.get(`/reports/${scanId}`)
export const downloadReport = (scanId, format) =>
  `http://127.0.0.1:8000/reports/${scanId}/download/${format}`
