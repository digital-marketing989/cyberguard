/**
 * CyberGuard API Client
 * Axios instance + typed API calls for all backend endpoints
 */
import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
})

// ─── Phishing ─────────────────────────────────────────────────────────────────
export const analyzePhishingText = (data) =>
  api.post('/phishing/analyze', data).then(r => r.data)

export const analyzePhishingFile = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/phishing/analyze-file', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data)
}

export const analyzePhishingQR = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/phishing/analyze-qr', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data)
}

// ─── URL Scan ─────────────────────────────────────────────────────────────────
export const scanURL = (url) =>
  api.post('/url/scan', { url }).then(r => r.data)

// ─── Deepfake ─────────────────────────────────────────────────────────────────
export const analyzeDeepfake = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/deepfake/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  }).then(r => r.data)
}

// ─── Impersonation ────────────────────────────────────────────────────────────
export const analyzeImpersonation = (data) =>
  api.post('/impersonation/analyze', data).then(r => r.data)

// ─── Auth Anomaly ─────────────────────────────────────────────────────────────
export const analyzeAuthLogs = (logs) =>
  api.post('/auth/analyze', { logs }).then(r => r.data)

export const uploadAuthCSV = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/auth/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data)
}

export const runSampleAuthAnalysis = () =>
  api.get('/auth/sample').then(r => r.data)

// ─── Network ──────────────────────────────────────────────────────────────────
export const runSampleNetworkAnalysis = () =>
  api.post('/network/analyze', { use_sample: true }).then(r => r.data)

export const runSampleAPIAbuseAnalysis = () =>
  api.post('/network/analyze-api', { use_sample: true }).then(r => r.data)

// ─── Dashboard ────────────────────────────────────────────────────────────────
export const getDashboardSummary = () =>
  api.get('/dashboard/summary').then(r => r.data)

export const getTimeline = (params = {}) =>
  api.get('/dashboard/timeline', { params }).then(r => r.data)

export const getThreatDistribution = () =>
  api.get('/dashboard/threat-distribution').then(r => r.data)

export const getRiskDistribution = () =>
  api.get('/dashboard/risk-distribution').then(r => r.data)

export const getTopTargets = () =>
  api.get('/dashboard/top-targets').then(r => r.data)

// ─── Incidents ────────────────────────────────────────────────────────────────
export const getIncidents = (params = {}) =>
  api.get('/incidents/', { params }).then(r => r.data)

export const getIncident = (id) =>
  api.get(`/incidents/${id}`).then(r => r.data)

export const updateIncident = (id, data) =>
  api.patch(`/incidents/${id}`, data).then(r => r.data)

export const createIncident = (data) =>
  api.post('/incidents/', data).then(r => r.data)

export default api
