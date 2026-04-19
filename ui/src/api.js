const API_BASE = import.meta.env.VITE_API_BASE_URL

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
    },
    ...options,
  })

  const text = await res.text()
  const data = text ? JSON.parse(text) : null

  if (!res.ok) {
    throw new Error(data?.detail || data?.message || res.statusText)
  }

  return data
}
const API = import.meta.env.VITE_API_URL;

export async function getHealth() {
  const res = await fetch(`${API}/health`);
  return res.json();
}

const targets = {
  list: () => request('/targets'),
  create: (payload) => request('/targets', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  delete: (id) => request(`/targets/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  }),
}

const scans = {
  list: () => request('/scans'),
  get: (id) => request(`/scans/${encodeURIComponent(id)}`),
  create: (form) => {
    const payload = {
      target_id: form.target_id,
      scan_type: form.scan_type,
      rate_limit: form.rate_limit || undefined,
      timeout: form.timeout || undefined,
    }

    return request('/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
}

const reports = {
  list: () => request('/reports/list'),
  summary: (scanId) => request(`/reports/${encodeURIComponent(scanId)}/summary`),
  generate: (payload) => request('/reports/generate', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  downloadUrl: (filename) => `${API_BASE}/reports/download/${encodeURIComponent(filename)}`,
}

export { targets, scans, reports }
