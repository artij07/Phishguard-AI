const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

export async function fetchDashboardStats() {
  return apiRequest('/api/dashboard/stats');
}

export async function fetchScanHistory(page = 1, pageSize = 10) {
  const data = await apiRequest(`/api/scans?page=${page}&page_size=${pageSize}`);
  return data;
}

export async function submitScan(type, payload) {
  return apiRequest(`/api/scans/${type}`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function downloadReportPdf(scanId) {
  const response = await fetch(`${API_BASE}/api/scans/${scanId}/report/pdf`);
  if (!response.ok) throw new Error('PDF report unavailable');
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `phishguard-${scanId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}
