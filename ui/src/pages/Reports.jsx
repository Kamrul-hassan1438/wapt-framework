import { useQuery } from '@tanstack/react-query'
import { reports } from '../api.js'
import { Download, FileText } from 'lucide-react'

const FORMAT_COLORS = {
  html: '#f97316', pdf: '#ef4444',
  json: '#22c55e', md: '#6366f1',
}

export default function Reports() {
  const { data = {}, isLoading } = useQuery({
    queryKey:        ['reports'],
    queryFn:         reports.list,
    refetchInterval: 10000,
  })

  const allReports = data.reports || []

  return (
    <div style={{ padding: 32 }}>
      <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 4 }}>Reports</h1>
      <p style={{ color: 'var(--muted)', marginBottom: 32 }}>
        Download generated penetration test reports
      </p>

      {isLoading ? (
        <p style={{ color: 'var(--muted)' }}>Loading...</p>
      ) : allReports.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <FileText size={48} color="var(--muted)" style={{ margin: '0 auto 16px' }} />
          <p style={{ color: 'var(--muted)' }}>
            No reports yet. Complete a scan and generate a report.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {allReports.map(report => {
            const fmt   = report.format
            const color = FORMAT_COLORS[fmt] || 'var(--muted)'
            return (
              <div key={report.filename} className="card" style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{
                    background: `${color}20`,
                    color,
                    padding: '6px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    letterSpacing: 1,
                    minWidth: 48,
                    textAlign: 'center',
                  }}>
                    {fmt}
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{report.filename}</div>
                    <div style={{ fontSize: 11, color: 'var(--muted)' }}>{report.size_human}</div>
                  </div>
                </div>
                <a
                  href={reports.downloadUrl(report.filename)}
                  download={report.filename}
                  className="btn btn-primary"
                  style={{ textDecoration: 'none' }}
                >
                  <Download size={14} /> Download
                </a>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}