import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { scans, reports } from '../api.js'
import { Download, RefreshCw } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export default function ScanDetail() {
  const { id } = useParams()

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey:        ['scan', id],
    queryFn:         () => scans.get(id),
    refetchInterval: scan => scan?.status === 'running' ? 3000 : false,
  })

  const { data: summary } = useQuery({
    queryKey: ['report-summary', id],
    queryFn:  () => reports.summary(id),
    enabled:  scan?.status === 'completed',
  })

  const generateMut = useMutation({
    mutationFn: () => reports.generate({
      scan_id: id,
      formats: ['html', 'pdf', 'json', 'markdown'],
    }),
  })

  if (scanLoading) return <div style={{ padding: 32, color: 'var(--muted)' }}>Loading scan...</div>
  if (!scan)       return <div style={{ padding: 32, color: 'var(--critical)' }}>Scan not found</div>

  const statusColor = {
    completed: 'var(--success)',
    running:   'var(--medium)',
    failed:    'var(--critical)',
    pending:   'var(--muted)',
  }[scan.status] || 'var(--muted)'

  const findings = summary?.stats ? [
    { label: 'Critical', count: summary.stats.critical, color: 'var(--critical)' },
    { label: 'High',     count: summary.stats.high,     color: 'var(--high)' },
    { label: 'Medium',   count: summary.stats.medium,   color: 'var(--medium)' },
    { label: 'Low',      count: summary.stats.low,      color: 'var(--low)' },
    { label: 'Info',     count: summary.stats.info,     color: 'var(--info)' },
  ] : []

  return (
    <div style={{ padding: 32 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 4 }}>
            {scan.scan_type?.toUpperCase()} Scan
          </h1>
          <code style={{ fontSize: 12, color: 'var(--muted)' }}>{scan.id}</code>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {scan.status === 'running' && (
            <button className="btn" style={{ color: 'var(--medium)' }}>
              <RefreshCw size={14} className="animate-spin" /> Running...
            </button>
          )}
          {scan.status === 'completed' && (
            <button className="btn btn-primary"
              onClick={() => generateMut.mutate()}
              disabled={generateMut.isPending}>
              <Download size={14} />
              {generateMut.isPending ? 'Generating...' : 'Generate Report'}
            </button>
          )}
        </div>
      </div>

      {/* Status card */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24 }}>
          {[
            { label: 'Status',   value: scan.status?.toUpperCase(),  color: statusColor },
            { label: 'Type',     value: scan.scan_type?.toUpperCase(), color: 'var(--text)' },
            { label: 'Started',  value: scan.started_at?.slice(0,16).replace('T',' ') || '—', color: 'var(--text)' },
            { label: 'Finished', value: scan.finished_at?.slice(0,16).replace('T',' ') || '—', color: 'var(--text)' },
          ].map(({ label, value, color }) => (
            <div key={label}>
              <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
                {label}
              </div>
              <div style={{ fontSize: 16, fontWeight: 700, color }}>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Running indicator */}
      {scan.status === 'running' && (
        <div className="card" style={{
          marginBottom: 24,
          borderLeft: '4px solid var(--medium)',
          animation: 'pulse 2s infinite',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <RefreshCw size={16} color="var(--medium)" />
            <span style={{ color: 'var(--medium)', fontWeight: 600 }}>
              Scan in progress — auto-refreshing every 3 seconds
            </span>
          </div>
        </div>
      )}

      {/* Findings breakdown */}
      {summary && (
        <>
          <div style={{ marginBottom: 16 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Findings</h2>
            <div style={{
              display: 'inline-flex',
              padding: '6px 14px',
              background: `${summary.risk_color || '#888'}20`,
              color: summary.risk_color || 'var(--muted)',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: 1,
            }}>
              Overall Risk: {summary.overall_risk}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
            {findings.map(({ label, count, color }) => (
              <div key={label} className="card" style={{
                textAlign: 'center',
                borderTop: `3px solid ${color}`,
                padding: '16px 12px',
              }}>
                <div style={{ fontSize: 32, fontWeight: 800, color }}>{count}</div>
                <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                  {label}
                </div>
              </div>
            ))}
          </div>

          {/* OWASP Coverage */}
          {summary.owasp?.length > 0 && (
            <div className="card" style={{ marginBottom: 24 }}>
              <h3 style={{ fontWeight: 700, marginBottom: 16 }}>OWASP Top 10 Coverage</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {summary.owasp.map(item => (
                  <div key={item.category} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    background: 'var(--bg3)',
                    borderRadius: 8,
                    fontSize: 13,
                  }}>
                    <span>{item.category}</span>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <span style={{ color: 'var(--muted)' }}>{item.count} findings</span>
                      <span className={`badge badge-${item.severity}`}>{item.severity}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {generateMut.isSuccess && (
        <div className="card" style={{ borderLeft: '4px solid var(--success)' }}>
          <p style={{ color: 'var(--success)', fontWeight: 600 }}>
            ✓ Reports are being generated — check the Reports page in a moment.
          </p>
        </div>
      )}
    </div>
  )
}