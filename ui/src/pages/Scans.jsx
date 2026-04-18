import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scans, targets } from '../api.js'
import { Play, Eye, Clock } from 'lucide-react'

const SCAN_TYPES = ['full', 'recon', 'scan', 'vuln', 'auth']
const STEALTH_MODES = ['normal', 'polite', 'stealth']

export default function Scans() {
  const qc  = useQueryClient()
  const nav = useNavigate()

  const { data: allScans   = [] } = useQuery({ queryKey: ['scans'],   queryFn: scans.list })
  const { data: allTargets = [] } = useQuery({ queryKey: ['targets'], queryFn: targets.list })

  const [form, setForm] = useState({
    target_id: '',
    scan_type: 'full',
    stealth:   'normal',
  })
  const [showForm, setShowForm] = useState(false)

  const createMut = useMutation({
    mutationFn: scans.create,
    onSuccess:  (scan) => {
      qc.invalidateQueries(['scans'])
      setShowForm(false)
      nav(`/scans/${scan.id}`)
    },
  })

  const statusColor = s => ({
    completed: 'var(--success)',
    running:   'var(--medium)',
    pending:   'var(--muted)',
    failed:    'var(--critical)',
    cancelled: 'var(--muted)',
  }[s] || 'var(--muted)')

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 4 }}>Scans</h1>
          <p style={{ color: 'var(--muted)' }}>Launch and manage penetration test scans</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Play size={15} /> New Scan
        </button>
      </div>

      {/* New scan form */}
      {showForm && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 style={{ fontWeight: 700, marginBottom: 16 }}>Launch Scan</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Target *
              </label>
              <select style={{ marginTop: 4 }}
                value={form.target_id}
                onChange={e => setForm(p => ({ ...p, target_id: e.target.value }))}>
                <option value="">Select target...</option>
                {allTargets.map(t => (
                  <option key={t.id} value={t.id}>{t.name} — {t.url}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Scan Type
              </label>
              <select style={{ marginTop: 4 }}
                value={form.scan_type}
                onChange={e => setForm(p => ({ ...p, scan_type: e.target.value }))}>
                {SCAN_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Stealth Mode
              </label>
              <select style={{ marginTop: 4 }}
                value={form.stealth}
                onChange={e => setForm(p => ({ ...p, stealth: e.target.value }))}>
                {STEALTH_MODES.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
          </div>

          <div style={{
            marginTop: 16,
            padding: '10px 14px',
            background: 'rgba(239,68,68,0.08)',
            borderRadius: 8,
            borderLeft: '3px solid var(--critical)',
            fontSize: 12,
            color: 'var(--critical)',
          }}>
            ⚠ Only scan targets you have explicit written permission to test.
          </div>

          <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
            <button className="btn btn-primary"
              disabled={!form.target_id || createMut.isPending}
              onClick={() => createMut.mutate(form)}>
              {createMut.isPending ? 'Launching...' : 'Launch Scan'}
            </button>
            <button className="btn" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Scans list */}
      {allScans.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <p style={{ color: 'var(--muted)' }}>No scans yet. Create a target and launch a scan.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {allScans.map(scan => (
            <div key={scan.id} className="card" style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
            }} onClick={() => nav(`/scans/${scan.id}`)}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>
                  {scan.scan_type?.toUpperCase()} Scan
                </div>
                <div style={{ fontSize: 12, color: 'var(--muted)', display: 'flex', gap: 16 }}>
                  <span>ID: {scan.id.slice(0, 8)}...</span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Clock size={11} />
                    {scan.created_at?.slice(0, 16).replace('T', ' ')}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <span style={{
                  color: statusColor(scan.status),
                  fontSize: 12,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}>
                  {scan.status}
                </span>
                <Eye size={16} color="var(--muted)" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}