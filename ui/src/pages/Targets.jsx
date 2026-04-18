import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { targets } from '../api.js'
import { Plus, Trash2, ExternalLink } from 'lucide-react'

export default function Targets() {
  const qc = useQueryClient()
  const { data = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn:  targets.list,
  })

  const createMut = useMutation({
    mutationFn: targets.create,
    onSuccess:  () => { qc.invalidateQueries(['targets']); setForm({ name:'', url:'', description:'', scope_notes:'' }) },
  })

  const deleteMut = useMutation({
    mutationFn: targets.delete,
    onSuccess:  () => qc.invalidateQueries(['targets']),
  })

  const [form, setForm] = useState({ name: '', url: '', description: '', scope_notes: '' })
  const [showForm, setShowForm] = useState(false)

  const handleSubmit = () => {
    if (!form.name || !form.url) return
    createMut.mutate(form)
    setShowForm(false)
  }

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 4 }}>Targets</h1>
          <p style={{ color: 'var(--muted)' }}>Manage penetration test targets</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={15} /> Add Target
        </button>
      </div>

      {/* Add target form */}
      {showForm && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 style={{ fontWeight: 700, marginBottom: 16 }}>New Target</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Name *
              </label>
              <input style={{ marginTop: 4 }} placeholder="My App"
                value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                URL *
              </label>
              <input style={{ marginTop: 4 }} placeholder="https://example.com"
                value={form.url} onChange={e => setForm(p => ({ ...p, url: e.target.value }))} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Description
              </label>
              <input style={{ marginTop: 4 }} placeholder="Production web app"
                value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                Scope / Permission Notes
              </label>
              <input style={{ marginTop: 4 }} placeholder="Written permission from client on 2026-04-01"
                value={form.scope_notes} onChange={e => setForm(p => ({ ...p, scope_notes: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
            <button className="btn btn-primary" onClick={handleSubmit}
              disabled={createMut.isPending}>
              {createMut.isPending ? 'Creating...' : 'Create Target'}
            </button>
            <button className="btn" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Targets table */}
      {isLoading ? (
        <p style={{ color: 'var(--muted)' }}>Loading...</p>
      ) : data.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <p style={{ color: 'var(--muted)', marginBottom: 16 }}>No targets yet.</p>
          <button className="btn btn-primary" onClick={() => setShowForm(true)}>
            <Plus size={15} /> Add your first target
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {data.map(target => (
            <div key={target.id} className="card" style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15 }}>{target.name}</div>
                <a href={target.url} target="_blank" rel="noopener noreferrer"
                  style={{ color: 'var(--accent2)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {target.url} <ExternalLink size={12} />
                </a>
                {target.description && (
                  <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 4 }}>
                    {target.description}
                  </div>
                )}
                {target.scope_notes && (
                  <div style={{ fontSize: 11, color: 'var(--success)', marginTop: 4 }}>
                    ✓ {target.scope_notes}
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>
                  {target.created_at?.slice(0,10)}
                </span>
                <button className="btn btn-danger"
                  onClick={() => deleteMut.mutate(target.id)}>
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}