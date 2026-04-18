import { useQuery } from '@tanstack/react-query'
import { scans, targets, reports } from '../api.js'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Activity, Target, AlertTriangle, FileText } from 'lucide-react'

const SEV_COLORS = {
  critical: '#ef4444', high: '#f97316',
  medium: '#eab308', low: '#3b82f6', info: '#6366f1',
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{
        background: `${color}20`,
        padding: 12,
        borderRadius: 10,
        display: 'flex',
      }}>
        <Icon size={20} color={color} />
      </div>
      <div>
        <div style={{ fontSize: 28, fontWeight: 800, lineHeight: 1 }}>{value}</div>
        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>{label}</div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: allScans  = [] } = useQuery({ queryKey: ['scans'],   queryFn: scans.list })
  const { data: allTargets = [] } = useQuery({ queryKey: ['targets'], queryFn: targets.list })
  const { data: rpts      = {} } = useQuery({ queryKey: ['reports'],  queryFn: reports.list })

  const completed = allScans.filter(s => s.status === 'completed').length
  const running   = allScans.filter(s => s.status === 'running').length

  // Aggregate severity counts from all scans that have summaries
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }

  const pieData = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] }))

  return (
    <div style={{ padding: 32 }}>
      <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 8 }}>Dashboard</h1>
      <p style={{ color: 'var(--muted)', marginBottom: 32 }}>
        WAPT Framework — Security Testing Platform
      </p>

      {/* Stat cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 16,
        marginBottom: 32,
      }}>
        <StatCard icon={Target}        label="Targets"         value={allTargets.length} color="var(--accent)" />
        <StatCard icon={Activity}      label="Total Scans"     value={allScans.length}   color="var(--success)" />
        <StatCard icon={AlertTriangle} label="Running"         value={running}            color="var(--medium)" />
        <StatCard icon={FileText}      label="Reports"         value={rpts.count || 0}   color="var(--high)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* Recent scans */}
        <div className="card">
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>Recent Scans</h2>
          {allScans.length === 0 ? (
            <p style={{ color: 'var(--muted)', fontSize: 13 }}>
              No scans yet. Create a target and run your first scan.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {allScans.slice(0, 8).map(scan => (
                <div key={scan.id} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 12px',
                  background: 'var(--bg3)',
                  borderRadius: 8,
                  fontSize: 13,
                }}>
                  <div>
                    <div style={{ fontWeight: 600 }}>{scan.scan_type?.toUpperCase()}</div>
                    <div style={{ color: 'var(--muted)', fontSize: 11 }}>
                      {scan.created_at?.slice(0, 16).replace('T', ' ')}
                    </div>
                  </div>
                  <span className={`badge badge-${
                    scan.status === 'completed' ? 'info' :
                    scan.status === 'running'   ? 'medium' :
                    scan.status === 'failed'    ? 'critical' : 'low'
                  }`}>
                    {scan.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Severity distribution */}
        <div className="card">
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>
            Severity Distribution
          </h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%"
                     innerRadius={55} outerRadius={85}
                     dataKey="value" paddingAngle={2}>
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg2)',
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{
              height: 200,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--muted)',
              fontSize: 13,
            }}>
              No findings data yet
            </div>
          )}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 12 }}>
            {Object.entries(SEV_COLORS).map(([sev, color]) => (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: color }} />
                {sev}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
