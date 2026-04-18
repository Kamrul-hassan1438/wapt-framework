import { Puzzle, CheckCircle } from 'lucide-react'

const BUILTIN_PLUGINS = [
  { name: 'open_redirect',    version: '1.0.0', author: 'WAPT Framework', category: 'vuln',    description: 'Open redirect detection in URL and form parameters' },
]

export default function Plugins() {
  return (
    <div style={{ padding: 32 }}>
      <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 4 }}>Plugins</h1>
      <p style={{ color: 'var(--muted)', marginBottom: 32 }}>
        Extend the framework with community and custom plugins
      </p>

      <div className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ fontWeight: 700, marginBottom: 8 }}>How to add a plugin</h2>
        <ol style={{ paddingLeft: 20, color: 'var(--muted)', fontSize: 13, lineHeight: 2 }}>
          <li>Create a <code>.py</code> file in the <code>plugins/</code> directory</li>
          <li>Inherit from <code>WAPTPlugin</code> and implement <code>async run()</code></li>
          <li>Set <code>name</code>, <code>version</code>, <code>author</code>, <code>description</code></li>
          <li>The plugin is auto-discovered on the next scan</li>
        </ol>
        <div style={{ marginTop: 12 }}>
          <code style={{ fontSize: 12, color: 'var(--accent2)' }}>
            See plugins/example_open_redirect.py for a complete example
          </code>
        </div>
      </div>

      <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Available Plugins</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {BUILTIN_PLUGINS.map(plugin => (
          <div key={plugin.name} className="card" style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
          }}>
            <Puzzle size={20} color="var(--accent)" />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontWeight: 700 }}>{plugin.name}</span>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>v{plugin.version}</span>
                <span className={`badge badge-${plugin.category === 'vuln' ? 'high' : 'info'}`}>
                  {plugin.category}
                </span>
              </div>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 2 }}>
                {plugin.description}
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                by {plugin.author}
              </div>
            </div>
            <CheckCircle size={16} color="var(--success)" />
          </div>
        ))}
      </div>
    </div>
  )
}