# 🖥️ WAPT Framework — React Frontend Dashboard

**A modern, dark-themed React dashboard for the WAPT penetration testing framework.**

Real-time scan monitoring, target management, finding visualization, and report generation all through an intuitive web interface.

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Features](#-features)
- [Environment Variables](#-environment-variables)
- [Development](#-development)
- [Deployment](#-deployment)
- [Project Structure](#-project-structure)
- [API Integration](#-api-integration)
- [Styling & Theme](#-styling--theme)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🚀 Quick Start

### Prerequisites

- **Node.js 18+** (`node --version`)
- **npm 9+** (`npm --version`)
- **Backend API running** at `http://localhost:8000` (or your deployed URL)

### Local Development (5 minutes)

```bash
# 1. Enter the UI directory
cd ui

# 2. Install dependencies (first time only)
npm install

# 3. Start the dev server
npm run dev

# Server runs at http://localhost:5173
# API calls proxy to http://localhost:8000/api (see vite.config.js)
```

**That's it.** The app auto-reloads when you save files.

### Production Build

```bash
# Build for production
npm run build

# Output goes to ui/dist/ — ready for Netlify/Vercel/anywhere
# Test the build locally:
npm run preview
# Visit http://localhost:4173
```

---

## 🏗️ Architecture

### Tech Stack

```
React 18              - UI framework
Vite 5                - Lightning-fast build tool
React Router v6       - Client-side routing
React Query           - Server state management
Axios                 - HTTP client
Recharts              - Data visualization
Lucide React          - Icon library
Tailwind-inspired CSS - Custom dark theme (no build step)
```

### Data Flow

```
Browser Request
     ↓
React Router (determines which page)
     ↓
Page Component (e.g., Dashboard.jsx)
     ↓
React Query Hook (useQuery, useMutation)
     ↓
api.js (axios client with env var URL)
     ↓
/api/targets, /api/scans, /api/reports, etc.
     ↓
FastAPI Backend (localhost:8000 or cloud URL)
     ↓
Database (SQLite or PostgreSQL)
     ↓
Response → React Query Cache → UI Update
```

### Folder Structure

```
ui/
├── public/                    # Static assets
│   └── favicon.svg
├── src/
│   ├── main.jsx              # React entry point
│   ├── index.css             # All styles (dark theme)
│   ├── api.js                # API client + interceptors
│   ├── App.jsx               # Router + sidebar layout
│   │
│   └── pages/                # Page components (one per route)
│       ├── Dashboard.jsx     # Overview, stats, recent scans
│       ├── Targets.jsx       # Create/list/delete targets
│       ├── Scans.jsx         # Launch scans, view all
│       ├── ScanDetail.jsx    # Findings, risk rating, reports
│       ├── Reports.jsx       # Download generated files
│       └── Plugins.jsx       # Plugin registry & guide
│
├── .env.development          # Dev: API at localhost:8000
├── .env.production           # Prod: API at your deployed URL
├── index.html                # HTML entry (Vite reads this)
├── vite.config.js            # Vite settings + proxy rules
├── package.json              # Dependencies + scripts
└── netlify.toml              # Netlify deployment config (in project root)
```

---

## ✨ Features

### 🎯 Dashboard (`/dashboard`)
- **At-a-glance metrics**: Targets, scans, completed/running, reports
- **Severity chart**: Donut chart showing Critical/High/Medium/Low/Info distribution
- **Recent scans table**: Latest 7 scans with status indicator
- **API status indicator**: Real-time connection check to backend

### 🎯 Targets (`/targets`)
- **Create target**: Modal form with name, URL, description, scope/authorization notes
- **Soft delete**: Remove targets from view (data preserved in DB)
- **Authorization tracking**: Clearly display which targets have written permission documented
- **External links**: Click URL to verify it's live before scanning

### 🎯 Scans (`/scans`)
- **Launch scan modal**: 
  - Select target from dropdown
  - Choose scan type: Recon / Scanner / Vulns / Auth / Full
  - Pick stealth mode: Normal / Polite / Stealth
  - Auto-navigate to scan detail on creation
- **Scan list**: All scans with status indicator (running/completed/failed/pending)
- **Live status**: Auto-updates to show running scans in real-time
- **CLI reminder**: "To actually run this scan, use: python cli.py scan <url>"

### 🎯 Scan Detail (`/scans/:id`)
- **Live updates**: Refreshes every 3 seconds while scan is running
- **Status display**: Current state, type, start time, duration
- **Severity breakdown**: 5 cards showing Critical/High/Medium/Low/Info counts
- **OWASP Top 10 mapping**: Which OWASP categories found + severity per category
- **Finding cards**: Expandable cards per vulnerability with:
  - Title, severity badge, CVSS score, confirmation status
  - URL, parameter, vulnerability type
  - Full description, remediation, references
- **Report generation**: One-click button to generate PDF/HTML/JSON/Markdown async
- **Overall risk rating**: Color-coded badge showing Critical/High/Medium/Low/Informational

### 🎯 Reports (`/reports`)
- **Format guide**: 4 cards explaining each report type (HTML/PDF/JSON/Markdown)
- **Download list**: All generated files with size, format badge, download button
- **Auto-refresh**: Page polls every 15 seconds for new reports
- **Direct download**: Click download → browser saves file immediately

### 🎯 Plugins (`/plugins`)
- **Plugin registry**: Active plugins with version, author, description
- **How-to guide**: 4-step tutorial for creating plugins (with code example)
- **API access list**: What plugins can access (engine, config, session, etc.)
- **Plugin ideas**: 8 example plugins to build next with difficulty levels

---

## ⚙️ Environment Variables

### Development (`.env.development`)

```env
VITE_API_URL=http://localhost:8000/api
VITE_APP_NAME=WAPT Framework
VITE_APP_VERSION=0.1.0
```

**How it works:**
- When you run `npm run dev`, Vite reads `.env.development`
- Vite's dev server (`vite.config.js`) proxies `/api/*` to `http://localhost:8000`
- So your code can just use `http://localhost:8000/api/targets` directly

### Production (`.env.production`)

```env
VITE_API_URL=https://your-backend.fly.dev/api
VITE_APP_NAME=WAPT Framework
VITE_APP_VERSION=0.1.0
```

**For Netlify deployment:**
1. Set `VITE_API_URL` in Netlify **Site → Build & deploy → Environment**
2. When Netlify runs `npm run build`, it reads this variable
3. The built app knows where to send API requests

**Examples of backend URLs:**
- `https://wapt-framework.fly.dev/api` (Fly.io)
- `https://wapt-framework.onrender.com/api` (Render)
- `https://wapt-production.up.railway.app/api` (Railway)
- `https://abc123.ngrok.io/api` (ngrok — changes per restart)

---

## 🛠️ Development

### File Organization

**Pages** (`src/pages/*.jsx`) — one per route:
- Each page is a full-screen component
- Uses `useQuery` for data fetching
- Uses `useMutation` for mutations (create, delete, generate)
- Renders modals, lists, forms, charts

**API Client** (`src/api.js`):
- Centralized Axios instance
- All fetch functions organized by resource (targets, scans, reports)
- Request/response interceptors for error handling
- Reads `VITE_API_URL` from env variables automatically

**Styling** (`src/index.css`):
- No CSS framework (no build step needed)
- CSS custom properties (variables) for theming
- Dark theme with accent colors (indigo, orange, red, blue)
- Mobile-responsive grid and flexbox

### Development Workflow

```bash
# Start dev server
npm run dev

# In another terminal, start the backend
cd .. && python cli.py server

# Now:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:8000
# - API Docs: http://localhost:8000/api/docs
```

Both servers auto-reload on file save.

### Adding a New Page

1. Create `src/pages/NewPage.jsx`:
```jsx
import { useQuery } from '@tanstack/react-query'
import { someApi } from '../api.js'

export default function NewPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['data'],
    queryFn: someApi.list,
  })

  return <div className="page">...</div>
}
```

2. Add route in `src/App.jsx`:
```jsx
<Route path="/newpage" element={<NewPage />} />
```

3. Add nav link in sidebar:
```jsx
{ to: '/newpage', label: 'New Page', Icon: SomeIcon },
```

---

## 🚀 Deployment

### Netlify (Recommended — Easiest)

**1. Push to GitHub**
```bash
git add .
git commit -m "Add WAPT frontend"
git push origin main
```

**2. Connect to Netlify**
- Go to **netlify.com**
- Click **"Add new site"** → **"Import an existing project"**
- Select your GitHub repo
- Netlify reads `netlify.toml` and fills in:
  - **Build command**: `cd ui && npm install && npm run build`
  - **Publish directory**: `ui/dist`
- Click **Deploy site**

**3. Set backend URL**
- Go to **Site settings** → **Build & deploy** → **Environment**
- Add variable: `VITE_API_URL=https://your-backend-url.fly.dev/api`
- Netlify redeploys automatically
- Now frontend → production backend ✅

**Result:** Frontend deployed to `https://your-site.netlify.app`

### Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# From project root
vercel

# Vercel auto-reads package.json scripts
# Build command: npm run build
# Output: dist/

# Set VITE_API_URL in Vercel dashboard
```

### Docker + Your Server

```dockerfile
# Dockerfile (in project root)
FROM node:20-alpine AS build
WORKDIR /app
COPY ui/ .
RUN npm install && npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY netlify.toml /etc/nginx/conf.d/default.conf
EXPOSE 80
```

```bash
docker build -t wapt-ui .
docker run -p 80:3000 -e VITE_API_URL=https://api.example.com wapt-ui
```

---

## 📡 API Integration

### How `api.js` Works

```javascript
// src/api.js
const BASE_URL = import.meta.env.VITE_API_URL  // Read from .env

const api = axios.create({ baseURL: BASE_URL })

// Every request goes through interceptors
api.interceptors.request.use(config => {
  // Add API key if stored in localStorage
  const apiKey = localStorage.getItem('wapt_api_key')
  if (apiKey) config.headers['X-API-Key'] = apiKey
  return config
})

// Handle 401 Unauthorized
api.interceptors.response.use(res => res, err => {
  if (err.response?.status === 401) {
    localStorage.removeItem('wapt_api_key')
  }
  return Promise.reject(err)
})

// Organized by resource
export const targets = {
  list:   () => api.get('/targets/').then(r => r.data),
  create: (data) => api.post('/targets/', data).then(r => r.data),
  get:    (id) => api.get(`/targets/${id}`).then(r => r.data),
  delete: (id) => api.delete(`/targets/${id}`),
}
```

### Using Queries & Mutations

```jsx
// Fetch data
const { data, isLoading, error } = useQuery({
  queryKey: ['targets'],
  queryFn: targets.list,
  refetchInterval: 10000,  // Auto-refetch every 10s
})

// Mutate data
const createMut = useMutation({
  mutationFn: targets.create,
  onSuccess: () => qc.invalidateQueries(['targets'])  // Refetch list
})

createMut.mutate({ name: 'Test', url: 'http://test.com' })
```

---

## 🎨 Styling & Theme

### Design System

All colors defined as CSS custom properties in `index.css`:

```css
:root {
  --bg:        #0f1117;     /* Dark black */
  --bg2:       #1a1d27;     /* Card bg */
  --bg3:       #22263a;     /* Input bg */
  --accent:    #6366f1;     /* Primary purple */
  --critical:  #ef4444;     /* Red */
  --high:      #f97316;     /* Orange */
  --medium:    #eab308;     /* Yellow */
  --low:       #3b82f6;     /* Blue */
  --success:   #22c55e;     /* Green */
}
```

### Using Styles

**Pre-built classes:**
```jsx
<div className="page">           {/* Full-width page with padding */}
<div className="card">           {/* Card container */}
<button className="btn">        {/* Button */}
<button className="btn btn-primary"> {/* Primary button */}
<span className="badge badge-critical"> {/* Severity badge */}
<input className="form-group"> {/* Input with label */}
```

**Utility classes:**
```jsx
<div className="flex items-center gap-3">  {/* flexbox helpers */}
<div className="text-muted">              {/* text color */}
<div className="mb-4">                    {/* margin bottom */}
```

**Custom colors:**
```jsx
<div style={{ color: 'var(--accent)' }}>  {/* Use CSS vars */}
```

---

## 🐛 Troubleshooting

### API Connection Issues

**Problem:** "Cannot GET /api/targets" error in console

**Solution:**
1. Check backend is running: `python cli.py server`
2. Verify `VITE_API_URL` is correct in `.env.development`
3. Check CORS is enabled in `main.py` (it should be by default)
4. In browser DevTools → Network tab → check failing request URL

### Page Returns 404 on Refresh (Netlify)

**Problem:** `/targets` page works, but F5 refresh returns 404

**Solution:** This is already fixed in `netlify.toml` with the SPA routing redirect:
```toml
[[redirects]]
  from   = "/*"
  to     = "/index.html"
  status = 200
```

If you get 404 still, make sure `netlify.toml` is in the **project root** (same level as `ui/` folder).

### Build Error: "Cannot find module"

```bash
# Clear node_modules and reinstall
rm -rf ui/node_modules
cd ui && npm install
```

### Port 5173 Already in Use

```bash
# Kill the process on port 5173
# macOS/Linux:
lsof -ti:5173 | xargs kill -9

# Windows:
netstat -ano | findstr :5173
taskkill /PID <PID> /F

# Or use a different port:
npm run dev -- --port 5174
```

### VITE_API_URL Not Being Read

Check `.env.production` or Netlify dashboard has the variable set. Note: `.env` files are only read at **build time**, not at runtime. Changes after build don't take effect.

For Netlify: Rebuild the site after changing environment variables.

---

## 🤝 Contributing

### Adding a Feature

1. Create a new branch: `git checkout -b feature/my-feature`
2. Make changes and test locally: `npm run dev`
3. Commit and push: `git push origin feature/my-feature`
4. Open a Pull Request on GitHub

### Code Style

- Use functional components with hooks
- Use `useQuery` for reads, `useMutation` for writes
- Extract reusable components
- Keep files under 500 lines (split big pages)
- Use existing CSS custom properties for colors

### Testing Pages Locally

```bash
# Build and preview production version
npm run build
npm run preview
# Visit http://localhost:4173
```

---

## 📦 Building for Production

```bash
# 1. Build
npm run build

# Output: ui/dist/ (production-ready, ~250KB gzipped)

# 2. Test locally
npm run preview

# 3. Deploy
# Option A: Netlify (click deploy)
# Option B: Docker (docker build .)
# Option C: Copy dist/ to your web server
```

### Build Output

```
dist/
├── index.html              (entry point)
├── assets/
│   ├── index-XXXX.js      (React + all code, minified)
│   ├── vendor-YYYY.js     (dependencies, minified)
│   └── index-ZZZZ.css     (all styles, minified)
└── favicon.svg
```

Total size: ~250 KB gzipped. Loads in <1s on fast 4G.

---

## 📚 Additional Resources

- [Vite Docs](https://vitejs.dev)
- [React Router v6](https://reactrouter.com/en/main)
- [TanStack Query (React Query)](https://tanstack.com/query/latest)
- [Axios](https://axios-http.com)
- [Recharts](https://recharts.org)
- [Lucide Icons](https://lucide.dev)

---

## 📝 License

Part of the WAPT Framework — MIT License

---

<div align="center">

**Built with React + Vite**  
For authorized security testing only ⚔️

</div>