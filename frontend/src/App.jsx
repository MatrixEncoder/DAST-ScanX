import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Scans from './pages/Scans'
import Findings from './pages/Findings'
import Reports from './pages/Reports'

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/"          element={<Dashboard />} />
            <Route path="/targets"   element={<Targets />} />
            <Route path="/scans"     element={<Scans />} />
            <Route path="/findings"  element={<Findings />} />
            <Route path="/reports"   element={<Reports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
