import { NavLink, Outlet } from 'react-router-dom'
import { MODULE_ROUTES } from '../routes.jsx'

const linkClass = ({ isActive }) =>
  `block rounded px-3 py-2 text-sm ${isActive ? 'bg-slate-900 text-white' : 'text-slate-700 hover:bg-slate-200'}`

export default function Layout() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 md:flex">
      <aside className="border-b border-slate-200 bg-white p-4 md:w-64 md:border-b-0 md:border-r">
        <h1 className="mb-4 text-lg font-semibold">Secure File Sharing</h1>
        <nav aria-label="Modules" className="space-y-1">
          <NavLink to="/" end className={linkClass}>
            Module status
          </NavLink>
          {MODULE_ROUTES.map((r) => (
            <NavLink key={r.path} to={r.path} className={linkClass}>
              <span className="mr-2 font-mono text-xs opacity-70">{r.code}</span>
              {r.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex-1 p-4 md:p-8">
        <Outlet />
      </main>
    </div>
  )
}
