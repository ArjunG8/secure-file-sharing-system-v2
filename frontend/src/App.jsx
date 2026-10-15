import { Route, Routes } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import ModuleStatusPage from './features/status/ModuleStatusPage.jsx'
import { MODULE_ROUTES } from './routes.jsx'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<ModuleStatusPage />} />
        {MODULE_ROUTES.map(({ path, Component }) => (
          <Route key={path} path={path} element={<Component />} />
        ))}
        <Route path="*" element={<p>Page not found.</p>} />
      </Route>
    </Routes>
  )
}
