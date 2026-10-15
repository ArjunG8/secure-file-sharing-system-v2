// Owner: M1. Holds the access token in memory and exposes login/logout.
// The refresh token is an HttpOnly cookie set by the backend - JavaScript never sees it.
import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { setAccessToken } from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)

  const signIn = useCallback((tokenResponse, currentUser) => {
    setAccessToken(tokenResponse.access_token)
    setUser(currentUser)
  }, [])

  const signOut = useCallback(() => {
    setAccessToken(null)
    setUser(null)
  }, [])

  const value = useMemo(() => ({ user, signIn, signOut }), [user, signIn, signOut])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
