// Owner: M1. Holds the access token in memory (never localStorage) and the current user.
// The refresh token is an HttpOnly cookie set by the backend - JavaScript never sees it.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { setAccessToken, setUnauthorizedHandler } from '../api/client.js'
import * as authApi from '../features/auth/api.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)

  const clear = useCallback(() => {
    setAccessToken(null)
    setUser(null)
  }, [])

  const refresh = useCallback(async () => {
    try {
      const tokens = await authApi.refresh()
      setAccessToken(tokens.access_token)
      return true
    } catch {
      clear()
      return false
    }
  }, [clear])

  const signIn = useCallback(async (email, password) => {
    const tokens = await authApi.login({ email, password })
    setAccessToken(tokens.access_token)
    const current = await authApi.me()
    setUser(current)
    return current
  }, [])

  const signOut = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      clear()
    }
  }, [clear])

  // Silent refresh on 401, and restore a session from the refresh cookie on page load.
  useEffect(() => {
    setUnauthorizedHandler(refresh)
    let cancelled = false
    refresh().then(async (ok) => {
      if (ok && !cancelled) {
        try {
          const current = await authApi.me()
          if (!cancelled) setUser(current)
        } catch {
          if (!cancelled) clear()
        }
      }
    })
    return () => {
      cancelled = true
      setUnauthorizedHandler(null)
    }
  }, [refresh, clear])

  const value = useMemo(
    () => ({ user, signIn, signOut, refresh, clearSession: clear }),
    [user, signIn, signOut, refresh, clear],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
