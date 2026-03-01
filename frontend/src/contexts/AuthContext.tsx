import { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react'
import { setGlobalLogout, clearGlobalLogout } from '../lib/api'

const TOKEN_KEY = 'newapi_tools_token'
const TOKEN_EXPIRY_KEY = 'newapi_tools_token_expiry'
const PREVIEW_TOKEN = '__preview__'

function isTruthyEnv(value: unknown) {
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').toLowerCase())
}

const PREVIEW_ENABLED = import.meta.env.DEV && isTruthyEnv(import.meta.env.VITE_PREVIEW_MODE)

interface AuthContextType {
  isAuthenticated: boolean
  token: string | null
  login: (password: string) => Promise<boolean>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [token, setToken] = useState<string | null>(() => {
    if (PREVIEW_ENABLED) {
      return PREVIEW_TOKEN
    }
    const savedToken = localStorage.getItem(TOKEN_KEY)
    const expiry = localStorage.getItem(TOKEN_EXPIRY_KEY)

    if (savedToken && expiry) {
      const expiryTime = parseInt(expiry, 10)
      if (Date.now() < expiryTime) {
        return savedToken
      }
      // Token expired, clear it
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(TOKEN_EXPIRY_KEY)
    }
    return null
  })

  const isAuthenticated = PREVIEW_ENABLED || token !== null

  // Check token expiry periodically
  useEffect(() => {
    if (PREVIEW_ENABLED) return
    const checkExpiry = () => {
      const expiry = localStorage.getItem(TOKEN_EXPIRY_KEY)
      if (expiry && Date.now() >= parseInt(expiry, 10)) {
        setToken(null)
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(TOKEN_EXPIRY_KEY)
      }
    }

    const interval = setInterval(checkExpiry, 60000) // Check every minute
    return () => clearInterval(interval)
  }, [])

  const login = useCallback(async (password: string): Promise<boolean> => {
    try {
      if (PREVIEW_ENABLED) {
        setToken(PREVIEW_TOKEN)
        return true
      }
      const apiUrl = import.meta.env.VITE_API_URL || ''
      const response = await fetch(`${apiUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password }),
      })

      if (!response.ok) {
        return false
      }

      const data = await response.json()
      if (data.success && data.token) {
        const newToken = data.token
        // Parse expires_at or default 24 hours
        let expiryTime: number
        if (data.expires_at) {
          expiryTime = new Date(data.expires_at).getTime()
        } else {
          expiryTime = Date.now() + 86400 * 1000
        }

        setToken(newToken)
        localStorage.setItem(TOKEN_KEY, newToken)
        localStorage.setItem(TOKEN_EXPIRY_KEY, expiryTime.toString())
        return true
      }
      return false
    } catch (error) {
      console.error('Login error:', error)
      return false
    }
  }, [])

  const logout = useCallback(() => {
    if (PREVIEW_ENABLED) return
    setToken(null)
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(TOKEN_EXPIRY_KEY)
  }, [])

  // Set global logout function for API interceptor
  useEffect(() => {
    setGlobalLogout(logout)
    return () => clearGlobalLogout()
  }, [logout])

  return (
    <AuthContext.Provider value={{ isAuthenticated, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}
