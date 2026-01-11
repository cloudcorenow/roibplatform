import { useState, useEffect, createContext, useContext } from 'react';
import { User } from '../types/users';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  register: (data: { email: string; password: string; name?: string }) => Promise<void>;
  logout: () => Promise<void>;
  error: string | null;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const API_URL = '/api';

let refreshPromise: Promise<void> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  if (refreshPromise) {
    await refreshPromise;
    return true;
  }

  refreshPromise = (async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token');
      }

      const response = await fetch(`${API_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      localStorage.setItem('access_token', data.accessToken);
    } finally {
      refreshPromise = null;
    }
  })();

  await refreshPromise;
  return true;
}

async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const token = localStorage.getItem('access_token');
  const sessionId = localStorage.getItem('session_id');

  if (!token) {
    throw new Error('No access token');
  }

  const headers: Record<string, string> = {
    ...options.headers as Record<string, string>,
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  if (sessionId) {
    headers['X-Session-ID'] = sessionId;
  }

  let response = await fetch(url, { ...options, headers });

  if (response.status === 401) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      const newToken = localStorage.getItem('access_token');
      headers.Authorization = `Bearer ${newToken}`;
      response = await fetch(url, { ...options, headers });
    }
  }

  return response;
}

function mapApiUserToUser(apiUser: any): User {
  return {
    id: apiUser.id,
    email: apiUser.email,
    firstName: apiUser.name?.split(' ')[0] || 'User',
    lastName: apiUser.name?.split(' ').slice(1).join(' ') || '',
    avatar: `https://images.pexels.com/photos/2379004/pexels-photo-2379004.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop`,
    status: 'active',
    role: {
      id: apiUser.role || 'user',
      name: apiUser.role === 'admin' ? 'Administrator' : 'User',
      description: apiUser.role === 'admin' ? 'Full system access' : 'Standard user access',
      permissions: [],
      isSystemRole: true,
      color: apiUser.role === 'admin' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    department: 'General',
    hireDate: new Date().toISOString().split('T')[0],
    lastLogin: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: 'system'
  };
}

export const useAuthProvider = () => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('access_token');
        const refreshToken = localStorage.getItem('refresh_token');

        if (!token || !refreshToken) {
          setIsLoading(false);
          return;
        }

        try {
          const response = await fetchWithAuth(`${API_URL}/auth/me`);

          if (response.ok) {
            const data = await response.json();
            setUser(mapApiUserToUser(data.user));
          } else {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            localStorage.removeItem('session_id');
          }
        } catch {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('session_id');
        }
      } catch (error) {
        console.error('Auth check failed:', error);
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();

    const pingSession = async () => {
      const sessionId = localStorage.getItem('session_id');
      const token = localStorage.getItem('access_token');

      if (sessionId && token) {
        try {
          const response = await fetch(`${API_URL}/auth/session/ping`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'X-Session-ID': sessionId,
              'Content-Type': 'application/json'
            }
          });

          if (!response.ok) {
            console.warn('Session ping failed, session may have expired');
            if (response.status === 401 || response.status === 404) {
              localStorage.removeItem('session_id');
            }
          }
        } catch (error) {
          console.error('Session ping error:', error);
        }
      }
    };

    const pingInterval = setInterval(pingSession, 5 * 60 * 1000);

    return () => clearInterval(pingInterval);
  }, []);

  const login = async (credentials: { email: string; password: string }) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('API server is not running. Please start the worker with: npm run dev:worker');
      }

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Login failed');
      }

      const data = await response.json();

      localStorage.setItem('access_token', data.accessToken);
      localStorage.setItem('refresh_token', data.refreshToken);
      if (data.sessionId) {
        localStorage.setItem('session_id', data.sessionId);
      }

      setUser(mapApiUserToUser(data.user));
      setError(null);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      setError(message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (data: { email: string; password: string; name?: string }) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('API server is not running. Please start the worker with: npm run dev:worker');
      }

      if (!response.ok) {
        const result = await response.json();
        throw new Error(result.error || 'Registration failed');
      }

      const result = await response.json();

      localStorage.setItem('access_token', result.accessToken);

      setUser(mapApiUserToUser(result.user));
      setError(null);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      setError(message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        await fetch(`${API_URL}/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('session_id');
      setUser(null);
      setError(null);
    }
  };

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    error
  };
};

export { AuthContext };
