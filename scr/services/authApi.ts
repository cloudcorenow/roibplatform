interface LoginCredentials {
  email: string;
  password: string;
}

interface AuthResponse {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  user?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
    tenantId: string;
  };
  error?: string;
}

class AuthAPI {
  private baseUrl: string;

  constructor() {
    this.baseUrl = '/api/auth';
  }

  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
      signal: AbortSignal.timeout(10000) // 10 second timeout
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }

    return data;
  }

  async refreshToken(refreshToken: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
      signal: AbortSignal.timeout(10000)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Token refresh failed');
    }

    return data;
  }

  async logout(accessToken: string): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        signal: AbortSignal.timeout(5000)
      });
    } catch (error) {
      // Don't throw on logout errors - just log them
      console.error('Logout API call failed:', error);
    }
  }

  async getCurrentUser(accessToken: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/me`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(10000)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to get user info');
    }

    return data;
  }
}

export const authApi = new AuthAPI();