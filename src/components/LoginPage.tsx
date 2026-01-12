import React, { useState } from 'react';
import { Mail, Lock, Eye, EyeOff, Shield, Zap, CheckCircle, User } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';

interface LoginPageProps {
  onLogin: (credentials: { email: string; password: string }) => Promise<void>;
  onRegister?: (data: { email: string; password: string; name?: string }) => Promise<void>;
  isLoading?: boolean;
  error?: string;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLogin,
  onRegister,
  isLoading = false,
  error
}) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = 'Please enter a valid email address';
    }

    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (mode === 'register' && formData.password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (mode === 'login' && formData.password.length < 6) {
      errors.password = 'Password must be at least 6 characters';
    }

    if (mode === 'register') {
      if (!formData.confirmPassword) {
        errors.confirmPassword = 'Please confirm your password';
      } else if (formData.password !== formData.confirmPassword) {
        errors.confirmPassword = 'Passwords do not match';
      }
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    try {
      if (mode === 'login') {
        await onLogin({ email: formData.email, password: formData.password });
      } else if (onRegister) {
        await onRegister({
          email: formData.email,
          password: formData.password,
          name: formData.name || undefined
        });
      }
    } catch (error) {
      // Error handling is managed by parent component
    }
  };

  const handleChange = (field: keyof typeof formData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (validationErrors[field]) {
      setValidationErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  const switchMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    setValidationErrors({});
    setFormData({ email: '', password: '', name: '', confirmPassword: '' });
  };

  const features = [
    {
      icon: Shield,
      title: 'Secure & Compliant',
      description: 'Enterprise-grade security with audit trails'
    },
    {
      icon: Zap,
      title: 'Lightning Fast',
      description: 'Global edge deployment for instant access'
    },
    {
      icon: CheckCircle,
      title: 'Audit Ready',
      description: 'IRS Section 41 compliant documentation'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#ade5f8] via-[#0073e6] to-[#004aad] flex">
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-[#004aad] via-[#0073e6] to-[#2c3c4d] p-12 flex-col justify-between relative overflow-hidden">
        <div className="absolute inset-0 opacity-10">
          <div className="absolute top-0 left-0 w-full h-full bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmZmZmYiIGZpbGwtb3BhY2l0eT0iMC4xIj48Y2lyY2xlIGN4PSIzMCIgY3k9IjMwIiByPSI0Ii8+PC9nPjwvZz48L3N2Zz4=')]"></div>
        </div>

        <div className="absolute top-20 right-20 w-64 h-64 bg-[#89c726] opacity-10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-80 h-80 bg-[#ade5f8] opacity-10 rounded-full blur-3xl"></div>

        <div className="relative z-10">
          <div className="flex items-center space-x-3 mb-8">
            <img src="https://imagedelivery.net/s0JEtwqnLquT1GUYjPcg5Q/4f0adeb3-3d2a-401c-7341-35969399f600/public" alt="ROI BLUEPRINT" className="w-16 h-16 object-contain" />
            <div>
              <h1 className="text-3xl font-bold text-white">ROI BLUEPRINT</h1>
              <p className="text-[#ade5f8] text-sm">R&D Tax Credit Platform</p>
            </div>
          </div>

          <div className="space-y-8">
            <div>
              <h2 className="text-4xl font-bold text-white mb-4 leading-tight">
                Maximize Your R&D Tax Credits
              </h2>
              <p className="text-[#ade5f8] text-lg leading-relaxed">
                Streamline your R&D documentation, track qualified activities, and ensure IRS compliance with our comprehensive platform.
              </p>
            </div>

            <div className="space-y-4">
              {features.map((feature, index) => (
                <div key={index} className="flex items-start space-x-4 bg-white/5 backdrop-blur-sm p-4 rounded-xl border border-white/10 transition-all duration-300 hover:bg-white/10">
                  <div className="w-12 h-12 bg-[#89c726] rounded-lg flex items-center justify-center flex-shrink-0">
                    <feature.icon className="h-6 w-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold text-lg">{feature.title}</h3>
                    <p className="text-[#ade5f8] text-sm">{feature.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="relative z-10">
          <div className="flex items-center space-x-2 text-[#ade5f8] text-sm">
            <div className="flex -space-x-2">
              <div className="w-8 h-8 rounded-full bg-[#89c726] border-2 border-white"></div>
              <div className="w-8 h-8 rounded-full bg-[#0073e6] border-2 border-white"></div>
              <div className="w-8 h-8 rounded-full bg-[#ade5f8] border-2 border-white"></div>
            </div>
            <p>Trusted by innovative companies to maximize their R&D tax benefits</p>
          </div>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center p-8 bg-white/95">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-3xl shadow-2xl border border-gray-100 p-10">
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center mb-6">
                <img src="https://imagedelivery.net/s0JEtwqnLquT1GUYjPcg5Q/4f0adeb3-3d2a-401c-7341-35969399f600/public" alt="ROI BLUEPRINT Logo" className="w-20 h-20 object-contain" />
              </div>
              <h2 className="text-3xl font-bold text-[#2c3c4d] mb-2">
                {mode === 'login' ? 'Welcome Back' : 'Create Account'}
              </h2>
              <p className="text-gray-600">
                {mode === 'login' ? 'Sign in to your ROI Blueprint account' : 'Get started with ROI Blueprint'}
              </p>
            </div>

            {error && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl">
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              {mode === 'register' && (
                <div>
                  <label className="block text-sm font-semibold text-[#2c3c4d] mb-2">
                    Full Name (Optional)
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <User className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => handleChange('name', e.target.value)}
                      className="w-full pl-12 pr-4 py-3.5 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-[#0073e6] focus:border-[#0073e6] hover:border-gray-300 transition-all"
                      placeholder="Enter your name"
                      disabled={isLoading}
                    />
                  </div>
                </div>
              )}

              <div>
                <label className="block text-sm font-semibold text-[#2c3c4d] mb-2">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Mail className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => handleChange('email', e.target.value)}
                    className={`w-full pl-12 pr-4 py-3.5 border-2 rounded-xl focus:ring-2 focus:ring-[#0073e6] focus:border-[#0073e6] transition-all ${
                      validationErrors.email ? 'border-red-300 bg-red-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                    placeholder="Enter your email"
                    disabled={isLoading}
                    autoComplete="email"
                    autoFocus
                  />
                </div>
                {validationErrors.email && (
                  <p className="mt-2 text-sm text-red-600">{validationErrors.email}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-semibold text-[#2c3c4d] mb-2">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={formData.password}
                    onChange={(e) => handleChange('password', e.target.value)}
                    className={`w-full pl-12 pr-12 py-3.5 border-2 rounded-xl focus:ring-2 focus:ring-[#0073e6] focus:border-[#0073e6] transition-all ${
                      validationErrors.password ? 'border-red-300 bg-red-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                    placeholder={mode === 'register' ? 'Create a password (min 8 characters)' : 'Enter your password'}
                    disabled={isLoading}
                    autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-400 hover:text-[#0073e6] transition-colors"
                    disabled={isLoading}
                  >
                    {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
                {validationErrors.password && (
                  <p className="mt-2 text-sm text-red-600">{validationErrors.password}</p>
                )}
              </div>

              {mode === 'register' && (
                <div>
                  <label className="block text-sm font-semibold text-[#2c3c4d] mb-2">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={formData.confirmPassword}
                      onChange={(e) => handleChange('confirmPassword', e.target.value)}
                      className={`w-full pl-12 pr-4 py-3.5 border-2 rounded-xl focus:ring-2 focus:ring-[#0073e6] focus:border-[#0073e6] transition-all ${
                        validationErrors.confirmPassword ? 'border-red-300 bg-red-50' : 'border-gray-200 hover:border-gray-300'
                      }`}
                      placeholder="Confirm your password"
                      disabled={isLoading}
                      autoComplete="new-password"
                    />
                  </div>
                  {validationErrors.confirmPassword && (
                    <p className="mt-2 text-sm text-red-600">{validationErrors.confirmPassword}</p>
                  )}
                </div>
              )}

              {mode === 'login' && (
                <div className="flex items-center justify-between">
                  <label className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      className="rounded border-gray-300 text-[#0073e6] focus:ring-[#0073e6] w-4 h-4"
                      disabled={isLoading}
                    />
                    <span className="ml-2 text-sm text-gray-600 font-medium">Remember me</span>
                  </label>
                  <button
                    type="button"
                    className="text-sm text-[#0073e6] hover:text-[#004aad] font-semibold transition-colors"
                    disabled={isLoading}
                  >
                    Forgot password?
                  </button>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-[#004aad] to-[#0073e6] text-white py-4 px-6 rounded-xl hover:from-[#0073e6] hover:to-[#89c726] focus:ring-4 focus:ring-[#ade5f8] transition-all duration-300 font-semibold text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center shadow-lg hover:shadow-xl"
              >
                {isLoading ? (
                  <LoadingSpinner size="sm" text="" />
                ) : (
                  <span>{mode === 'login' ? 'Sign In' : 'Create Account'}</span>
                )}
              </button>
            </form>

            <div className="mt-8 pt-6 border-t border-gray-200">
              <p className="text-center text-sm text-gray-600">
                {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}{' '}
                <button
                  onClick={switchMode}
                  className="text-[#0073e6] hover:text-[#004aad] font-semibold transition-colors"
                  disabled={isLoading}
                >
                  {mode === 'login' ? 'Create Account' : 'Sign In'}
                </button>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
