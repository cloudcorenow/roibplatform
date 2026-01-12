import { useState, useCallback } from 'react';
import { useToast } from '../components/Toast';

export interface ErrorInfo {
  message: string;
  code?: string;
  details?: string;
  timestamp: string;
  context?: string;
}

export function useErrorHandler() {
  const [errors, setErrors] = useState<ErrorInfo[]>([]);
  const { showError } = useToast();

  const handleError = useCallback((error: Error | string, context?: string) => {
    const errorInfo: ErrorInfo = {
      message: typeof error === 'string' ? error : error.message,
      code: typeof error === 'object' && 'code' in error ? (error as any).code : undefined,
      details: typeof error === 'object' && 'details' in error ? (error as any).details : undefined,
      timestamp: new Date().toISOString(),
      context
    };

    setErrors(prev => [errorInfo, ...prev.slice(0, 9)]); // Keep last 10 errors

    // Show user-friendly error message
    const userMessage = getUserFriendlyMessage(errorInfo.message, errorInfo.code);
    const priority = getErrorPriority(errorInfo.code);
    showError(context || 'Error', userMessage, priority);

    // Log to console for debugging
    console.error(`[${context || 'Error'}]`, error);

    // In production, send to error tracking service
    if (import.meta.env.PROD) {
      // Example: Sentry.captureException(error, { 
      //   tags: { context, code: errorInfo.code },
      //   extra: { errorId: errorInfo.timestamp }
      // });
    }
  }, [showError]);

  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  const getErrorById = useCallback((errorId: string) => {
    return errors.find(error => error.timestamp === errorId);
  }, [errors]);

  return {
    errors,
    handleError,
    clearErrors,
    getErrorById
  };
}

function getUserFriendlyMessage(errorMessage: string, code?: string): string {
  // Map error codes to user-friendly messages
  const codeMap: Record<string, string> = {
    'UNAUTHORIZED': 'Your session has expired. Please log in again.',
    'FORBIDDEN': 'You do not have permission to perform this action.',
    'NOT_FOUND': 'The requested item could not be found.',
    'VALIDATION_ERROR': 'Please check your input and try again.',
    'RATE_LIMIT_EXCEEDED': 'Too many requests. Please wait a moment and try again.',
    'NETWORK_ERROR': 'Unable to connect to server. Please check your internet connection.',
    'TIMEOUT': 'The request timed out. Please try again.',
    'SERVER_ERROR': 'A server error occurred. Please try again later.',
    'TOKEN_INVALID': 'Your session is invalid. Please log in again.',
    'TENANT_INVALID': 'Invalid account access. Please contact support.',
    'CENTRALREACH_ERROR': 'Unable to connect to CentralReach. Please check your integration settings.',
    'QUICKBOOKS_ERROR': 'Unable to connect to QuickBooks. Please check your integration settings.'
  };

  if (code && codeMap[code]) {
    return codeMap[code];
  }

  // Check for partial matches in error message
  const messageMap: Record<string, string> = {
    'network request failed': 'Unable to connect to server. Please check your internet connection.',
    'fetch failed': 'Network connection failed. Please try again.',
    'timeout': 'The request timed out. Please try again.',
    'permission denied': 'You do not have permission to perform this action.',
    'validation failed': 'Please check your input and try again.',
    'not found': 'The requested item could not be found.',
    'unauthorized': 'Please log in to continue.',
    'forbidden': 'Access denied. You do not have the required permissions.'
  };

  const lowerMessage = errorMessage.toLowerCase();
  for (const [key, message] of Object.entries(messageMap)) {
    if (lowerMessage.includes(key)) {
      return message;
    }
  }

  // Default fallback
  return 'An unexpected error occurred. Please try again.';
}

function getErrorPriority(code?: string): 'high' | 'normal' {
  const highPriorityCodes = [
    'UNAUTHORIZED',
    'FORBIDDEN', 
    'TOKEN_INVALID',
    'TENANT_INVALID',
    'SERVER_ERROR'
  ];
  
  return code && highPriorityCodes.includes(code) ? 'high' : 'normal';
}