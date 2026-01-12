export async function withRetry<T>(
  operation: () => Promise<T>,
  maxAttempts: number = 3,
  getDelay: (attempt: number, error?: Error) => number = (attempt) => Math.min(1000 * Math.pow(2, attempt - 1), 10000)
): Promise<T> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      // Don't retry on client errors (4xx) unless it's rate limiting
      if (lastError.cause === 'client_error' && lastError.cause !== 'rate_limit') {
        throw lastError;
      }

      // If this is the last attempt, throw the error
      if (attempt === maxAttempts) {
        throw lastError;
      }

      // Wait before retrying
      const delay = getDelay(attempt, lastError);
      await new Promise(resolve => setTimeout(resolve, delay));
      
      console.warn(`Retry attempt ${attempt}/${maxAttempts} after ${delay}ms delay:`, lastError.message);
    }
  }

  throw lastError!;
}

export function createExponentialBackoff(baseDelay: number = 1000, maxDelay: number = 10000) {
  return (attempt: number) => Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
}

export function createLinearBackoff(baseDelay: number = 1000, maxDelay: number = 10000) {
  return (attempt: number) => Math.min(baseDelay * attempt, maxDelay);
}