// Performance monitoring utilities

export interface PerformanceMetric {
  name: string;
  duration: number;
  timestamp: number;
  metadata?: Record<string, any>;
}

class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private maxMetrics = 100;
  private enabled: boolean;

  constructor() {
    // Enable performance monitoring based on environment
    this.enabled = import.meta.env.DEV || 
                  (import.meta.env.PROD && import.meta.env.VITE_ENABLE_PERF === 'true');
  }

  startTiming(name: string): () => void {
    if (!this.enabled) return () => {}; // No-op if disabled
    
    const startTime = performance.now();
    
    return () => {
      if (!this.enabled) return;
      
      const duration = performance.now() - startTime;
      this.recordMetric({
        name,
        duration,
        timestamp: Date.now()
      });
    };
  }

  recordMetric(metric: PerformanceMetric): void {
    if (!this.enabled) return;
    
    this.metrics.push(metric);
    
    // Keep only recent metrics
    if (this.metrics.length > this.maxMetrics) {
      this.metrics = this.metrics.slice(-this.maxMetrics);
    }

    // Log slow operations in development
    if (import.meta.env.DEV && metric.duration > 1000) {
      console.warn(`🐌 Slow operation: ${metric.name} took ${metric.duration.toFixed(2)}ms`);
    }
  }

  getMetrics(name?: string): PerformanceMetric[] {
    return name 
      ? this.metrics.filter(m => m.name === name)
      : this.metrics;
  }

  getAverageTime(name: string): number {
    const nameMetrics = this.getMetrics(name);
    if (nameMetrics.length === 0) return 0;
    
    const total = nameMetrics.reduce((sum, metric) => sum + metric.duration, 0);
    return total / nameMetrics.length;
  }

  clearMetrics(): void {
    this.metrics = [];
  }

  isEnabled(): boolean {
    return this.enabled;
  }
}

export const performanceMonitor = new PerformanceMonitor();

// React hook for component performance monitoring
export function usePerformanceMonitor(componentName: string) {
  const startTiming = (operationName: string) => {
    return performanceMonitor.startTiming(`${componentName}.${operationName}`);
  };

  return { 
    startTiming,
    isEnabled: performanceMonitor.isEnabled()
  };
}

// Decorator for timing async functions
export function withTiming<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  name: string
): T {
  return (async (...args: any[]) => {
    const endTiming = performanceMonitor.startTiming(name);
    try {
      const result = await fn(...args);
      return result;
    } finally {
      endTiming();
    }
  }) as T;
}

// Performance utilities for React components
export function measureRender(componentName: string) {
  if (!performanceMonitor.isEnabled()) return;
  
  const startTime = performance.now();
  
  // Use requestIdleCallback to measure after render
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => {
      const duration = performance.now() - startTime;
      performanceMonitor.recordMetric({
        name: `${componentName}.render`,
        duration,
        timestamp: Date.now()
      });
    });
  }
}