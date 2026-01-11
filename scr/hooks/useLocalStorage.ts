import { useState, useEffect } from 'react';

const STORAGE_VERSION = '1.0.0';

interface StorageData<T> {
  version: string;
  data: T;
  timestamp: number;
}

export function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      if (!item) return initialValue;
      
      const parsed = JSON.parse(item) as StorageData<T>;
      
      // Check version compatibility
      if (parsed.version !== STORAGE_VERSION) {
        console.warn(`Storage version mismatch for ${key}. Resetting to initial value.`);
        return initialValue;
      }
      
      return parsed.data;
    } catch (error) {
      console.error(`Error reading localStorage key "${key}":`, error);
      return initialValue;
    }
  });

  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      
      const storageData: StorageData<T> = {
        version: STORAGE_VERSION,
        data: valueToStore,
        timestamp: Date.now()
      };
      
      window.localStorage.setItem(key, JSON.stringify(storageData));
    } catch (error) {
      console.error(`Error setting localStorage key "${key}":`, error);
    }
  };

  // Listen for storage events to sync across tabs
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === key && e.newValue) {
        try {
          const parsed = JSON.parse(e.newValue) as StorageData<T>;
          if (parsed.version === STORAGE_VERSION) {
            setStoredValue(parsed.data);
          }
        } catch (error) {
          console.error(`Error syncing storage for ${key}:`, error);
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [key]);

  return [storedValue, setValue] as const;
}