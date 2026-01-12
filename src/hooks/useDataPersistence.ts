import { useState, useEffect } from 'react';

export function useDataPersistence<T>(key: string, initialData: T) {
  const [data, setData] = useState<T>(() => {
    try {
      const saved = localStorage.getItem(key);
      return saved ? JSON.parse(saved) : initialData;
    } catch (error) {
      console.error(`Error loading data for ${key}:`, error);
      return initialData;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
      console.error(`Error saving data for ${key}:`, error);
    }
  }, [key, data]);

  return [data, setData] as const;
}

export function clearAllData() {
  const keys = [
    'firmflowz-clients',
    'firmflowz-projects',
    'firmflowz-timeentries',
    'firmflowz-notes',
    'firmflowz-employees',
    'firmflowz-expenses',
    'firmflowz-contractors',
    'firmflowz-contractortimeentries',
    'firmflowz-knowledgebase',
    'firmflowz-milestones',
    'firmflowz-compliance',
    'firmflowz-experiments',
    'firmflowz-autotimeentries',
    'firmflowz-aianalyses',
    'firmflowz-assessments',
    'firmflowz-tasks',
    'firmflowz-task-templates'
  ];
  
  keys.forEach(key => {
    try {
      localStorage.removeItem(key);
    } catch (error) {
      console.error(`Error clearing ${key}:`, error);
    }
  });
}