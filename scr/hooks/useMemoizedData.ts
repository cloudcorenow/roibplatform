import { useMemo } from 'react';
import { TimeEntry, Project, TechnicalNote, Expense } from '../types';

export function useMemoizedClientData(
  timeEntries: TimeEntry[],
  projects: Project[],
  technicalNotes: TechnicalNote[],
  expenses: Expense[],
  selectedClientId: string | null
) {
  return useMemo(() => {
    if (!selectedClientId) {
      return {
        clientTimeEntries: [],
        clientProjects: [],
        clientNotes: [],
        clientExpenses: []
      };
    }

    return {
      clientTimeEntries: timeEntries.filter(entry => entry.clientId === selectedClientId),
      clientProjects: projects.filter(project => project.clientId === selectedClientId),
      clientNotes: technicalNotes.filter(note => note.clientId === selectedClientId),
      clientExpenses: expenses.filter(expense => expense.clientId === selectedClientId)
    };
  }, [timeEntries, projects, technicalNotes, expenses, selectedClientId]);
}

export function useMemoizedStats(timeEntries: TimeEntry[], projects: Project[]) {
  return useMemo(() => {
    const totalHours = timeEntries.reduce((total, entry) => total + entry.duration, 0);
    const rndHours = timeEntries.filter(entry => entry.isRnD).reduce((total, entry) => total + entry.duration, 0);
    const activeProjects = projects.filter(project => project.status === 'active').length;
    const rndProjects = projects.filter(project => project.isRnD).length;

    return {
      totalHours,
      rndHours,
      activeProjects,
      rndProjects,
      rndPercentage: totalHours > 0 ? Math.round((rndHours / totalHours) * 100) : 0
    };
  }, [timeEntries, projects]);
}

export function useMemoizedProjectProgress(projects: Project[], timeEntries: TimeEntry[]) {
  return useMemo(() => {
    return projects.map(project => {
      const projectTimeEntries = timeEntries.filter(entry => entry.projectId === project.id);
      const actualHours = projectTimeEntries.reduce((total, entry) => total + entry.duration, 0);
      
      return {
        ...project,
        actualHours,
        efficiency: project.totalHours > 0 ? (actualHours / project.totalHours) * 100 : 0
      };
    });
  }, [projects, timeEntries]);
}