export interface Task {
  id: string;
  tenantId: string;
  title: string;
  description: string;
  status: 'todo' | 'in-progress' | 'review' | 'completed' | 'cancelled';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  category: 'research' | 'development' | 'testing' | 'documentation' | 'analysis' | 'experiment' | 'other';
  
  // Relationships
  projectId?: string;
  projectName?: string;
  parentTaskId?: string;
  dependsOn: string[]; // Task IDs this task depends on
  subtasks: string[]; // Child task IDs
  
  // Assignment
  assignedTo: string[]; // Employee IDs
  assignedNames: string[]; // Employee names for display
  createdBy: string;
  createdByName: string;
  
  // R&D Classification
  isRnD: boolean;
  technicalUncertainty?: string;
  experimentationRequired: boolean;
  rndJustification?: string;
  
  // Time & Progress
  estimatedHours: number;
  actualHours: number;
  progress: number; // 0-100
  
  // Dates
  startDate?: string;
  dueDate?: string;
  completedDate?: string;
  createdAt: string;
  updatedAt: string;
  
  // Metadata
  tags: string[];
  attachments: string[];
  comments: TaskComment[];
  
  // Templates
  templateId?: string;
  isTemplate: boolean;
}

export interface TaskComment {
  id: string;
  taskId: string;
  author: string;
  authorName: string;
  content: string;
  timestamp: string;
  isInternal: boolean;
}

export interface TaskTemplate {
  id: string;
  name: string;
  description: string;
  category: Task['category'];
  estimatedHours: number;
  isRnD: boolean;
  tags: string[];
  subtaskTemplates: {
    title: string;
    description: string;
    estimatedHours: number;
    order: number;
  }[];
  checklist: {
    item: string;
    required: boolean;
  }[];
}

export interface TaskFilter {
  status?: Task['status'][];
  priority?: Task['priority'][];
  category?: Task['category'][];
  assignedTo?: string[];
  projectId?: string;
  isRnD?: boolean;
  dueDateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
}

export interface TaskStats {
  total: number;
  byStatus: Record<Task['status'], number>;
  byPriority: Record<Task['priority'], number>;
  overdue: number;
  completedThisWeek: number;
  totalEstimatedHours: number;
  totalActualHours: number;
  rndTasks: number;
}