import React, { useState } from 'react';
import { AuthProvider } from './components/AuthProvider';
import { LoginPage } from './components/LoginPage';
import { UserProfile } from './components/UserProfile';
import { MobileNav } from './components/MobileNav';
import { useAuth } from './hooks/useAuth';
import { useNotifications } from './hooks/useNotifications';
import { generateTaskNotifications, checkOverdueTasks } from './utils/taskNotifications';
import { 
  Building2, 
  Timer, 
  Receipt, 
  FolderOpen, 
  BookOpen, 
  TestTube, 
  UserCheck, 
  Database, 
  CalendarDays, 
  TrendingUp, 
  ShieldCheck, 
  FileBarChart, 
  Zap, 
  Brain, 
  Eye, 
  Target, 
  Workflow,
  Users,
  Shield,
  Calculator
} from 'lucide-react';
import { UserManagement } from './components/UserManagement';
import { RoleManagement } from './components/RoleManagement';
import { ProfileSettings } from './components/ProfileSettings';
import { NotificationsPage } from './components/NotificationsPage';
import { AccountSettings } from './components/AccountSettings';
import { TaskManagement } from './components/TaskManagement';
import { TimeTracker } from './components/TimeTracker';
import { TechnicalNotes } from './components/TechnicalNotes';
import { ClientsPage } from './features/clients/ClientsPage';
import TimeEntriesPage from './features/time/TimeEntriesPage';
import { ContractorManagement } from './components/ContractorManagement';
import { KnowledgeBase } from './components/KnowledgeBase';
import { Calendar as CalendarComponent } from './components/Calendar';
import { ComplianceWizard } from './components/ComplianceWizard';
import { CPAPortal } from './components/CPAPortal';
import { ExperimentTracker } from './components/ExperimentTracker';
import { IRSAuditReports } from './components/IRSAuditReports';
import { AutoTimeIntegration } from './components/AutoTimeIntegration';
import { AIRnDAnalyzer } from './components/AIRnDAnalyzer';
import { AnalyticsDashboard } from './components/AnalyticsDashboard';
import { CentralReachIntegration } from './components/CentralReachIntegration';
import { IntegrationsHub } from './components/IntegrationsHub';
import { ExpenseTracker } from './components/ExpenseTracker';
import { DocumentManager } from './components/DocumentManager';
import { NewAssessmentWizard } from './components/NewAssessmentWizard';
import { TaxPlanningHub } from './components/TaxPlanningHub';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ToastContainer, useToast } from './components/Toast';
import { useDataPersistence } from './hooks/useDataPersistence';
import { generateId } from './utils/formatters';
import {
  mockClients,
  mockProjects,
  mockTimeEntries,
  mockTechnicalNotes,
  mockEmployees,
  mockExpenses,
  mockDocuments,
  mockContractors,
  mockContractorTimeEntries,
  mockKnowledgeBaseEntries,
  mockMilestones,
  mockClientCompliance,
  mockExperiments,
  mockAutoTimeEntries,
  mockRnDAIAnalyses,
} from './data/mockData';
import { mockTasks } from './data/mockTasks';
import {
  mockUsers,
  mockRoles,
  mockPermissions,
  mockUserInvitations
} from './data/mockUsers';
import type {
  Client,
  TimeEntry,
  Project,
  TechnicalNote,
  ChangeLogEntry,
  Contractor,
  ContractorTimeEntry,
  KnowledgeBaseEntry,
  Milestone,
  ClientCompliance,
  Employee,
  Expense,
  Document,
  Experiment,
  AutoTimeEntry,
  RnDAIAnalysis,
  User,
  Role,
  Permission,
  UserInvitation,
  Task
} from './types';

type ActiveView = 
  | 'clients' 
  | 'time-tracker' 
  | 'technical-notes' 
  | 'contractors' 
  | 'knowledge-base' 
  | 'calendar' 
  | 'compliance' 
  | 'cpa-portal'
  | 'experiments'
  | 'audit-reports'
  | 'auto-time'
  | 'ai-analyzer'
  | 'analytics'
  | 'expenses'
  | 'assessment'
  | 'integrations'
  | 'users'
  | 'roles'
  | 'tax-planning';

function AppContent() {
  const { user, isAuthenticated, isLoading, login, register, error } = useAuth();
  const { toasts, removeToast, showSuccess, showError, showWarning, showInfo } = useToast();
  const { 
    notifications, 
    unreadCount, 
    addNotification, 
    markAsRead, 
    markAllAsRead, 
    deleteNotification, 
    clearAllNotifications 
  } = useNotifications(user?.id || '', { showSuccess, showInfo, showWarning, showError });
  const [activeView, setActiveView] = useState<ActiveView>('clients');
  const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
  const [showProfileSettings, setShowProfileSettings] = useState(false);
  const [showNotificationsPage, setShowNotificationsPage] = useState(false);
  const [showAccountSettings, setShowAccountSettings] = useState(false);
  
  // Data persistence hooks
  const [clients, setClients] = useDataPersistence('roiblueprint-clients', mockClients);
  const [projects, setProjects] = useDataPersistence('roiblueprint-projects', mockProjects);
  const [timeEntries, setTimeEntries] = useDataPersistence('roiblueprint-timeentries', mockTimeEntries);
  const [technicalNotes, setTechnicalNotes] = useDataPersistence('roiblueprint-notes', mockTechnicalNotes);
  const [employees] = useDataPersistence('roiblueprint-employees', mockEmployees);
  const [expenses, setExpenses] = useDataPersistence('roiblueprint-expenses', mockExpenses);
  const [contractors] = useDataPersistence('roiblueprint-contractors', mockContractors);
  const [contractorTimeEntries, setContractorTimeEntries] = useDataPersistence('roiblueprint-contractortimeentries', mockContractorTimeEntries);
  const [knowledgeBaseEntries, setKnowledgeBaseEntries] = useDataPersistence('roiblueprint-knowledgebase', mockKnowledgeBaseEntries);
  const [milestones, setMilestones] = useDataPersistence('roiblueprint-milestones', mockMilestones);
  const [clientCompliance, setClientCompliance] = useDataPersistence('roiblueprint-compliance', mockClientCompliance);
  const [experiments, setExperiments] = useDataPersistence('roiblueprint-experiments', mockExperiments);
  const [autoTimeEntries, setAutoTimeEntries] = useDataPersistence('roiblueprint-autotimeentries', mockAutoTimeEntries);
  const [aiAnalyses, setAiAnalyses] = useDataPersistence('roiblueprint-aianalyses', mockRnDAIAnalyses);
  const [documents, setDocuments] = useDataPersistence('roiblueprint-documents', mockDocuments);
  const [assessmentData, setAssessmentData] = useDataPersistence('roiblueprint-assessments', {});
  const [users, setUsers] = useDataPersistence('roiblueprint-users', mockUsers);
  const [roles, setRoles] = useDataPersistence('roiblueprint-roles', mockRoles);
  const [userInvitations, setUserInvitations] = useDataPersistence('roiblueprint-invitations', mockUserInvitations);
  const [tasks, setTasks] = useDataPersistence<Task[]>('roiblueprint-tasks', mockTasks);
  const [taskTemplates] = useDataPersistence('roiblueprint-task-templates', []);
  
  // Track which tasks have already triggered overdue notifications
  const [notifiedOverdueTasks, setNotifiedOverdueTasks] = useState<Set<string>>(new Set());
  
  // Check for overdue tasks periodically
  React.useEffect(() => {
    const checkOverdue = () => {
      const overdueNotifications = checkOverdueTasks(tasks);
      overdueNotifications.forEach(notificationData => {
        // Only send notification if we haven't already notified for this task
        if (!notifiedOverdueTasks.has(notificationData.taskId)) {
          setNotifiedOverdueTasks(prev => new Set([...prev, notificationData.taskId]));
        const notifications = generateTaskNotifications(notificationData, user?.id || '');
        notifications.forEach(notification => {
          addNotification(notification);
        });
        }
      });
    };

    // Initial check
    checkOverdue();
    
    // Check for overdue tasks every hour
    const interval = setInterval(checkOverdue, 60 * 60 * 1000);
    
    return () => clearInterval(interval);
  }, [tasks, user?.id, addNotification, notifiedOverdueTasks]);

  // Show loading screen while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-cyan-50 to-teal-50 flex items-center justify-center">
        <div className="text-center">
          <div className="w-20 h-20 mx-auto mb-4">
            <img src="/Favicon (1) copy.png" alt="ROI BLUEPRINT Logo" className="w-full h-full object-contain" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">ROI BLUEPRINT</h1>
          <p className="text-gray-600 mb-4">R&D Tax Credit Platform</p>
          <div className="flex items-center justify-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
            <span className="text-gray-600">Initializing application...</span>
          </div>
        </div>
      </div>
    );
  }

  // Show login page if not authenticated
  if (!isAuthenticated) {
    return <LoginPage onLogin={login} onRegister={register} isLoading={isLoading} error={error} />;
  }

  // Event handlers
  const handleAddClient = (client: Omit<Client, 'id'>) => {
    const newClient: Client = { ...client, id: generateId() };
    setClients(prev => [...prev, newClient]);
    showSuccess('Client added successfully');
  };

  const handleAddProject = (project: Omit<Project, 'id'>) => {
    const newProject: Project = { ...project, id: generateId() };
    setProjects(prev => [...prev, newProject]);
    showSuccess('Project added successfully');
  };

  const handleAddTimeEntry = (entry: Omit<TimeEntry, 'id'>) => {
    const newEntry: TimeEntry = { ...entry, id: generateId() };
    setTimeEntries(prev => [...prev, newEntry]);
    showSuccess('Time entry added successfully');
  };

  const handleUpdateTimeEntry = (id: string, updates: Partial<TimeEntry>) => {
    setTimeEntries(prev => prev.map(entry => 
      entry.id === id ? { ...entry, ...updates } : entry
    ));
    showSuccess('Time entry updated');
  };

  const handleAddTechnicalNote = (note: Omit<TechnicalNote, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newNote: TechnicalNote = {
      ...note,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 1,
      changeLog: []
    };
    setTechnicalNotes(prev => [...prev, newNote]);
    showSuccess('Technical note created successfully');
  };

  const handleUpdateTechnicalNote = (id: string, updates: Partial<TechnicalNote>) => {
    setTechnicalNotes(prev => prev.map(note => 
      note.id === id ? { ...note, ...updates, updatedAt: new Date().toISOString() } : note
    ));
    showSuccess('Technical note updated');
  };

  const handleAddChangeLog = (noteId: string, entry: Omit<ChangeLogEntry, 'id' | 'timestamp'>) => {
    const newEntry: ChangeLogEntry = {
      ...entry,
      id: generateId(),
      timestamp: new Date().toISOString()
    };
    
    setTechnicalNotes(prev => prev.map(note => 
      note.id === noteId ? {
        ...note,
        changeLog: [...note.changeLog, newEntry],
        version: note.version + 1,
        updatedAt: new Date().toISOString()
      } : note
    ));
    showSuccess('Change log entry added');
  };

  const handleAddContractorTime = (entry: Omit<ContractorTimeEntry, 'id'>) => {
    const newEntry: ContractorTimeEntry = { ...entry, id: generateId() };
    setContractorTimeEntries(prev => [...prev, newEntry]);
    showSuccess('Contractor time logged successfully');
  };

  const handleAddKnowledgeBaseEntry = (entry: Omit<KnowledgeBaseEntry, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newEntry: KnowledgeBaseEntry = {
      ...entry,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    setKnowledgeBaseEntries(prev => [...prev, newEntry]);
    showSuccess('Knowledge base entry created successfully');
  };

  const handleUpdateKnowledgeBaseEntry = (id: string, updates: Partial<KnowledgeBaseEntry>) => {
    setKnowledgeBaseEntries(prev => prev.map(entry => 
      entry.id === id ? { ...entry, ...updates, updatedAt: new Date().toISOString() } : entry
    ));
    showSuccess('Knowledge base entry updated');
  };

  const handleAddMilestone = (milestone: Omit<Milestone, 'id'>) => {
    const newMilestone: Milestone = { ...milestone, id: generateId() };
    setMilestones(prev => [...prev, newMilestone]);
    showSuccess('Milestone added successfully');
  };

  const handleUpdateMilestone = (id: string, updates: Partial<Milestone>) => {
    setMilestones(prev => prev.map(milestone => 
      milestone.id === id ? { ...milestone, ...updates } : milestone
    ));
    showSuccess('Milestone updated');
  };

  const handleUpdateCompliance = (clientId: string, completedItems: string[]) => {
    setClientCompliance(prev => prev.map(compliance => 
      compliance.clientId === clientId ? {
        ...compliance,
        completedItems,
        lastUpdated: new Date().toISOString(),
        overallScore: Math.round((completedItems.length / 10) * 100)
      } : compliance
    ));
    showSuccess('Compliance status updated');
  };

  const handleAddExperiment = (experiment: Omit<Experiment, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newExperiment: Experiment = {
      ...experiment,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    setExperiments(prev => [...prev, newExperiment]);
    showSuccess('Experiment created successfully');
  };

  const handleUpdateExperiment = (id: string, updates: Partial<Experiment>) => {
    setExperiments(prev => prev.map(experiment => 
      experiment.id === id ? { ...experiment, ...updates, updatedAt: new Date().toISOString() } : experiment
    ));
    showSuccess('Experiment updated');
  };

  const handleApproveAutoTimeEntry = (entryId: string) => {
    setAutoTimeEntries(prev => prev.map(entry => 
      entry.id === entryId ? { 
        ...entry, 
        metadata: { ...entry.metadata, approved: true, rejected: false }
      } : entry
    ));
    showSuccess('Time entry approved');
  };

  const handleRejectAutoTimeEntry = (entryId: string) => {
    setAutoTimeEntries(prev => prev.map(entry => 
      entry.id === entryId ? { 
        ...entry, 
        metadata: { ...entry.metadata, approved: false, rejected: true }
      } : entry
    ));
    showSuccess('Time entry rejected');
  };

  const handleUpdateAutoTimeEntry = (entryId: string, updates: Partial<AutoTimeEntry>) => {
    setAutoTimeEntries(prev => prev.map(entry => 
      entry.id === entryId ? { ...entry, ...updates } : entry
    ));
    showSuccess('Time entry updated');
  };

  const handleAnalyzeTask = (taskDescription: string) => {
    // This would normally call an AI service
    showSuccess('Task analyzed successfully');
  };

  const handleAddExpense = (expense: Omit<Expense, 'id'>) => {
    console.log('handleAddExpense called with:', expense);
    const newExpense: Expense = { 
      ...expense, 
      id: generateId(),
      clientId: selectedClientId || '1' // Use selected client or default
    };
    console.log('Creating new expense:', newExpense);
    setExpenses(prev => {
      const updated = [...prev, newExpense];
      console.log('Updated expenses array:', updated);
      return updated;
    });
    showSuccess('Expense added successfully');
  };

  const handleUpdateExpense = (id: string, updates: Partial<Expense>) => {
    console.log('handleUpdateExpense called:', id, updates);
    setExpenses(prev => prev.map(expense => 
      expense.id === id ? { ...expense, ...updates } : expense
    ));
    showSuccess('Expense updated');
  };

  const handleDeleteExpense = (id: string) => {
    console.log('handleDeleteExpense called:', id);
    setExpenses(prev => prev.filter(expense => expense.id !== id));
    showSuccess('Expense deleted');
  };

  const handleAddDocument = (document: Omit<Document, 'id' | 'uploadedAt'>) => {
    console.log('handleAddDocument called with:', document);
    const newDocument: Document = { 
      ...document, 
      id: generateId(),
      clientId: selectedClientId || '1',
      uploadedAt: new Date().toISOString()
    };
    console.log('Creating new document:', newDocument);
    setDocuments(prev => {
      const updated = [...prev, newDocument];
      console.log('Updated documents array:', updated);
      return updated;
    });
    showSuccess('Document uploaded successfully');
  };

  const handleDeleteDocument = (id: string) => {
    console.log('handleDeleteDocument called:', id);
    setDocuments(prev => prev.filter(document => document.id !== id));
    showSuccess('Document deleted');
  };

  const handleUpdateDocument = (id: string, updates: Partial<Document>) => {
    console.log('handleUpdateDocument called:', id, updates);
    setDocuments(prev => prev.map(document => 
      document.id === id ? { ...document, ...updates } : document
    ));
    showSuccess('Document updated');
  };

  const handleUpdateAssessment = (clientId: string, answers: Record<string, any>, score: number) => {
    setAssessmentData(prev => ({
      ...prev,
      [clientId]: {
        answers,
        score,
        lastUpdated: new Date().toISOString()
      }
    }));
  };

  const handleAddUser = (userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newUser: User = {
      ...userData,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    setUsers(prev => [...prev, newUser]);
    showSuccess('User added successfully');
  };

  const handleUpdateUser = (id: string, updates: Partial<User>) => {
    setUsers(prev => prev.map(user => 
      user.id === id ? { ...user, ...updates } : user
    ));
    showSuccess('User updated successfully');
  };

  const handleDeleteUser = (id: string) => {
    setUsers(prev => prev.filter(user => user.id !== id));
    showSuccess('User removed successfully');
  };

  const handleAddRole = (roleData: Omit<Role, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newRole: Role = {
      ...roleData,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    setRoles(prev => [...prev, newRole]);
    showSuccess('Role created successfully');
  };

  const handleUpdateRole = (id: string, updates: Partial<Role>) => {
    setRoles(prev => prev.map(role => 
      role.id === id ? { ...role, ...updates } : role
    ));
    showSuccess('Role updated successfully');
  };

  const handleDeleteRole = (id: string) => {
    setRoles(prev => prev.filter(role => role.id !== id));
    showSuccess('Role deleted successfully');
  };

  const handleUpdateProfile = (updates: Partial<UserType>) => {
    // In a real app, this would call an API to update the user profile
    showSuccess('Profile updated successfully');
    setShowProfileSettings(false);
  };

  const handleUpdateAccountSettings = (settings: any) => {
    // In a real app, this would call an API to update account settings
    showSuccess('Account settings updated successfully');
  };

  const handleInviteUser = (invitationData: Omit<UserInvitation, 'id' | 'invitedAt' | 'token'>) => {
    const newInvitation: UserInvitation = {
      ...invitationData,
      id: generateId(),
      invitedAt: new Date().toISOString(),
      token: `inv_${generateId()}`
    };
    setUserInvitations(prev => [...prev, newInvitation]);
    showSuccess('Invitation sent successfully');
  };

  const handleCancelInvitation = (id: string) => {
    setUserInvitations(prev => prev.map(invitation => 
      invitation.id === id ? { ...invitation, status: 'cancelled' as const } : invitation
    ));
    showSuccess('Invitation cancelled');
  };

  const handleResendInvitation = (id: string) => {
    setUserInvitations(prev => prev.map(invitation => 
      invitation.id === id ? { 
        ...invitation, 
        invitedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        token: `inv_${generateId()}`
      } : invitation
    ));
    showSuccess('Invitation resent successfully');
  };

  const handleAddTask = (taskData: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newTask: Task = {
      ...taskData,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    setTasks(prev => [...prev, newTask]);
    showSuccess('Task created successfully');
    
    // Send notifications to assigned users
    taskData.assignedTo.forEach((userId, index) => {
      const assigneeName = taskData.assignedNames[index];
      addNotification({
        type: 'task_assigned',
        title: 'New Task Assigned',
        message: `You have been assigned to "${taskData.title}"`,
        priority: taskData.priority === 'urgent' ? 'high' : taskData.priority === 'high' ? 'medium' : 'low',
        userId,
        relatedId: newTask.id
      });
    });
  };

  const handleUpdateTask = (id: string, updates: Partial<Task>) => {
    const task = tasks.find(t => t.id === id);
    if (!task) return;
    
    setTasks(prev => prev.map(task => 
      task.id === id ? { ...task, ...updates, updatedAt: new Date().toISOString() } : task
    ));
    showSuccess('Task updated successfully');
    
    // Generate appropriate notifications based on what was updated
    let notificationType: 'task_updated' | 'task_completed' | 'task_assigned' = 'task_updated';
    
    if (updates.status === 'completed' && task.status !== 'completed') {
      notificationType = 'task_completed';
    } else if (updates.assignedTo && updates.assignedTo.length > 0) {
      notificationType = 'task_assigned';
    }
    
    const notifications = generateTaskNotifications({
      type: notificationType,
      taskId: id,
      taskTitle: task.title,
      projectName: task.projectName,
      assignedUsers: updates.assignedTo || task.assignedTo,
      createdBy: task.createdBy,
      priority: task.priority,
      dueDate: task.dueDate
    }, user?.id || '');
    
    notifications.forEach(notification => {
      addNotification(notification);
    });
  };

  const handleDeleteTask = (id: string) => {
    setTasks(prev => prev.filter(task => task.id !== id));
    showSuccess('Task deleted successfully');
  };

  const handleAddTaskComment = (taskId: string, comment: string) => {
    const task = tasks.find(t => t.id === taskId);
    if (!task) return;
    
    const newComment = {
      id: generateId(),
      taskId,
      author: user?.id || '1',
      authorName: user ? `${user.firstName} ${user.lastName}` : 'Current User',
      content: comment,
      timestamp: new Date().toISOString(),
      isInternal: false
    };
    
    setTasks(prev => prev.map(task => 
      task.id === taskId ? {
        ...task,
        comments: [...task.comments, newComment],
        updatedAt: new Date().toISOString()
      } : task
    ));
    showSuccess('Comment added successfully');
    
    // Notify task assignees and creator about new comment
    const notifyUsers = [task.createdBy, ...task.assignedTo].filter(userId => userId !== user?.id);
    notifyUsers.forEach(userId => {
      addNotification({
        type: 'comment_added',
        title: 'New Comment',
        message: `${user?.firstName || 'Someone'} commented on "${task.title}"`,
        priority: 'low',
        userId,
        relatedId: taskId
      });
    });
  };

  const handleCreateFromTemplate = (templateId: string, projectId: string, assignedTo: string[]) => {
    // This would create tasks from a template - simplified for now
    const project = projects.find(p => p.id === projectId);
    const assignedEmployees = employees.filter(emp => assignedTo.includes(emp.id));
    
    const newTask: Task = {
      id: generateId(),
      tenantId: 'demo-tenant',
      title: `Task from Template ${templateId}`,
      description: 'Task created from template',
      status: 'todo',
      priority: 'medium',
      category: 'development',
      projectId,
      projectName: project?.name,
      parentTaskId: undefined,
      dependsOn: [],
      subtasks: [],
      assignedTo,
      assignedNames: assignedEmployees.map(emp => emp.name),
      createdBy: user?.id || '1',
      createdByName: user ? `${user.firstName} ${user.lastName}` : 'Current User',
      isRnD: true,
      technicalUncertainty: '',
      experimentationRequired: false,
      rndJustification: '',
      estimatedHours: 8,
      actualHours: 0,
      progress: 0,
      startDate: new Date().toISOString().split('T')[0],
      dueDate: '',
      completedDate: undefined,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      tags: [],
      attachments: [],
      comments: [],
      templateId,
      isTemplate: false
    };
    
    setTasks(prev => [...prev, newTask]);
    showSuccess('Task created from template');
  };

  // Navigation items
  const navigationItems = [
    { id: 'clients', label: 'Clients', icon: Building2 },
    { id: 'time-tracker', label: 'Time Tracking', icon: Timer },
    { id: 'tasks', label: 'Tasks', icon: Target },
    { id: 'expenses', label: 'Expenses', icon: Receipt },
    { id: 'documents', label: 'VaultDocs', icon: FolderOpen },
    { id: 'technical-notes', label: 'Documentation', icon: BookOpen },
    { id: 'experiments', label: 'Experiments', icon: TestTube },
    { id: 'contractors', label: 'Contractors', icon: UserCheck },
    { id: 'knowledge-base', label: 'Knowledge Base', icon: Database },
    { id: 'calendar', label: 'Calendar', icon: CalendarDays },
    { id: 'analytics', label: 'Analytics', icon: TrendingUp },
    { id: 'compliance', label: 'Compliance', icon: ShieldCheck },
    { id: 'audit-reports', label: 'Audit Reports', icon: FileBarChart },
    { id: 'auto-time', label: 'Auto Time', icon: Zap },
    { id: 'ai-analyzer', label: 'AI Analyzer', icon: Brain },
    { id: 'cpa-portal', label: 'CPA Portal', icon: Eye },
    { id: 'assessment', label: 'Assessment Wizard', icon: Target },
    { id: 'integrations', label: 'Integrations', icon: Workflow },
    { id: 'users', label: 'Users', icon: Users },
    { id: 'roles', label: 'Roles', icon: Shield },
    { id: 'tax-planning', label: 'Tax Planning', icon: Calculator }
  ];

  const selectedClient = clients.find(c => c.id === selectedClientId);
  const selectedCompliance = clientCompliance.find(c => c.clientId === selectedClientId);

  const renderActiveView = () => {
    switch (activeView) {
      case 'clients':
        return (
          <ClientsPage
            selectedClientId={selectedClientId}
            onSelectClient={setSelectedClientId}
          />
        );
      case 'time-tracker':
        return (
          <TimeTracker
            timeEntries={timeEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            employees={employees.filter(e => e.clientId === selectedClientId)}
            tasks={tasks.filter(t => !selectedClientId || projects.find(p => p.id === t.projectId)?.clientId === selectedClientId)}
            onAddTimeEntry={handleAddTimeEntry}
            onUpdateTimeEntry={handleUpdateTimeEntry}
          />
        );
      case 'tasks':
        return (
          <TaskManagement
            tasks={tasks.filter(t => !selectedClientId || projects.find(p => p.id === t.projectId)?.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            employees={employees.filter(e => e.clientId === selectedClientId)}
            templates={taskTemplates}
            onAddTask={handleAddTask}
            onUpdateTask={handleUpdateTask}
            onDeleteTask={handleDeleteTask}
            onAddComment={handleAddTaskComment}
            onCreateFromTemplate={handleCreateFromTemplate}
          />
        );
      case 'expenses':
        return (
          <ExpenseTracker
            expenses={expenses.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddExpense={handleAddExpense}
            onUpdateExpense={handleUpdateExpense}
            onDeleteExpense={handleDeleteExpense}
          />
        );
      case 'documents':
        return (
          <DocumentManager
            documents={documents.filter(d => d.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddDocument={handleAddDocument}
            onDeleteDocument={handleDeleteDocument}
            onUpdateDocument={handleUpdateDocument}
          />
        );
      case 'technical-notes':
        return (
          <TechnicalNotes
            notes={technicalNotes.filter(n => n.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddNote={handleAddTechnicalNote}
            onUpdateNote={handleUpdateTechnicalNote}
          />
        );
      case 'experiments':
        return (
          <ExperimentTracker
            experiments={experiments.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddExperiment={handleAddExperiment}
            onUpdateExperiment={handleUpdateExperiment}
          />
        );
      case 'contractors':
        return (
          <ContractorManagement
            contractors={contractors.filter(c => c.clientId === selectedClientId)}
            contractorTimeEntries={contractorTimeEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddContractor={() => {}}
            onUpdateContractor={() => {}}
            onAddContractorTime={handleAddContractorTime}
          />
        );
      case 'knowledge-base':
        return (
          <KnowledgeBase
            entries={knowledgeBaseEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddEntry={handleAddKnowledgeBaseEntry}
            onUpdateEntry={handleUpdateKnowledgeBaseEntry}
          />
        );
      case 'calendar':
        return (
          <CalendarComponent
            milestones={milestones.filter(m => m.clientId === selectedClientId)}
            timeEntries={timeEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onAddMilestone={handleAddMilestone}
            onUpdateMilestone={handleUpdateMilestone}
          />
        );
      case 'analytics':
        return (
          <AnalyticsDashboard
            timeEntries={timeEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            expenses={expenses.filter(e => e.clientId === selectedClientId)}
            employees={employees.filter(e => e.clientId === selectedClientId)}
          />
        );
      case 'compliance':
        return selectedCompliance ? (
          <ComplianceWizard
            clientCompliance={selectedCompliance}
            onUpdateCompliance={handleUpdateCompliance}
          />
        ) : (
          <div className="text-center py-8">
            <p className="text-gray-500">Select a client to view compliance status</p>
          </div>
        );
      case 'assessment':
        return selectedClientId ? (
          <NewAssessmentWizard
            clientId={selectedClientId}
            onUpdateAssessment={handleUpdateAssessment}
            answers={assessmentData[selectedClientId]?.answers || {}}
            showSuccess={showSuccess}
          />
        ) : (
          <div className="text-center py-8">
            <p className="text-gray-500">Select a client to begin R&D assessment</p>
          </div>
        );
      case 'audit-reports':
        return (
          <IRSAuditReports
            clients={clients}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            timeEntries={timeEntries.filter(e => e.clientId === selectedClientId)}
            employees={employees.filter(e => e.clientId === selectedClientId)}
            expenses={expenses.filter(e => e.clientId === selectedClientId)}
            contractorTimeEntries={contractorTimeEntries.filter(e => e.clientId === selectedClientId)}
            selectedClientId={selectedClientId}
          />
        );
      case 'auto-time':
        return (
          <AutoTimeIntegration
            autoTimeEntries={autoTimeEntries.filter(e => e.clientId === selectedClientId)}
            projects={projects.filter(p => p.clientId === selectedClientId)}
            onApproveEntry={handleApproveAutoTimeEntry}
            onRejectEntry={handleRejectAutoTimeEntry}
            onUpdateEntry={handleUpdateAutoTimeEntry}
          />
        );
      case 'ai-analyzer':
        return (
          <AIRnDAnalyzer
            analyses={aiAnalyses}
            onAnalyzeTask={handleAnalyzeTask}
          />
        );
      case 'cpa-portal':
        return (
          <CPAPortal
            clients={clients}
            projects={projects}
            timeEntries={timeEntries}
            technicalNotes={technicalNotes}
            expenses={expenses}
            selectedClientId={selectedClientId}
          />
        );
      case 'integrations':
        return (
          <IntegrationsHub
            onSyncComplete={(result) => {
              if (result.success) {
                showSuccess(`Sync completed: ${result.syncedRecords} records synced`);
              } else {
                showError(`Sync failed: ${result.message}`);
              }
            }}
          />
        );
      case 'users':
        return (
          <UserManagement
            users={users}
            roles={roles}
            invitations={userInvitations}
            onAddUser={handleAddUser}
            onUpdateUser={handleUpdateUser}
            onDeleteUser={handleDeleteUser}
            onInviteUser={handleInviteUser}
            onCancelInvitation={handleCancelInvitation}
            onResendInvitation={handleResendInvitation}
          />
        );
      case 'roles':
        return (
          <RoleManagement
            roles={roles}
            permissions={mockPermissions}
            users={users}
            onAddRole={handleAddRole}
            onUpdateRole={handleUpdateRole}
            onDeleteRole={handleDeleteRole}
          />
        );
      case 'tax-planning':
        return (
          <TaxPlanningHub
            clientId={selectedClientId}
          />
        );
      default:
        return <div>Select a view from the sidebar</div>;
    }
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-cyan-50 to-teal-50">
        {/* Mobile Navigation */}
        <MobileNav
          navigationItems={navigationItems}
          activeView={activeView}
          onViewChange={setActiveView}
          selectedClient={selectedClient}
        />
        
        <div className="flex">
          {/* Sidebar */}
          <div className="hidden lg:flex w-16 bg-slate-800 border-r border-slate-700 flex-col">
            {/* Logo */}
            <div className="h-16 flex items-center justify-center border-b border-slate-700">
              <img src="/Favicon (1) copy.png" alt="ROI BLUEPRINT" className="w-10 h-10 object-contain" />
            </div>

            {/* Navigation Icons */}
            <nav className="flex-1 py-4">
              {navigationItems.map((item) => (
                <div key={item.id} className="relative group">
                  <button
                    onClick={() => setActiveView(item.id as ActiveView)}
                    className={`w-full h-12 flex items-center justify-center transition-all duration-200 relative ${
                      activeView === item.id 
                        ? 'text-blue-400 bg-slate-700' 
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                    }`}
                  >
                    <item.icon className="h-5 w-5" />
                    {activeView === item.id && (
                      <div className="absolute left-0 top-1/2 transform -translate-y-1/2 w-1 h-6 bg-blue-400 rounded-r-full" />
                    )}
                  </button>
                  
                  {/* Tooltip */}
                  <div className="absolute left-full ml-2 top-1/2 transform -translate-y-1/2 bg-slate-900 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap z-50">
                    {item.label}
                  </div>
                </div>
              ))}
            </nav>

            {/* Client Indicator */}
            {selectedClient && (
              <div className="p-2 border-t border-slate-700">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-xs">
                    {selectedClient.name.split(' ').map(word => word[0]).join('').substring(0, 2)}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Expanded Client Info Panel */}
          {selectedClient && (
            <div className="hidden xl:block w-64 bg-slate-50 border-r border-slate-200 p-4">
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-slate-900">{selectedClient.name}</h2>
                <p className="text-sm text-slate-600">{selectedClient.industry}</p>
              </div>
              
              <div className="space-y-3">
                <div className="bg-white p-3 rounded-lg border border-slate-200">
                  <p className="text-xs text-slate-500 uppercase tracking-wide">Contact</p>
                  <p className="text-sm font-medium text-slate-900">{selectedClient.contactPerson}</p>
                  <p className="text-xs text-slate-600">{selectedClient.email}</p>
                </div>
                
                <div className="bg-white p-3 rounded-lg border border-slate-200">
                  <p className="text-xs text-slate-500 uppercase tracking-wide">Tax Year</p>
                  <p className="text-sm font-medium text-slate-900">{selectedClient.taxYear}</p>
                </div>
                
                <div className="bg-white p-3 rounded-lg border border-slate-200">
                  <p className="text-xs text-slate-500 uppercase tracking-wide">Estimated Credit</p>
                  <p className="text-sm font-medium text-green-600">${selectedClient.estimatedCredit.toLocaleString()}</p>
                </div>
                
                <div className="bg-white p-3 rounded-lg border border-slate-200">
                  <p className="text-xs text-slate-500 uppercase tracking-wide">Status</p>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                    selectedClient.status === 'active' ? 'bg-green-100 text-green-800' :
                    selectedClient.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-slate-100 text-slate-800'
                  }`}>
                    {selectedClient.status}
                  </span>
                </div>
              </div>
              
              <button
                onClick={() => setSelectedClientId(null)}
                className="w-full mt-4 text-sm text-slate-600 hover:text-slate-800 py-2 px-3 rounded-lg hover:bg-white transition-colors"
              >
                ← Back to Clients
              </button>
            </div>
          )}

          {/* Main Content */}
          <div className="flex-1 flex flex-col bg-white">
            {/* Header with User Profile */}
            <div className="hidden lg:block bg-white border-b border-gray-200 px-4 lg:px-8 py-4">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-semibold text-gray-900">
                    {navigationItems.find(item => item.id === activeView)?.label || 'Dashboard'}
                  </h1>
                  {user && (
                    <p className="text-sm text-gray-600">
                      Welcome back, {user.firstName}
                    </p>
                  )}
                </div>
                <UserProfile 
                  onShowProfileSettings={() => setShowProfileSettings(true)}
                  onShowNotifications={() => setShowNotificationsPage(true)}
                  onShowAccountSettings={() => setShowAccountSettings(true)}
                  notifications={notifications}
                  unreadCount={unreadCount}
                  onMarkAsRead={markAsRead}
                  onMarkAllAsRead={markAllAsRead}
                  onDeleteNotification={deleteNotification}
                  onClearAllNotifications={clearAllNotifications}
                />
              </div>
            </div>
            
            {/* Page Content */}
            <div className="flex-1 p-4 lg:p-8 overflow-auto">
              {renderActiveView()}
            </div>
          </div>
        </div>

        <ToastContainer toasts={toasts} onRemove={removeToast} />

        {/* Modal Components */}
        {showProfileSettings && user && (
          <ProfileSettings
            user={user}
            onUpdateProfile={handleUpdateProfile}
            onClose={() => setShowProfileSettings(false)}
          />
        )}

        {showNotificationsPage && (
          <NotificationsPage
            notifications={notifications}
            unreadCount={unreadCount}
            onMarkAsRead={markAsRead}
            onMarkAllAsRead={markAllAsRead}
            onDelete={deleteNotification}
            onClearAll={clearAllNotifications}
            onClose={() => setShowNotificationsPage(false)}
          />
        )}

        {showAccountSettings && user && (
          <AccountSettings
            user={user}
            onUpdateSettings={handleUpdateAccountSettings}
            onClose={() => setShowAccountSettings(false)}
          />
        )}
      </div>
    </ErrorBoundary>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
