export interface Client {
  id: string;
  name: string;
  industry: string;
  contactPerson: string;
  email: string;
  phone: string;
  address: string;
  taxYear: string;
  status: 'active' | 'inactive' | 'pending';
  onboardingDate: string;
  totalProjects: number;
  estimatedCredit: number;
}

export interface TimeEntry {
  id: string;
  clientId: string;
  projectId: string;
  projectName: string;
  task: string;
  duration: number; // in minutes
  date: string;
  status: 'active' | 'completed' | 'paused';
  isRnD: boolean;
  notes?: string;
  employeeIds: string[];
  employeeNames: string[];
}

export interface Project {
  id: string;
  clientId: string;
  name: string;
  description: string;
  status: 'active' | 'completed' | 'on-hold';
  progress: number;
  totalHours: number;
  isRnD: boolean;
  startDate: string;
  endDate?: string;
  teamMembers: string[];
  budget: number;
  rndObjective: string;
  technicalUncertainty: string;
  systematicProcess: string;
}

export interface TechnicalNote {
  id: string;
  clientId: string;
  title: string;
  content: string;
  projectId: string;
  projectName: string;
  author: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
  isRnDQualified: boolean;
  uncertaintyDescription: string;
  experimentationDetails: string;
  version: number;
  changeLog: ChangeLogEntry[];
}

export interface ChangeLogEntry {
  id: string;
  timestamp: string;
  author: string;
  action: 'created' | 'updated' | 'deleted';
  changes: string;
  previousVersion?: string;
}

export interface Contractor {
  id: string;
  clientId: string;
  name: string;
  company: string;
  email: string;
  phone: string;
  specialization: string;
  hourlyRate: number;
  isActive: boolean;
  rndQualified: boolean;
  contractStartDate: string;
  contractEndDate?: string;
}

export interface ContractorTimeEntry {
  id: string;
  clientId: string;
  contractorId: string;
  contractorName: string;
  projectId: string;
  projectName: string;
  task: string;
  duration: number;
  date: string;
  hourlyRate: number;
  isRnD: boolean;
  invoiceNumber?: string;
  notes?: string;
}

export interface KnowledgeBaseEntry {
  id: string;
  clientId: string;
  title: string;
  content: string;
  category: 'lessons-learned' | 'failed-experiments' | 'code-snippets' | 'best-practices';
  projectId?: string;
  projectName?: string;
  author: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
  isPublic: boolean;
  relatedSprint?: string;
}

export interface Milestone {
  id: string;
  clientId: string;
  projectId: string;
  title: string;
  description: string;
  dueDate: string;
  status: 'pending' | 'in-progress' | 'completed' | 'overdue';
  type: 'project' | 'tax-deadline' | 'sprint' | 'compliance';
  isRnDRelated: boolean;
  assignedTo: string[];
}

export interface ComplianceItem {
  id: string;
  title: string;
  description: string;
  category: 'documentation' | 'qualification' | 'audit-prep' | 'ongoing';
  isRequired: boolean;
  helpText: string;
  relatedDocs: string[];
}

export interface ClientCompliance {
  clientId: string;
  completedItems: string[];
  lastUpdated: string;
  overallScore: number;
}

export interface CPAUser {
  id: string;
  name: string;
  email: string;
  firm: string;
  accessLevel: 'read-only' | 'reports-only';
  clientAccess: string[];
  lastLogin?: string;
  isActive: boolean;
}

export interface Employee {
  id: string;
  clientId: string;
  name: string;
  role: string;
  department: string;
  rndPercentage: number;
  hourlyRate: number;
  isActive: boolean;
  qualifications: string[];
  rndActivities: string[];
}

export interface Expense {
  id: string;
  clientId: string;
  description: string;
  amount: number;
  category: string;
  date: string;
  projectId?: string;
  isRnD: boolean;
  receipt?: string;
  vendor: string;
  justification: string;
}

export interface SourceControlActivity {
  id: string;
  clientId: string;
  repository: string;
  commits: number;
  author: string;
  date: string;
  projectId: string;
  linesAdded: number;
  linesRemoved: number;
  branchName: string;
  commitMessages: string[];
}

export interface Experiment {
  id: string;
  clientId: string;
  projectId: string;
  projectName: string;
  title: string;
  hypothesis: string;
  technicalUncertainty: string;
  technologies: string[];
  methodology: string;
  expectedOutcome: string;
  actualResults: string;
  status: 'planned' | 'in-progress' | 'completed' | 'failed';
  startDate: string;
  endDate?: string;
  author: string;
  collaborators: string[];
  isRnDQualified: boolean;
  passFailStatus: 'pass' | 'fail' | 'partial' | 'inconclusive';
  issuesFound: string[];
  lessonsLearned: string;
  nextSteps: string;
  relatedExperiments: string[];
  attachments: string[];
  createdAt: string;
  updatedAt: string;
}

export interface IRSAuditReport {
  id: string;
  clientId: string;
  quarter: string;
  year: string;
  generatedAt: string;
  qualifiedRnDTime: number;
  totalPayrollCosts: number;
  contractorCosts: number;
  supplyCosts: number;
  projects: {
    id: string;
    name: string;
    rndHours: number;
    technicalChallenges: string;
    personnelSummary: string;
    costs: number;
  }[];
  personnelSummary: {
    employeeCount: number;
    avgRnDPercentage: number;
    totalRnDHours: number;
    qualifications: string[];
  };
  complianceNotes: string[];
}

export interface AutoTimeEntry {
  id: string;
  clientId: string;
  source: 'github' | 'gitlab' | 'jira' | 'vscode' | 'manual';
  sourceId: string;
  projectId: string;
  duration: number;
  activity: string;
  timestamp: string;
  isRnD: boolean;
  confidence: number;
  metadata: {
    repository?: string;
    branch?: string;
    commits?: string[];
    ticketId?: string;
    fileTypes?: string[];
  };
}

export interface Document {
  id: string;
  clientId: string;
  name: string;
  description: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  fileUrl: string;
  category: 'technical-documentation' | 'financial-records' | 'contracts' | 'research-reports' | 'compliance-documents' | 'receipts-invoices' | 'employee-records' | 'other';
  projectId?: string;
  projectName?: string;
  isRnDRelated: boolean;
  tags: string[];
  uploadedAt: string;
  uploadedBy: string;
  confidentialityLevel: 'public' | 'internal' | 'confidential' | 'restricted';
}

export interface RnDAIAnalysis {
  id: string;
  taskDescription: string;
  isRnDQualified: boolean;
  confidence: number;
  reasoning: string;
  suggestedTags: string[];
  technicalUncertainty: string;
  recommendedDocumentation: string[];
  irsSection41Alignment: string;
  timestamp: string;
}

// Re-export user types for convenience
export type { User, Role, Permission, UserInvitation } from './types/users';
export type { Task, TaskTemplate, TaskComment, TaskFilter, TaskStats } from './tasks';