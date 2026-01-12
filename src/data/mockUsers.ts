import { User, Role, Permission, UserInvitation, UserActivity } from '../types/users';

export const mockPermissions: Permission[] = [
  // Client Management
  { id: 'clients-create', name: 'Create Clients', description: 'Add new clients to the system', resource: 'clients', action: 'create', scope: 'all' },
  { id: 'clients-read', name: 'View Clients', description: 'View client information', resource: 'clients', action: 'read', scope: 'all' },
  { id: 'clients-update', name: 'Edit Clients', description: 'Modify client information', resource: 'clients', action: 'update', scope: 'all' },
  { id: 'clients-delete', name: 'Delete Clients', description: 'Remove clients from the system', resource: 'clients', action: 'delete', scope: 'all' },

  // Time Tracking
  { id: 'time-create', name: 'Log Time', description: 'Create time entries', resource: 'time', action: 'create', scope: 'own' },
  { id: 'time-read', name: 'View Time Entries', description: 'View time tracking data', resource: 'time', action: 'read', scope: 'team' },
  { id: 'time-update', name: 'Edit Time Entries', description: 'Modify time entries', resource: 'time', action: 'update', scope: 'own' },
  { id: 'time-manage', name: 'Manage All Time', description: 'Full time tracking management', resource: 'time', action: 'manage', scope: 'all' },

  // Projects
  { id: 'projects-create', name: 'Create Projects', description: 'Add new projects', resource: 'projects', action: 'create', scope: 'all' },
  { id: 'projects-read', name: 'View Projects', description: 'View project information', resource: 'projects', action: 'read', scope: 'all' },
  { id: 'projects-update', name: 'Edit Projects', description: 'Modify project details', resource: 'projects', action: 'update', scope: 'all' },
  { id: 'projects-delete', name: 'Delete Projects', description: 'Remove projects', resource: 'projects', action: 'delete', scope: 'all' },

  // Documentation
  { id: 'docs-create', name: 'Create Documentation', description: 'Add technical notes and documentation', resource: 'documentation', action: 'create', scope: 'all' },
  { id: 'docs-read', name: 'View Documentation', description: 'Access technical documentation', resource: 'documentation', action: 'read', scope: 'all' },
  { id: 'docs-update', name: 'Edit Documentation', description: 'Modify documentation', resource: 'documentation', action: 'update', scope: 'own' },
  { id: 'docs-manage', name: 'Manage Documentation', description: 'Full documentation management', resource: 'documentation', action: 'manage', scope: 'all' },

  // Expenses
  { id: 'expenses-create', name: 'Add Expenses', description: 'Record new expenses', resource: 'expenses', action: 'create', scope: 'all' },
  { id: 'expenses-read', name: 'View Expenses', description: 'View expense records', resource: 'expenses', action: 'read', scope: 'all' },
  { id: 'expenses-update', name: 'Edit Expenses', description: 'Modify expense records', resource: 'expenses', action: 'update', scope: 'all' },
  { id: 'expenses-delete', name: 'Delete Expenses', description: 'Remove expense records', resource: 'expenses', action: 'delete', scope: 'all' },

  // Analytics & Reports
  { id: 'analytics-read', name: 'View Analytics', description: 'Access analytics dashboard', resource: 'analytics', action: 'read', scope: 'all' },
  { id: 'reports-read', name: 'View Reports', description: 'Access audit reports', resource: 'reports', action: 'read', scope: 'all' },
  { id: 'reports-create', name: 'Generate Reports', description: 'Create and export reports', resource: 'reports', action: 'create', scope: 'all' },

  // User Management
  { id: 'users-create', name: 'Invite Users', description: 'Invite new users to the system', resource: 'users', action: 'create', scope: 'all' },
  { id: 'users-read', name: 'View Users', description: 'View user information', resource: 'users', action: 'read', scope: 'all' },
  { id: 'users-update', name: 'Edit Users', description: 'Modify user information and roles', resource: 'users', action: 'update', scope: 'all' },
  { id: 'users-delete', name: 'Remove Users', description: 'Deactivate or remove users', resource: 'users', action: 'delete', scope: 'all' },

  // Role Management
  { id: 'roles-create', name: 'Create Roles', description: 'Create new roles', resource: 'roles', action: 'create', scope: 'all' },
  { id: 'roles-read', name: 'View Roles', description: 'View role information', resource: 'roles', action: 'read', scope: 'all' },
  { id: 'roles-update', name: 'Edit Roles', description: 'Modify role permissions', resource: 'roles', action: 'update', scope: 'all' },
  { id: 'roles-delete', name: 'Delete Roles', description: 'Remove custom roles', resource: 'roles', action: 'delete', scope: 'all' },

  // System Administration
  { id: 'system-manage', name: 'System Administration', description: 'Full system administration access', resource: 'system', action: 'manage', scope: 'all' }
];

export const mockRoles: Role[] = [
  {
    id: 'admin',
    name: 'Administrator',
    description: 'Full system access with all permissions',
    permissions: mockPermissions,
    isSystemRole: true,
    color: 'bg-red-100 text-red-800',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'manager',
    name: 'Project Manager',
    description: 'Manage projects, view analytics, and oversee team activities',
    permissions: mockPermissions.filter(p => 
      p.resource !== 'users' && p.resource !== 'roles' && p.resource !== 'system'
    ),
    isSystemRole: true,
    color: 'bg-blue-100 text-blue-800',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'developer',
    name: 'Developer',
    description: 'Track time, manage documentation, and work on projects',
    permissions: mockPermissions.filter(p => 
      ['time', 'projects', 'documentation', 'expenses'].includes(p.resource) &&
      (p.action !== 'delete' || p.resource === 'time')
    ),
    isSystemRole: true,
    color: 'bg-green-100 text-green-800',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'analyst',
    name: 'R&D Analyst',
    description: 'View analytics, generate reports, and access documentation',
    permissions: mockPermissions.filter(p => 
      ['analytics', 'reports', 'documentation', 'projects', 'clients'].includes(p.resource) &&
      ['read', 'create'].includes(p.action)
    ),
    isSystemRole: true,
    color: 'bg-purple-100 text-purple-800',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  },
  {
    id: 'viewer',
    name: 'Viewer',
    description: 'Read-only access to view data and reports',
    permissions: mockPermissions.filter(p => p.action === 'read'),
    isSystemRole: true,
    color: 'bg-gray-100 text-gray-800',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z'
  }
];

export const mockUsers: User[] = [
  {
    id: '1',
    email: 'admin@roiblueprint.com',
    firstName: 'John',
    lastName: 'Administrator',
    avatar: 'https://images.pexels.com/photos/2379004/pexels-photo-2379004.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop',
    status: 'active',
    role: mockRoles[0], // Admin
    department: 'Management',
    hireDate: '2024-01-01',
    lastLogin: '2024-12-18T10:30:00Z',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-12-18T10:30:00Z',
    createdBy: 'system'
  },
  {
    id: '2',
    email: 'sarah.chen@roiblueprint.com',
    firstName: 'Sarah',
    lastName: 'Chen',
    avatar: 'https://images.pexels.com/photos/1239291/pexels-photo-1239291.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop',
    status: 'active',
    role: mockRoles[2], // Developer
    department: 'Engineering',
    hireDate: '2024-02-15',
    lastLogin: '2024-12-18T09:45:00Z',
    createdAt: '2024-02-15T00:00:00Z',
    updatedAt: '2024-12-18T09:45:00Z',
    createdBy: '1'
  },
  {
    id: '3',
    email: 'emily.watson@roiblueprint.com',
    firstName: 'Emily',
    lastName: 'Watson',
    avatar: 'https://images.pexels.com/photos/1181686/pexels-photo-1181686.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop',
    status: 'active',
    role: mockRoles[1], // Manager
    department: 'Research',
    hireDate: '2024-03-01',
    lastLogin: '2024-12-17T16:20:00Z',
    createdAt: '2024-03-01T00:00:00Z',
    updatedAt: '2024-12-17T16:20:00Z',
    createdBy: '1'
  },
  {
    id: '4',
    email: 'mike.johnson@roiblueprint.com',
    firstName: 'Mike',
    lastName: 'Johnson',
    avatar: 'https://images.pexels.com/photos/1222271/pexels-photo-1222271.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop',
    status: 'active',
    role: mockRoles[2], // Developer
    department: 'Engineering',
    hireDate: '2024-04-10',
    lastLogin: '2024-12-18T08:15:00Z',
    createdAt: '2024-04-10T00:00:00Z',
    updatedAt: '2024-12-18T08:15:00Z',
    createdBy: '1'
  },
  {
    id: '5',
    email: 'lisa.rodriguez@roiblueprint.com',
    firstName: 'Lisa',
    lastName: 'Rodriguez',
    avatar: 'https://images.pexels.com/photos/1130626/pexels-photo-1130626.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop',
    status: 'pending',
    role: mockRoles[3], // Analyst
    department: 'Analytics',
    hireDate: '2024-12-01',
    createdAt: '2024-11-25T00:00:00Z',
    updatedAt: '2024-11-25T00:00:00Z',
    createdBy: '1'
  }
];

export const mockUserInvitations: UserInvitation[] = [
  {
    id: '1',
    email: 'new.developer@example.com',
    roleId: 'developer',
    invitedBy: '1',
    invitedAt: '2024-12-15T10:00:00Z',
    expiresAt: '2024-12-22T10:00:00Z',
    status: 'pending',
    token: 'inv_abc123def456'
  },
  {
    id: '2',
    email: 'analyst@example.com',
    roleId: 'analyst',
    invitedBy: '3',
    invitedAt: '2024-12-10T14:30:00Z',
    expiresAt: '2024-12-17T14:30:00Z',
    status: 'expired',
    token: 'inv_xyz789uvw012'
  }
];

export const mockUserActivity: UserActivity[] = [
  {
    id: '1',
    userId: '2',
    action: 'login',
    resource: 'auth',
    timestamp: '2024-12-18T09:45:00Z',
    ipAddress: '192.168.1.100'
  },
  {
    id: '2',
    userId: '2',
    action: 'create',
    resource: 'time_entry',
    resourceId: '1',
    timestamp: '2024-12-18T10:30:00Z',
    ipAddress: '192.168.1.100'
  },
  {
    id: '3',
    userId: '3',
    action: 'update',
    resource: 'project',
    resourceId: '1',
    timestamp: '2024-12-17T16:20:00Z',
    ipAddress: '192.168.1.105'
  },
  {
    id: '4',
    userId: '1',
    action: 'create',
    resource: 'user',
    resourceId: '5',
    timestamp: '2024-11-25T00:00:00Z',
    ipAddress: '192.168.1.101'
  }
];