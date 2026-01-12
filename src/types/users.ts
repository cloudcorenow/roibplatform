export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  status: 'active' | 'inactive' | 'pending';
  role: Role;
  department?: string;
  hireDate: string;
  lastLogin?: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  isSystemRole: boolean;
  color: string;
  createdAt: string;
  updatedAt: string;
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'manage';
  scope: 'own' | 'team' | 'all';
}

export interface UserInvitation {
  id: string;
  email: string;
  roleId: string;
  invitedBy: string;
  invitedAt: string;
  expiresAt: string;
  status: 'pending' | 'accepted' | 'expired' | 'cancelled';
  token: string;
}

export interface UserActivity {
  id: string;
  userId: string;
  action: string;
  resource: string;
  resourceId?: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
}