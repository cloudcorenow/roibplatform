import React, { useState } from 'react';
import { Users, Plus, Search, Shield, Mail, Calendar, Activity, Settings, Eye, Edit3, Trash2, UserPlus, Crown, Clock } from 'lucide-react';
import { User, Role, UserInvitation } from '../types/users';
import { formatDateTime, formatDate, getStatusColor } from '../utils/formatters';

interface UserManagementProps {
  users: User[];
  roles: Role[];
  invitations: UserInvitation[];
  onAddUser: (user: Omit<User, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateUser: (id: string, updates: Partial<User>) => void;
  onDeleteUser: (id: string) => void;
  onInviteUser: (invitation: Omit<UserInvitation, 'id' | 'invitedAt' | 'token'>) => void;
  onCancelInvitation: (id: string) => void;
  onResendInvitation: (id: string) => void;
}

export const UserManagement: React.FC<UserManagementProps> = ({
  users,
  roles,
  invitations,
  onAddUser,
  onUpdateUser,
  onDeleteUser,
  onInviteUser,
  onCancelInvitation,
  onResendInvitation
}) => {
  const [activeTab, setActiveTab] = useState<'users' | 'invitations' | 'activity'>('users');
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [showEditForm, setShowEditForm] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  
  const [inviteForm, setInviteForm] = useState({
    email: '',
    roleId: '',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] // 7 days from now
  });

  const [editForm, setEditForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    roleId: '',
    department: '',
    status: 'active' as const
  });

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.firstName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.lastName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.department?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === 'all' || user.role.id === filterRole;
    const matchesStatus = filterStatus === 'all' || user.status === filterStatus;
    return matchesSearch && matchesRole && matchesStatus;
  });

  const handleInviteUser = () => {
    if (!inviteForm.email || !inviteForm.roleId) return;
    
    onInviteUser({
      email: inviteForm.email,
      roleId: inviteForm.roleId,
      invitedBy: '1', // Current user ID
      expiresAt: new Date(inviteForm.expiresAt).toISOString(),
      status: 'pending'
    });

    setInviteForm({
      email: '',
      roleId: '',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
    });
    setShowInviteForm(false);
  };

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setEditForm({
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      roleId: user.role.id,
      department: user.department || '',
      status: user.status
    });
    setShowEditForm(true);
  };

  const handleUpdateUser = () => {
    if (!selectedUser) return;
    
    const selectedRole = roles.find(r => r.id === editForm.roleId);
    if (!selectedRole) return;

    onUpdateUser(selectedUser.id, {
      firstName: editForm.firstName,
      lastName: editForm.lastName,
      email: editForm.email,
      role: selectedRole,
      department: editForm.department,
      status: editForm.status,
      updatedAt: new Date().toISOString()
    });

    setShowEditForm(false);
    setSelectedUser(null);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <Activity className="h-3 w-3" />;
      case 'inactive': return <Clock className="h-3 w-3" />;
      case 'pending': return <Mail className="h-3 w-3" />;
      default: return <Users className="h-3 w-3" />;
    }
  };

  const userStats = {
    total: users.length,
    active: users.filter(u => u.status === 'active').length,
    pending: users.filter(u => u.status === 'pending').length,
    pendingInvitations: invitations.filter(i => i.status === 'pending').length
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">User Management</h1>
          <p className="text-gray-600 mt-2">Manage team members, roles, and permissions</p>
        </div>
        <button
          onClick={() => setShowInviteForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
        >
          <UserPlus className="h-4 w-4" />
          <span>Invite User</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Users className="h-4 w-4 mr-1" />
            Total Users
          </h4>
          <p className="text-2xl font-bold text-blue-600">{userStats.total}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <Activity className="h-4 w-4 mr-1" />
            Active Users
          </h4>
          <p className="text-2xl font-bold text-green-600">{userStats.active}</p>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-yellow-900 mb-2 flex items-center">
            <Clock className="h-4 w-4 mr-1" />
            Pending Users
          </h4>
          <p className="text-2xl font-bold text-yellow-600">{userStats.pending}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Mail className="h-4 w-4 mr-1" />
            Pending Invites
          </h4>
          <p className="text-2xl font-bold text-purple-600">{userStats.pendingInvitations}</p>
        </div>
      </div>

      {showInviteForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Invite New User</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
              <input
                type="email"
                value={inviteForm.email}
                onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="user@example.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
              <select
                value={inviteForm.roleId}
                onChange={(e) => setInviteForm({ ...inviteForm, roleId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select a role</option>
                {roles.map(role => (
                  <option key={role.id} value={role.id}>{role.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Expires On</label>
              <input
                type="date"
                value={inviteForm.expiresAt}
                onChange={(e) => setInviteForm({ ...inviteForm, expiresAt: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowInviteForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleInviteUser}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Send Invitation
            </button>
          </div>
        </div>
      )}

      {showEditForm && selectedUser && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Edit User</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">First Name</label>
              <input
                type="text"
                value={editForm.firstName}
                onChange={(e) => setEditForm({ ...editForm, firstName: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Last Name</label>
              <input
                type="text"
                value={editForm.lastName}
                onChange={(e) => setEditForm({ ...editForm, lastName: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
              <input
                type="email"
                value={editForm.email}
                onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
              <select
                value={editForm.roleId}
                onChange={(e) => setEditForm({ ...editForm, roleId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {roles.map(role => (
                  <option key={role.id} value={role.id}>{role.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Department</label>
              <input
                type="text"
                value={editForm.department}
                onChange={(e) => setEditForm({ ...editForm, department: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
              <select
                value={editForm.status}
                onChange={(e) => setEditForm({ ...editForm, status: e.target.value as any })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="pending">Pending</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowEditForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleUpdateUser}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Update User
            </button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('users')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'users'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Users ({users.length})
            </button>
            <button
              onClick={() => setActiveTab('invitations')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'invitations'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Invitations ({invitations.length})
            </button>
            <button
              onClick={() => setActiveTab('activity')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'activity'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Activity Log
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'users' && (
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="flex space-x-3">
                  <div className="relative">
                    <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search users..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <select
                    value={filterRole}
                    onChange={(e) => setFilterRole(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Roles</option>
                    {roles.map(role => (
                      <option key={role.id} value={role.id}>{role.name}</option>
                    ))}
                  </select>
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Status</option>
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="pending">Pending</option>
                  </select>
                </div>
              </div>

              <div className="space-y-4">
                {filteredUsers.map((user) => (
                  <div key={user.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                          {user.avatar ? (
                            <img src={user.avatar} alt={`${user.firstName} ${user.lastName}`} className="w-12 h-12 rounded-lg object-cover" />
                          ) : (
                            <span className="text-white font-bold text-sm">
                              {user.firstName[0]}{user.lastName[0]}
                            </span>
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h4 className="font-semibold text-gray-900">{user.firstName} {user.lastName}</h4>
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                              {getStatusIcon(user.status)}
                              <span className="ml-1 capitalize">{user.status}</span>
                            </span>
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${user.role.color}`}>
                              {user.role.isSystemRole && <Crown className="h-3 w-3 mr-1" />}
                              {user.role.name}
                            </span>
                          </div>
                          <div className="space-y-1 text-sm text-gray-600">
                            <p className="flex items-center">
                              <Mail className="h-3 w-3 mr-2" />
                              {user.email}
                            </p>
                            {user.department && (
                              <p className="flex items-center">
                                <Users className="h-3 w-3 mr-2" />
                                {user.department}
                              </p>
                            )}
                            <p className="flex items-center">
                              <Calendar className="h-3 w-3 mr-2" />
                              Joined {formatDate(user.hireDate)}
                            </p>
                            {user.lastLogin && (
                              <p className="flex items-center">
                                <Activity className="h-3 w-3 mr-2" />
                                Last login {formatDateTime(user.lastLogin)}
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleEditUser(user)}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          title="Edit User"
                        >
                          <Edit3 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => onDeleteUser(user.id)}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Delete User"
                          disabled={user.role.id === 'admin'}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
                {filteredUsers.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <Users className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                    <p>No users found matching your criteria</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'invitations' && (
            <div className="space-y-4">
              {invitations.map((invitation) => {
                const role = roles.find(r => r.id === invitation.roleId);
                const inviter = users.find(u => u.id === invitation.invitedBy);
                const isExpired = new Date(invitation.expiresAt) < new Date();
                
                return (
                  <div key={invitation.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h4 className="font-medium text-gray-900">{invitation.email}</h4>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                            invitation.status === 'pending' && !isExpired ? 'bg-yellow-100 text-yellow-800' :
                            invitation.status === 'accepted' ? 'bg-green-100 text-green-800' :
                            'bg-red-100 text-red-800'
                          }`}>
                            {isExpired ? 'Expired' : invitation.status}
                          </span>
                          {role && (
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${role.color}`}>
                              {role.name}
                            </span>
                          )}
                        </div>
                        <div className="text-sm text-gray-600 space-y-1">
                          <p>Invited by {inviter?.firstName} {inviter?.lastName} on {formatDateTime(invitation.invitedAt)}</p>
                          <p>Expires on {formatDateTime(invitation.expiresAt)}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {invitation.status === 'pending' && !isExpired && (
                          <button
                            onClick={() => onResendInvitation(invitation.id)}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                            title="Resend Invitation"
                          >
                            <Mail className="h-4 w-4" />
                          </button>
                        )}
                        <button
                          onClick={() => onCancelInvitation(invitation.id)}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Cancel Invitation"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
              {invitations.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <Mail className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No pending invitations</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'activity' && (
            <div className="space-y-4">
              <div className="text-center py-8 text-gray-500">
                <Activity className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>Activity log feature coming soon</p>
                <p className="text-sm mt-1">Track user actions and system events</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};