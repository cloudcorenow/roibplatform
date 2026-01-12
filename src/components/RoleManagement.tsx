import React, { useState } from 'react';
import { Shield, Plus, Search, Crown, Users, Settings, Edit3, Trash2, CheckCircle, XCircle } from 'lucide-react';
import { Role, Permission, User } from '../types/users';
import { formatDateTime, getStatusColor } from '../utils/formatters';

interface RoleManagementProps {
  roles: Role[];
  permissions: Permission[];
  users: User[];
  onAddRole: (role: Omit<Role, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateRole: (id: string, updates: Partial<Role>) => void;
  onDeleteRole: (id: string) => void;
}

export const RoleManagement: React.FC<RoleManagementProps> = ({
  roles,
  permissions,
  users,
  onAddRole,
  onUpdateRole,
  onDeleteRole
}) => {
  const [selectedRole, setSelectedRole] = useState<Role | null>(roles[0] || null);
  const [showNewRoleForm, setShowNewRoleForm] = useState(false);
  const [showEditForm, setShowEditForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  
  const [newRole, setNewRole] = useState({
    name: '',
    description: '',
    permissions: [] as Permission[],
    color: 'bg-blue-100 text-blue-800'
  });

  const [editRole, setEditRole] = useState({
    name: '',
    description: '',
    permissions: [] as Permission[],
    color: 'bg-blue-100 text-blue-800'
  });

  const filteredRoles = roles.filter(role =>
    role.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    role.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleAddRole = () => {
    if (!newRole.name || !newRole.description) return;
    
    onAddRole({
      ...newRole,
      isSystemRole: false
    });

    setNewRole({
      name: '',
      description: '',
      permissions: [],
      color: 'bg-blue-100 text-blue-800'
    });
    setShowNewRoleForm(false);
  };

  const handleEditRole = (role: Role) => {
    setSelectedRole(role);
    setEditRole({
      name: role.name,
      description: role.description,
      permissions: [...role.permissions],
      color: role.color
    });
    setShowEditForm(true);
  };

  const handleUpdateRole = () => {
    if (!selectedRole) return;
    
    onUpdateRole(selectedRole.id, {
      name: editRole.name,
      description: editRole.description,
      permissions: editRole.permissions,
      color: editRole.color,
      updatedAt: new Date().toISOString()
    });

    setShowEditForm(false);
    setSelectedRole(null);
  };

  const togglePermission = (permission: Permission, isEdit = false) => {
    const currentPermissions = isEdit ? editRole.permissions : newRole.permissions;
    const hasPermission = currentPermissions.some(p => p.id === permission.id);
    
    const updatedPermissions = hasPermission
      ? currentPermissions.filter(p => p.id !== permission.id)
      : [...currentPermissions, permission];

    if (isEdit) {
      setEditRole({ ...editRole, permissions: updatedPermissions });
    } else {
      setNewRole({ ...newRole, permissions: updatedPermissions });
    }
  };

  const groupedPermissions = permissions.reduce((groups, permission) => {
    const resource = permission.resource;
    if (!groups[resource]) {
      groups[resource] = [];
    }
    groups[resource].push(permission);
    return groups;
  }, {} as Record<string, Permission[]>);

  const colorOptions = [
    'bg-blue-100 text-blue-800',
    'bg-green-100 text-green-800',
    'bg-purple-100 text-purple-800',
    'bg-orange-100 text-orange-800',
    'bg-pink-100 text-pink-800',
    'bg-indigo-100 text-indigo-800',
    'bg-teal-100 text-teal-800',
    'bg-gray-100 text-gray-800'
  ];

  const getUsersWithRole = (roleId: string) => {
    return users.filter(user => user.role.id === roleId);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Role Management</h1>
          <p className="text-gray-600 mt-2">Define roles and manage permissions for your team</p>
        </div>
        <button
          onClick={() => setShowNewRoleForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
        >
          <Plus className="h-4 w-4" />
          <span>Create Role</span>
        </button>
      </div>

      {showNewRoleForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Role</h3>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Role Name</label>
                <input
                  type="text"
                  value={newRole.name}
                  onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="e.g., Senior Developer"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Color Theme</label>
                <div className="flex flex-wrap gap-2">
                  {colorOptions.map(color => (
                    <button
                      key={color}
                      onClick={() => setNewRole({ ...newRole, color })}
                      className={`w-8 h-8 rounded-lg border-2 ${
                        newRole.color === color ? 'border-gray-400' : 'border-transparent'
                      } ${color.split(' ')[0]} flex items-center justify-center`}
                    >
                      {newRole.color === color && <CheckCircle className="h-4 w-4" />}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Description</label>
              <textarea
                value={newRole.description}
                onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Describe the role and its responsibilities..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">Permissions</label>
              <div className="space-y-4">
                {Object.entries(groupedPermissions).map(([resource, resourcePermissions]) => (
                  <div key={resource} className="border border-gray-200 rounded-lg p-4">
                    <h4 className="font-medium text-gray-900 mb-3 capitalize">{resource.replace('-', ' ')}</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {resourcePermissions.map(permission => {
                        const isSelected = newRole.permissions.some(p => p.id === permission.id);
                        return (
                          <label
                            key={permission.id}
                            className={`flex items-center p-2 rounded cursor-pointer transition-colors ${
                              isSelected ? 'bg-blue-50 border border-blue-200' : 'hover:bg-gray-50'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => togglePermission(permission)}
                              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            <div className="ml-2">
                              <p className="text-sm font-medium text-gray-900">{permission.name}</p>
                              <p className="text-xs text-gray-600">{permission.description}</p>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewRoleForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddRole}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Create Role
            </button>
          </div>
        </div>
      )}

      {showEditForm && selectedRole && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Edit Role: {selectedRole.name}</h3>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Role Name</label>
                <input
                  type="text"
                  value={editRole.name}
                  onChange={(e) => setEditRole({ ...editRole, name: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  disabled={selectedRole.isSystemRole}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Color Theme</label>
                <div className="flex flex-wrap gap-2">
                  {colorOptions.map(color => (
                    <button
                      key={color}
                      onClick={() => setEditRole({ ...editRole, color })}
                      disabled={selectedRole.isSystemRole}
                      className={`w-8 h-8 rounded-lg border-2 ${
                        editRole.color === color ? 'border-gray-400' : 'border-transparent'
                      } ${color.split(' ')[0]} flex items-center justify-center disabled:opacity-50`}
                    >
                      {editRole.color === color && <CheckCircle className="h-4 w-4" />}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Description</label>
              <textarea
                value={editRole.description}
                onChange={(e) => setEditRole({ ...editRole, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                disabled={selectedRole.isSystemRole}
              />
            </div>
            {!selectedRole.isSystemRole && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Permissions</label>
                <div className="space-y-4">
                  {Object.entries(groupedPermissions).map(([resource, resourcePermissions]) => (
                    <div key={resource} className="border border-gray-200 rounded-lg p-4">
                      <h4 className="font-medium text-gray-900 mb-3 capitalize">{resource.replace('-', ' ')}</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {resourcePermissions.map(permission => {
                          const isSelected = editRole.permissions.some(p => p.id === permission.id);
                          return (
                            <label
                              key={permission.id}
                              className={`flex items-center p-2 rounded cursor-pointer transition-colors ${
                                isSelected ? 'bg-blue-50 border border-blue-200' : 'hover:bg-gray-50'
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => togglePermission(permission, true)}
                                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                              />
                              <div className="ml-2">
                                <p className="text-sm font-medium text-gray-900">{permission.name}</p>
                                <p className="text-xs text-gray-600">{permission.description}</p>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowEditForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleUpdateRole}
              disabled={selectedRole.isSystemRole}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              Update Role
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
            <div className="relative mb-4">
              <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search roles..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            
            <div className="space-y-2">
              {filteredRoles.map((role) => {
                const userCount = getUsersWithRole(role.id).length;
                
                return (
                  <div
                    key={role.id}
                    onClick={() => setSelectedRole(role)}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      selectedRole?.id === role.id
                        ? 'border-blue-200 bg-blue-50'
                        : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${role.color}`}>
                          {role.isSystemRole && <Crown className="h-3 w-3 mr-1" />}
                          {role.name}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-gray-600 mb-2">{role.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">{userCount} users</span>
                      <span className="text-xs text-gray-500">{role.permissions.length} permissions</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="lg:col-span-3">
          {selectedRole ? (
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900">{selectedRole.name}</h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${selectedRole.color}`}>
                      {selectedRole.isSystemRole && <Crown className="h-3 w-3 mr-1" />}
                      {selectedRole.isSystemRole ? 'System Role' : 'Custom Role'}
                    </span>
                  </div>
                  <p className="text-gray-600 mb-4">{selectedRole.description}</p>
                  <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <span>{selectedRole.permissions.length} permissions</span>
                    <span>{getUsersWithRole(selectedRole.id).length} users</span>
                    <span>Updated {formatDateTime(selectedRole.updatedAt)}</span>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleEditRole(selectedRole)}
                    className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                    title="Edit Role"
                  >
                    <Edit3 className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => onDeleteRole(selectedRole.id)}
                    disabled={selectedRole.isSystemRole || getUsersWithRole(selectedRole.id).length > 0}
                    className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Delete Role"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h4 className="text-md font-semibold text-gray-900 mb-3">Permissions</h4>
                  <div className="space-y-4">
                    {Object.entries(groupedPermissions).map(([resource, resourcePermissions]) => {
                      const rolePermissions = selectedRole.permissions.filter(p => p.resource === resource);
                      if (rolePermissions.length === 0) return null;

                      return (
                        <div key={resource} className="border border-gray-200 rounded-lg p-4">
                          <h5 className="font-medium text-gray-900 mb-3 capitalize flex items-center">
                            <Shield className="h-4 w-4 mr-2" />
                            {resource.replace('-', ' ')}
                          </h5>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {rolePermissions.map(permission => (
                              <div key={permission.id} className="flex items-center p-2 bg-green-50 rounded border border-green-200">
                                <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                                <div>
                                  <p className="text-sm font-medium text-gray-900">{permission.name}</p>
                                  <p className="text-xs text-gray-600">{permission.scope} scope</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <h4 className="text-md font-semibold text-gray-900 mb-3">Users with this Role</h4>
                  <div className="space-y-2">
                    {getUsersWithRole(selectedRole.id).map(user => (
                      <div key={user.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                        <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                          {user.avatar ? (
                            <img src={user.avatar} alt={`${user.firstName} ${user.lastName}`} className="w-8 h-8 rounded-lg object-cover" />
                          ) : (
                            <span className="text-white font-bold text-xs">
                              {user.firstName[0]}{user.lastName[0]}
                            </span>
                          )}
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium text-gray-900">{user.firstName} {user.lastName}</p>
                          <p className="text-xs text-gray-600">{user.email}</p>
                        </div>
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                          {user.status}
                        </span>
                      </div>
                    ))}
                    {getUsersWithRole(selectedRole.id).length === 0 && (
                      <p className="text-sm text-gray-500 text-center py-4">No users assigned to this role</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
              <Shield className="h-16 w-16 mx-auto mb-4 text-gray-300" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Role Selected</h3>
              <p className="text-gray-600">Select a role from the sidebar to view its details and permissions</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};