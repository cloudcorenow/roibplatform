import React, { useState } from 'react';
import { User, LogOut, Settings, ChevronDown, Bell } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { Notification } from '../hooks/useNotifications';
import { NotificationCenter } from './NotificationCenter';
import { formatDateTime } from '../utils/formatters';

interface UserProfileProps {
  onShowProfileSettings: () => void;
  onShowNotifications: () => void;
  onShowAccountSettings: () => void;
  notifications: Notification[];
  unreadCount: number;
  onMarkAsRead: (id: string) => void;
  onMarkAllAsRead: () => void;
  onDeleteNotification: (id: string) => void;
  onClearAllNotifications: () => void;
}

export const UserProfile: React.FC<UserProfileProps> = ({
  onShowProfileSettings,
  onShowNotifications,
  onShowAccountSettings,
  notifications,
  unreadCount,
  onMarkAsRead,
  onMarkAllAsRead,
  onDeleteNotification,
  onClearAllNotifications
}) => {
  const { user, logout } = useAuth();
  const [showDropdown, setShowDropdown] = useState(false);

  if (!user) return null;

  return (
    <div className="flex items-center space-x-2 sm:space-x-3">
      <NotificationCenter
        notifications={notifications}
        unreadCount={unreadCount}
        onMarkAsRead={onMarkAsRead}
        onMarkAllAsRead={onMarkAllAsRead}
        onDelete={onDeleteNotification}
        onClearAll={onClearAllNotifications}
      />
      
      <div className="relative">
      <button
        onClick={() => setShowDropdown(!showDropdown)}
        className="flex items-center space-x-2 sm:space-x-3 p-2 rounded-lg hover:bg-gray-100 transition-colors min-h-[44px]"
      >
        <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
          {user.avatar ? (
            <img 
              src={user.avatar} 
              alt={`${user.firstName} ${user.lastName}`} 
              className="w-8 h-8 rounded-lg object-cover" 
            />
          ) : (
            <span className="text-white font-bold text-xs">
              {user.firstName[0]}{user.lastName[0]}
            </span>
          )}
        </div>
        <div className="text-left hidden sm:block">
          <p className="text-sm font-medium text-gray-900">{user.firstName} {user.lastName}</p>
          <p className="text-xs text-gray-500">{user.role.name}</p>
        </div>
        <ChevronDown className="h-4 w-4 text-gray-400 hidden sm:block" />
      </button>

      {showDropdown && (
        <>
          <div 
            className="fixed inset-0 z-10" 
            onClick={() => setShowDropdown(false)}
          />
          <div className="absolute right-0 mt-2 w-64 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
            <div className="p-4 border-b border-gray-200">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                  {user.avatar ? (
                    <img 
                      src={user.avatar} 
                      alt={`${user.firstName} ${user.lastName}`} 
                      className="w-10 h-10 rounded-lg object-cover" 
                    />
                  ) : (
                    <span className="text-white font-bold text-sm">
                      {user.firstName[0]}{user.lastName[0]}
                    </span>
                  )}
                </div>
                <div>
                  <p className="font-medium text-gray-900">{user.firstName} {user.lastName}</p>
                  <p className="text-sm text-gray-600">{user.email}</p>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${user.role.color}`}>
                    {user.role.name}
                  </span>
                </div>
              </div>
              {user.lastLogin && (
                <p className="text-xs text-gray-500 mt-2">
                  Last login: {formatDateTime(user.lastLogin)}
                </p>
              )}
            </div>

            <div className="p-2">
              <button
                onClick={() => {
                  setShowDropdown(false);
                  onShowProfileSettings();
                }}
                className="w-full flex items-center space-x-3 px-3 py-2 text-left text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <User className="h-4 w-4" />
                <span className="text-sm">Profile Settings</span>
              </button>
              <button
                onClick={() => {
                  setShowDropdown(false);
                  onShowNotifications();
                }}
                className="w-full flex items-center space-x-3 px-3 py-2 text-left text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <Bell className="h-4 w-4" />
                <span className="text-sm">Notifications</span>
              </button>
              <button
                onClick={() => {
                  setShowDropdown(false);
                  onShowAccountSettings();
                }}
                className="w-full flex items-center space-x-3 px-3 py-2 text-left text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <Settings className="h-4 w-4" />
                <span className="text-sm">Account Settings</span>
              </button>
            </div>

            <div className="p-2 border-t border-gray-200">
              <button
                onClick={() => {
                  setShowDropdown(false);
                  logout();
                }}
                className="w-full flex items-center space-x-3 px-3 py-2 text-left text-red-600 hover:bg-red-50 rounded-lg transition-colors"
              >
                <LogOut className="h-4 w-4" />
                <span className="text-sm">Sign Out</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
    </div>
  );
};