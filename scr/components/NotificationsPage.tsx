import React, { useState } from 'react';
import { Bell, X, Check, CheckCheck, Trash2, Filter, Search, Clock, User, Target, MessageSquare, Calendar, Settings, Volume2, VolumeX } from 'lucide-react';
import { Notification } from '../hooks/useNotifications';
import { formatDateTime } from '../utils/formatters';

interface NotificationsPageProps {
  notifications: Notification[];
  unreadCount: number;
  onMarkAsRead: (id: string) => void;
  onMarkAllAsRead: () => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
  onClose: () => void;
}

export const NotificationsPage: React.FC<NotificationsPageProps> = ({
  notifications,
  unreadCount,
  onMarkAsRead,
  onMarkAllAsRead,
  onDelete,
  onClearAll,
  onClose
}) => {
  const [filter, setFilter] = useState<'all' | 'unread' | 'task_assigned' | 'task_completed' | 'task_overdue'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [notificationSettings, setNotificationSettings] = useState({
    emailNotifications: true,
    pushNotifications: true,
    taskAssignments: true,
    taskCompletions: true,
    overdueReminders: true,
    weeklyDigest: false
  });

  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'task_assigned': return <Target className="h-5 w-5 text-blue-600" />;
      case 'task_updated': return <Target className="h-5 w-5 text-yellow-600" />;
      case 'task_completed': return <Target className="h-5 w-5 text-green-600" />;
      case 'task_overdue': return <Target className="h-5 w-5 text-red-600" />;
      case 'comment_added': return <MessageSquare className="h-5 w-5 text-purple-600" />;
      case 'milestone_due': return <Calendar className="h-5 w-5 text-orange-600" />;
      default: return <Bell className="h-5 w-5 text-gray-600" />;
    }
  };

  const getPriorityColor = (priority: Notification['priority']) => {
    switch (priority) {
      case 'high': return 'border-l-red-500 bg-red-50';
      case 'medium': return 'border-l-yellow-500 bg-yellow-50';
      case 'low': return 'border-l-blue-500 bg-blue-50';
    }
  };

  const getTypeLabel = (type: Notification['type']) => {
    switch (type) {
      case 'task_assigned': return 'Task Assignment';
      case 'task_updated': return 'Task Update';
      case 'task_completed': return 'Task Completion';
      case 'task_overdue': return 'Overdue Task';
      case 'comment_added': return 'New Comment';
      case 'milestone_due': return 'Milestone Due';
      default: return 'Notification';
    }
  };

  const filteredNotifications = notifications.filter(notification => {
    // Filter by type
    if (filter !== 'all' && notification.type !== filter) return false;
    
    // Filter by read status
    if (filter === 'unread' && notification.isRead) return false;
    
    // Filter by search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return notification.title.toLowerCase().includes(searchLower) ||
             notification.message.toLowerCase().includes(searchLower);
    }
    
    return true;
  });

  const notificationStats = {
    total: notifications.length,
    unread: unreadCount,
    taskAssignments: notifications.filter(n => n.type === 'task_assigned').length,
    taskCompletions: notifications.filter(n => n.type === 'task_completed').length,
    overdue: notifications.filter(n => n.type === 'task_overdue').length
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Bell className="h-5 w-5 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900">Notifications</h2>
              <p className="text-sm text-gray-600">{unreadCount} unread notifications</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllAsRead}
                className="text-blue-600 hover:text-blue-700 text-sm font-medium px-3 py-1 rounded hover:bg-blue-50"
              >
                Mark All Read
              </button>
            )}
            <button
              onClick={onClearAll}
              className="text-red-600 hover:text-red-700 text-sm font-medium px-3 py-1 rounded hover:bg-red-50"
            >
              Clear All
            </button>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 p-2 rounded-lg hover:bg-gray-100"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="flex h-[calc(90vh-80px)]">
          {/* Sidebar */}
          <div className="w-64 bg-gray-50 p-4 border-r border-gray-200 overflow-y-auto">
            {/* Statistics */}
            <div className="space-y-3 mb-6">
              <div className="bg-blue-100 p-3 rounded-lg">
                <p className="text-sm font-medium text-blue-900">Total</p>
                <p className="text-xl font-bold text-blue-600">{notificationStats.total}</p>
              </div>
              <div className="bg-yellow-100 p-3 rounded-lg">
                <p className="text-sm font-medium text-yellow-900">Unread</p>
                <p className="text-xl font-bold text-yellow-600">{notificationStats.unread}</p>
              </div>
            </div>

            {/* Filters */}
            <div className="space-y-2 mb-6">
              <h4 className="text-sm font-medium text-gray-900 mb-2">Filter by Type</h4>
              <button
                onClick={() => setFilter('all')}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  filter === 'all' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                All Notifications ({notificationStats.total})
              </button>
              <button
                onClick={() => setFilter('unread')}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  filter === 'unread' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                Unread ({notificationStats.unread})
              </button>
              <button
                onClick={() => setFilter('task_assigned')}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  filter === 'task_assigned' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                Task Assignments ({notificationStats.taskAssignments})
              </button>
              <button
                onClick={() => setFilter('task_completed')}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  filter === 'task_completed' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                Completions ({notificationStats.taskCompletions})
              </button>
              <button
                onClick={() => setFilter('task_overdue')}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  filter === 'task_overdue' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                Overdue ({notificationStats.overdue})
              </button>
            </div>

            {/* Notification Settings */}
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-900 mb-2 flex items-center">
                <Settings className="h-4 w-4 mr-1" />
                Settings
              </h4>
              <div className="space-y-2">
                <label className="flex items-center justify-between text-sm">
                  <span className="text-gray-700">Email Notifications</span>
                  <input
                    type="checkbox"
                    checked={notificationSettings.emailNotifications}
                    onChange={(e) => setNotificationSettings({ ...notificationSettings, emailNotifications: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </label>
                <label className="flex items-center justify-between text-sm">
                  <span className="text-gray-700">Push Notifications</span>
                  <input
                    type="checkbox"
                    checked={notificationSettings.pushNotifications}
                    onChange={(e) => setNotificationSettings({ ...notificationSettings, pushNotifications: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </label>
                <label className="flex items-center justify-between text-sm">
                  <span className="text-gray-700">Task Assignments</span>
                  <input
                    type="checkbox"
                    checked={notificationSettings.taskAssignments}
                    onChange={(e) => setNotificationSettings({ ...notificationSettings, taskAssignments: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </label>
                <label className="flex items-center justify-between text-sm">
                  <span className="text-gray-700">Weekly Digest</span>
                  <input
                    type="checkbox"
                    checked={notificationSettings.weeklyDigest}
                    onChange={(e) => setNotificationSettings({ ...notificationSettings, weeklyDigest: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </label>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 flex flex-col">
            {/* Search Bar */}
            <div className="p-4 border-b border-gray-200">
              <div className="relative">
                <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search notifications..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>

            {/* Notifications List */}
            <div className="flex-1 overflow-y-auto">
              {filteredNotifications.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <div className="text-center">
                    <Bell className="h-16 w-16 mx-auto mb-4 text-gray-300" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No notifications</h3>
                    <p className="text-gray-600">
                      {filter === 'unread' ? 'All caught up! No unread notifications.' : 'No notifications match your current filter.'}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="divide-y divide-gray-100">
                  {filteredNotifications.map((notification) => (
                    <div
                      key={notification.id}
                      className={`p-4 border-l-4 ${getPriorityColor(notification.priority)} ${
                        !notification.isRead ? 'bg-blue-50' : 'bg-white'
                      } hover:bg-gray-50 transition-colors`}
                    >
                      <div className="flex items-start space-x-3">
                        <div className="flex-shrink-0 mt-1">
                          {getNotificationIcon(notification.type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-1">
                                <p className={`text-sm font-medium ${
                                  !notification.isRead ? 'text-gray-900' : 'text-gray-700'
                                }`}>
                                  {notification.title}
                                </p>
                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                                  {getTypeLabel(notification.type)}
                                </span>
                                {notification.priority === 'high' && (
                                  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                    High Priority
                                  </span>
                                )}
                              </div>
                              <p className="text-sm text-gray-600 mb-2">
                                {notification.message}
                              </p>
                              <div className="flex items-center space-x-4 text-xs text-gray-500">
                                <span className="flex items-center">
                                  <Clock className="h-3 w-3 mr-1" />
                                  {formatDateTime(notification.timestamp)}
                                </span>
                                {!notification.isRead && (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                    New
                                  </span>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center space-x-1 ml-2">
                              {!notification.isRead && (
                                <button
                                  onClick={() => onMarkAsRead(notification.id)}
                                  className="text-blue-600 hover:text-blue-700 p-1 rounded hover:bg-blue-100"
                                  title="Mark as read"
                                >
                                  <Check className="h-4 w-4" />
                                </button>
                              )}
                              <button
                                onClick={() => onDelete(notification.id)}
                                className="text-gray-400 hover:text-gray-600 p-1 rounded hover:bg-gray-100"
                                title="Delete"
                              >
                                <X className="h-4 w-4" />
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Footer Actions */}
            {filteredNotifications.length > 0 && (
              <div className="p-4 border-t border-gray-200 bg-gray-50">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-gray-600">
                    Showing {filteredNotifications.length} of {notifications.length} notifications
                  </p>
                  <div className="flex space-x-2">
                    {unreadCount > 0 && (
                      <button
                        onClick={onMarkAllAsRead}
                        className="text-blue-600 hover:text-blue-700 text-sm font-medium px-3 py-1 rounded hover:bg-blue-50"
                      >
                        Mark All Read
                      </button>
                    )}
                    <button
                      onClick={onClearAll}
                      className="text-red-600 hover:text-red-700 text-sm font-medium px-3 py-1 rounded hover:bg-red-50"
                    >
                      Clear All
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};