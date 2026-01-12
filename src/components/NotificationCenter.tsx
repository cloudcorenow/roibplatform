import React, { useState } from 'react';
import { Bell, X, Check, CheckCheck, Trash2, Clock, User, Target, MessageSquare, Calendar } from 'lucide-react';
import { Notification } from '../hooks/useNotifications';
import { formatDateTime } from '../utils/formatters';

interface NotificationCenterProps {
  notifications: Notification[];
  unreadCount: number;
  onMarkAsRead: (id: string) => void;
  onMarkAllAsRead: () => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
}

export const NotificationCenter: React.FC<NotificationCenterProps> = ({
  notifications,
  unreadCount,
  onMarkAsRead,
  onMarkAllAsRead,
  onDelete,
  onClearAll
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState<'all' | 'unread' | 'task_assigned' | 'task_completed'>('all');

  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'task_assigned': return <Target className="h-4 w-4 text-blue-600" />;
      case 'task_updated': return <Target className="h-4 w-4 text-yellow-600" />;
      case 'task_completed': return <Target className="h-4 w-4 text-green-600" />;
      case 'task_overdue': return <Target className="h-4 w-4 text-red-600" />;
      case 'comment_added': return <MessageSquare className="h-4 w-4 text-purple-600" />;
      case 'milestone_due': return <Calendar className="h-4 w-4 text-orange-600" />;
      default: return <Bell className="h-4 w-4 text-gray-600" />;
    }
  };

  const getPriorityColor = (priority: Notification['priority']) => {
    switch (priority) {
      case 'high': return 'border-l-red-500 bg-red-50';
      case 'medium': return 'border-l-yellow-500 bg-yellow-50';
      case 'low': return 'border-l-blue-500 bg-blue-50';
    }
  };

  const filteredNotifications = notifications.filter(notification => {
    switch (filter) {
      case 'unread': return !notification.isRead;
      case 'task_assigned': return notification.type === 'task_assigned';
      case 'task_completed': return notification.type === 'task_completed';
      default: return true;
    }
  });

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded-lg min-h-[44px] min-w-[44px]"
      >
        <Bell className="h-6 w-6" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center font-medium min-w-[20px]">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <>
          <div 
            className="fixed inset-0 z-10" 
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-white rounded-lg shadow-lg border border-gray-200 z-20 max-h-96 overflow-hidden">
            <div className="p-4 border-b border-gray-200">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-semibold text-gray-900">Notifications</h3>
                <div className="flex items-center space-x-2">
                  {unreadCount > 0 && (
                    <button
                      onClick={onMarkAllAsRead}
                      className="text-blue-600 hover:text-blue-700 text-sm font-medium p-1 min-h-[32px]"
                      title="Mark all as read"
                    >
                      <CheckCheck className="h-4 w-4" />
                    </button>
                  )}
                  <button
                    onClick={onClearAll}
                    className="text-gray-400 hover:text-gray-600 p-1 min-h-[32px] min-w-[32px]"
                    title="Clear all"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => setIsOpen(false)}
                    className="text-gray-400 hover:text-gray-600 p-1 min-h-[32px] min-w-[32px]"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>
              
              <div className="flex flex-wrap gap-1">
                <button
                  onClick={() => setFilter('all')}
                  className={`px-2 py-1 rounded text-xs font-medium min-h-[32px] ${
                    filter === 'all' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => setFilter('unread')}
                  className={`px-2 py-1 rounded text-xs font-medium min-h-[32px] ${
                    filter === 'unread' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
                  }`}
                >
                  Unread ({unreadCount})
                </button>
                <button
                  onClick={() => setFilter('task_assigned')}
                  className={`px-2 py-1 rounded text-xs font-medium min-h-[32px] ${
                    filter === 'task_assigned' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
                  }`}
                >
                  Assignments
                </button>
                <button
                  onClick={() => setFilter('task_completed')}
                  className={`px-2 py-1 rounded text-xs font-medium min-h-[32px] ${
                    filter === 'task_completed' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
                  }`}
                >
                  Completed
                </button>
              </div>
            </div>

            <div className="max-h-80 overflow-y-auto">
              {filteredNotifications.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  <Bell className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p className="text-sm">No notifications</p>
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
                              <p className={`text-sm font-medium ${
                                !notification.isRead ? 'text-gray-900' : 'text-gray-700'
                              }`}>
                                {notification.title}
                              </p>
                              <p className="text-sm text-gray-600 mt-1">
                                {notification.message}
                              </p>
                              <div className="flex items-center space-x-2 mt-2">
                                <Clock className="h-3 w-3 text-gray-400" />
                                <span className="text-xs text-gray-500">
                                  {formatDateTime(notification.timestamp)}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center space-x-1 ml-2">
                              {!notification.isRead && (
                                <button
                                  onClick={() => onMarkAsRead(notification.id)}
                                  className="text-blue-600 hover:text-blue-700 p-1 rounded min-h-[32px] min-w-[32px]"
                                  title="Mark as read"
                                >
                                  <Check className="h-3 w-3" />
                                </button>
                              )}
                              <button
                                onClick={() => onDelete(notification.id)}
                                className="text-gray-400 hover:text-gray-600 p-1 rounded min-h-[32px] min-w-[32px]"
                                title="Delete"
                              >
                                <X className="h-3 w-3" />
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
          </div>
        </>
      )}
    </div>
  );
};