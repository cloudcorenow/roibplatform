import { useState, useEffect, useCallback } from 'react';

export interface Notification {
  id: string;
  type: 'task_assigned' | 'task_updated' | 'task_completed' | 'task_overdue' | 'comment_added' | 'milestone_due';
  title: string;
  message: string;
  timestamp: string;
  isRead: boolean;
  priority: 'low' | 'medium' | 'high';
  actionUrl?: string;
  relatedId?: string;
  userId: string;
}

interface ToastFunctions {
  showSuccess: (title: string, message?: string) => void;
  showInfo: (title: string, message?: string) => void;
  showWarning: (title: string, message?: string) => void;
  showError: (title: string, message?: string, priority?: 'high' | 'normal') => void;
}

export function useNotifications(userId: string, toastFunctions: ToastFunctions) {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  // Load notifications from localStorage
  useEffect(() => {
    const saved = localStorage.getItem(`notifications-${userId}`);
    if (saved) {
      try {
        setNotifications(JSON.parse(saved));
      } catch (error) {
        console.error('Failed to load notifications:', error);
      }
    }
  }, [userId]);

  // Save notifications to localStorage
  useEffect(() => {
    localStorage.setItem(`notifications-${userId}`, JSON.stringify(notifications));
  }, [notifications, userId]);

  const addNotification = useCallback((notification: Omit<Notification, 'id' | 'timestamp' | 'isRead'>) => {
    const newNotification: Notification = {
      ...notification,
      id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      isRead: false
    };

    setNotifications(prev => [newNotification, ...prev.slice(0, 49)]); // Keep last 50

    // Show toast notification
    switch (notification.type) {
      case 'task_assigned':
        toastFunctions.showInfo(notification.title, notification.message);
        break;
      case 'task_completed':
        toastFunctions.showSuccess(notification.title, notification.message);
        break;
      case 'task_overdue':
        toastFunctions.showWarning(notification.title, notification.message);
        break;
      default:
        toastFunctions.showInfo(notification.title, notification.message);
    }
  }, [toastFunctions]);

  const markAsRead = useCallback((notificationId: string) => {
    setNotifications(prev => prev.map(notif => 
      notif.id === notificationId ? { ...notif, isRead: true } : notif
    ));
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications(prev => prev.map(notif => ({ ...notif, isRead: true })));
  }, []);

  const deleteNotification = useCallback((notificationId: string) => {
    setNotifications(prev => prev.filter(notif => notif.id !== notificationId));
  }, []);

  const clearAllNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const unreadCount = notifications.filter(n => !n.isRead).length;

  return {
    notifications,
    unreadCount,
    addNotification,
    markAsRead,
    markAllAsRead,
    deleteNotification,
    clearAllNotifications
  };
}