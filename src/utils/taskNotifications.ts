import { Task } from '../types/tasks';

export interface TaskNotificationData {
  type: 'task_assigned' | 'task_updated' | 'task_completed' | 'task_overdue' | 'comment_added';
  taskId: string;
  taskTitle: string;
  projectName?: string;
  assignedUsers: string[];
  createdBy: string;
  priority: Task['priority'];
  dueDate?: string;
}

export function generateTaskNotifications(
  notificationData: TaskNotificationData,
  currentUserId: string
): Array<{
  type: TaskNotificationData['type'];
  title: string;
  message: string;
  priority: 'low' | 'medium' | 'high';
  userId: string;
  relatedId: string;
}> {
  const notifications = [];
  const { type, taskId, taskTitle, projectName, assignedUsers, createdBy, priority, dueDate } = notificationData;

  const getPriorityLevel = (taskPriority: Task['priority']): 'low' | 'medium' | 'high' => {
    switch (taskPriority) {
      case 'urgent': return 'high';
      case 'high': return 'medium';
      default: return 'low';
    }
  };

  const projectContext = projectName ? ` in ${projectName}` : '';

  switch (type) {
    case 'task_assigned':
      assignedUsers.forEach(userId => {
        if (userId !== currentUserId) {
          notifications.push({
            type: 'task_assigned',
            title: 'New Task Assignment',
            message: `You've been assigned to "${taskTitle}"${projectContext}`,
            priority: getPriorityLevel(priority),
            userId,
            relatedId: taskId
          });
        }
      });
      break;

    case 'task_completed':
      // Notify creator and all assignees
      const completionNotifyUsers = [createdBy, ...assignedUsers].filter(userId => userId !== currentUserId);
      completionNotifyUsers.forEach(userId => {
        notifications.push({
          type: 'task_completed',
          title: 'Task Completed',
          message: `"${taskTitle}" has been completed${projectContext}`,
          priority: 'medium',
          userId,
          relatedId: taskId
        });
      });
      break;

    case 'task_updated':
      // Notify assignees about updates
      assignedUsers.forEach(userId => {
        if (userId !== currentUserId) {
          notifications.push({
            type: 'task_updated',
            title: 'Task Updated',
            message: `"${taskTitle}" has been updated${projectContext}`,
            priority: 'low',
            userId,
            relatedId: taskId
          });
        }
      });
      break;

    case 'task_overdue':
      // Notify assignees about overdue tasks
      assignedUsers.forEach(userId => {
        notifications.push({
          type: 'task_overdue',
          title: 'Task Overdue',
          message: `"${taskTitle}" is overdue${dueDate ? ` (due ${dueDate})` : ''}`,
          priority: 'high',
          userId,
          relatedId: taskId
        });
      });
      break;

    case 'comment_added':
      // Notify creator and assignees about new comments
      const commentNotifyUsers = [createdBy, ...assignedUsers].filter(userId => userId !== currentUserId);
      commentNotifyUsers.forEach(userId => {
        notifications.push({
          type: 'comment_added',
          title: 'New Comment',
          message: `New comment added to "${taskTitle}"${projectContext}`,
          priority: 'low',
          userId,
          relatedId: taskId
        });
      });
      break;
  }

  return notifications;
}

export function checkOverdueTasks(tasks: Task[]): TaskNotificationData[] {
  const now = new Date();
  const overdueNotifications: TaskNotificationData[] = [];
  
  // Only check tasks that became overdue in the last 24 hours to prevent spam
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  tasks.forEach(task => {
    if (task.dueDate && task.status !== 'completed' && task.status !== 'cancelled') {
      const dueDate = new Date(task.dueDate);
      // Only notify if task became overdue recently (within last 24 hours)
      if (dueDate < now && dueDate >= oneDayAgo) {
        overdueNotifications.push({
          type: 'task_overdue',
          taskId: task.id,
          taskTitle: task.title,
          projectName: task.projectName,
          assignedUsers: task.assignedTo,
          createdBy: task.createdBy,
          priority: task.priority,
          dueDate: task.dueDate
        });
      }
    }
  });

  return overdueNotifications;
}