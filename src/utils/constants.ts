// Application constants

export const APP_CONFIG = {
  name: 'ROI BLUEPRINT',
  version: '1.0.0',
  description: 'R&D Tax Credit Platform',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  supportedFileTypes: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'image/jpeg',
    'image/png',
    'image/gif',
    'text/plain'
  ]
} as const;

export const API_CONFIG = {
  timeout: 10000, // 10 seconds
  retryAttempts: 3,
  retryDelay: 1000, // 1 second base delay
  maxRetryDelay: 10000 // 10 seconds max delay
} as const;

export const PAGINATION_CONFIG = {
  defaultLimit: 50,
  maxLimit: 200,
  defaultOffset: 0
} as const;

export const VALIDATION_CONFIG = {
  maxStringLength: 1000,
  maxTextLength: 10000,
  maxFileNameLength: 255,
  maxEmailLength: 254,
  maxPhoneLength: 20
} as const;

export const CACHE_CONFIG = {
  shortTerm: 300, // 5 minutes
  mediumTerm: 1800, // 30 minutes
  longTerm: 3600, // 1 hour
  veryLongTerm: 86400 // 24 hours
} as const;

export const DEMO_CREDENTIALS = [
  { email: 'admin@roiblueprint.com', password: 'admin123', role: 'Administrator' },
  { email: 'manager@roiblueprint.com', password: 'manager123', role: 'Project Manager' },
  { email: 'dev@roiblueprint.com', password: 'dev123', role: 'Developer' }
] as const;

export const R_AND_D_CATEGORIES = [
  'Algorithm Development',
  'System Architecture',
  'Performance Optimization',
  'Security Research',
  'User Experience Research',
  'Data Analysis',
  'Machine Learning',
  'Prototype Development',
  'Technical Documentation',
  'Quality Assurance'
] as const;

export const EXPENSE_CATEGORIES = [
  'Equipment',
  'Software',
  'Supplies',
  'Contractor Services',
  'Travel',
  'Training',
  'Research Materials',
  'Cloud Services',
  'Other'
] as const;