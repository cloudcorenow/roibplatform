import { z } from 'zod';

// Base validation schemas
export const emailSchema = z.string().email('Invalid email address');
export const phoneSchema = z.string().regex(/^\+?[\d\s\-\(\)]+$/, 'Invalid phone number');
export const currencySchema = z.number().min(0, 'Amount must be positive');
export const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Invalid date format (YYYY-MM-DD)');
export const tenantIdSchema = z.string().regex(/^[a-zA-Z0-9_-]+$/, 'Invalid tenant ID').max(50);
export const userIdSchema = z.string().regex(/^[a-zA-Z0-9_-]+$/, 'Invalid user ID').max(50);

// Time Entry Schemas
export const TimeEntrySchema = z.object({
  tenantId: tenantIdSchema,
  id: z.string().uuid(),
  date: dateSchema,
  client: z.string().min(1, 'Client is required').max(255),
  project: z.string().min(1, 'Project is required').max(255),
  service: z.string().min(1, 'Service is required').max(255),
  durationMin: z.number().int().min(1, 'Duration must be at least 1 minute').max(1440, 'Duration cannot exceed 24 hours'),
  notes: z.string().max(10000, 'Notes too long').optional(),
  isRnD: z.boolean().default(true),
  employeeId: z.string().optional(),
  employeeName: z.string().max(255).optional(),
  projectId: z.string().optional(),
  projectName: z.string().max(255).optional(),
  status: z.enum(['active', 'completed', 'paused']).optional(),
  createdAt: z.string().datetime().optional(),
  updatedAt: z.string().datetime().optional(),
  createdBy: z.string().optional()
});

export const TimeEntryCreateSchema = z.object({
  date: dateSchema,
  client: z.string().min(1, 'Client is required').max(255),
  project: z.string().min(1, 'Project is required').max(255),
  service: z.string().min(1, 'Service is required').max(255),
  durationMin: z.number().int().min(1, 'Duration must be at least 1 minute').max(1440, 'Duration cannot exceed 24 hours'),
  notes: z.string().max(10000, 'Notes too long').optional(),
  isRnD: z.boolean().default(true)
});

export const TimeEntryListResponseSchema = z.object({
  items: z.array(TimeEntrySchema),
  paging: z.object({
    limit: z.number().int().min(1).max(200),
    offset: z.number().int().min(0),
    nextOffset: z.number().int().min(0).nullable(),
    prevOffset: z.number().int().min(0).nullable(),
    from: z.string().optional(),
    to: z.string().optional()
  }),
  total: z.number().int().min(0)
});

// API Error Schema
export const ApiErrorSchema = z.object({
  error: z.string(),
  details: z.string().optional(),
  code: z.string().optional(),
  timestamp: z.string().datetime().optional()
});

// Pagination validation
export const paginationSchema = z.object({
  limit: z.number().int().min(1).max(200).default(50),
  offset: z.number().int().min(0).default(0)
});

// Date range validation
export const dateRangeSchema = z.object({
  from: dateSchema.optional(),
  to: dateSchema.optional()
}).refine(data => {
  if (data.from && data.to) {
    return new Date(data.from) <= new Date(data.to);
  }
  return true;
}, 'Start date must be before end date');

// Client validation
export const clientSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  industry: z.string().max(255).optional(),
  contactPerson: z.string().min(1, 'Contact person is required').max(255),
  email: emailSchema,
  phone: phoneSchema.optional(),
  address: z.string().max(500).optional(),
  taxYear: z.string().regex(/^\d{4}$/, 'Invalid tax year'),
  status: z.enum(['active', 'inactive', 'pending']),
  estimatedCredit: currencySchema.optional()
});

// Project validation
export const projectSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  description: z.string().max(1000).optional(),
  status: z.enum(['active', 'completed', 'on-hold']),
  isRnD: z.boolean().default(true),
  budget: currencySchema.optional(),
  startDate: dateSchema,
  endDate: dateSchema.optional()
});

// Expense validation
export const expenseSchema = z.object({
  description: z.string().min(1, 'Description is required').max(255),
  amount: currencySchema.min(0.01, 'Amount must be greater than 0'),
  category: z.string().min(1, 'Category is required'),
  date: dateSchema,
  vendor: z.string().min(1, 'Vendor is required').max(255),
  isRnD: z.boolean().default(true),
  justification: z.string().max(1000).optional()
});

// User validation
export const userSchema = z.object({
  email: emailSchema,
  firstName: z.string().min(1, 'First name is required').max(100),
  lastName: z.string().min(1, 'Last name is required').max(100),
  roleId: z.string().min(1, 'Role is required'),
  department: z.string().max(100).optional(),
  status: z.enum(['active', 'inactive', 'pending'])
});

// Input sanitization
export function sanitizeInput(input: string, maxLength: number = 1000): string {
  return input
    .trim()
    .substring(0, maxLength)
    .replace(/[<>]/g, '') // Basic XSS protection
    .replace(/\0/g, ''); // Remove null bytes
}

// Validation helper
export function validateAndSanitize<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new Error(`Validation failed: ${result.error.errors.map(e => e.message).join(', ')}`);
  }
  return result.data;
}