import { useState } from 'react';

export interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  custom?: (value: any) => string | null;
}

export interface ValidationRules {
  [key: string]: ValidationRule;
}

export interface ValidationErrors {
  [key: string]: string;
}

export function useFormValidation(rules: ValidationRules) {
  const [errors, setErrors] = useState<ValidationErrors>({});

  const validateField = (name: string, value: any): string | null => {
    const rule = rules[name];
    if (!rule) return null;

    if (rule.required && (!value || (typeof value === 'string' && value.trim() === ''))) {
      return `${name} is required`;
    }

    if (typeof value === 'string') {
      if (rule.minLength && value.length < rule.minLength) {
        return `${name} must be at least ${rule.minLength} characters`;
      }

      if (rule.maxLength && value.length > rule.maxLength) {
        return `${name} must be no more than ${rule.maxLength} characters`;
      }

      if (rule.pattern && !rule.pattern.test(value)) {
        return `${name} format is invalid`;
      }
    }

    if (rule.custom) {
      return rule.custom(value);
    }

    return null;
  };

  const validateForm = (data: any): boolean => {
    const newErrors: ValidationErrors = {};
    let isValid = true;

    Object.keys(rules).forEach(fieldName => {
      const error = validateField(fieldName, data[fieldName]);
      if (error) {
        newErrors[fieldName] = error;
        isValid = false;
      }
    });

    setErrors(newErrors);
    return isValid;
  };

  const validateSingleField = (name: string, value: any) => {
    const error = validateField(name, value);
    setErrors(prev => ({
      ...prev,
      [name]: error || ''
    }));
    return !error;
  };

  const clearErrors = () => {
    setErrors({});
  };

  return {
    errors,
    validateForm,
    validateSingleField,
    clearErrors
  };
}