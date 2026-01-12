import React, { useState } from 'react';
import { Building2 } from 'lucide-react';
import { Client } from '../../types';
import { useFormValidation } from '../../hooks/useFormValidation';

interface ClientFormProps {
  onSubmit: (client: Omit<Client, 'id'>) => void;
  onCancel: () => void;
  initialData?: Partial<Client>;
}

export const ClientForm: React.FC<ClientFormProps> = ({
  onSubmit,
  onCancel,
  initialData = {}
}) => {
  const [formData, setFormData] = useState({
    name: initialData.name || '',
    industry: initialData.industry || '',
    contactPerson: initialData.contactPerson || '',
    email: initialData.email || '',
    phone: initialData.phone || '',
    address: initialData.address || '',
    taxYear: initialData.taxYear || '2024',
    status: initialData.status || 'active' as const,
    onboardingDate: initialData.onboardingDate || new Date().toISOString().split('T')[0],
    totalProjects: initialData.totalProjects || 0,
    estimatedCredit: initialData.estimatedCredit || 0
  });

  const { errors, validateForm } = useFormValidation({
    name: { required: true, minLength: 2 },
    contactPerson: { required: true, minLength: 2 },
    email: { 
      required: true, 
      pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      custom: (value) => {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          return 'Please enter a valid email address';
        }
        return null;
      }
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (validateForm(formData)) {
      onSubmit(formData);
    }
  };

  const handleChange = (field: keyof typeof formData, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="bg-white p-8 rounded-lg shadow-lg border border-gray-200">
      <div className="flex items-center space-x-3 mb-6">
        <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
          <Building2 className="h-5 w-5 text-white" />
        </div>
        <h3 className="text-xl font-semibold text-slate-800">Add New Client</h3>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Company Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => handleChange('name', e.target.value)}
              className={`w-full border rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                errors.name ? 'border-red-300' : 'border-gray-300'
              }`}
              placeholder="Company name..."
            />
            {errors.name && <p className="text-red-600 text-xs mt-1">{errors.name}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Industry</label>
            <input
              type="text"
              value={formData.industry}
              onChange={(e) => handleChange('industry', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="e.g., Software Development, Biotechnology..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Contact Person *</label>
            <input
              type="text"
              value={formData.contactPerson}
              onChange={(e) => handleChange('contactPerson', e.target.value)}
              className={`w-full border rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                errors.contactPerson ? 'border-red-300' : 'border-gray-300'
              }`}
              placeholder="Primary contact name..."
            />
            {errors.contactPerson && <p className="text-red-600 text-xs mt-1">{errors.contactPerson}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Email *</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => handleChange('email', e.target.value)}
              className={`w-full border rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                errors.email ? 'border-red-300' : 'border-gray-300'
              }`}
              placeholder="contact@company.com"
            />
            {errors.email && <p className="text-red-600 text-xs mt-1">{errors.email}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Phone</label>
            <input
              type="tel"
              value={formData.phone}
              onChange={(e) => handleChange('phone', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="(555) 123-4567"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Tax Year</label>
            <select
              value={formData.taxYear}
              onChange={(e) => handleChange('taxYear', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="2024">2024</option>
              <option value="2023">2023</option>
              <option value="2022">2022</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-slate-700 mb-2">Address</label>
            <input
              type="text"
              value={formData.address}
              onChange={(e) => handleChange('address', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Company address..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Estimated R&D Credit</label>
            <input
              type="number"
              value={formData.estimatedCredit}
              onChange={(e) => handleChange('estimatedCredit', parseFloat(e.target.value) || 0)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="0"
              min="0"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Status</label>
            <select
              value={formData.status}
              onChange={(e) => handleChange('status', e.target.value as any)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="active">Active</option>
              <option value="pending">Pending</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end space-x-4 mt-8 pt-6 border-t border-slate-200">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-slate-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Add Client
          </button>
        </div>
      </form>
    </div>
  );
};