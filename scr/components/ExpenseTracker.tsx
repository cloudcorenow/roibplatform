import React, { useState } from 'react';
import { Plus, Search, DollarSign, Calendar, Tag, FileText, Receipt, Building, CheckCircle, XCircle, TrendingUp, CreditCard } from 'lucide-react';
import { Expense, Project } from '../types';
import { formatCurrency, formatDate } from '../utils/formatters';

interface ExpenseTrackerProps {
  expenses: Expense[];
  projects: Project[];
  onAddExpense: (expense: Omit<Expense, 'id'>) => void;
  onUpdateExpense: (id: string, updates: Partial<Expense>) => void;
  onDeleteExpense: (id: string) => void;
}

export const ExpenseTracker: React.FC<ExpenseTrackerProps> = ({
  expenses,
  projects,
  onAddExpense,
  onUpdateExpense,
  onDeleteExpense
}) => {
  const [showNewExpenseForm, setShowNewExpenseForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterRnD, setFilterRnD] = useState<string>('all');
  const [newExpense, setNewExpense] = useState({
    description: '',
    amount: 0,
    category: 'Equipment',
    date: new Date().toISOString().split('T')[0],
    projectId: '',
    isRnD: true,
    vendor: '',
    justification: ''
  });

  const categories = ['Equipment', 'Software', 'Supplies', 'Contractor Services', 'Travel', 'Training', 'Other'];

  const filteredExpenses = expenses.filter(expense => {
    const matchesSearch = expense.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         expense.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         expense.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = filterCategory === 'all' || expense.category === filterCategory;
    const matchesRnD = filterRnD === 'all' || 
                      (filterRnD === 'rnd' && expense.isRnD) ||
                      (filterRnD === 'non-rnd' && !expense.isRnD);
    return matchesSearch && matchesCategory && matchesRnD;
  });

  const handleAddExpense = () => {
    console.log('handleAddExpense called in component');
    if (!newExpense.description || !newExpense.vendor || newExpense.amount <= 0) return;
    
    console.log('Calling onAddExpense with:', newExpense);
    onAddExpense(newExpense);

    setNewExpense({
      description: '',
      amount: 0,
      category: 'Equipment',
      date: new Date().toISOString().split('T')[0],
      projectId: '',
      isRnD: true,
      vendor: '',
      justification: ''
    });
    setShowNewExpenseForm(false);
  };

  const handleButtonClick = () => {
    console.log('Add Expense button clicked!');
    console.log('Current showNewExpenseForm state:', showNewExpenseForm);
    setShowNewExpenseForm(true);
    console.log('Set showNewExpenseForm to true');
  };
  const totalExpenses = filteredExpenses.reduce((total, expense) => total + expense.amount, 0);
  const rndExpenses = filteredExpenses.filter(expense => expense.isRnD).reduce((total, expense) => total + expense.amount, 0);
  const rndPercentage = totalExpenses > 0 ? Math.round((rndExpenses / totalExpenses) * 100) : 0;

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div className="flex-1 min-w-0">
          <h1 className="text-4xl font-bold text-slate-800">
            Expense Tracking
          </h1>
          <p className="text-slate-600 mt-2 text-sm sm:text-base">Monitor and categorize your R&D expenses for tax credit optimization</p>
        </div>
        <button
          onClick={handleButtonClick}
          className="bg-blue-600 text-white px-4 sm:px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 shadow-sm min-h-[44px]"
        >
          <Plus className="h-4 w-4 sm:mr-2" />
          <span className="hidden sm:inline">Add Expense</span>
        </button>
      </div>


      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 lg:gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-3 flex items-center">
            <DollarSign className="h-4 w-4 mr-1" />
            Total Expenses
          </h4>
          <p className="text-xl sm:text-2xl lg:text-3xl font-bold text-blue-600">{formatCurrency(totalExpenses)}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-3 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            R&D Expenses
          </h4>
          <p className="text-xl sm:text-2xl lg:text-3xl font-bold text-green-600">{formatCurrency(rndExpenses)}</p>
        </div>
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-gray-700 mb-3 flex items-center">
            <TrendingUp className="h-4 w-4 mr-1" />
            R&D Percentage
          </h4>
          <p className="text-xl sm:text-2xl lg:text-3xl font-bold text-slate-700">{rndPercentage}%</p>
        </div>
      </div>

      {showNewExpenseForm && (
        <div className="bg-white p-4 sm:p-6 rounded-lg shadow-lg border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <CreditCard className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">Add New Expense</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Description</label>
              <input
                type="text"
                value={newExpense.description}
                onChange={(e) => setNewExpense({ ...newExpense, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                placeholder="Expense description..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Amount</label>
              <input
                type="number"
                value={newExpense.amount}
                onChange={(e) => setNewExpense({ ...newExpense, amount: parseFloat(e.target.value) || 0 })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                min="0"
                step="0.01"
                inputMode="decimal"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Category</label>
              <select
                value={newExpense.category}
                onChange={(e) => setNewExpense({ ...newExpense, category: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                {categories.map(category => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Date</label>
              <input
                type="date"
                value={newExpense.date}
                onChange={(e) => setNewExpense({ ...newExpense, date: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Vendor</label>
              <input
                type="text"
                value={newExpense.vendor}
                onChange={(e) => setNewExpense({ ...newExpense, vendor: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                placeholder="Vendor name..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Project (Optional)</label>
              <select
                value={newExpense.projectId}
                onChange={(e) => setNewExpense({ ...newExpense, projectId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                <option value="">No specific project</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-sm font-medium text-slate-700 mb-2">R&D Justification</label>
              <textarea
                value={newExpense.justification}
                onChange={(e) => setNewExpense({ ...newExpense, justification: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[88px]"
                rows={3}
                placeholder="Explain how this expense relates to R&D activities..."
              />
            </div>
            <div className="sm:col-span-2 flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newExpense.isRnD}
                  onChange={(e) => setNewExpense({ ...newExpense, isRnD: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-slate-700 font-medium">R&D Qualified Expense</span>
              </label>
            </div>
          </div>
          <div className="flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-3 mt-6">
            <button
              onClick={() => setShowNewExpenseForm(false)}
              className="w-full sm:w-auto px-4 py-3 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 min-h-[44px]"
            >
              Cancel
            </button>
            <button
              onClick={handleAddExpense}
              className="w-full sm:w-auto px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 min-h-[44px]"
            >
              Add Expense
            </button>
          </div>
        </div>
      )}

      <div className="bg-white p-4 sm:p-6 rounded-lg shadow-md border border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Receipt className="h-4 w-4 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">Expense Records</h3>
          </div>
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <div className="relative">
              <Search className="h-4 w-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                placeholder="Search expenses..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full sm:w-auto pl-9 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              />
            </div>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="w-full sm:w-auto border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
            >
              <option value="all">All Categories</option>
              {categories.map(category => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
            <select
              value={filterRnD}
              onChange={(e) => setFilterRnD(e.target.value)}
              className="w-full sm:w-auto border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
            >
              <option value="all">All Expenses</option>
              <option value="rnd">R&D Only</option>
              <option value="non-rnd">Non-R&D Only</option>
            </select>
          </div>
        </div>

        <div className="space-y-4">
          {filteredExpenses.map((expense) => {
            const project = projects.find(p => p.id === expense.projectId);
            
            return (
              <div key={expense.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between space-y-3 sm:space-y-0">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="font-semibold text-slate-800">{expense.description}</h4>
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-600">
                        {expense.category}
                      </span>
                      {expense.isRnD && (
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-green-100 text-green-800">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          R&D
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-4 text-sm text-slate-600">
                      <div className="flex items-center">
                        <Building className="h-4 w-4 mr-1" />
                        <span className="font-medium">{expense.vendor}</span>
                      </div>
                      <div className="flex items-center">
                        <Calendar className="h-4 w-4 mr-1" />
                        <span className="font-medium">{formatDate(expense.date)}</span>
                      </div>
                      {project && (
                        <div className="flex items-center">
                          <Tag className="h-4 w-4 mr-1" />
                          <span className="font-medium">{project.name}</span>
                        </div>
                      )}
                    </div>
                    {expense.justification && (
                      <p className="text-sm text-slate-600 mt-3 italic bg-gray-50 p-3 rounded-lg">{expense.justification}</p>
                    )}
                  </div>
                  <div className="flex items-center justify-between sm:flex-col sm:text-right sm:ml-4">
                    <p className="text-lg font-semibold text-slate-800">{formatCurrency(expense.amount)}</p>
                    <button
                      onClick={() => onDeleteExpense(expense.id)}
                      className="text-red-600 hover:text-red-700 text-sm sm:mt-2 font-medium hover:bg-red-50 px-3 py-2 rounded transition-colors min-h-[44px]"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
          {filteredExpenses.length === 0 && (
            <div className="text-center py-12 text-slate-500">
              <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Receipt className="h-8 w-8 text-indigo-500" />
              </div>
              <p className="text-lg font-medium">No expenses found</p>
              <p className="text-sm mt-1">Try adjusting your search criteria</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};