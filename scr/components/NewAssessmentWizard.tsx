import React, { useState, useMemo } from 'react';
import {
  Building,
  Target,
  DollarSign,
  Users,
  TrendingUp,
  ChevronRight,
  ChevronLeft,
  Check,
  ChevronDown,
  ChevronUp,
  Award,
  Clock,
  Send,
  Mail,
  ArrowLeft,
  Zap,
  RefreshCcw,
  Play,
} from 'lucide-react';
import { AssessmentFormData, CalculationResults } from '../types/assessment';
import { STATES_ARRAY } from '../data/stateRDCredits';
import {
  calculateAssessmentResults,
  formatCurrency,
  formatPercent,
} from '../utils/assessmentCalculations';

interface NewAssessmentWizardProps {
  clientId: string;
  onUpdateAssessment: (clientId: string, answers: Record<string, any>, score: number) => void;
  answers: Record<string, any>;
  showSuccess: (title: string, message?: string) => void;
}

const INITIAL_FORM_DATA: Partial<AssessmentFormData> = {
  disqualifying_factors: [],
  contact_name: '',
  contact_title: '',
  contact_email: '',
  contact_phone: '',
  business_name: '',
  healthcare_type: 'DPC',
  business_state: 'CA',
  business_age: 0,
  number_of_locations: 1,
  tax_entity_type: 'S-Corp',
  has_related_entities: 'no',
  tech_activities: [],
  clinical_activities: [],
  compliance_activities: [],
  tax_year: '2024',
  accounting_method: 'Cash',
  annual_revenue: 0,
  federal_fee_rate: 0.75,
  state_fee_rate: 0.25,
  prior_year_1_revenue: 0,
  prior_year_1_wages: 0,
  prior_year_2_revenue: 0,
  prior_year_2_wages: 0,
  prior_year_3_revenue: 0,
  prior_year_3_wages: 0,
  prior_year_4_revenue: 0,
  prior_year_4_wages: 0,
  rd_wage_percentage: 20,
  total_annual_wages: 0,
  total_w2_employees: 0,
  supply_expenses: 0,
  contract_research: 0,
  prior_staff_change: 'same',
  rd_credit_years: 0,
  qualifying_activity_years: '0',
  annual_growth_rate: 5,
  planned_initiatives: [],
};

export const NewAssessmentWizard: React.FC<NewAssessmentWizardProps> = ({
  clientId,
  onUpdateAssessment,
  answers,
  showSuccess,
}) => {
  const [formData, setFormData] = useState<Partial<AssessmentFormData>>({
    ...INITIAL_FORM_DATA,
    ...answers,
  });
  const [currentSection, setCurrentSection] = useState(0);
  const [showResults, setShowResults] = useState(false);
  const [expandedResults, setExpandedResults] = useState<Record<string, boolean>>({
    current: true,
    future: false,
    lookback: false,
    timeline: false,
  });

  const calculations = useMemo(
    () => calculateAssessmentResults(formData),
    [formData]
  );

  const hasDisqualifier = formData.disqualifying_factors &&
    formData.disqualifying_factors.some(factor => factor !== 'None of these apply - We are a for-profit US business');
  const canProceed = !hasDisqualifier || formData.disqualifying_factors?.includes('None of these apply - We are a for-profit US business');

  const sections = [
    { id: 'eligibility', title: 'Eligibility', shortTitle: 'Eligibility' },
    { id: 'client_info', title: 'Client Info', shortTitle: 'Client Info' },
    { id: 'rd_activities', title: 'Activities', shortTitle: 'Activities' },
    { id: 'revenue_history', title: 'Revenue', shortTitle: 'Revenue' },
    { id: 'payroll_expenses', title: 'Expenses', shortTitle: 'Expenses' },
    { id: 'growth_projection', title: 'Growth', shortTitle: 'Growth' },
  ];

  const updateField = (field: keyof AssessmentFormData, value: any) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const toggleArrayField = (field: keyof AssessmentFormData, value: string) => {
    setFormData((prev) => {
      const current = (prev[field] as string[]) || [];

      if (field === 'disqualifying_factors') {
        if (value === 'None of these apply - We are a for-profit US business') {
          return { ...prev, [field]: [value] };
        } else {
          const updated = current.includes(value)
            ? current.filter((v) => v !== value)
            : [...current.filter(v => v !== 'None of these apply - We are a for-profit US business'), value];
          return { ...prev, [field]: updated };
        }
      }

      const updated = current.includes(value)
        ? current.filter((v) => v !== value)
        : [...current, value];
      return { ...prev, [field]: updated };
    });
  };

  const handleNext = () => {
    if (currentSection < sections.length - 1) {
      setCurrentSection(currentSection + 1);
    } else {
      completeAssessment();
    }
  };

  const handlePrevious = () => {
    if (currentSection > 0) {
      setCurrentSection(currentSection - 1);
    }
  };

  const completeAssessment = () => {
    setShowResults(true);
    onUpdateAssessment(clientId, formData, calculations.totalCredit);
    showSuccess('Assessment Completed!', 'View your comprehensive R&D analysis below.');
  };

  const progress = ((currentSection + 1) / sections.length) * 100;

  const isPassThrough = ['S-Corp', 'LLC (S-Corp)', 'LLC (Partnership)', 'Partnership', 'Sole Proprietor'].includes(
    formData.tax_entity_type || ''
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-8 py-6 flex items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-600 to-cyan-400 flex items-center justify-center text-white font-bold text-2xl">
            R
          </div>
          <div>
            <div className="text-2xl font-bold" style={{ color: '#0056b3', letterSpacing: '2px' }}>
              ROI BLUEPRINT
            </div>
            <div className="text-xs tracking-widest text-gray-600">
              RESEARCH <span style={{ color: '#0073e6' }}>OPTIMIZE</span> INNOVATE
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-8 py-8">
        {!showResults ? (
          <>
            {/* Title and Progress */}
            <div className="mb-6">
              <div className="flex justify-between items-center mb-4">
                <h1 className="text-4xl font-bold text-gray-900">R&D Tax Credit Assessment</h1>
                <span className="text-lg text-gray-600">Section {currentSection + 1} of {sections.length}</span>
              </div>
              <div className="w-full h-2 bg-gray-300 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 transition-all duration-400"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>

            {/* Step Indicators */}
            <div className="flex justify-between items-center mb-8">
              {sections.map((section, index) => (
                <div key={section.id} className="flex items-center flex-1">
                  <div className="flex flex-col items-center">
                    <div
                      className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-base mb-2 transition-all ${
                        index === currentSection
                          ? 'bg-blue-600 text-white'
                          : index < currentSection
                          ? 'bg-green-600 text-white'
                          : 'bg-gray-400 text-white'
                      }`}
                    >
                      {index < currentSection ? <Check className="w-5 h-5" /> : index + 1}
                    </div>
                    <div className={`text-xs font-medium ${index === currentSection ? 'text-blue-600' : index < currentSection ? 'text-green-600' : 'text-gray-600'}`}>
                      {section.shortTitle}
                    </div>
                  </div>
                  {index < sections.length - 1 && (
                    <div className={`flex-1 h-1 mx-2 mb-6 rounded ${index < currentSection ? 'bg-green-600' : 'bg-gray-300'}`} />
                  )}
                </div>
              ))}
            </div>

            {/* Back Button */}
            {currentSection > 0 && (
              <button
                onClick={handlePrevious}
                className="flex items-center gap-2 px-6 py-2 mb-6 rounded-lg font-semibold bg-gray-800 text-white hover:bg-gray-900 transition"
              >
                <ChevronLeft className="w-5 h-5" />
                Back
              </button>
            )}

            {/* Live Credit Estimate - Only show after first section */}
            {currentSection > 0 && (
              <div className="bg-gradient-to-r from-blue-700 to-blue-600 rounded-lg p-6 mb-8 text-white">
                <div className="text-sm font-semibold uppercase tracking-wider mb-4">
                  LIVE CREDIT ESTIMATE
                </div>
                <div className="grid grid-cols-4 gap-6">
                  <div>
                    <div className="text-3xl font-bold mb-1">{formatCurrency(calculations.totalQRE)}</div>
                    <div className="text-sm opacity-90">Total QRE</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold mb-1">{formatCurrency(calculations.federalCredit)}</div>
                    <div className="text-sm opacity-90">Federal Credit</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold mb-1">{formatCurrency(calculations.stateCredit)}</div>
                    <div className="text-sm opacity-90">State Credit</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold mb-1" style={{ color: '#89c726' }}>
                      {formatCurrency(calculations.totalCredit)}
                    </div>
                    <div className="text-sm opacity-90">Total Credit</div>
                  </div>
                </div>
              </div>
            )}

            {/* Form Section */}
            <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-8">
              {currentSection === 0 && <EligibilitySection formData={formData} toggleArrayField={toggleArrayField} />}
              {currentSection === 1 && <ClientInfoSection formData={formData} updateField={updateField} />}
              {currentSection === 2 && <RDActivitiesSection formData={formData} toggleArrayField={toggleArrayField} />}
              {currentSection === 3 && <RevenueHistorySection formData={formData} updateField={updateField} isPassThrough={isPassThrough} />}
              {currentSection === 4 && <PayrollExpensesSection formData={formData} updateField={updateField} />}
              {currentSection === 5 && <GrowthProjectionSection formData={formData} updateField={updateField} toggleArrayField={toggleArrayField} />}
            </div>

            {/* Navigation */}
            <div className="flex justify-end mt-8">
              <button
                onClick={handleNext}
                disabled={currentSection === 0 && !canProceed}
                className="px-8 py-3 rounded-lg font-semibold flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed bg-blue-600 text-white hover:bg-blue-700 transition"
              >
                {currentSection === sections.length - 1 ? (
                  <>
                    Results Page
                    <Check className="w-5 h-5" />
                  </>
                ) : (
                  <>
                    Next: Continue
                    <ChevronRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>
          </>
        ) : (
          <ResultsDisplay
            formData={formData}
            calculations={calculations}
            expandedResults={expandedResults}
            setExpandedResults={setExpandedResults}
            onReset={() => {
              setShowResults(false);
              setCurrentSection(0);
              setFormData(INITIAL_FORM_DATA);
            }}
          />
        )}
      </div>
    </div>
  );
};

const EligibilitySection: React.FC<any> = ({ formData, toggleArrayField }) => {
  const disqualifiers = [
    { label: 'None of these apply - We are a for-profit US business', isDisqualifying: false },
    { label: 'Non-profit organization', isDisqualifying: true },
    { label: 'Government entity', isDisqualifying: true },
    { label: 'Primary operations outside the US', isDisqualifying: true },
    { label: 'Funded primarily by government grants', isDisqualifying: true },
    { label: 'We do contract research for other companies', isDisqualifying: true },
    { label: 'Customers own our research/development results', isDisqualifying: true },
    { label: 'We only do social sciences/humanities research', isDisqualifying: true },
    { label: 'We only do market research/surveys', isDisqualifying: true },
    { label: 'We only do quality control testing', isDisqualifying: true },
  ];

  return (
    <div>
      <div className="flex items-center gap-3 mb-2">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          1
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Eligibility Quick Check</h2>
          <p className="text-gray-600">Verify qualification before proceeding</p>
        </div>
      </div>

      <div className="mt-8">
        <p className="text-blue-600 font-medium mb-6">
          Confirm basic eligibility requirements are met.
        </p>

        <div className="mb-4">
          <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
            DISQUALIFYING FACTORS
          </h3>
          <p className="text-gray-700 mb-4">Confirm none of these apply to your organization</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {disqualifiers.map((factor) => {
            const isChecked = formData.disqualifying_factors?.includes(factor.label) || false;
            const shouldHighlight = factor.isDisqualifying && isChecked;

            return (
              <label
                key={factor.label}
                className={`flex items-start gap-3 p-4 rounded-lg border-2 cursor-pointer transition ${
                  shouldHighlight
                    ? 'border-red-500 bg-red-50'
                    : isChecked && !factor.isDisqualifying
                    ? 'border-gray-400 bg-gray-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={() => toggleArrayField('disqualifying_factors', factor.label)}
                  className="mt-1 w-4 h-4 flex-shrink-0"
                  style={{ accentColor: '#0073e6' }}
                />
                <div className="flex-1">
                  <span className="text-sm text-gray-800">{factor.label}</span>
                  {factor.isDisqualifying && (
                    <span className="ml-2 inline-block px-2 py-0.5 text-xs font-semibold text-red-700 bg-red-100 rounded">
                      Disqualifying
                    </span>
                  )}
                </div>
              </label>
            );
          })}
        </div>
      </div>
    </div>
  );
};

const ClientInfoSection: React.FC<any> = ({ formData, updateField }) => {
  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          2
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Client & Practice Information</h2>
          <p className="text-gray-600">Basic information about the practice and primary contact</p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4 pb-2 border-b-2 border-blue-200">
          Contact Information
        </h3>
        <div className="grid grid-cols-2 gap-4">
          <FormField label="Contact Name" value={formData.contact_name} onChange={(v) => updateField('contact_name', v)} />
          <FormField label="Contact Title" value={formData.contact_title} onChange={(v) => updateField('contact_title', v)} />
          <FormField label="Contact Email" type="email" value={formData.contact_email} onChange={(v) => updateField('contact_email', v)} />
          <FormField label="Contact Phone" type="tel" value={formData.contact_phone} onChange={(v) => updateField('contact_phone', v)} />
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4 pb-2 border-b-2 border-blue-200">
          Business Information
        </h3>
        <div className="grid grid-cols-2 gap-4">
          <FormField label="Business Name" value={formData.business_name} onChange={(v) => updateField('business_name', v)} />
          <SelectField
            label="Healthcare Type"
            value={formData.healthcare_type}
            onChange={(v) => updateField('healthcare_type', v)}
            options={[
              { value: 'DPC', label: 'Direct Primary Care (DPC)' },
              { value: 'Concierge', label: 'Concierge Medicine' },
              { value: 'Hybrid', label: 'Hybrid (DPC + Traditional)' },
              { value: 'Other', label: 'Other' },
            ]}
          />
          <SelectField
            label="Business State"
            value={formData.business_state}
            onChange={(v) => updateField('business_state', v)}
            options={STATES_ARRAY.map((s) => ({ value: s.value, label: s.label }))}
          />
          <FormField label="Business Age (Years)" type="number" value={formData.business_age} onChange={(v) => updateField('business_age', Number(v))} />
          <FormField label="Number of Locations" type="number" value={formData.number_of_locations} onChange={(v) => updateField('number_of_locations', Number(v))} />
          <SelectField
            label="Tax Entity Type"
            value={formData.tax_entity_type}
            onChange={(v) => updateField('tax_entity_type', v)}
            options={[
              { value: 'S-Corp', label: 'S-Corporation' },
              { value: 'C-Corp', label: 'C-Corporation' },
              { value: 'LLC (S-Corp)', label: 'LLC taxed as S-Corp' },
              { value: 'LLC (C-Corp)', label: 'LLC taxed as C-Corp' },
              { value: 'LLC (Partnership)', label: 'LLC taxed as Partnership' },
              { value: 'Partnership', label: 'Partnership' },
              { value: 'Sole Proprietor', label: 'Sole Proprietor' },
            ]}
          />
          <SelectField
            label="Related Entities (Controlled Group)"
            value={formData.has_related_entities}
            onChange={(v) => updateField('has_related_entities', v)}
            options={[
              { value: 'no', label: 'No related entities' },
              { value: 'yes', label: 'Yes, part of controlled group' },
            ]}
          />
          {formData.has_related_entities === 'yes' && (
            <>
              <FormField label="Group Total Revenue" type="number" prefix="$" value={formData.group_total_revenue} onChange={(v) => updateField('group_total_revenue', Number(v))} />
              <FormField label="Group Total QRE" type="number" prefix="$" value={formData.group_total_qre} onChange={(v) => updateField('group_total_qre', Number(v))} />
            </>
          )}
        </div>
      </div>
    </div>
  );
};

const RDActivitiesSection: React.FC<any> = ({ formData, toggleArrayField }) => {
  const techActivities = [
    'Custom EHR/EMR features or integrations',
    'Telemedicine platform development',
    'Patient engagement apps or portals',
    'AI/ML for diagnostics or triage',
    'Medical device integration',
    'Data analytics or predictive modeling',
    'Custom billing or payment systems',
    'Health data security solutions',
    'Wearable device integration',
    'Custom workflows or automation',
    'Interoperability solutions (FHIR, HL7)',
    'Cloud infrastructure or architecture',
  ];

  const clinicalActivities = [
    'Novel treatment protocols',
    'Care coordination systems',
    'Population health programs',
    'Chronic disease management',
    'Preventive care programs',
    'Quality metrics development',
    'Patient outcome tracking',
    'Care pathway optimization',
    'Risk stratification methods',
    'Evidence-based protocol development',
  ];

  const complianceActivities = [
    'HIPAA compliance solutions',
    'Regulatory compliance automation',
    'Quality assurance systems',
    'Clinical documentation improvement',
    'Audit trail development',
    'Consent management systems',
    'Privacy-enhancing technologies',
    'Compliance reporting systems',
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          3
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">R&D Activities</h2>
          <p className="text-gray-600">Activities we will review for R&D qualification</p>
        </div>
      </div>

      <ActivityGroup
        title="Technology & Software Activities"
        activities={techActivities}
        selectedActivities={formData.tech_activities || []}
        onToggle={(activity) => toggleArrayField('tech_activities', activity)}
      />
      <ActivityGroup
        title="Clinical Protocol & Care Delivery"
        activities={clinicalActivities}
        selectedActivities={formData.clinical_activities || []}
        onToggle={(activity) => toggleArrayField('clinical_activities', activity)}
      />
      <ActivityGroup
        title="Compliance & Process Innovation"
        activities={complianceActivities}
        selectedActivities={formData.compliance_activities || []}
        onToggle={(activity) => toggleArrayField('compliance_activities', activity)}
      />
    </div>
  );
};

const RevenueHistorySection: React.FC<any> = ({ formData, updateField, isPassThrough }) => {
  const currentYear = Number(formData.tax_year) || 2024;
  const year1 = currentYear - 1;
  const year2 = currentYear - 2;
  const year3 = currentYear - 3;
  const year4 = currentYear - 4;

  const avgGrossReceipts = ((formData.prior_year_1_revenue || 0) +
                             (formData.prior_year_2_revenue || 0) +
                             (formData.prior_year_3_revenue || 0)) / 3;

  const avgW2Wages = ((formData.prior_year_1_wages || 0) +
                      (formData.prior_year_2_wages || 0) +
                      (formData.prior_year_3_wages || 0)) / 3;

  const estPriorQRE = avgW2Wages * ((formData.rd_wage_percentage || 20) / 100);

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          4
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Revenue & Tax Information</h2>
          <p className="text-gray-600">Gross receipts and tax liability details</p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          TAX RETURN INFORMATION
        </h3>

        <div className="border-l-4 border-blue-600 bg-blue-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Basic tax return details</strong> - helps us reference the correct line items for your entity type.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Tax Year Being Assessed</label>
            <select
              value={formData.tax_year}
              onChange={(e) => updateField('tax_year', e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
            >
              <option value="2026">2026</option>
              <option value="2025">2025</option>
              <option value="2024">2024</option>
              <option value="2023">2023</option>
            </select>
            <p className="text-xs text-gray-600 italic mt-1">Select the tax year for this assessment</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Accounting Method</label>
            <select
              value={formData.accounting_method}
              onChange={(e) => updateField('accounting_method', e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
            >
              <option value="Cash Basis">Cash Basis</option>
              <option value="Accrual">Accrual</option>
            </select>
            <p className="text-xs text-gray-600 italic mt-1">How income/expenses are reported on tax return</p>
          </div>
        </div>

        <div className="border-l-4 border-blue-600 bg-blue-50 p-4">
          <p className="text-sm text-gray-800">
            <strong>Where to find Gross Receipts on Tax Return:</strong>
            <br />
            Select entity type in Step 1 to see the specific line item
          </p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          GROSS RECEIPTS - TAX YEAR
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Enter gross receipts for the tax year being assessed.</strong> This is total revenue BEFORE any deductions.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Gross Receipts (Tax Year)</label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
              <input
                type="number"
                value={formData.annual_revenue || ''}
                onChange={(e) => updateField('annual_revenue', Number(e.target.value))}
                className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <p className="text-xs text-gray-600 italic mt-1">From tax return - see line item reference above</p>
          </div>

          <div className="border-l-4 border-blue-600 bg-blue-50 p-4 flex items-center">
            <p className="text-sm text-gray-800">
              <strong>Tip:</strong> If tax return not yet filed, use P&L total revenue. We'll true-up during engagement.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 mt-6">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Federal Fee Rate %</label>
            <input
              type="number"
              step="0.01"
              value={formData.federal_fee_rate || 0.75}
              onChange={(e) => updateField('federal_fee_rate', Number(e.target.value))}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-blue-600 mt-1">Default: 0.75%</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">State Fee Rate %</label>
            <input
              type="number"
              step="0.01"
              value={formData.state_fee_rate || 0.25}
              onChange={(e) => updateField('state_fee_rate', Number(e.target.value))}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-blue-600 mt-1">Default: 0.25%</p>
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          PRIOR YEARS - GROSS RECEIPTS & W-2 WAGES
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Enter gross receipts and W-2 wages for each prior year.</strong> Wages are used to estimate prior QRE for credit calculation.
          </p>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <p className="text-sm text-gray-800">
            <strong>Years to enter based on Tax Year {currentYear}:</strong>
            <br />
            Year 1 = <strong>{year1}</strong> | Year 2 = <strong>{year2}</strong> | Year 3 = <strong>{year3}</strong> | Year 4 = <strong>{year4}</strong> (optional)
          </p>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-2">Year 1 Gross Receipts</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_1_revenue || ''}
                  onChange={(e) => updateField('prior_year_1_revenue', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-gray-600 italic mt-1">Most recent prior year</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-blue-700 mb-2">Year 1 W-2 Wages</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_1_wages || ''}
                  onChange={(e) => updateField('prior_year_1_wages', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-blue-600 italic mt-1">For prior QRE estimate</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-2">Year 2 Gross Receipts</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_2_revenue || ''}
                  onChange={(e) => updateField('prior_year_2_revenue', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-gray-600 italic mt-1">2 years ago</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-blue-700 mb-2">Year 2 W-2 Wages</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_2_wages || ''}
                  onChange={(e) => updateField('prior_year_2_wages', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-blue-600 italic mt-1">For prior QRE estimate</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-2">Year 3 Gross Receipts</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_3_revenue || ''}
                  onChange={(e) => updateField('prior_year_3_revenue', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-gray-600 italic mt-1">3 years ago</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-blue-700 mb-2">Year 3 W-2 Wages</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_3_wages || ''}
                  onChange={(e) => updateField('prior_year_3_wages', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-blue-600 italic mt-1">For prior QRE estimate</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-2">Year 4 Gross Receipts (Optional)</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_4_revenue || ''}
                  onChange={(e) => updateField('prior_year_4_revenue', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-gray-600 italic mt-1">For Traditional method</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-blue-700 mb-2">Year 4 W-2 Wages (Optional)</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
                <input
                  type="number"
                  value={formData.prior_year_4_wages || ''}
                  onChange={(e) => updateField('prior_year_4_wages', Number(e.target.value))}
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <p className="text-xs text-blue-600 italic mt-1">For prior QRE estimate</p>
            </div>
          </div>
        </div>

        <div className="border-l-4 border-green-600 bg-green-50 rounded-lg p-6 mt-6">
          <div className="grid grid-cols-3 gap-6 text-center">
            <div>
              <div className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">
                AVG. GROSS RECEIPTS
              </div>
              <div className="text-3xl font-bold text-blue-700">
                {formatCurrency(avgGrossReceipts)}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">
                AVG. W-2 WAGES
              </div>
              <div className="text-3xl font-bold text-blue-700">
                {formatCurrency(avgW2Wages)}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">
                EST. PRIOR QRE
              </div>
              <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
                {formatCurrency(estPriorQRE)}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const PayrollExpensesSection: React.FC<any> = ({ formData, updateField }) => {
  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          5
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Qualifying Expenses</h2>
          <p className="text-gray-600">Staff, wages, and R&D expense information used to estimate your credit opportunity</p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          R&D WAGE PERCENTAGE
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Estimate the percentage of total wages spent on R&D activities.</strong> Default is 20% (conservative). Adjust based on your practice's R&D intensity.
          </p>
        </div>

        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-900 mb-3">R&D Wage Percentage</label>
          <div className="flex items-center gap-6">
            <div className="flex-1">
              <div className="relative">
                <input
                  type="range"
                  min="5"
                  max="50"
                  value={formData.rd_wage_percentage || 20}
                  onChange={(e) => updateField('rd_wage_percentage', Number(e.target.value))}
                  className="w-full h-3 rounded-lg appearance-none cursor-pointer"
                  style={{
                    background: `linear-gradient(to right, #89c726 0%, #89c726 ${((formData.rd_wage_percentage || 20) - 5) * (100 / 45)}%, #e5e7eb ${((formData.rd_wage_percentage || 20) - 5) * (100 / 45)}%, #e5e7eb 100%)`,
                  }}
                />
              </div>
              <div className="flex justify-between text-xs text-gray-600 mt-2">
                <span>5%</span>
                <span>50%</span>
              </div>
            </div>
            <div className="w-24 h-16 rounded-lg flex items-center justify-center font-bold text-2xl text-white" style={{ backgroundColor: '#89c726' }}>
              {formData.rd_wage_percentage || 20}%
            </div>
          </div>
          <p className="text-xs text-gray-600 italic mt-2">Percentage of total wages that qualify as R&D expenses</p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          ANNUAL WAGES
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Current year figures:</strong> Total W-2 wages paid to all employees.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Total W-2 Wages (Tax Year)</label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
              <input
                type="number"
                value={formData.total_annual_wages || ''}
                onChange={(e) => updateField('total_annual_wages', Number(e.target.value))}
                className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <p className="text-xs text-gray-600 italic mt-1">From P&L or payroll records - all wages and salaries</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Total W-2 Employees</label>
            <input
              type="number"
              value={formData.total_w2_employees || ''}
              onChange={(e) => updateField('total_w2_employees', Number(e.target.value))}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-gray-600 italic mt-1">Total headcount of W-2 employees</p>
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          OTHER R&D EXPENSES
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Optional:</strong> Additional expenses that qualify for R&D credit. Leave blank if unsure - we'll identify during engagement.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">R&D Supplies</label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
              <input
                type="number"
                value={formData.supply_expenses || ''}
                onChange={(e) => updateField('supply_expenses', Number(e.target.value))}
                className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <p className="text-xs text-gray-600 italic mt-1">Medical/lab supplies, prototyping materials, software licenses, cloud services (100% qualifies)</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Contract R&D (1099)</label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">$</span>
              <input
                type="number"
                value={formData.contract_research || ''}
                onChange={(e) => updateField('contract_research', Number(e.target.value))}
                className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <p className="text-xs text-gray-600 italic mt-1">Software devs, IT consultants, research contractors (65% qualifies)</p>
          </div>
        </div>

        <div className="border-l-4 border-blue-600 bg-blue-50 p-4">
          <p className="text-sm text-gray-800">
            <strong>Note:</strong> Contractor payments qualify at 65% per IRS rules (auto-calculated). These are estimates - we'll refine during engagement.
          </p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          PRIOR YEAR COMPARISON
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>For lookback estimates:</strong> How did your R&D-eligible staff compare in prior years?
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-900 mb-2">R&D Staff in Prior 3 Years vs Now</label>
          <select
            value={formData.prior_staff_change || 'same'}
            onChange={(e) => updateField('prior_staff_change', e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
          >
            <option value="">Select...</option>
            <option value="more">More R&D staff than prior years</option>
            <option value="same">Similar R&D staffing levels</option>
            <option value="fewer">Fewer R&D staff than prior years</option>
          </select>
          <p className="text-xs text-gray-600 italic mt-1">Accounts for turnover and growth when estimating lookback credits</p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          PRIOR R&D CREDIT HISTORY
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>Important:</strong> You may have been conducting R&D without claiming the credit. Many practices can <strong>look back up to 3 years</strong> to claim missed credits!
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Years Previously Claimed R&D Credits</label>
            <input
              type="number"
              min="0"
              value={formData.rd_credit_years || ''}
              onChange={(e) => updateField('rd_credit_years', Number(e.target.value))}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-gray-600 italic mt-1">Enter 0 if never claimed</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-2">Years with R&D Expenses (prior 3 yrs)</label>
            <select
              value={formData.qualifying_activity_years || '0'}
              onChange={(e) => updateField('qualifying_activity_years', e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
            >
              <option value="0">0 - First year of R&D activity (uses 6% rate)</option>
              <option value="1">1 year of R&D activity</option>
              <option value="2">2 years of R&D activity</option>
              <option value="3">3+ years of R&D activity (uses 14% rate)</option>
            </select>
            <p className="text-xs text-blue-600 italic mt-1">This determines your ASC credit rate - 6% first year vs 14% thereafter</p>
          </div>
        </div>
      </div>
    </div>
  );
};

const GrowthProjectionSection: React.FC<any> = ({ formData, updateField, toggleArrayField }) => {
  const initiatives = [
    'AI and machine learning implementation',
    'Custom software development',
    'Major system integrations',
    'Telehealth platform expansion',
    'Advanced analytics implementation',
    'Mobile app development',
    'Workflow automation projects',
    'Compliance system development',
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-full bg-black text-white flex items-center justify-center font-bold">
          6
        </div>
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Growth & Future R&D</h2>
          <p className="text-gray-600">Growth trajectory and future innovation interests</p>
        </div>
      </div>

      <div className="bg-blue-50 border-l-4 border-blue-600 p-4 mb-6">
        <p className="text-sm text-blue-900">
          <strong>Growth rate drives the 3-Year Future Projection. Innovations help us identify consulting opportunities.</strong>
        </p>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          GROWTH EXPECTATIONS
        </h3>

        <div className="border-l-4 border-gray-900 bg-gray-50 p-4 mb-4">
          <p className="text-sm text-gray-800">
            <strong>ROI Booster:</strong> With improved R&D capture and strategic guidance, many clients see 5-8% effective growth in qualifying expenses beyond their baseline growth.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-900 mb-2">
            Expected Annual Growth Rate <span className="text-gray-600 font-normal">(Enter your projected growth (5% minimum))</span>
          </label>
          <div className="relative w-64">
            <input
              type="number"
              min="5"
              value={formData.annual_growth_rate || ''}
              onChange={(e) => updateField('annual_growth_rate', Number(e.target.value))}
              className="w-full px-4 py-2 pr-12 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">%</span>
          </div>
          <p className="text-xs text-gray-600 italic mt-2">
            Your baseline growth rate. ROI Blueprint typically amplifies R&D capture through better documentation and new qualifying activities.
          </p>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4">
          INNOVATIONS YOU'D LIKE TO PURSUE
        </h3>

        <p className="text-sm text-gray-800 mb-4">Check any initiatives of interest</p>

        <div className="grid grid-cols-2 gap-4">
          {initiatives.map((initiative) => (
            <label
              key={initiative}
              className="flex items-center gap-3 p-3 rounded-lg border border-gray-300 cursor-pointer hover:bg-gray-50 transition"
            >
              <input
                type="checkbox"
                checked={formData.planned_initiatives?.includes(initiative) || false}
                onChange={() => toggleArrayField('planned_initiatives', initiative)}
                className="w-4 h-4 rounded border-gray-300"
                style={{ accentColor: '#0073e6' }}
              />
              <span className="text-sm text-gray-800">{initiative}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
};

const FormField: React.FC<any> = ({
  label,
  value,
  onChange,
  type = 'text',
  prefix,
  suffix,
  helper,
}) => {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <div className="relative">
        {prefix && (
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">
            {prefix}
          </span>
        )}
        <input
          type={type}
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          className={`w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
            prefix ? 'pl-8' : ''
          } ${suffix ? 'pr-12' : ''}`}
        />
        {suffix && (
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 font-medium text-sm">
            {suffix}
          </span>
        )}
      </div>
      {helper && <p className="text-xs text-gray-500 mt-1 italic">{helper}</p>}
    </div>
  );
};

const SelectField: React.FC<any> = ({ label, value, onChange, options }) => {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <select
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
      >
        {options.map((opt: any) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
};

const ActivityGroup: React.FC<any> = ({
  title,
  activities,
  selectedActivities,
  onToggle,
}) => {
  return (
    <div>
      <h3 className="text-sm font-bold text-blue-700 uppercase tracking-wider mb-4 pb-2 border-b-2 border-blue-200">
        {title}
      </h3>
      <div className="grid grid-cols-2 gap-3">
        {activities.map((activity: string) => (
          <label
            key={activity}
            className={`flex items-start gap-3 p-3 rounded-lg border-2 cursor-pointer transition ${
              selectedActivities.includes(activity)
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-300 hover:border-gray-400'
            }`}
          >
            <input
              type="checkbox"
              checked={selectedActivities.includes(activity)}
              onChange={() => onToggle(activity)}
              className="mt-1 w-4 h-4"
              style={{ accentColor: '#0073e6' }}
            />
            <span className="text-sm text-gray-800">{activity}</span>
          </label>
        ))}
      </div>
    </div>
  );
};

const ResultsDisplay: React.FC<any> = ({
  formData,
  calculations,
  expandedResults,
  setExpandedResults,
  onReset,
}) => {
  const toggleSection = (section: string) => {
    setExpandedResults((prev: any) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const currentYear = new Date().getFullYear();
  const taxYear = Number(formData.tax_year) || currentYear;
  const activitiesCount = formData.rd_activities?.length || 0;
  const totalValue7Years = calculations.totalCredit + calculations.threeYearFuture.totalCredits + calculations.lookback.total;

  return (
    <div className="space-y-6">
      {/* Edit Assessment Button */}
      <button
        onClick={onReset}
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white border border-gray-300 hover:bg-gray-50 transition"
      >
        <ArrowLeft className="w-4 h-4" />
        <span className="font-medium">Edit Assessment</span>
      </button>

      {/* ROI Blueprint Badge */}
      <div className="flex justify-center">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-gray-800 text-green-400">
          <Award className="w-5 h-5" />
          <span className="font-bold text-sm">ROI BLUEPRINT ASSESSMENT RESULTS</span>
        </div>
      </div>

      {/* Main Title */}
      <h1 className="text-4xl font-bold text-center text-gray-900">Your R&D Tax Credit Opportunity</h1>

      {/* Info Grid */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="grid grid-cols-4 gap-6">
          <div>
            <div className="text-sm text-gray-600 mb-1">Practice Name</div>
            <div className="font-medium">{formData.business_name || 'Not provided'}</div>
          </div>
          <div>
            <div className="text-sm text-gray-600 mb-1">Contact</div>
            <div className="font-medium">{formData.contact_name || 'Not provided'}</div>
          </div>
          <div>
            <div className="text-sm text-gray-600 mb-1">Tax Year</div>
            <div className="font-medium text-blue-600">{taxYear}</div>
          </div>
          <div>
            <div className="text-sm text-gray-600 mb-1">State</div>
            <div className="font-medium">{formData.business_state || 'N/A'}</div>
          </div>
        </div>
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="text-sm text-gray-600 mb-1">Activities Identified</div>
          <div className="font-medium">{activitiesCount} potential qualifying</div>
        </div>
      </div>

      {/* Total Potential Value (7 Years) */}
      <div className="bg-white rounded-2xl border-2 p-8" style={{ borderColor: '#B8E5E8' }}>
        <div className="flex items-center gap-2 justify-center mb-6">
          <Zap className="w-6 h-6 text-blue-600" />
          <h2 className="text-base font-bold text-blue-600 uppercase tracking-wide">TOTAL POTENTIAL VALUE (7 YEARS)</h2>
        </div>
        <div className="text-7xl font-bold text-center mb-3" style={{ color: '#89c726' }}>
          {formatCurrency(totalValue7Years)}
        </div>
        <div className="text-center text-gray-700 mb-8 text-base">Net benefit after service fees</div>

        <div className="grid grid-cols-4 gap-4">
          <div className="bg-white rounded-xl border-2 p-6 text-center" style={{ borderColor: '#B8E5E8' }}>
            <div className="text-sm text-gray-700 mb-3">{taxYear}</div>
            <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
              {formatCurrency(calculations.totalCredit)}
            </div>
          </div>
          <div className="bg-white rounded-xl border-2 p-6 text-center" style={{ borderColor: '#B8E5E8' }}>
            <div className="text-sm text-gray-700 mb-3">{taxYear + 1}-{taxYear + 3}</div>
            <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
              {formatCurrency(calculations.threeYearFuture.totalCredits)}
            </div>
          </div>
          <div className="bg-white rounded-xl border-2 p-6 text-center" style={{ borderColor: '#B8E5E8' }}>
            <div className="text-sm text-gray-700 mb-3">{taxYear - 3}-{taxYear - 1} Lookback</div>
            <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
              {formatCurrency(calculations.lookback.total)}
            </div>
          </div>
          <div className="bg-white rounded-xl border-2 p-6 text-center" style={{ borderColor: '#B8E5E8' }}>
            <div className="text-sm text-gray-700 mb-3">Your ROI</div>
            <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
              {calculations.roi > 0 ? `${calculations.roi.toFixed(1)}x` : '0x'}
            </div>
          </div>
        </div>
      </div>

      {/* 2026 Tax Credit Section */}
      <ResultSectionNew
        icon={<DollarSign className="w-6 h-6 text-blue-600" />}
        title={`${taxYear} Tax Credit`}
        subtitle={`Estimated R&D credit for tax year ${taxYear}`}
        value={formatCurrency(calculations.totalCredit)}
        valueColor="#89c726"
        expanded={expandedResults.current}
        onToggle={() => toggleSection('current')}
      >
        <div className="space-y-6">
          {/* Qualified Wages Calculation */}
          <div>
            <h4 className="text-sm font-bold text-gray-900 mb-4">QUALIFIED WAGES CALCULATION</h4>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-white rounded-lg border border-gray-300 p-4 text-center">
                <div className="text-sm text-gray-600 mb-2">Total Wages</div>
                <div className="text-2xl font-bold text-gray-900">{formatCurrency(formData.total_annual_wages)}</div>
              </div>
              <div className="bg-white rounded-lg border border-gray-300 p-4 text-center">
                <div className="text-sm text-gray-600 mb-2">R&D Percentage</div>
                <div className="text-2xl font-bold" style={{ color: '#89c726' }}>{formData.rd_wage_percentage}%</div>
              </div>
              <div className="bg-white rounded-lg border border-gray-300 p-4 text-center">
                <div className="text-sm text-gray-600 mb-2">Qualified Wages</div>
                <div className="text-2xl font-bold" style={{ color: '#89c726' }}>{formatCurrency(calculations.qualifiedWages)}</div>
              </div>
            </div>
            <div className="border-l-4 border-gray-900 bg-gray-50 p-3 mt-4">
              <p className="text-sm text-gray-800">
                <strong>Note - Conservative Defaults:</strong> R&D wage percentage default is 20%. Time studies during engagement typically increase qualifying percentages.
              </p>
            </div>
          </div>

          {/* Total QRE */}
          <div>
            <h4 className="text-sm font-bold text-gray-900 mb-4">TOTAL QUALIFIED RESEARCH EXPENSES (QRE)</h4>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-white rounded-lg border border-gray-300 p-4">
                <div className="text-sm text-gray-600 mb-1">Qualified Wages</div>
                <div className="text-2xl font-bold text-gray-900 mb-1">{formatCurrency(calculations.qualifiedWages)}</div>
                <div className="text-xs text-gray-600">Total Wages x {formData.rd_wage_percentage}% R&D</div>
              </div>
              <div className="bg-white rounded-lg border border-gray-300 p-4">
                <div className="text-sm text-gray-600 mb-1">Service Fee QRE</div>
                <div className="text-2xl font-bold text-gray-900 mb-1">{formatCurrency(calculations.serviceFeeQRE || 0)}</div>
                <div className="text-xs text-gray-600">77% of fee (42% Advisory + 35% Cloud)</div>
              </div>
              <div className="bg-white rounded-lg border-2 border-green-600 bg-green-50 p-4">
                <div className="text-sm text-gray-600 mb-1">Total QRE</div>
                <div className="text-2xl font-bold text-gray-900">{formatCurrency(calculations.totalQRE)}</div>
              </div>
            </div>
          </div>

          {/* Calculation Method Comparison */}
          <div>
            <h4 className="text-sm font-bold text-gray-900 mb-4">CALCULATION METHOD COMPARISON</h4>
            <div className="grid grid-cols-2 gap-6">
              <div className={`rounded-lg border-2 p-6 ${calculations.bestMethod === 'ASC' ? 'border-green-600 bg-green-50' : 'border-gray-300 bg-white'}`}>
                {calculations.bestMethod === 'ASC' && (
                  <div className="inline-block px-3 py-1 rounded-full text-xs font-bold bg-green-600 text-white mb-2">
                    RECOMMENDED
                  </div>
                )}
                <div className="font-bold text-lg mb-2">ASC METHOD (Section B)</div>
                <div className="text-4xl font-bold mb-2" style={{ color: '#89c726' }}>
                  {formatCurrency(calculations.ascCredit)}
                </div>
                <div className="text-sm text-gray-600 mb-1">{formatPercent(calculations.ascRate, 0)} x QRE (first year)</div>
                <div className="text-xs text-gray-600">({formatPercent(calculations.ascRate, 0)} first-year rate applied)</div>
              </div>
              <div className={`rounded-lg border-2 p-6 ${calculations.bestMethod === 'Traditional' ? 'border-green-600 bg-green-50' : 'border-gray-300 bg-white'}`}>
                {calculations.bestMethod === 'Traditional' && (
                  <div className="inline-block px-3 py-1 rounded-full text-xs font-bold bg-green-600 text-white mb-2">
                    RECOMMENDED
                  </div>
                )}
                <div className="font-bold text-lg mb-2">TRADITIONAL (Section A)</div>
                <div className="text-4xl font-bold mb-2 text-gray-900">
                  {formatCurrency(calculations.traditionalCredit)}
                </div>
                <div className="text-sm text-gray-600 mb-1">20% x Credit Base (50% rule applied)</div>
                <div className="text-xs text-gray-600">Base {formatCurrency(calculations.traditionalBase)} | Credit Base {formatCurrency(calculations.traditionalBase * 0)}</div>
              </div>
            </div>
            <div className="mt-4 text-sm text-gray-700">
              <strong>ASC is better by {formatCurrency(Math.abs(calculations.ascCredit - calculations.traditionalCredit))}.</strong> ASC is simpler and typically better when you have consistent prior QRE history.
            </div>
          </div>

          {/* Federal and Total Credit */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-white rounded-lg border border-gray-300 p-6 text-center">
              <div className="text-sm text-gray-600 mb-2">FEDERAL CREDIT</div>
              <div className="text-4xl font-bold" style={{ color: '#89c726' }}>
                {formatCurrency(calculations.federalCredit)}
              </div>
              <div className="text-sm text-gray-600 mt-1">ASC Method</div>
            </div>
            <div className="bg-white rounded-lg border-2 border-green-600 bg-green-50 p-6 text-center">
              <div className="text-sm text-gray-600 mb-2">TOTAL CREDIT</div>
              <div className="text-4xl font-bold" style={{ color: '#89c726' }}>
                {formatCurrency(calculations.totalCredit)}
              </div>
              <div className="text-sm text-gray-600 mt-1">Dollar-for-dollar savings</div>
            </div>
          </div>

          {/* Tip Box */}
          <div className="border-l-4 border-blue-600 bg-blue-50 p-4">
            <p className="text-sm text-gray-800">
              <strong>Tip:</strong> Provide your estimated tax liability above to see how much credit you can use this year vs. carry forward to future years.
            </p>
          </div>
        </div>
      </ResultSectionNew>

      {/* 2027-2029 Future Projection */}
      <ResultSectionNew
        icon={<TrendingUp className="w-6 h-6 text-blue-600" />}
        title={`${taxYear + 1}-${taxYear + 3} Future Projection`}
        subtitle={`Projected credits with ${formData.annual_growth_rate}% annual growth`}
        value={formatCurrency(calculations.threeYearFuture.totalCredits)}
        valueColor="#0073e6"
        expanded={expandedResults.future}
        onToggle={() => toggleSection('future')}
      >
        <div className="space-y-4">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-300">
                <th className="text-left py-3 text-sm font-bold text-gray-900">YEAR</th>
                <th className="text-right py-3 text-sm font-bold text-gray-900">FEDERAL</th>
                <th className="text-right py-3 text-sm font-bold text-gray-900">TOTAL</th>
              </tr>
            </thead>
            <tbody>
              {[1, 2, 3].map((year) => {
                const yearKey = `year${year}` as 'year1' | 'year2' | 'year3';
                const yearCredit = calculations.threeYearFuture[yearKey];
                return (
                  <tr key={year} className="border-b border-gray-200">
                    <td className="py-3 text-gray-900">
                      {taxYear + year}{year === 1 ? ' (tax year)' : ''}
                    </td>
                    <td className="py-3 text-right text-blue-600 font-medium">{formatCurrency(yearCredit)}</td>
                    <td className="py-3 text-right text-gray-900 font-bold">{formatCurrency(yearCredit)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="bg-white rounded-lg border-2 border-blue-600 p-4 flex justify-between items-center">
            <div className="font-bold text-lg">3-YEAR FUTURE</div>
            <div className="text-3xl font-bold text-blue-600">{formatCurrency(calculations.threeYearFuture.totalCredits)}</div>
          </div>
          <div className="border-l-4 border-green-600 bg-green-50 p-4">
            <p className="text-sm text-gray-800">
              <strong>Growth Trajectory:</strong> With ROI Blueprint's guidance, many clients see higher effective growth through improved R&D capture, new qualifying activities, and optimized documentation.
            </p>
          </div>
        </div>
      </ResultSectionNew>

      {/* 2023-2025 Lookback */}
      <ResultSectionNew
        icon={<RefreshCcw className="w-6 h-6 text-blue-600" />}
        title={`${taxYear - 3}-${taxYear - 1} Lookback`}
        subtitle={calculations.canLookback && calculations.lookback.total > 0 ? `Available lookback credits` : 'Not available'}
        value={formatCurrency(calculations.lookback.total)}
        valueColor="#0073e6"
        expanded={expandedResults.lookback}
        onToggle={() => toggleSection('lookback')}
      >
        {calculations.canLookback && calculations.lookback.total > 0 ? (
          <div className="space-y-4">
            <div className="bg-blue-50 border-l-4 border-blue-600 p-4">
              <p className="text-sm text-blue-900">
                <strong>Great news!</strong> You may be able to claim R&D credits for prior tax years.
              </p>
            </div>
            {[1, 2, 3].map((year) => {
              const yearKey = `year${year}` as 'year1' | 'year2' | 'year3';
              const yearCredit = calculations.lookback[yearKey];
              if (yearCredit === 0) return null;
              return (
                <div key={year} className="flex justify-between items-center p-4 bg-gray-50 rounded-lg">
                  <div className="font-medium">Prior Year {year}</div>
                  <div className="text-xl font-bold text-blue-700">{formatCurrency(yearCredit)}</div>
                </div>
              );
            })}
            <div className="bg-white rounded-lg border-2 border-blue-600 p-4 flex justify-between items-center">
              <div className="font-bold text-lg">TOTAL LOOKBACK</div>
              <div className="text-3xl font-bold text-blue-600">{formatCurrency(calculations.lookback.total)}</div>
            </div>
          </div>
        ) : (
          <div className="text-center py-8 text-gray-600">
            <p className="font-medium">Previously claimed credits or insufficient business history.</p>
          </div>
        )}
      </ResultSectionNew>

      {/* QSB - Payroll Tax Offset */}
      <div className="bg-white rounded-lg border border-gray-300 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Target className="w-6 h-6 text-blue-600" />
          <h3 className="text-xl font-bold text-blue-700">Qualified Small Business (QSB) - Payroll Tax Offset</h3>
        </div>
        <p className="text-gray-700 mb-4">
          Your practice may be eligible for up to <strong style={{ color: '#89c726' }}>{formatCurrency(Math.min(calculations.totalCredit, 500000))}</strong> annually in payroll tax offsets under IRC Section 41(h). This can provide immediate cash flow benefits via reduced payroll tax deposits (Form 8974).
        </p>
        <div className="bg-blue-50 border-l-4 border-blue-600 p-4">
          <p className="text-sm text-gray-800">
            <strong>QSB Requirements:</strong> Gross receipts under $5M | Maximum 5 lifetime elections | Up to $500,000/year cap
          </p>
        </div>
      </div>

      {/* ROI Blueprint Optimization */}
      <div className="bg-white rounded-lg border border-gray-300 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <TrendingUp className="w-6 h-6 text-green-600" />
            <div>
              <h3 className="text-xl font-bold text-blue-700">ROI Blueprint Optimization Opportunity</h3>
              <p className="text-gray-600">How we maximize your credit potential</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold" style={{ color: '#89c726' }}>
              {formatCurrency(calculations.optimizationPotential || calculations.totalCredit * 0.15)} Potential
            </div>
          </div>
        </div>
      </div>

      {/* Next Steps & Timeline */}
      <ResultSectionNew
        icon={<Clock className="w-6 h-6 text-green-600" />}
        title="Next Steps & Timeline"
        subtitle="Quick reference, getting started, and ROI process"
        value=""
        expanded={expandedResults.timeline}
        onToggle={() => toggleSection('timeline')}
      >
        <div className="space-y-4">
          <div className="bg-blue-50 border-l-4 border-blue-600 p-4">
            <p className="text-sm text-gray-800">
              Our streamlined process makes capturing your R&D credit simple. From kickoff to claim filing, we handle the documentation and compliance work while you focus on your practice.
            </p>
          </div>
        </div>
      </ResultSectionNew>

      {/* Ready to Capture CTA */}
      <div className="bg-blue-50 rounded-lg border-2 border-blue-200 p-8">
        <h2 className="text-3xl font-bold text-center text-gray-900 mb-2">
          Ready to Capture {formatCurrency(totalValue7Years)} in Tax Savings?
        </h2>
        <p className="text-center text-gray-600 mb-8">
          We identified {activitiesCount} potentially qualifying activities. Our team will review and document each for maximum credit.
        </p>

        <div className="grid grid-cols-2 gap-6 max-w-4xl mx-auto">
          <div className="bg-white rounded-lg border-2 border-blue-600 p-8 text-center">
            <div className="w-16 h-16 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-4">
              <Play className="w-8 h-8 text-gray-900" />
            </div>
            <h3 className="text-2xl font-bold text-gray-900 mb-2">Start Engagement</h3>
            <p className="text-gray-600 mb-4">Begin onboarding and activity documentation.</p>
            <p className="text-sm text-blue-600 font-medium mb-6">Est. Annual Fee: {formatCurrency(calculations.adjustedFees)}</p>
            <button className="w-full px-6 py-3 rounded-lg font-bold text-white bg-blue-600 hover:bg-blue-700 transition">
              Start Engagement
            </button>
          </div>

          <div className="bg-white rounded-lg border-2 border-blue-600 p-8 text-center">
            <div className="w-16 h-16 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-4">
              <Send className="w-8 h-8 text-green-600" />
            </div>
            <h3 className="text-2xl font-bold text-gray-900 mb-2">Send Estimate</h3>
            <p className="text-gray-600 mb-4">Email assessment summary to the client.</p>
            <div className="h-8 mb-6"></div>
            <button className="w-full px-6 py-3 rounded-lg font-bold text-white bg-blue-600 hover:bg-blue-700 transition">
              Send Estimate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const ResultSectionNew: React.FC<any> = ({ icon, title, subtitle, value, valueColor, expanded, onToggle, children }) => {
  return (
    <div className="bg-white rounded-lg border-2 border-gray-200 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-6 hover:bg-gray-50 transition"
      >
        <div className="flex items-center gap-3">
          <div className="flex-shrink-0">{icon}</div>
          <div className="text-left">
            <h3 className="text-xl font-bold text-blue-700">{title}</h3>
            <p className="text-sm text-gray-600">{subtitle}</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {value && (
            <div className="text-3xl font-bold" style={{ color: valueColor || '#0073e6' }}>
              {value}
            </div>
          )}
          {expanded ? (
            <ChevronUp className="w-6 h-6 text-gray-600 flex-shrink-0" />
          ) : (
            <ChevronDown className="w-6 h-6 text-gray-600 flex-shrink-0" />
          )}
        </div>
      </button>
      {expanded && <div className="p-6 border-t-2 border-gray-200 bg-gray-50">{children}</div>}
    </div>
  );
};

const ResultSection: React.FC<any> = ({ title, expanded, onToggle, children }) => {
  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-6 hover:bg-gray-50 transition"
      >
        <h3 className="text-xl font-bold text-blue-700">{title}</h3>
        {expanded ? (
          <ChevronUp className="w-6 h-6 text-gray-600" />
        ) : (
          <ChevronDown className="w-6 h-6 text-gray-600" />
        )}
      </button>
      {expanded && <div className="p-6 border-t border-gray-200">{children}</div>}
    </div>
  );
};
