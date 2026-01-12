import React, { useState, useEffect } from 'react';
import { Target, ChevronRight, ChevronLeft, CheckCircle, AlertTriangle, DollarSign, TrendingUp, Award, Building, Users, Shield, ChevronDown } from 'lucide-react';

interface AssessmentWizardProps {
  clientId: string;
  onUpdateAssessment: (clientId: string, answers: Record<string, any>, score: number) => void;
  answers: Record<string, any>;
  showSuccess: (title: string, message?: string) => void;
}

const SERVICE_FEES = {
  FEDERAL_RATE: 0.015,
  STATE_ADDON: 0.005,
  ADVISORY_SPLIT: 0.65,
  CLOUD_SPLIT: 0.35,
  CONTRACT_RESEARCH_RATE: 0.65
};

const STATE_CREDIT_RATES: Record<string, { rate: number; cap: number; label: string }> = {
  'AL': { rate: 0.05, cap: 50000, label: 'Alabama' },
  'AZ': { rate: 0.24, cap: 0, label: 'Arizona' },
  'AR': { rate: 0.10, cap: 100000, label: 'Arkansas' },
  'CA': { rate: 0.15, cap: 0, label: 'California' },
  'CO': { rate: 0.03, cap: 250000, label: 'Colorado' },
  'CT': { rate: 0.20, cap: 0, label: 'Connecticut' },
  'GA': { rate: 0.10, cap: 0, label: 'Georgia' },
  'HI': { rate: 0.20, cap: 2000000, label: 'Hawaii' },
  'ID': { rate: 0.03, cap: 200000, label: 'Idaho' },
  'IL': { rate: 0.065, cap: 2000000, label: 'Illinois' },
  'IN': { rate: 0.15, cap: 1000000, label: 'Indiana' },
  'IA': { rate: 0.065, cap: 100000, label: 'Iowa' },
  'KS': { rate: 0.065, cap: 0, label: 'Kansas' },
  'KY': { rate: 0.05, cap: 0, label: 'Kentucky' },
  'LA': { rate: 0.40, cap: 300000, label: 'Louisiana' },
  'ME': { rate: 0.05, cap: 100000, label: 'Maine' },
  'MD': { rate: 0.10, cap: 0, label: 'Maryland' },
  'MA': { rate: 0.10, cap: 0, label: 'Massachusetts' },
  'MO': { rate: 0.065, cap: 280000, label: 'Missouri' },
  'NJ': { rate: 0.10, cap: 1000000, label: 'New Jersey' },
  'NM': { rate: 0.04, cap: 6000000, label: 'New Mexico' },
  'NY': { rate: 0.09, cap: 3000000, label: 'New York' },
  'NC': { rate: 0.0325, cap: 2250000, label: 'North Carolina' },
  'OH': { rate: 0.085, cap: 2000000, label: 'Ohio' },
  'OK': { rate: 0.10, cap: 300000, label: 'Oklahoma' },
  'OR': { rate: 0.05, cap: 2000000, label: 'Oregon' },
  'RI': { rate: 0.165, cap: 75000, label: 'Rhode Island' },
  'SC': { rate: 0.05, cap: 0, label: 'South Carolina' },
  'UT': { rate: 0.05, cap: 150000, label: 'Utah' },
  'VT': { rate: 0.27, cap: 25000, label: 'Vermont' },
  'VA': { rate: 0.15, cap: 0, label: 'Virginia' },
  'WV': { rate: 0.10, cap: 0, label: 'West Virginia' },
  'WI': { rate: 0.05, cap: 0, label: 'Wisconsin' }
};

export const AssessmentWizard: React.FC<AssessmentWizardProps> = ({
  clientId,
  onUpdateAssessment,
  answers,
  showSuccess
}) => {
  const [currentSection, setCurrentSection] = useState(0);
  const [responses, setResponses] = useState<Record<string, any>>(answers);
  const [isDisqualified, setIsDisqualified] = useState(false);
  const [disqualificationReasons, setDisqualificationReasons] = useState<Array<{ label: string; reason: string }>>([]);
  const [showResults, setShowResults] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({ current: true });

  const sections = [
    {
      id: 'client_info',
      title: 'Client & Practice Information',
      subtitle: 'Basic information about the practice and primary contact',
      icon: <Building className="w-5 h-5" />
    },
    {
      id: 'qualification',
      title: 'Eligibility Screening',
      subtitle: 'Confirm basic eligibility for R&D tax credits',
      icon: <Shield className="w-5 h-5" />
    },
    {
      id: 'revenue_history',
      title: 'Revenue & R&D History',
      subtitle: 'Financial information and prior R&D credit history',
      icon: <DollarSign className="w-5 h-5" />
    },
    {
      id: 'payroll_expenses',
      title: 'Payroll & Expenses',
      subtitle: 'Staff composition and wage information',
      icon: <Users className="w-5 h-5" />
    },
    {
      id: 'rd_activities',
      title: 'Potentially Qualifying Activities',
      subtitle: 'Activities we will review for R&D qualification',
      icon: <Target className="w-5 h-5" />
    },
    {
      id: 'growth_projection',
      title: 'Growth & Future R&D',
      subtitle: 'Planned investments and growth trajectory',
      icon: <TrendingUp className="w-5 h-5" />
    }
  ];

  useEffect(() => {
    const reasons = checkDisqualification();
    setIsDisqualified(reasons.length > 0);
    setDisqualificationReasons(reasons);

    if (currentSection === 1) {
      const score = calculateScore();
      onUpdateAssessment(clientId, responses, score);
    }
  }, [responses]);

  const checkDisqualification = () => {
    const factors = responses.disqualifying_factors || [];
    const disqualifiers: Array<{ label: string; reason: string }> = [];
    const badValues = ['nonprofit', 'government', 'work_outside_us', 'government_funded', 'contract_research', 'customer_owns_results', 'only_social_sciences', 'only_market_research', 'only_quality_testing'];

    badValues.forEach(val => {
      if (factors.includes(val)) {
        const reasons: Record<string, { label: string; reason: string }> = {
          'nonprofit': { label: 'Non-profit organization', reason: 'Non-profit organizations are not eligible for R&D tax credits' },
          'government': { label: 'Government entity', reason: 'Government entities cannot claim R&D tax credits' },
          'work_outside_us': { label: 'Primary operations outside the US', reason: 'R&D must be performed primarily in the United States' },
          'government_funded': { label: 'Funded primarily by government grants', reason: 'Government grant-funded research is excluded' },
          'contract_research': { label: 'We do contract research for other companies', reason: 'Contract research typically benefits the customer' },
          'customer_owns_results': { label: 'Customers own our research/development results', reason: 'You must own the intellectual property' },
          'only_social_sciences': { label: 'We only do social sciences/humanities research', reason: 'Social sciences/humanities research is excluded' },
          'only_market_research': { label: 'We only do market research/surveys', reason: 'Market research is excluded' },
          'only_quality_testing': { label: 'We only do quality control testing', reason: 'Quality control testing is excluded' }
        };
        disqualifiers.push(reasons[val]);
      }
    });

    return disqualifiers;
  };

  const calculateAssessment = () => {
    const revenue = parseCurrency(responses.annual_revenue);
    const totalWages = parseCurrency(responses.total_annual_wages) || (revenue * 0.55);

    const staff = {
      high_level: parseInt(responses.high_level_staff) || 0,
      supervisors: parseInt(responses.supervisor_director) || 0,
      support: parseInt(responses.support_staff) || 0
    };

    const totalStaff = Object.values(staff).reduce((a, b) => a + b, 0);

    let qualifiedWages = 0;
    if (totalStaff > 0 && totalWages > 0) {
      const avgWage = totalWages / totalStaff;
      qualifiedWages += staff.high_level * avgWage * 0.65;
      qualifiedWages += staff.supervisors * avgWage * 0.55;
      qualifiedWages += staff.support * avgWage * 0.35;
    }

    const stateData = STATE_CREDIT_RATES[responses.business_state] || { rate: 0, cap: 0, label: 'N/A' };
    const hasStateCredit = stateData.rate > 0;

    const feeRate = hasStateCredit
      ? SERVICE_FEES.FEDERAL_RATE + SERVICE_FEES.STATE_ADDON
      : SERVICE_FEES.FEDERAL_RATE;
    const serviceFee = revenue * feeRate;

    const advisoryFee = serviceFee * SERVICE_FEES.ADVISORY_SPLIT;
    const cloudFee = serviceFee * SERVICE_FEES.CLOUD_SPLIT;

    const advisoryQRE = advisoryFee * SERVICE_FEES.CONTRACT_RESEARCH_RATE;
    const cloudQRE = cloudFee;
    const feeQRE = advisoryQRE + cloudQRE;

    const totalQRE = qualifiedWages + feeQRE;

    const federalCredit = Math.round(totalQRE * 0.14);

    let stateCredit = 0;
    if (hasStateCredit) {
      stateCredit = Math.round(totalQRE * stateData.rate);
      if (stateData.cap > 0) stateCredit = Math.min(stateCredit, stateData.cap);
    }

    const totalCredit = federalCredit + stateCredit;

    const yearsInBusiness = parseInt(responses.business_age) || 0;
    const yearsClaimed = parseInt(responses.rd_credit_years) || 0;
    const canLookback = yearsClaimed === 0 && yearsInBusiness >= 1;
    const lookbackYears = Math.min(3, yearsInBusiness);

    const isStartupEligible = revenue < 5000000 && yearsClaimed < 5;
    const payrollOffset = isStartupEligible ? Math.min(federalCredit, 250000) : 0;

    const growthRate = Math.max(parseFloat(responses.annual_growth_rate) || 3, 3) / 100;
    const threeYearFuture = { years: [] as any[], totalCredits: 0, growthRate: growthRate * 100 };
    for (let i = 1; i <= 3; i++) {
      const yearFed = Math.round(federalCredit * Math.pow(1 + growthRate, i));
      const yearState = Math.round(stateCredit * Math.pow(1 + growthRate, i));
      threeYearFuture.years.push({ year: i, federal: yearFed, state: yearState, total: yearFed + yearState });
      threeYearFuture.totalCredits += yearFed + yearState;
    }

    const lookback = { available: canLookback, years: [] as any[], total: 0 };
    if (canLookback) {
      const currentYear = new Date().getFullYear();
      for (let i = 1; i <= lookbackYears; i++) {
        const mult = Math.pow(0.95, i);
        const yearFed = Math.round(federalCredit * mult);
        const yearState = Math.round(stateCredit * mult);
        lookback.years.push({ taxYear: currentYear - i, federal: yearFed, state: yearState, total: yearFed + yearState });
        lookback.total += yearFed + yearState;
      }
    }

    const currentFee = Math.round(serviceFee);
    let futureFee = 0;
    for (let i = 1; i <= 3; i++) {
      futureFee += Math.round(serviceFee * Math.pow(1 + growthRate, i));
    }

    let lookbackFee = 0;
    if (canLookback) {
      for (let i = 1; i <= lookbackYears; i++) {
        lookbackFee += Math.round(serviceFee * Math.pow(0.95, i));
      }
    }

    const totalFees = currentFee + futureFee + lookbackFee;
    const totalGross = totalCredit + threeYearFuture.totalCredits + lookback.total;
    const totalNet = totalGross - totalFees;

    const techActivities = (responses.tech_activities || []).length;
    const clinicalActivities = (responses.clinical_activities || []).length;
    const complianceActivities = (responses.compliance_activities || []).length;
    const totalActivities = techActivities + clinicalActivities + complianceActivities;

    return {
      revenue,
      totalWages,
      totalStaff,
      qualifiedWages: Math.round(qualifiedWages),
      feeQRE: Math.round(feeQRE),
      advisoryQRE: Math.round(advisoryQRE),
      cloudQRE: Math.round(cloudQRE),
      totalQRE: Math.round(totalQRE),
      federalCredit,
      stateCredit,
      totalCredit,
      stateData,
      hasStateCredit,
      feeRate: feeRate * 100,
      serviceFee: Math.round(serviceFee),
      advisoryFee: Math.round(advisoryFee),
      cloudFee: Math.round(cloudFee),
      yearsInBusiness,
      yearsClaimed,
      isStartupEligible,
      payrollOffset,
      threeYearFuture,
      lookback,
      fees: {
        current: currentFee,
        future: futureFee,
        lookback: lookbackFee,
        total: totalFees,
        gross: totalGross,
        net: totalNet
      },
      activities: {
        tech: techActivities,
        clinical: clinicalActivities,
        compliance: complianceActivities,
        total: totalActivities
      }
    };
  };

  const calculateScore = (): number => {
    if (isDisqualified) return 0;
    const calc = calculateAssessment();
    return Math.round((calc.totalCredit / 100000) * 100);
  };

  const parseCurrency = (value: any): number => {
    if (!value) return 0;
    return parseFloat(String(value).replace(/[^0-9.-]/g, '')) || 0;
  };

  const formatCurrency = (value: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(value || 0);
  };

  const formatPercent = (value: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'percent',
      minimumFractionDigits: 1,
      maximumFractionDigits: 1
    }).format(value || 0);
  };

  const handleInput = (id: string, value: any) => {
    const newResponses = { ...responses, [id]: value };
    setResponses(newResponses);

    const score = calculateScore();
    onUpdateAssessment(clientId, newResponses, score);
  };

  const handleCheckbox = (fieldId: string, value: string) => {
    const current = responses[fieldId] || [];
    const newValue = current.includes(value)
      ? current.filter((v: string) => v !== value)
      : [...current, value];
    handleInput(fieldId, newValue);
  };

  const formatCurrencyInput = (value: string): string => {
    let num = value.replace(/[^0-9]/g, '');
    if (num) {
      num = parseInt(num).toLocaleString();
    }
    return num;
  };

  const nextSection = () => {
    if (currentSection === 1 && isDisqualified) return;

    if (currentSection < sections.length - 1) {
      setCurrentSection(currentSection + 1);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      setShowResults(true);
      showSuccess('Assessment completed!', 'View your comprehensive R&D analysis below.');
    }
  };

  const prevSection = () => {
    if (currentSection > 0) {
      setCurrentSection(currentSection - 1);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const resetAssessment = () => {
    setCurrentSection(0);
    setResponses({});
    setIsDisqualified(false);
    setDisqualificationReasons([]);
    setShowResults(false);
    setExpandedSections({ current: true });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const toggleSection = (sectionId: string) => {
    setExpandedSections(prev => ({ ...prev, [sectionId]: !prev[sectionId] }));
  };

  if (showResults && !isDisqualified) {
    const calc = calculateAssessment();
    const hasState = calc.stateCredit > 0;
    const stateLabel = calc.stateData.label || responses.business_state || 'N/A';

    return (
      <div className="space-y-6">
        <div className="text-center">
          <div className="inline-flex items-center gap-2 bg-[#2c3c4d] text-[#89c726] px-4 py-2 rounded-full text-xs font-semibold uppercase tracking-wide mb-4">
            <Award className="w-4 h-4" />
            ROI BLUEPRINT ASSESSMENT RESULTS
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Your R&D Tax Credit Opportunity</h1>
        </div>

        <div className="bg-gradient-to-br from-slate-700 to-blue-800 rounded-2xl p-8 text-white text-center shadow-lg">
          <div className="flex items-center justify-center gap-2 text-[#89c726] text-xs font-semibold uppercase tracking-wide mb-4">
            <Award className="w-4 h-4" />
            TOTAL POTENTIAL VALUE (7 YEARS)
          </div>
          <div className="text-6xl font-bold mb-2">{formatCurrency(calc.fees.net)}</div>
          <div className="text-gray-300 text-sm mb-6">Net benefit after service fees</div>

          <div className="grid grid-cols-4 gap-4">
            <div className="bg-white/10 rounded-lg p-4">
              <div className="text-xs text-gray-300 mb-1">Current Year</div>
              <div className="text-xl font-bold">{formatCurrency(calc.totalCredit)}</div>
            </div>
            <div className="bg-white/10 rounded-lg p-4">
              <div className="text-xs text-gray-300 mb-1">3-Year Future</div>
              <div className="text-xl font-bold">{formatCurrency(calc.threeYearFuture.totalCredits)}</div>
            </div>
            <div className="bg-white/10 rounded-lg p-4">
              <div className="text-xs text-gray-300 mb-1">3-Year Lookback</div>
              <div className="text-xl font-bold">{formatCurrency(calc.lookback.total)}</div>
            </div>
            <div className="bg-white/10 rounded-lg p-4">
              <div className="text-xs text-gray-300 mb-1">Your ROI</div>
              <div className="text-xl font-bold">{calc.fees.total > 0 ? Math.round(calc.fees.net / calc.fees.total) : 0}x</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div
            className="flex items-center justify-between p-6 cursor-pointer hover:bg-gray-50"
            onClick={() => toggleSection('current')}
          >
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center text-blue-600 border-l-4 border-[#89c726]">
                <DollarSign className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Current Year Tax Credit</h3>
                <p className="text-sm text-gray-600">Estimated R&D credit for this tax year</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-2xl font-bold text-blue-600">{formatCurrency(calc.totalCredit)}</span>
              <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform ${expandedSections.current ? 'rotate-180' : ''}`} />
            </div>
          </div>

          {expandedSections.current && (
            <div className="p-6 border-t border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wider font-semibold mb-3">Qualified Research Expenses (QRE)</div>
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="text-xs text-gray-600 mb-1">Qualified Wages</div>
                  <div className="text-lg font-semibold">{formatCurrency(calc.qualifiedWages)}</div>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="text-xs text-gray-600 mb-1">Advisory Services (65%)</div>
                  <div className="text-lg font-semibold">{formatCurrency(calc.advisoryQRE)}</div>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="text-xs text-gray-600 mb-1">Cloud Computing</div>
                  <div className="text-lg font-semibold">{formatCurrency(calc.cloudQRE)}</div>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg border-l-4 border-[#89c726]">
                  <div className="text-xs text-blue-600 mb-1">Total QRE</div>
                  <div className="text-lg font-bold text-blue-600">{formatCurrency(calc.totalQRE)}</div>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="bg-gray-50 p-4 rounded-lg text-center">
                  <div className="text-xs text-gray-600 mb-1">FEDERAL CREDIT</div>
                  <div className="text-2xl font-bold text-blue-600">{formatCurrency(calc.federalCredit)}</div>
                  <div className="text-xs text-gray-500">ASC Method @ 14%</div>
                </div>
                {hasState && (
                  <div className="bg-gray-50 p-4 rounded-lg text-center">
                    <div className="text-xs text-gray-600 mb-1">STATE CREDIT</div>
                    <div className="text-2xl font-bold text-blue-600">{formatCurrency(calc.stateCredit)}</div>
                    <div className="text-xs text-gray-500">@ {formatPercent(calc.stateData.rate)}</div>
                  </div>
                )}
                <div className="bg-gray-50 p-4 rounded-lg text-center border-l-4 border-[#89c726]">
                  <div className="text-xs text-blue-600 mb-1">TOTAL CREDIT</div>
                  <div className="text-2xl font-bold text-blue-600">{formatCurrency(calc.totalCredit)}</div>
                  <div className="text-xs text-gray-500">Dollar-for-dollar savings</div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div
            className="flex items-center justify-between p-6 cursor-pointer hover:bg-gray-50"
            onClick={() => toggleSection('future')}
          >
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center text-blue-600 border-l-4 border-[#89c726]">
                <TrendingUp className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">3-Year Future Projection</h3>
                <p className="text-sm text-gray-600">Projected credits with {calc.threeYearFuture.growthRate}% annual growth</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-2xl font-bold text-blue-600">{formatCurrency(calc.threeYearFuture.totalCredits)}</span>
              <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform ${expandedSections.future ? 'rotate-180' : ''}`} />
            </div>
          </div>

          {expandedSections.future && (
            <div className="p-6 border-t border-gray-200">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-xs text-gray-600 uppercase tracking-wider">
                    <th className="pb-3">YEAR</th>
                    <th className="pb-3 text-right">FEDERAL</th>
                    {hasState && <th className="pb-3 text-right">STATE</th>}
                    <th className="pb-3 text-right">TOTAL</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {calc.threeYearFuture.years.map((y: any) => (
                    <tr key={y.year} className="border-t border-gray-100">
                      <td className="py-3">Year {y.year}</td>
                      <td className="py-3 text-right text-blue-600">{formatCurrency(y.federal)}</td>
                      {hasState && <td className="py-3 text-right text-blue-600">{formatCurrency(y.state)}</td>}
                      <td className="py-3 text-right font-semibold">{formatCurrency(y.total)}</td>
                    </tr>
                  ))}
                  <tr className="border-t-2 border-gray-200 bg-gray-50 font-semibold">
                    <td className="py-3">3-YEAR TOTAL</td>
                    <td colSpan={hasState ? 2 : 1}></td>
                    <td className="py-3 text-right text-blue-600 text-lg">{formatCurrency(calc.threeYearFuture.totalCredits)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}
        </div>

        {calc.isStartupEligible && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
            <h3 className="flex items-center gap-2 text-blue-900 font-semibold mb-2">
              <CheckCircle className="w-5 h-5" />
              Startup Payroll Tax Offset Eligible
            </h3>
            <p className="text-sm text-blue-800">
              Your practice qualifies for up to <strong>{formatCurrency(calc.payrollOffset)}</strong> annually in payroll tax offsets under IRC Section 41(h).
              This provides immediate cash flow benefits via reduced payroll tax deposits.
            </p>
          </div>
        )}

        <div className="flex justify-center gap-4 pt-6">
          <button
            onClick={resetAssessment}
            className="px-6 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors font-semibold"
          >
            New Assessment
          </button>
          <button
            onClick={() => window.print()}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-semibold"
          >
            Print Results
          </button>
        </div>
      </div>
    );
  }

  if (isDisqualified && currentSection === 1) {
    return (
      <div className="space-y-6">
        <div className="bg-red-50 border-2 border-red-500 rounded-xl p-8">
          <div className="flex items-center gap-3 text-red-900 mb-4">
            <AlertTriangle className="w-8 h-8" />
            <h2 className="text-2xl font-bold">Not Currently Eligible</h2>
          </div>
          <p className="text-red-800 mb-6">Based on your responses, your organization has disqualifying factors.</p>

          <div className="bg-white rounded-lg p-6 border border-red-200 mb-6">
            <h4 className="text-red-900 font-semibold mb-4">Disqualifying Factors:</h4>
            {disqualificationReasons.map((r, i) => (
              <div key={i} className="border-l-4 border-red-500 pl-4 mb-4 last:mb-0">
                <div className="font-semibold text-red-900">{r.label}</div>
                <div className="text-sm text-red-700">{r.reason}</div>
              </div>
            ))}
          </div>

          <div className="bg-blue-50 rounded-lg p-6 border border-blue-200 mb-6">
            <h4 className="text-blue-900 font-semibold mb-2">Future Opportunities</h4>
            <p className="text-sm text-blue-800">If your structure changes, you may become eligible. Contact ROI Blueprint to discuss options.</p>
          </div>

          <div className="text-center">
            <button
              onClick={resetAssessment}
              className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-semibold text-lg"
            >
              Start New Assessment
            </button>
          </div>
        </div>
      </div>
    );
  }

  const calc = calculateAssessment();
  const progress = ((currentSection + 1) / sections.length) * 100;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">R&D Tax Credit Assessment</h1>
          <p className="text-gray-600 mt-1">Section {currentSection + 1} of {sections.length}</p>
        </div>
      </div>

      <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">
            Section {currentSection + 1} of {sections.length}
          </span>
          <span className="text-sm font-medium text-blue-600">{Math.round(progress)}% Complete</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className="bg-gradient-to-r from-[#2c3c4d] to-blue-600 h-2 rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <div className="bg-gradient-to-br from-[#004aad] to-[#003d91] rounded-lg p-6 text-white">
        <div className="text-xs uppercase tracking-wide opacity-80 mb-4">Live Credit Estimate</div>
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold">{formatCurrency(calc.totalQRE)}</div>
            <div className="text-xs opacity-80">Total QRE</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold">{formatCurrency(calc.federalCredit)}</div>
            <div className="text-xs opacity-80">Federal Credit</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold">{formatCurrency(calc.stateCredit)}</div>
            <div className="text-xs opacity-80">State Credit</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-[#89c726]">{formatCurrency(calc.totalCredit)}</div>
            <div className="text-xs opacity-80">Total Credit</div>
          </div>
        </div>
        <div className="mt-3 pt-3 border-t border-white/10 flex justify-between text-xs">
          <span className="opacity-70">Service Fee ({calc.feeRate}% of revenue)</span>
          <span className="font-semibold">{formatCurrency(calc.serviceFee)}</span>
        </div>
      </div>

      {currentSection === 1 && isDisqualified && (
        <div className="bg-red-50 border border-red-500 rounded-lg p-6">
          <div className="flex items-center gap-2 text-red-900 font-semibold mb-2">
            <AlertTriangle className="w-5 h-5" />
            Disqualifying Factors Detected
          </div>
          <p className="text-red-800 mb-4">Based on your current selections, your organization may not be eligible for R&D tax credits.</p>
          {disqualificationReasons.map((r, i) => (
            <div key={i} className="text-sm text-red-700 mb-1">* {r.label}</div>
          ))}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="bg-gradient-to-r from-gray-50 to-gray-100 border-b border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="text-blue-600">
              {sections[currentSection].icon}
            </div>
            <h2 className="text-xl font-semibold text-[#004aad]">{sections[currentSection].title}</h2>
          </div>
          <p className="text-sm text-gray-600">{sections[currentSection].subtitle}</p>
        </div>

        <div className="p-6">
          {currentSection === 0 && renderClientInfo()}
          {currentSection === 1 && renderQualification()}
          {currentSection === 2 && renderRevenueHistory()}
          {currentSection === 3 && renderPayrollExpenses()}
          {currentSection === 4 && renderRDActivities()}
          {currentSection === 5 && renderGrowthProjection()}
        </div>
      </div>

      <div className="flex justify-between pt-6 border-t border-gray-200">
        <button
          onClick={prevSection}
          disabled={currentSection === 0}
          className="flex items-center gap-2 px-6 py-3 text-gray-600 border-2 border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed font-semibold"
        >
          <ChevronLeft className="w-4 h-4" />
          Previous
        </button>
        <button
          onClick={nextSection}
          disabled={currentSection === 1 && isDisqualified}
          className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-[#004aad] to-[#0073e6] text-white rounded-lg hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed font-semibold transition-all"
        >
          {currentSection === sections.length - 1 ? 'Complete Assessment' : 'Next Section'}
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );

  function renderClientInfo() {
    return (
      <div className="space-y-6">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Contact Information</div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Contact Name</label>
              <input
                type="text"
                value={responses.contact_name || ''}
                onChange={(e) => handleInput('contact_name', e.target.value)}
                placeholder="Decision maker name"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Title/Role</label>
              <input
                type="text"
                value={responses.contact_title || ''}
                onChange={(e) => handleInput('contact_title', e.target.value)}
                placeholder="e.g., Owner, CFO, Office Manager"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Email Address</label>
              <input
                type="email"
                value={responses.contact_email || ''}
                onChange={(e) => handleInput('contact_email', e.target.value)}
                placeholder="email@practice.com"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Phone Number</label>
              <input
                type="tel"
                value={responses.contact_phone || ''}
                onChange={(e) => handleInput('contact_phone', e.target.value)}
                placeholder="(555) 555-5555"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Practice Information</div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Practice/Business Name</label>
              <input
                type="text"
                value={responses.business_name || ''}
                onChange={(e) => handleInput('business_name', e.target.value)}
                placeholder="Enter practice name"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Primary State</label>
              <select
                value={responses.business_state || ''}
                onChange={(e) => handleInput('business_state', e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select state...</option>
                {Object.entries(STATE_CREDIT_RATES).map(([code, data]) => (
                  <option key={code} value={code}>
                    {data.label} {data.rate > 0 ? `(${formatPercent(data.rate)} credit)` : ''}
                  </option>
                ))}
                <option value="OTHER">Other (no state credit)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Years in Business</label>
              <input
                type="number"
                value={responses.business_age || ''}
                onChange={(e) => handleInput('business_age', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Number of Locations</label>
              <input
                type="number"
                value={responses.number_of_locations || ''}
                onChange={(e) => handleInput('number_of_locations', e.target.value)}
                placeholder="1"
                min="1"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

  function renderQualification() {
    const factors = responses.disqualifying_factors || [];

    return (
      <div className="space-y-6">
        <div className="bg-blue-50 border-l-4 border-[#89c726] rounded p-4 mb-6">
          <p className="text-sm text-gray-700">
            <strong className="text-[#004aad]">Important:</strong> Please confirm none of these disqualifying factors apply to your organization
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {[
            { value: 'none_apply', label: 'None of these apply - We are a for-profit US business' },
            { value: 'nonprofit', label: 'Non-profit organization', disqualifier: true },
            { value: 'government', label: 'Government entity', disqualifier: true },
            { value: 'work_outside_us', label: 'Primary operations outside the US', disqualifier: true },
            { value: 'government_funded', label: 'Funded primarily by government grants', disqualifier: true },
            { value: 'contract_research', label: 'We do contract research for other companies', disqualifier: true },
            { value: 'customer_owns_results', label: 'Customers own our research/development results', disqualifier: true },
            { value: 'only_social_sciences', label: 'We only do social sciences/humanities research', disqualifier: true },
            { value: 'only_market_research', label: 'We only do market research/surveys', disqualifier: true },
            { value: 'only_quality_testing', label: 'We only do quality control testing', disqualifier: true }
          ].map(opt => {
            const isSelected = factors.includes(opt.value);
            return (
              <label
                key={opt.value}
                className={`flex items-start gap-3 p-4 border rounded-lg cursor-pointer transition-all ${
                  opt.disqualifier ? 'hover:bg-red-50 border-gray-300' : 'hover:bg-blue-50'
                } ${isSelected ? (opt.disqualifier ? 'border-red-500 bg-red-50' : 'border-blue-500 bg-blue-50 border-l-4 border-l-[#89c726]') : ''}`}
              >
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => handleCheckbox('disqualifying_factors', opt.value)}
                  className="mt-0.5 w-4 h-4 accent-blue-600"
                />
                <span className="text-sm text-gray-900 flex-1">
                  {opt.label}
                  {opt.disqualifier && (
                    <span className="ml-2 text-xs px-2 py-0.5 bg-red-200 text-red-800 rounded-full font-semibold">Disqualifying</span>
                  )}
                </span>
              </label>
            );
          })}
        </div>
      </div>
    );
  }

  function renderRevenueHistory() {
    return (
      <div className="space-y-6">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Revenue Information</div>
          <div className="bg-[#fef9e7] border-l-4 border-[#89c726] rounded p-4 mb-4">
            <p className="text-sm text-gray-700">
              <strong className="text-[#004aad]">From your P&L (Profit & Loss statement):</strong> These figures help us determine which calculation method maximizes your credit.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Current Year Gross Revenue
                <span className="block text-xs text-gray-500 font-normal mt-1">Most recent full year from your P&L or YTD annualized</span>
              </label>
              <div className="relative">
                <span className="absolute left-3 top-2.5 text-gray-500 font-medium">$</span>
                <input
                  type="text"
                  value={responses.annual_revenue ? formatCurrencyInput(responses.annual_revenue) : ''}
                  onChange={(e) => handleInput('annual_revenue', e.target.value.replace(/,/g, ''))}
                  placeholder="0"
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                3-Year Average Gross Revenue
                <span className="block text-xs text-gray-500 font-normal mt-1">Average of last 3 years - needed for ASC calculation method</span>
              </label>
              <div className="relative">
                <span className="absolute left-3 top-2.5 text-gray-500 font-medium">$</span>
                <input
                  type="text"
                  value={responses.avg_revenue_3yr ? formatCurrencyInput(responses.avg_revenue_3yr) : ''}
                  onChange={(e) => handleInput('avg_revenue_3yr', e.target.value.replace(/,/g, ''))}
                  placeholder="0"
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">R&D Credit History</div>
          <div className="bg-[#fef9e7] border-l-4 border-[#89c726] rounded p-4 mb-4">
            <p className="text-sm text-gray-700">
              <strong className="text-[#004aad]">Important:</strong> You may have been conducting R&D activities without claiming the credit. Many practices can <strong>look back 3+ years</strong> to claim missed credits!
            </p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Years Previously Claimed R&D Credits
                <span className="block text-xs text-gray-500 font-normal mt-1">If 0, you may qualify as a Startup for enhanced benefits</span>
              </label>
              <input
                type="number"
                value={responses.rd_credit_years || ''}
                onChange={(e) => handleInput('rd_credit_years', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Years Conducting R&D Activities
                <span className="block text-xs text-gray-500 font-normal mt-1">Even if you never claimed - developing protocols, customizing software, improving processes all count</span>
              </label>
              <input
                type="number"
                value={responses.qualifying_activity_years || ''}
                onChange={(e) => handleInput('qualifying_activity_years', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

  function renderPayrollExpenses() {
    return (
      <div className="space-y-6">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Staff Counts by Role</div>
          <div className="bg-[#fef9e7] border-l-4 border-[#89c726] rounded p-4 mb-4">
            <p className="text-sm text-gray-700">
              <strong className="text-[#004aad]">W-2 employees only:</strong> Count staff who spend time on qualifying activities. We will help determine exact qualification rates during our consultation.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                High Level
                <span className="block text-xs text-gray-500 font-normal">(MD, DO, PA, NP, BCBA, Director)</span>
              </label>
              <input
                type="number"
                value={responses.high_level_staff || ''}
                onChange={(e) => handleInput('high_level_staff', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Mid Level
                <span className="block text-xs text-gray-500 font-normal">(BCBA, RN, Clinical & Ops supervisors)</span>
              </label>
              <input
                type="number"
                value={responses.supervisor_director || ''}
                onChange={(e) => handleInput('supervisor_director', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Support Staff
                <span className="block text-xs text-gray-500 font-normal">(RBT, MA, LVN, admin, etc.)</span>
              </label>
              <input
                type="number"
                value={responses.support_staff || ''}
                onChange={(e) => handleInput('support_staff', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Wage & Expense Information</div>
          <div className="bg-[#fef9e7] border-l-4 border-[#89c726] rounded p-4 mb-4">
            <p className="text-sm text-gray-700">
              <strong className="text-[#004aad]">Current year figures:</strong> Total W-2 wages paid to all employees.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Current Year Total W-2 Wages
                <span className="block text-xs text-gray-500 font-normal mt-1">From your P&L - all wages and salaries paid this year</span>
              </label>
              <div className="relative">
                <span className="absolute left-3 top-2.5 text-gray-500 font-medium">$</span>
                <input
                  type="text"
                  value={responses.total_annual_wages ? formatCurrencyInput(responses.total_annual_wages) : ''}
                  onChange={(e) => handleInput('total_annual_wages', e.target.value.replace(/,/g, ''))}
                  placeholder="0"
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Wages as % of Revenue
                <span className="block text-xs text-gray-500 font-normal mt-1">Leave blank to auto-calculate, or override if known</span>
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={responses.wage_percentage || ''}
                  onChange={(e) => handleInput('wage_percentage', e.target.value)}
                  placeholder="Auto"
                  min="0"
                  max="100"
                  className="w-full pr-8 pl-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <span className="absolute right-3 top-2.5 text-gray-500 font-medium">%</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  function renderRDActivities() {
    const techActivities = responses.tech_activities || [];
    const clinicalActivities = responses.clinical_activities || [];
    const complianceActivities = responses.compliance_activities || [];

    const renderActivityGroup = (title: string, note: string, fieldId: string, options: Array<{ value: string; label: string }>, selected: string[]) => (
      <div className="mb-6">
        <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">{title}</div>
        <div className="bg-[#fef9e7] border-l-4 border-[#89c726] rounded p-4 mb-4">
          <p className="text-sm text-gray-700" dangerouslySetInnerHTML={{ __html: note }} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          {options.map(opt => {
            const isSelected = selected.includes(opt.value);
            return (
              <label
                key={opt.value}
                className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-all hover:border-blue-500 hover:bg-blue-50 ${
                  isSelected ? 'border-blue-500 bg-gray-50 border-l-4 border-l-[#89c726]' : 'border-gray-300'
                }`}
              >
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => handleCheckbox(fieldId, opt.value)}
                  className="mt-0.5 w-4 h-4 accent-blue-600"
                />
                <span className="text-sm text-gray-900">{opt.label}</span>
              </label>
            );
          })}
        </div>
      </div>
    );

    return (
      <div className="space-y-6">
        {renderActivityGroup(
          'Technology Development Activities',
          '<strong class="text-[#004aad]">Don\'t worry if you\'re unsure!</strong> Not all activities will qualify, but we\'ll guide you through what counts. Check anything that applies - our team will evaluate each during consultation.',
          'tech_activities',
          [
            { value: 'emr_customization', label: 'EMR/EHR system customization for clinical workflows' },
            { value: 'telehealth_development', label: 'Telehealth platform development or modification' },
            { value: 'patient_portal', label: 'Patient portal or mobile app development' },
            { value: 'clinical_analytics', label: 'Clinical analytics and outcome measurement tools' },
            { value: 'workflow_automation', label: 'Clinical workflow automation systems' },
            { value: 'system_integration', label: 'Software system integration projects' },
            { value: 'api_development', label: 'API development or data exchange systems' },
            { value: 'clinical_decision_support', label: 'Clinical decision support tools' },
            { value: 'population_health', label: 'Population health management tools' },
            { value: 'ai_ml_implementation', label: 'AI/Machine learning implementation' },
            { value: 'data_warehouse', label: 'Data warehouse or reporting systems' },
            { value: 'cybersecurity', label: 'Healthcare cybersecurity solutions' }
          ],
          techActivities
        )}

        {renderActivityGroup(
          'Clinical Protocol Activities',
          '<strong class="text-[#004aad]">These often qualify!</strong> Developing, testing, or improving clinical approaches is core R&D activity.',
          'clinical_activities',
          [
            { value: 'treatment_protocols', label: 'Developing new treatment protocols' },
            { value: 'protocol_adaptation', label: 'Adapting protocols for specific populations' },
            { value: 'outcome_measurement', label: 'Patient outcome measurement systems' },
            { value: 'quality_improvement', label: 'Systematic quality improvement programs' },
            { value: 'care_coordination', label: 'Care coordination system development' },
            { value: 'patient_safety', label: 'Patient safety initiative development' },
            { value: 'chronic_care', label: 'Chronic care management program development' },
            { value: 'preventive_care', label: 'Preventive care program development' },
            { value: 'behavioral_interventions', label: 'Behavioral health intervention development' },
            { value: 'remote_monitoring', label: 'Remote patient monitoring programs' }
          ],
          clinicalActivities
        )}

        {renderActivityGroup(
          'Compliance & Process Activities',
          '<strong class="text-[#004aad]">Process improvements count too!</strong> Building systems to meet regulations or improve operations can qualify.',
          'compliance_activities',
          [
            { value: 'hipaa_systems', label: 'HIPAA compliance system development' },
            { value: 'regulatory_automation', label: 'Regulatory reporting automation' },
            { value: 'billing_optimization', label: 'Revenue cycle/billing system optimization' },
            { value: 'credentialing_systems', label: 'Credentialing system development' },
            { value: 'audit_systems', label: 'Audit and compliance tracking systems' },
            { value: 'documentation_systems', label: 'Clinical documentation improvement' },
            { value: 'interoperability', label: 'Healthcare interoperability projects' },
            { value: 'value_based_care', label: 'Value-based care program development' }
          ],
          complianceActivities
        )}
      </div>
    );
  }

  function renderGrowthProjection() {
    const plannedInitiatives = responses.planned_initiatives || [];

    return (
      <div className="space-y-6">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Growth Expectations</div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">
                Expected Annual Growth Rate
                <span className="block text-xs text-gray-500 font-normal">(Minimum 3% recommended)</span>
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={responses.annual_growth_rate || ''}
                  onChange={(e) => handleInput('annual_growth_rate', e.target.value)}
                  placeholder="3"
                  min="0"
                  max="100"
                  className="w-full pr-8 pl-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <span className="absolute right-3 top-2.5 text-gray-500 font-medium">%</span>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Planned Technology Investments (Next 2 Years)</div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Total Planned Tech Investment</label>
              <div className="relative">
                <span className="absolute left-3 top-2.5 text-gray-500 font-medium">$</span>
                <input
                  type="text"
                  value={responses.planned_tech_investment ? formatCurrencyInput(responses.planned_tech_investment) : ''}
                  onChange={(e) => handleInput('planned_tech_investment', e.target.value.replace(/,/g, ''))}
                  placeholder="0"
                  className="w-full pl-8 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 mb-1">Planned Technical Staff Additions</label>
              <input
                type="number"
                value={responses.planned_staff_additions || ''}
                onChange={(e) => handleInput('planned_staff_additions', e.target.value)}
                placeholder="0"
                min="0"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-4 pb-2 border-b-2 border-[#89c726]">Planned R&D Initiatives</div>
          <p className="text-sm text-gray-600 mb-4">Check initiatives you plan to undertake</p>
          <div className="grid grid-cols-2 gap-3">
            {[
              { value: 'ai_implementation', label: 'AI and machine learning implementation' },
              { value: 'custom_software', label: 'Custom software development' },
              { value: 'system_integrations', label: 'Major system integrations' },
              { value: 'telehealth_expansion', label: 'Telehealth platform expansion' },
              { value: 'data_analytics', label: 'Advanced analytics implementation' },
              { value: 'mobile_development', label: 'Mobile app development' },
              { value: 'automation_projects', label: 'Workflow automation projects' },
              { value: 'compliance_systems', label: 'Compliance system development' }
            ].map(opt => {
              const isSelected = plannedInitiatives.includes(opt.value);
              return (
                <label
                  key={opt.value}
                  className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-all hover:border-blue-500 hover:bg-blue-50 ${
                    isSelected ? 'border-blue-500 bg-gray-50 border-l-4 border-l-[#89c726]' : 'border-gray-300'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => handleCheckbox('planned_initiatives', opt.value)}
                    className="mt-0.5 w-4 h-4 accent-blue-600"
                  />
                  <span className="text-sm text-gray-900">{opt.label}</span>
                </label>
              );
            })}
          </div>
        </div>
      </div>
    );
  }
};
