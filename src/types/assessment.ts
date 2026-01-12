export interface AssessmentFormData {
  // Section 1: Eligibility
  disqualifying_factors: string[];

  // Section 2: Client Info
  contact_name: string;
  contact_title: string;
  contact_email: string;
  contact_phone: string;
  business_name: string;
  healthcare_type: string;
  business_state: string;
  business_age: number;
  number_of_locations: number;
  tax_entity_type: string;
  has_related_entities: string;
  group_total_revenue?: number;
  group_total_qre?: number;

  // Section 3: R&D Activities
  tech_activities: string[];
  clinical_activities: string[];
  compliance_activities: string[];

  // Section 4: Revenue History
  tax_year: string;
  accounting_method: string;
  annual_revenue: number;
  federal_fee_rate: number;
  state_fee_rate: number;
  prior_year_1_revenue: number;
  prior_year_1_wages: number;
  prior_year_2_revenue: number;
  prior_year_2_wages: number;
  prior_year_3_revenue: number;
  prior_year_3_wages: number;
  prior_year_4_revenue?: number;
  prior_year_4_wages?: number;
  federal_tax_liability?: number;
  state_tax_liability?: number;
  owner_percentage?: number;

  // Section 5: Qualifying Expenses
  rd_wage_percentage: number;
  total_annual_wages: number;
  total_w2_employees: number;
  supply_expenses: number;
  contract_research: number;
  prior_staff_change: string;
  rd_credit_years: number;
  qualifying_activity_years: string;

  // Section 6: Growth Projection
  annual_growth_rate: number;
  planned_initiatives: string[];
}

export interface StateRDCredit {
  rate: number;
  cap: number;
}

export interface CalculationResults {
  // QRE Components
  qualifiedWages: number;
  clientQRE: number;
  serviceFee: number;
  advisoryFee: number;
  cloudFee: number;
  advisoryQRE: number;
  cloudQRE: number;
  feeQRE: number;
  totalQRE: number;

  // Federal Credits
  ascCredit: number;
  ascRate: number;
  traditionalCredit: number;
  traditionalRate: number;
  traditionalBase: number;
  federalCredit: number;
  bestMethod: 'ASC' | 'Traditional';

  // State Credits
  stateCredit: number;
  stateRate: number;
  stateCap: number;

  // Total Credits
  totalCredit: number;

  // Startup/QSB
  isStartupEligible: boolean;
  payrollOffset: number;

  // Tax Liability Utilization
  federalUsable: number;
  federalCarryForward: number;
  stateUsable: number;
  stateCarryForward: number;

  // Future Projections
  threeYearFuture: {
    year1: number;
    year2: number;
    year3: number;
    totalCredits: number;
    totalFees: number;
  };

  // Lookback
  canLookback: boolean;
  lookback: {
    year1: number;
    year2: number;
    year3: number;
    total: number;
    totalFees: number;
  };

  // Controlled Group
  isControlledGroup: boolean;
  groupTotalQRE: number;
  entityQREShare: number;

  // Fees
  currentFee: number;
  futureFee: number;
  lookbackFee: number;
  totalFees: number;
  adjustedFees: number;

  // Totals
  totalGross: number;
  totalNet: number;
  roi: number;
}

export interface Assessment {
  id: string;
  tenant_id: string;
  client_id: string;
  status: 'draft' | 'completed' | 'archived';
  responses: AssessmentFormData;
  results: CalculationResults;
  score: number;
  completed_at?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}
