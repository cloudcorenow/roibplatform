import { AssessmentFormData, CalculationResults } from '../types/assessment';
import { STATE_RD_CREDITS } from '../data/stateRDCredits';

const SERVICE_FEES = {
  ADVISORY_SPLIT: 0.65,
  CLOUD_SPLIT: 0.35,
  CONTRACT_RESEARCH_RATE: 0.65,
};

export function calculateAssessmentResults(data: Partial<AssessmentFormData>): CalculationResults {
  // Extract form data with defaults
  const rdPercent = (data.rd_wage_percentage || 20) / 100;
  const totalWages = data.total_annual_wages || 0;
  const supplyExpenses = data.supply_expenses || 0;
  const contractResearch = data.contract_research || 0;
  const revenue = data.annual_revenue || 0;
  const federalFeeRate = (data.federal_fee_rate || 0.75) / 100;
  const stateFeeRate = (data.state_fee_rate || 0.25) / 100;
  const totalFeeRate = federalFeeRate + stateFeeRate;
  const yearsClaimed = data.rd_credit_years || 0;
  const yearsActivity = parseInt(data.qualifying_activity_years || '0');
  const yearsInBusiness = data.business_age || 0;
  const growthRate = Math.max((data.annual_growth_rate || 10) / 100, 0.03);
  const hasRelatedEntities = data.has_related_entities === 'yes';
  const groupTotalRevenue = data.group_total_revenue || 0;
  const groupTotalQRE = data.group_total_qre || 0;
  const federalTaxLiability = data.federal_tax_liability || 0;
  const stateTaxLiability = data.state_tax_liability || 0;
  const stateCode = data.business_state || 'CA';
  const priorStaffChange = data.prior_staff_change || 'same';

  // Get state credit info
  const stateData = STATE_RD_CREDITS[stateCode] || { rate: 0, cap: 0 };

  // Calculate Qualified Wages
  const qualifiedWages = totalWages * rdPercent;

  // Calculate Service Fee QRE Contribution
  const serviceFee = revenue * totalFeeRate / (1 + totalFeeRate);
  const advisoryFee = serviceFee * SERVICE_FEES.ADVISORY_SPLIT;
  const cloudFee = serviceFee * SERVICE_FEES.CLOUD_SPLIT;
  const advisoryQRE = advisoryFee * SERVICE_FEES.CONTRACT_RESEARCH_RATE;
  const cloudQRE = cloudFee;
  const feeQRE = advisoryQRE + cloudQRE;

  // Calculate Client QRE
  const contractQRE = contractResearch * SERVICE_FEES.CONTRACT_RESEARCH_RATE;
  const clientQRE = qualifiedWages + supplyExpenses + contractQRE;

  // Total QRE
  let totalQRE = clientQRE + feeQRE;
  let entityTotalQRE = totalQRE;

  // Controlled Group Adjustment
  const isControlledGroup = hasRelatedEntities && groupTotalQRE > 0;
  if (isControlledGroup) {
    totalQRE = groupTotalQRE;
  }
  const entityQREShare = isControlledGroup && groupTotalQRE > 0 ? entityTotalQRE / groupTotalQRE : 1;

  // Calculate ASC Method
  let ascCredit = 0;
  let ascRate = 0;
  if (yearsActivity === 0) {
    // First year R&D
    ascRate = 0.06;
    ascCredit = totalQRE * 0.06;
  } else {
    // Established R&D
    ascRate = 0.14;
    const priorYear1Wages = data.prior_year_1_wages || 0;
    const priorYear2Wages = data.prior_year_2_wages || 0;
    const priorYear3Wages = data.prior_year_3_wages || 0;
    const priorYear4Wages = data.prior_year_4_wages || 0;

    const priorYearsCount = priorYear4Wages > 0 ? 4 : 3;
    const priorWagesSum = priorYear1Wages + priorYear2Wages + priorYear3Wages + priorYear4Wages;
    const priorAvgWages = priorWagesSum / priorYearsCount;
    const priorQRE = priorAvgWages * 0.20; // Assume 20% R&D

    const ascExcess = Math.max(0, totalQRE - (0.5 * priorQRE));
    ascCredit = ascExcess * 0.14;
  }

  // Calculate Traditional Method
  const priorYear1Revenue = data.prior_year_1_revenue || 0;
  const priorYear2Revenue = data.prior_year_2_revenue || 0;
  const priorYear3Revenue = data.prior_year_3_revenue || 0;
  const priorYear4Revenue = data.prior_year_4_revenue || 0;

  const priorYearsCount = priorYear4Revenue > 0 ? 4 : 3;
  const priorRevenueSum = priorYear1Revenue + priorYear2Revenue + priorYear3Revenue + priorYear4Revenue;
  const avgRevenue = priorRevenueSum / priorYearsCount;

  const traditionalBasePercent = 0.03;
  const traditionalBase = avgRevenue * traditionalBasePercent;
  const traditionalRate = 0.20;

  // 50% Rule (IRS Form 6765)
  const excessOverBase = totalQRE - traditionalBase;
  const fiftyPercent = totalQRE * 0.5;

  let creditBase = 0;
  if (excessOverBase <= 0) {
    creditBase = fiftyPercent;
  } else {
    creditBase = Math.min(excessOverBase, fiftyPercent);
  }

  const traditionalCredit = creditBase * traditionalRate;

  // Determine Best Method
  const federalCredit = Math.max(ascCredit, traditionalCredit);
  const bestMethod: 'ASC' | 'Traditional' = ascCredit >= traditionalCredit ? 'ASC' : 'Traditional';

  // Apply controlled group share
  const entityFederalCredit = federalCredit * entityQREShare;

  // Calculate State Credit
  let stateCredit = totalQRE * stateData.rate;
  if (stateData.cap > 0) {
    stateCredit = Math.min(stateCredit, stateData.cap);
  }
  const entityStateCredit = stateCredit * entityQREShare;

  // Total Credit
  const totalCredit = entityFederalCredit + entityStateCredit;

  // Startup Eligibility (QSB - Qualified Small Business)
  const isStartupEligible = revenue < 5000000 && yearsClaimed < 5;
  const payrollOffset = isStartupEligible ? Math.min(entityFederalCredit, 500000) : 0;

  // Credit Utilization vs Tax Liability
  let federalUsable = 0;
  let federalCarryForward = 0;

  if (federalTaxLiability > 0) {
    if (isStartupEligible && payrollOffset > 0) {
      const remainingCredit = entityFederalCredit - payrollOffset;
      federalUsable = payrollOffset + Math.min(remainingCredit, federalTaxLiability);
      federalCarryForward = Math.max(0, remainingCredit - federalTaxLiability);
    } else {
      federalUsable = Math.min(entityFederalCredit, federalTaxLiability);
      federalCarryForward = Math.max(0, entityFederalCredit - federalTaxLiability);
    }
  } else {
    federalUsable = entityFederalCredit;
  }

  let stateUsable = 0;
  let stateCarryForward = 0;

  if (stateTaxLiability > 0) {
    stateUsable = Math.min(entityStateCredit, stateTaxLiability);
    stateCarryForward = Math.max(0, entityStateCredit - stateTaxLiability);
  } else {
    stateUsable = entityStateCredit;
  }

  // 3-Year Future Projection
  const year1Future = totalCredit * (1 + growthRate);
  const year2Future = totalCredit * Math.pow(1 + growthRate, 2);
  const year3Future = totalCredit * Math.pow(1 + growthRate, 3);
  const threeYearFutureTotal = year1Future + year2Future + year3Future;

  const year1FutureFee = serviceFee * (1 + growthRate);
  const year2FutureFee = serviceFee * Math.pow(1 + growthRate, 2);
  const year3FutureFee = serviceFee * Math.pow(1 + growthRate, 3);
  const threeYearFutureFees = year1FutureFee + year2FutureFee + year3FutureFee;

  // Lookback Credits
  const canLookback = yearsClaimed === 0 && yearsInBusiness >= 1;
  const lookbackYears = canLookback ? Math.min(3, yearsInBusiness) : 0;

  const lookbackAdjustment = {
    more: 1.25,
    fewer: 0.75,
    same: 1.0,
  }[priorStaffChange] || 1.0;

  let year1Lookback = 0;
  let year2Lookback = 0;
  let year3Lookback = 0;
  let lookbackTotal = 0;
  let lookbackTotalFees = 0;

  if (canLookback) {
    for (let i = 1; i <= lookbackYears; i++) {
      const mult = Math.pow(0.95, i) * lookbackAdjustment;
      const yearCredit = totalCredit * mult;
      const yearFee = serviceFee * mult;

      if (i === 1) year1Lookback = yearCredit;
      if (i === 2) year2Lookback = yearCredit;
      if (i === 3) year3Lookback = yearCredit;

      lookbackTotal += yearCredit;
      lookbackTotalFees += yearFee;
    }
  }

  // Fee Calculations
  const currentFee = serviceFee;
  const futureFee = threeYearFutureFees;
  const lookbackFee = lookbackTotalFees;
  let totalFees = currentFee + futureFee + lookbackFee;

  // Total Gross
  const totalGross = totalCredit + threeYearFutureTotal + lookbackTotal;

  // Minimum 3x ROI guarantee
  const minROI = 3;
  const maxAllowedFees = Math.floor(totalGross / minROI);
  let adjustedFees = totalFees;

  if (totalFees > maxAllowedFees) {
    adjustedFees = maxAllowedFees;
  }

  // Total Net
  const totalNet = totalGross - adjustedFees;
  const roi = adjustedFees > 0 ? totalGross / adjustedFees : 0;

  return {
    qualifiedWages,
    clientQRE,
    serviceFee,
    advisoryFee,
    cloudFee,
    advisoryQRE,
    cloudQRE,
    feeQRE,
    totalQRE,
    ascCredit,
    ascRate,
    traditionalCredit,
    traditionalRate,
    traditionalBase,
    federalCredit: entityFederalCredit,
    bestMethod,
    stateCredit: entityStateCredit,
    stateRate: stateData.rate,
    stateCap: stateData.cap,
    totalCredit,
    isStartupEligible,
    payrollOffset,
    federalUsable,
    federalCarryForward,
    stateUsable,
    stateCarryForward,
    threeYearFuture: {
      year1: year1Future,
      year2: year2Future,
      year3: year3Future,
      totalCredits: threeYearFutureTotal,
      totalFees: threeYearFutureFees,
    },
    canLookback,
    lookback: {
      year1: year1Lookback,
      year2: year2Lookback,
      year3: year3Lookback,
      total: lookbackTotal,
      totalFees: lookbackTotalFees,
    },
    isControlledGroup,
    groupTotalQRE,
    entityQREShare,
    currentFee,
    futureFee,
    lookbackFee,
    totalFees,
    adjustedFees,
    totalGross,
    totalNet,
    roi,
  };
}

export function formatCurrency(value: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(value);
}

export function formatPercent(value: number, decimals: number = 1): string {
  return `${(value * 100).toFixed(decimals)}%`;
}
