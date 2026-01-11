import { Client, TimeEntry, Project, TechnicalNote, Employee, Expense, SourceControlActivity } from '../types';
import { Contractor, ContractorTimeEntry, KnowledgeBaseEntry, Milestone, ClientCompliance } from '../types';
import { Experiment, AutoTimeEntry, RnDAIAnalysis } from '../types';

export const mockClients: Client[] = [
  {
    id: '1',
    name: 'TechCorp Industries',
    industry: 'Software Development',
    contactPerson: 'Sarah Johnson',
    email: 'sarah.johnson@techcorp.com',
    phone: '(555) 123-4567',
    address: '123 Innovation Drive, San Francisco, CA 94105',
    taxYear: '2024',
    status: 'active',
    onboardingDate: '2024-01-15',
    totalProjects: 3,
    estimatedCredit: 485000
  },
  {
    id: '2',
    name: 'BioMed Solutions',
    industry: 'Biotechnology',
    contactPerson: 'Dr. Michael Chen',
    email: 'mchen@biomed-solutions.com',
    phone: '(555) 987-6543',
    address: '456 Research Blvd, Boston, MA 02101',
    taxYear: '2024',
    status: 'active',
    onboardingDate: '2024-03-01',
    totalProjects: 2,
    estimatedCredit: 320000
  },
  {
    id: '3',
    name: 'GreenTech Innovations',
    industry: 'Clean Energy',
    contactPerson: 'Lisa Rodriguez',
    email: 'lrodriguez@greentech.com',
    phone: '(555) 456-7890',
    address: '789 Sustainability Way, Austin, TX 78701',
    taxYear: '2024',
    status: 'pending',
    onboardingDate: '2024-11-01',
    totalProjects: 1,
    estimatedCredit: 150000
  }
];

export const mockProjects: Project[] = [
  {
    id: '1',
    clientId: '1',
    name: 'AI-Powered Analytics Engine',
    description: 'Development of machine learning algorithms for real-time data analysis with novel optimization techniques',
    status: 'active',
    progress: 78,
    totalHours: 456,
    isRnD: true,
    startDate: '2024-09-01',
    teamMembers: ['Sarah Chen', 'Mike Johnson', 'Alex Rodriguez'],
    budget: 250000,
    rndObjective: 'Develop novel machine learning algorithms that can process real-time data streams with 50% better performance than existing solutions',
    technicalUncertainty: 'Unknown how to optimize gradient descent for streaming data while maintaining accuracy above 95%',
    systematicProcess: 'Iterative algorithm development, A/B testing, performance benchmarking, and systematic parameter optimization'
  },
  {
    id: '2',
    clientId: '1',
    name: 'Quantum Computing Interface',
    description: 'Research into quantum state management and error correction protocols',
    status: 'active',
    progress: 45,
    totalHours: 234,
    isRnD: true,
    startDate: '2024-10-15',
    teamMembers: ['Dr. Emily Watson', 'James Park'],
    budget: 180000,
    rndObjective: 'Create quantum error correction system with 15% improvement in fidelity over current methods',
    technicalUncertainty: 'Uncertain how to implement topological error correction in current quantum hardware constraints',
    systematicProcess: 'Theoretical modeling, simulation testing, hardware prototyping, and systematic error analysis'
  },
  {
    id: '3',
    clientId: '1',
    name: 'Blockchain Security Protocol',
    description: 'Novel cryptographic approaches for distributed ledger security',
    status: 'active',
    progress: 92,
    totalHours: 678,
    isRnD: true,
    startDate: '2024-08-01',
    teamMembers: ['Carlos Martinez', 'Lisa Zhang', 'David Kim'],
    budget: 320000,
    rndObjective: 'Develop new consensus mechanism that reduces energy consumption by 60% while maintaining security',
    technicalUncertainty: 'Unknown how to balance energy efficiency with cryptographic security in proof-of-stake systems',
    systematicProcess: 'Cryptographic analysis, security modeling, consensus algorithm development, and systematic vulnerability testing'
  },
  {
    id: '4',
    clientId: '2',
    name: 'Gene Therapy Delivery System',
    description: 'Novel nanoparticle-based drug delivery mechanism for targeted gene therapy',
    status: 'active',
    progress: 65,
    totalHours: 890,
    isRnD: true,
    startDate: '2024-06-01',
    teamMembers: ['Dr. Sarah Kim', 'Robert Chen', 'Maria Lopez'],
    budget: 450000,
    rndObjective: 'Develop nanoparticle delivery system with 80% targeting accuracy for specific cell types',
    technicalUncertainty: 'Unknown how to prevent immune system rejection while maintaining therapeutic efficacy',
    systematicProcess: 'Molecular design, in-vitro testing, biocompatibility analysis, and systematic efficacy evaluation'
  },
  {
    id: '5',
    clientId: '2',
    name: 'Protein Folding Prediction AI',
    description: 'Machine learning model for predicting protein structures with unprecedented accuracy',
    status: 'active',
    progress: 38,
    totalHours: 567,
    isRnD: true,
    startDate: '2024-09-15',
    teamMembers: ['Dr. Alex Thompson', 'Jennifer Wu'],
    budget: 280000,
    rndObjective: 'Create AI model that predicts protein folding with 95% accuracy for novel protein sequences',
    technicalUncertainty: 'Uncertain how to incorporate quantum mechanical effects into classical ML models',
    systematicProcess: 'Dataset curation, model architecture research, training optimization, and systematic validation'
  },
  {
    id: '6',
    clientId: '3',
    name: 'Solar Panel Efficiency Enhancement',
    description: 'Research into perovskite-silicon tandem solar cells for improved energy conversion',
    status: 'active',
    progress: 25,
    totalHours: 234,
    isRnD: true,
    startDate: '2024-11-01',
    teamMembers: ['Dr. Mark Wilson', 'Anna Garcia'],
    budget: 200000,
    rndObjective: 'Achieve 35% efficiency in perovskite-silicon tandem cells while maintaining 25-year stability',
    technicalUncertainty: 'Unknown how to prevent perovskite degradation under real-world environmental conditions',
    systematicProcess: 'Material synthesis, stability testing, efficiency measurement, and systematic degradation analysis'
  }
];

export const mockTimeEntries: TimeEntry[] = [
  {
    id: '1',
    clientId: '1',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    task: 'Algorithm optimization research',
    duration: 225, // 3h 45m
    date: '2024-12-18',
    status: 'active',
    isRnD: true,
    notes: 'Working on gradient descent optimization for streaming data',
    employeeIds: ['1'],
    employeeNames: ['Sarah Chen']
  },
  {
    id: '2',
    clientId: '1',
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    task: 'Error correction protocol design',
    duration: 135, // 2h 15m
    date: '2024-12-18',
    status: 'completed',
    isRnD: true,
    employeeIds: ['2'],
    employeeNames: ['Dr. Emily Watson']
  },
  {
    id: '3',
    clientId: '2',
    projectId: '4',
    projectName: 'Gene Therapy Delivery System',
    task: 'Nanoparticle synthesis experimentation',
    duration: 480, // 8h
    date: '2024-12-18',
    status: 'completed',
    isRnD: true,
    notes: 'Testing new polymer compositions for improved targeting',
    employeeIds: ['4'],
    employeeNames: ['Dr. Sarah Kim']
  }
];

export const mockTechnicalNotes: TechnicalNote[] = [
  {
    id: '1',
    clientId: '1',
    title: 'Algorithm Performance Analysis - Streaming Data Optimization',
    content: `# Research Objective
Investigation into optimizing machine learning algorithm performance for real-time data processing. This research focuses on reducing computational complexity while maintaining accuracy thresholds above 95%.

## Technical Uncertainty
The primary challenge is determining how to adapt traditional gradient descent optimization for streaming data environments where the data distribution changes continuously. Existing literature provides limited guidance on maintaining model accuracy while processing infinite data streams.

## Systematic Experimentation Process
1. **Baseline Establishment**: Implemented standard gradient descent with fixed learning rates
2. **Adaptive Learning Rate Research**: Developed novel adaptive learning rate algorithms
3. **Memory Management**: Created custom data structures for efficient stream processing
4. **Performance Benchmarking**: Systematic comparison against existing solutions

## Experimental Results
- Performance improvements of 34% in processing speed
- Accuracy maintained at 97.2% (above 95% threshold)
- Memory usage reduced by 28% through optimized data structures
- Novel vectorization techniques reduced computational overhead by 15%

## R&D Qualification
This work qualifies for R&D tax credits as it involves:
• Development of new algorithmic approaches not available in existing literature
• Systematic experimentation to overcome technical uncertainty in streaming data processing
• Novel application of machine learning principles to real-time data analysis
• Technological advancement beyond current industry standards`,
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    author: 'Sarah Chen',
    createdAt: '2024-12-18T10:00:00Z',
    updatedAt: '2024-12-18T14:00:00Z',
    tags: ['algorithm', 'optimization', 'machine-learning', 'streaming-data'],
    isRnDQualified: true,
    uncertaintyDescription: 'Unknown how to maintain ML model accuracy above 95% while processing infinite data streams with changing distributions',
    experimentationDetails: 'Systematic testing of 15 different adaptive learning rate algorithms with controlled A/B testing methodology'
  },
  {
    id: '2',
    clientId: '1',
    title: 'Quantum Error Correction Protocol Development',
    content: `# Quantum State Management Research
Developing novel approaches to quantum error correction using topological qubits and surface codes for improved fidelity in quantum computing systems.

## Technical Challenge
Current quantum error correction methods suffer from high overhead and limited scalability. The technical uncertainty lies in implementing topological error correction within existing quantum hardware constraints while achieving target fidelity improvements.

## Research Methodology
- Theoretical modeling of topological qubit behavior
- Simulation of error correction protocols
- Hardware implementation testing
- Systematic fidelity measurement and analysis

## Key Findings
- Implemented new error correction algorithm with 15% improvement in fidelity
- Reduced decoherence time by 23% through environmental isolation techniques
- Developed custom quantum gate sequences for improved state preparation
- Novel surface code implementation showing promise for scalable quantum computing

## R&D Qualification
This research represents genuine technological advancement in quantum computing, addressing fundamental uncertainties in error correction that are not solved by existing methods.`,
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    author: 'Dr. Emily Watson',
    createdAt: '2024-12-17T09:00:00Z',
    updatedAt: '2024-12-17T16:30:00Z',
    tags: ['quantum', 'error-correction', 'research', 'topological-qubits'],
    isRnDQualified: true,
    uncertaintyDescription: 'Uncertain how to implement topological error correction in current quantum hardware while achieving 15% fidelity improvement',
    experimentationDetails: 'Systematic testing of 8 different surface code configurations with controlled quantum state measurements'
  }
];

export const mockEmployees: Employee[] = [
  {
    id: '1',
    clientId: '1',
    name: 'Sarah Chen',
    role: 'Senior ML Engineer',
    department: 'R&D',
    rndPercentage: 95,
    hourlyRate: 85,
    isActive: true,
    qualifications: ['PhD Computer Science', 'Machine Learning Specialization'],
    rndActivities: ['Algorithm development', 'Research experimentation', 'Technical documentation']
  },
  {
    id: '2',
    clientId: '1',
    name: 'Dr. Emily Watson',
    role: 'Quantum Research Lead',
    department: 'R&D',
    rndPercentage: 100,
    hourlyRate: 120,
    isActive: true,
    qualifications: ['PhD Physics', 'Quantum Computing Research'],
    rndActivities: ['Quantum algorithm research', 'Error correction development', 'Theoretical modeling']
  },
  {
    id: '3',
    clientId: '1',
    name: 'Mike Johnson',
    role: 'Software Engineer',
    department: 'Engineering',
    rndPercentage: 60,
    hourlyRate: 75,
    isActive: true,
    qualifications: ['MS Computer Science', 'Software Architecture'],
    rndActivities: ['Prototype development', 'Performance optimization', 'System integration']
  },
  {
    id: '4',
    clientId: '2',
    name: 'Dr. Sarah Kim',
    role: 'Biomedical Research Scientist',
    department: 'R&D',
    rndPercentage: 100,
    hourlyRate: 110,
    isActive: true,
    qualifications: ['PhD Biomedical Engineering', 'Gene Therapy Research'],
    rndActivities: ['Drug delivery research', 'Nanoparticle development', 'Biocompatibility testing']
  }
];

export const mockExpenses: Expense[] = [
  {
    id: '1',
    clientId: '1',
    description: 'High-performance GPU cluster for ML training',
    amount: 15000,
    category: 'Equipment',
    date: '2024-12-15',
    projectId: '1',
    isRnD: true,
    vendor: 'NVIDIA Corporation',
    justification: 'Required for training novel ML algorithms that exceed capabilities of existing hardware'
  },
  {
    id: '2',
    clientId: '1',
    description: 'Quantum computing simulator license',
    amount: 5000,
    category: 'Software',
    date: '2024-12-10',
    projectId: '2',
    isRnD: true,
    vendor: 'IBM Quantum',
    justification: 'Specialized software for quantum error correction research not available through standard channels'
  },
  {
    id: '3',
    clientId: '2',
    description: 'Specialized nanoparticle synthesis equipment',
    amount: 25000,
    category: 'Equipment',
    date: '2024-12-05',
    projectId: '4',
    isRnD: true,
    vendor: 'BioTech Instruments',
    justification: 'Custom equipment required for novel drug delivery system development'
  }
];

export const mockSourceControlActivity: SourceControlActivity[] = [
  {
    id: '1',
    clientId: '1',
    repository: 'ai-analytics-engine',
    commits: 23,
    author: 'Sarah Chen',
    date: '2024-12-17',
    projectId: '1',
    linesAdded: 1250,
    linesRemoved: 340,
    branchName: 'feature/streaming-optimization',
    commitMessages: ['Implement adaptive learning rate', 'Optimize memory usage', 'Add performance benchmarks']
  },
  {
    id: '2',
    clientId: '1',
    repository: 'quantum-interface',
    commits: 8,
    author: 'Dr. Emily Watson',
    date: '2024-12-17',
    projectId: '2',
    linesAdded: 560,
    linesRemoved: 120,
    branchName: 'feature/error-correction',
    commitMessages: ['Implement surface codes', 'Add fidelity measurements', 'Optimize gate sequences']
  },
  {
    id: '3',
    clientId: '2',
    repository: 'gene-therapy-delivery',
    commits: 15,
    author: 'Dr. Sarah Kim',
    date: '2024-12-16',
    projectId: '4',
    linesAdded: 890,
    linesRemoved: 200,
    branchName: 'feature/nanoparticle-targeting',
    commitMessages: ['Implement targeting algorithm', 'Add biocompatibility tests', 'Optimize delivery efficiency']
  }
];

export const mockContractors: Contractor[] = [
  {
    id: '1',
    clientId: '1',
    name: 'Alex Thompson',
    company: 'ML Consulting Inc.',
    email: 'alex@mlconsulting.com',
    phone: '(555) 234-5678',
    specialization: 'Machine Learning & AI',
    hourlyRate: 150,
    isActive: true,
    rndQualified: true,
    contractStartDate: '2024-09-01',
    contractEndDate: '2025-08-31'
  },
  {
    id: '2',
    clientId: '1',
    name: 'Maria Santos',
    company: 'Quantum Solutions LLC',
    email: 'maria@quantumsolutions.com',
    phone: '(555) 345-6789',
    specialization: 'Quantum Computing',
    hourlyRate: 175,
    isActive: true,
    rndQualified: true,
    contractStartDate: '2024-10-01',
    contractEndDate: ''
  },
  {
    id: '3',
    clientId: '2',
    name: 'Dr. James Wilson',
    company: 'BioTech Research Partners',
    email: 'jwilson@biotechresearch.com',
    phone: '(555) 456-7890',
    specialization: 'Biomedical Engineering',
    hourlyRate: 200,
    isActive: true,
    rndQualified: true,
    contractStartDate: '2024-08-15',
    contractEndDate: '2025-02-15'
  }
];

export const mockContractorTimeEntries: ContractorTimeEntry[] = [
  {
    id: '1',
    clientId: '1',
    contractorId: '1',
    contractorName: 'Alex Thompson',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    task: 'Advanced algorithm optimization consulting',
    duration: 480, // 8 hours
    date: '2024-12-17',
    hourlyRate: 150,
    isRnD: true,
    invoiceNumber: 'INV-2024-001',
    notes: 'Provided expertise on novel optimization techniques for streaming data processing'
  },
  {
    id: '2',
    clientId: '1',
    contractorId: '2',
    contractorName: 'Maria Santos',
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    task: 'Quantum error correction protocol review',
    duration: 360, // 6 hours
    date: '2024-12-16',
    hourlyRate: 175,
    isRnD: true,
    invoiceNumber: 'QS-2024-012',
    notes: 'Reviewed and provided feedback on topological error correction implementation'
  },
  {
    id: '3',
    clientId: '2',
    contractorId: '3',
    contractorName: 'Dr. James Wilson',
    projectId: '4',
    projectName: 'Gene Therapy Delivery System',
    task: 'Nanoparticle design consultation',
    duration: 240, // 4 hours
    date: '2024-12-15',
    hourlyRate: 200,
    isRnD: true,
    invoiceNumber: 'BTR-2024-008',
    notes: 'Consulted on novel nanoparticle targeting mechanisms'
  }
];

export const mockKnowledgeBaseEntries: KnowledgeBaseEntry[] = [
  {
    id: '1',
    clientId: '1',
    title: 'Lessons from Gradient Descent Optimization Failures',
    content: `# What We Learned from Failed Optimization Attempts

## The Problem
Our initial approach to optimizing gradient descent for streaming data resulted in significant accuracy degradation. Here's what went wrong and what we learned.

## Failed Approaches
1. **Fixed Learning Rate**: Caused oscillation in loss function
2. **Momentum-based Methods**: Led to overshooting optimal parameters
3. **Batch Normalization**: Introduced computational overhead without benefits

## Key Insights
- Streaming data requires adaptive learning rates that respond to data distribution changes
- Traditional optimization methods assume static data distributions
- Memory constraints in streaming environments require novel approaches

## What Worked
Eventually, we developed a hybrid approach combining:
- Adaptive learning rates based on data variance
- Lightweight momentum with decay
- Custom memory management for streaming contexts

## Code Snippet
\`\`\`python
def adaptive_learning_rate(data_variance, base_lr=0.01):
    return base_lr * (1 / (1 + data_variance))
\`\`\`

## Next Steps
This approach will be tested on larger datasets and different streaming scenarios.`,
    category: 'lessons-learned',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    author: 'Sarah Chen',
    createdAt: '2024-12-15T10:00:00Z',
    updatedAt: '2024-12-15T10:00:00Z',
    tags: ['machine-learning', 'optimization', 'streaming-data', 'gradient-descent'],
    isPublic: true,
    relatedSprint: 'Sprint 2024-12'
  },
  {
    id: '2',
    clientId: '1',
    title: 'Quantum Error Correction Code Snippets',
    content: `# Useful Quantum Error Correction Code

## Surface Code Implementation
Here are the key code snippets for implementing surface codes in our quantum error correction system.

## Stabilizer Measurement
\`\`\`python
def measure_stabilizers(qubits, stabilizer_ops):
    results = []
    for op in stabilizer_ops:
        measurement = apply_pauli_measurement(qubits, op)
        results.append(measurement)
    return results
\`\`\`

## Error Syndrome Decoding
\`\`\`python
def decode_syndrome(syndrome, code_distance):
    # Minimum weight perfect matching algorithm
    graph = build_syndrome_graph(syndrome)
    matching = minimum_weight_matching(graph)
    return extract_correction(matching)
\`\`\`

## Performance Notes
- Surface codes show 15% improvement in fidelity
- Decoding time scales as O(n^3) with code distance
- Memory requirements are manageable for distances up to 7

## References
- Fowler et al. (2012) - Surface code implementation
- Dennis et al. (2002) - Topological quantum memory`,
    category: 'code-snippets',
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    author: 'Dr. Emily Watson',
    createdAt: '2024-12-14T14:30:00Z',
    updatedAt: '2024-12-14T14:30:00Z',
    tags: ['quantum-computing', 'error-correction', 'surface-codes', 'python'],
    isPublic: true,
    relatedSprint: 'Sprint 2024-12'
  },
  {
    id: '3',
    clientId: '2',
    title: 'Failed Nanoparticle Synthesis Experiments',
    content: `# Nanoparticle Synthesis Failures - December 2024

## Experiment Overview
Attempted to synthesize targeting nanoparticles using three different polymer compositions. All three approaches failed to achieve desired targeting specificity.

## Failed Formulations

### Formulation A: PEG-PLGA Core
- **Composition**: 70% PLGA, 30% PEG
- **Target Size**: 50-100nm
- **Result**: Particles aggregated, size >500nm
- **Reason for Failure**: Insufficient stabilization during synthesis

### Formulation B: Chitosan-Based
- **Composition**: Chitosan with crosslinked albumin
- **Target Size**: 80-120nm
- **Result**: Rapid degradation in physiological conditions
- **Reason for Failure**: Poor crosslinking density

### Formulation C: Lipid Nanoparticles
- **Composition**: DSPC/Cholesterol/PEG-lipid
- **Target Size**: 60-100nm
- **Result**: Poor drug loading efficiency (<10%)
- **Reason for Failure**: Incompatible drug-lipid interactions

## Key Learnings
1. Polymer molecular weight critically affects particle stability
2. Crosslinking must be optimized for each polymer system
3. Drug-carrier compatibility testing is essential before synthesis
4. pH and ionic strength during synthesis significantly impact outcomes

## Next Approaches
- Test hybrid polymer-lipid systems
- Optimize crosslinking chemistry
- Implement real-time particle size monitoring during synthesis`,
    category: 'failed-experiments',
    projectId: '4',
    projectName: 'Gene Therapy Delivery System',
    author: 'Dr. Sarah Kim',
    createdAt: '2024-12-13T16:45:00Z',
    updatedAt: '2024-12-13T16:45:00Z',
    tags: ['nanoparticles', 'drug-delivery', 'polymer-synthesis', 'biomedical'],
    isPublic: true,
    relatedSprint: 'Sprint 2024-12'
  },
  {
    id: '4',
    clientId: '1',
    title: 'Best Practices for R&D Documentation',
    content: `# R&D Documentation Best Practices

## Why Documentation Matters
Proper documentation is crucial for R&D tax credit qualification and audit defense. Here are our team's best practices.

## Technical Uncertainty Documentation
- **Always document the "why"**: Explain why existing solutions don't work
- **Be specific**: Vague statements like "improve performance" are insufficient
- **Quantify uncertainty**: Use specific metrics and thresholds

## Experimentation Process
- **Hypothesis-driven**: Each experiment should test a specific hypothesis
- **Document failures**: Failed experiments are as valuable as successful ones
- **Version control**: Track all code changes with meaningful commit messages

## Time Tracking Guidelines
- **Real-time logging**: Don't rely on memory at end of day
- **Task specificity**: "Coding" is too vague, "Implementing error correction algorithm" is better
- **R&D vs. routine**: Clearly distinguish between research and routine development

## Code Documentation
- **Comment experimental code**: Explain the research purpose
- **Document assumptions**: What assumptions are being tested?
- **Link to research**: Reference related technical notes and experiments

## Review Process
- **Weekly reviews**: Team reviews all R&D documentation weekly
- **Peer validation**: Have colleagues review technical uncertainty descriptions
- **Compliance check**: Regular compliance reviews with finance team

## Tools and Templates
- Use standardized templates for experiment documentation
- Maintain consistent naming conventions
- Regular backups of all documentation`,
    category: 'best-practices',
    projectId: '',
    author: 'Mike Johnson',
    createdAt: '2024-12-12T11:20:00Z',
    updatedAt: '2024-12-12T11:20:00Z',
    tags: ['documentation', 'best-practices', 'compliance', 'r&d-tax-credit'],
    isPublic: true,
    relatedSprint: ''
  }
];

export const mockMilestones: Milestone[] = [
  {
    id: '1',
    clientId: '1',
    projectId: '1',
    title: 'Algorithm Optimization Milestone',
    description: 'Complete optimization of streaming data algorithms with 50% performance improvement',
    dueDate: '2024-12-31',
    status: 'in-progress',
    type: 'project',
    isRnDRelated: true,
    assignedTo: ['Sarah Chen', 'Mike Johnson']
  },
  {
    id: '2',
    clientId: '1',
    projectId: '2',
    title: 'Quantum Error Correction Prototype',
    description: 'Deliver working prototype of quantum error correction system',
    dueDate: '2025-01-15',
    status: 'pending',
    type: 'project',
    isRnDRelated: true,
    assignedTo: ['Dr. Emily Watson']
  },
  {
    id: '3',
    clientId: '1',
    projectId: '',
    title: 'Q4 2024 Tax Filing Deadline',
    description: 'Submit R&D tax credit documentation for Q4 2024',
    dueDate: '2025-01-31',
    status: 'pending',
    type: 'tax-deadline',
    isRnDRelated: true,
    assignedTo: ['Finance Team']
  },
  {
    id: '4',
    clientId: '2',
    projectId: '4',
    title: 'Nanoparticle Synthesis Completion',
    description: 'Complete development of targeting nanoparticle system',
    dueDate: '2025-02-28',
    status: 'pending',
    type: 'project',
    isRnDRelated: true,
    assignedTo: ['Dr. Sarah Kim', 'Robert Chen']
  },
  {
    id: '5',
    clientId: '1',
    projectId: '',
    title: 'Sprint 2024-12 Review',
    description: 'Complete sprint review and retrospective for December 2024',
    dueDate: '2024-12-20',
    status: 'completed',
    type: 'sprint',
    isRnDRelated: true,
    assignedTo: ['All Team Members']
  }
];

export const mockClientCompliance: ClientCompliance[] = [
  {
    clientId: '1',
    completedItems: [
      'project-qualification',
      'time-tracking',
      'technical-documentation',
      'employee-qualification',
      'source-control',
      'project-management'
    ],
    lastUpdated: '2024-12-18T10:00:00Z',
    overallScore: 75
  },
  {
    clientId: '2',
    completedItems: [
      'project-qualification',
      'time-tracking',
      'technical-documentation',
      'expense-tracking'
    ],
    lastUpdated: '2024-12-17T15:30:00Z',
    overallScore: 60
  },
  {
    clientId: '3',
    completedItems: [
      'project-qualification',
      'time-tracking'
    ],
    lastUpdated: '2024-12-16T09:15:00Z',
    overallScore: 25
  }
];

export const mockExperiments: Experiment[] = [
  {
    id: '1',
    clientId: '1',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    title: 'Gradient Descent Optimization for Streaming Data',
    hypothesis: 'Adaptive learning rates based on data variance will improve convergence speed by 40% while maintaining accuracy above 95%',
    technicalUncertainty: 'Unknown how to maintain model accuracy above 95% while processing infinite data streams with changing distributions',
    technologies: ['Python', 'TensorFlow', 'NumPy', 'Streaming Analytics', 'Machine Learning'],
    methodology: 'Systematic testing of 15 different adaptive learning rate algorithms with controlled A/B testing methodology',
    expectedOutcome: 'Achieve 40% improvement in processing speed with maintained accuracy',
    actualResults: 'Achieved 34% improvement in processing speed with 97.2% accuracy maintained',
    status: 'completed',
    startDate: '2024-11-01',
    endDate: '2024-12-15',
    author: 'Sarah Chen',
    collaborators: ['Mike Johnson', 'Alex Rodriguez'],
    isRnDQualified: true,
    passFailStatus: 'pass',
    issuesFound: ['Memory usage higher than expected', 'Convergence instability with certain data patterns'],
    lessonsLearned: 'Adaptive learning rates work best when combined with momentum decay. Memory optimization requires custom data structures.',
    nextSteps: 'Test on larger datasets and implement memory optimization techniques',
    relatedExperiments: [],
    attachments: [],
    createdAt: '2024-11-01T09:00:00Z',
    updatedAt: '2024-12-15T16:30:00Z'
  },
  {
    id: '2',
    clientId: '1',
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    title: 'Topological Error Correction Implementation',
    hypothesis: 'Surface codes with topological protection will achieve 15% improvement in quantum state fidelity',
    technicalUncertainty: 'Uncertain how to implement topological error correction in current quantum hardware while achieving target fidelity improvement',
    technologies: ['Quantum Computing', 'Python', 'Qiskit', 'Surface Codes', 'Error Correction'],
    methodology: 'Systematic testing of 8 different surface code configurations with controlled quantum state measurements',
    expectedOutcome: '15% improvement in fidelity with reduced decoherence time',
    actualResults: 'Achieved 15% improvement in fidelity and 23% reduction in decoherence time',
    status: 'completed',
    startDate: '2024-10-15',
    endDate: '2024-12-10',
    author: 'Dr. Emily Watson',
    collaborators: ['James Park'],
    isRnDQualified: true,
    passFailStatus: 'pass',
    issuesFound: ['Hardware limitations with gate fidelity', 'Scaling challenges beyond distance 5'],
    lessonsLearned: 'Topological codes show excellent promise but require high-fidelity gates. Environmental isolation is critical.',
    nextSteps: 'Investigate hybrid error correction approaches and improved gate implementations',
    relatedExperiments: [],
    attachments: [],
    createdAt: '2024-10-15T10:00:00Z',
    updatedAt: '2024-12-10T14:45:00Z'
  },
  {
    id: '3',
    clientId: '2',
    projectId: '4',
    projectName: 'Gene Therapy Delivery System',
    title: 'Nanoparticle Targeting Mechanism Development',
    hypothesis: 'Hybrid polymer-lipid nanoparticles will achieve 80% targeting accuracy for specific cell types',
    technicalUncertainty: 'Unknown how to prevent immune system rejection while maintaining therapeutic efficacy and targeting specificity',
    technologies: ['Biomedical Engineering', 'Polymer Chemistry', 'Lipid Nanoparticles', 'Cell Biology'],
    methodology: 'Systematic synthesis and testing of 12 different polymer-lipid combinations with in-vitro targeting assays',
    expectedOutcome: '80% targeting accuracy with minimal immune response',
    actualResults: '',
    status: 'in-progress',
    startDate: '2024-11-15',
    endDate: '',
    author: 'Dr. Sarah Kim',
    collaborators: ['Robert Chen', 'Maria Lopez'],
    isRnDQualified: true,
    passFailStatus: 'inconclusive',
    issuesFound: [],
    lessonsLearned: '',
    nextSteps: 'Complete current synthesis batch and begin targeting assays',
    relatedExperiments: [],
    attachments: [],
    createdAt: '2024-11-15T08:30:00Z',
    updatedAt: '2024-12-18T11:20:00Z'
  }
];

export const mockAutoTimeEntries: AutoTimeEntry[] = [
  {
    id: '1',
    clientId: '1',
    source: 'github',
    sourceId: 'commit-abc123',
    projectId: '1',
    duration: 180, // 3 hours
    activity: 'Implemented adaptive learning rate algorithm',
    timestamp: '2024-12-18T10:30:00Z',
    isRnD: true,
    confidence: 0.92,
    metadata: {
      repository: 'ai-analytics-engine',
      branch: 'feature/adaptive-learning',
      commits: [
        'Implement adaptive learning rate calculation',
        'Add variance-based rate adjustment',
        'Optimize memory usage for streaming data'
      ],
      approved: false,
      rejected: false
    }
  },
  {
    id: '2',
    clientId: '1',
    source: 'jira',
    sourceId: 'RND-456',
    projectId: '2',
    duration: 240, // 4 hours
    activity: 'Quantum error correction protocol development',
    timestamp: '2024-12-17T14:00:00Z',
    isRnD: true,
    confidence: 0.88,
    metadata: {
      ticketId: 'RND-456',
      approved: true,
      rejected: false
    }
  },
  {
    id: '3',
    clientId: '1',
    source: 'vscode',
    sourceId: 'session-789',
    projectId: '1',
    duration: 120, // 2 hours
    activity: 'Code debugging and performance optimization',
    timestamp: '2024-12-18T16:00:00Z',
    isRnD: true,
    confidence: 0.75,
    metadata: {
      fileTypes: ['.py', '.ipynb'],
      approved: false,
      rejected: false
    }
  },
  {
    id: '4',
    clientId: '1',
    source: 'github',
    sourceId: 'commit-def456',
    projectId: '3',
    duration: 90, // 1.5 hours
    activity: 'Documentation update and code comments',
    timestamp: '2024-12-18T09:00:00Z',
    isRnD: false,
    confidence: 0.65,
    metadata: {
      repository: 'blockchain-security',
      branch: 'docs/update-readme',
      commits: ['Update README with installation instructions'],
      approved: false,
      rejected: false
    }
  }
];

export const mockRnDAIAnalyses: RnDAIAnalysis[] = [
  {
    id: '1',
    taskDescription: 'Developing a new machine learning algorithm to optimize real-time data processing with improved accuracy',
    isRnDQualified: true,
    confidence: 0.94,
    reasoning: 'This task involves developing new algorithmic approaches for real-time data processing, which represents technological innovation beyond existing solutions. The focus on optimization and improved accuracy indicates systematic experimentation to overcome technical uncertainty.',
    suggestedTags: ['machine-learning', 'algorithm', 'optimization', 'real-time', 'data-processing'],
    technicalUncertainty: 'The optimal approach for balancing real-time processing speed with accuracy improvements is not established in current literature.',
    recommendedDocumentation: [
      'Technical specifications and performance requirements',
      'Experimental methodology and testing protocols',
      'Benchmark comparisons with existing solutions',
      'Algorithm design decisions and trade-offs',
      'Performance metrics and validation results'
    ],
    irsSection41Alignment: 'Meets IRC Section 41 four-part test: technological in nature, addresses technical uncertainty, involves systematic experimentation, and aims to improve business component functionality.',
    timestamp: '2024-12-18T10:15:00Z'
  },
  {
    id: '2',
    taskDescription: 'Fixing a bug in the user login system where passwords are not being validated correctly',
    isRnDQualified: false,
    confidence: 0.89,
    reasoning: 'This task involves routine debugging and maintenance of existing functionality. Bug fixes typically do not involve technological uncertainty or systematic experimentation, and are considered routine development activities.',
    suggestedTags: ['bug-fix', 'authentication', 'maintenance', 'validation'],
    technicalUncertainty: 'No significant technical uncertainty - this is a standard debugging task using established methods.',
    recommendedDocumentation: [],
    irsSection41Alignment: 'Does not meet IRC Section 41 requirements as it involves routine maintenance rather than qualified research activities.',
    timestamp: '2024-12-17T15:30:00Z'
  },
  {
    id: '3',
    taskDescription: 'Researching and implementing quantum error correction protocols for improved qubit stability',
    isRnDQualified: true,
    confidence: 0.96,
    reasoning: 'This task involves cutting-edge quantum computing research with significant technical uncertainty. Quantum error correction represents a frontier technology area with substantial innovation potential and systematic experimentation requirements.',
    suggestedTags: ['quantum-computing', 'error-correction', 'research', 'protocols', 'stability'],
    technicalUncertainty: 'Implementation of quantum error correction in practical quantum systems involves substantial technical challenges not fully resolved by existing methods.',
    recommendedDocumentation: [
      'Quantum system specifications and constraints',
      'Error correction protocol design and rationale',
      'Experimental setup and measurement procedures',
      'Fidelity improvement metrics and analysis',
      'Comparison with existing error correction methods'
    ],
    irsSection41Alignment: 'Strongly aligns with IRC Section 41 as it involves technological advancement in quantum computing with clear technical uncertainty and systematic research approach.',
    timestamp: '2024-12-16T11:45:00Z'
  }
];

export const mockDocuments: Document[] = [
  {
    id: '1',
    clientId: '1',
    name: 'Algorithm Research Documentation',
    description: 'Comprehensive documentation of machine learning algorithm research and development process',
    fileName: 'ml-algorithm-research.pdf',
    fileSize: 2048576,
    fileType: 'application/pdf',
    fileUrl: '/documents/ml-algorithm-research.pdf',
    category: 'technical-documentation',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    isRnDRelated: true,
    tags: ['machine-learning', 'algorithm', 'research', 'optimization'],
    uploadedAt: '2024-12-18T10:00:00Z',
    uploadedBy: 'Sarah Chen',
    confidentialityLevel: 'internal'
  },
  {
    id: '2',
    clientId: '1',
    name: 'Quantum Computing Research Contract',
    description: 'Contract agreement for quantum computing research collaboration',
    fileName: 'quantum-research-contract.docx',
    fileSize: 512000,
    fileType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    fileUrl: '/documents/quantum-research-contract.docx',
    category: 'contracts',
    projectId: '2',
    projectName: 'Quantum Computing Interface',
    isRnDRelated: true,
    tags: ['contract', 'quantum-computing', 'collaboration'],
    uploadedAt: '2024-12-17T14:30:00Z',
    uploadedBy: 'Dr. Emily Watson',
    confidentialityLevel: 'confidential'
  },
  {
    id: '3',
    clientId: '1',
    name: 'GPU Equipment Purchase Receipt',
    description: 'Receipt for high-performance GPU cluster purchase for ML research',
    fileName: 'gpu-purchase-receipt.pdf',
    fileSize: 256000,
    fileType: 'application/pdf',
    fileUrl: '/documents/gpu-purchase-receipt.pdf',
    category: 'receipts-invoices',
    projectId: '1',
    projectName: 'AI-Powered Analytics Engine',
    isRnDRelated: true,
    tags: ['receipt', 'equipment', 'gpu', 'hardware'],
    uploadedAt: '2024-12-15T09:15:00Z',
    uploadedBy: 'Mike Johnson',
    confidentialityLevel: 'internal'
  },
  {
    id: '4',
    clientId: '2',
    name: 'Nanoparticle Synthesis Lab Report',
    description: 'Detailed lab report on nanoparticle synthesis experiments and results',
    fileName: 'nanoparticle-lab-report.pdf',
    fileSize: 3145728,
    fileType: 'application/pdf',
    fileUrl: '/documents/nanoparticle-lab-report.pdf',
    category: 'research-reports',
    projectId: '4',
    projectName: 'Gene Therapy Delivery System',
    isRnDRelated: true,
    tags: ['nanoparticles', 'synthesis', 'lab-report', 'biomedical'],
    uploadedAt: '2024-12-14T16:45:00Z',
    uploadedBy: 'Dr. Sarah Kim',
    confidentialityLevel: 'confidential'
  },
  {
    id: '5',
    clientId: '1',
    name: 'Employee R&D Qualification Records',
    description: 'Documentation of employee qualifications and R&D activity percentages',
    fileName: 'employee-rnd-qualifications.xlsx',
    fileSize: 1024000,
    fileType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    fileUrl: '/documents/employee-rnd-qualifications.xlsx',
    category: 'employee-records',
    isRnDRelated: true,
    tags: ['employees', 'qualifications', 'rnd-percentage', 'compliance'],
    uploadedAt: '2024-12-13T11:20:00Z',
    uploadedBy: 'HR Department',
    confidentialityLevel: 'restricted'
  },
  {
    id: '6',
    clientId: '3',
    name: 'Solar Panel Efficiency Test Results',
    description: 'Test results and analysis for perovskite-silicon tandem solar cell efficiency',
    fileName: 'solar-efficiency-tests.pdf',
    fileSize: 1536000,
    fileType: 'application/pdf',
    fileUrl: '/documents/solar-efficiency-tests.pdf',
    category: 'research-reports',
    projectId: '6',
    projectName: 'Solar Panel Efficiency Enhancement',
    isRnDRelated: true,
    tags: ['solar', 'efficiency', 'perovskite', 'testing'],
    uploadedAt: '2024-12-12T13:30:00Z',
    uploadedBy: 'Dr. Mark Wilson',
    confidentialityLevel: 'internal'
  }
];