import React, { useState } from 'react';
import { Brain, Zap, CheckCircle, XCircle, AlertTriangle, Lightbulb, FileText, Tag } from 'lucide-react';
import { RnDAIAnalysis } from '../types';

interface AIRnDAnalyzerProps {
  analyses: RnDAIAnalysis[];
  onAnalyzeTask: (taskDescription: string) => void;
}

export const AIRnDAnalyzer: React.FC<AIRnDAnalyzerProps> = ({
  analyses,
  onAnalyzeTask
}) => {
  const [taskDescription, setTaskDescription] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentAnalysis, setCurrentAnalysis] = useState<RnDAIAnalysis | null>(null);

  const handleAnalyze = async () => {
    if (!taskDescription.trim()) return;
    
    setIsAnalyzing(true);
    
    // Simulate AI analysis
    setTimeout(() => {
      const analysis: RnDAIAnalysis = {
        id: Date.now().toString(),
        taskDescription,
        isRnDQualified: analyzeRnDQualification(taskDescription),
        confidence: Math.random() * 0.4 + 0.6, // 60-100%
        reasoning: generateReasoning(taskDescription),
        suggestedTags: generateTags(taskDescription),
        technicalUncertainty: generateUncertainty(taskDescription),
        recommendedDocumentation: generateDocumentation(taskDescription),
        irsSection41Alignment: generateIRSAlignment(taskDescription),
        timestamp: new Date().toISOString()
      };
      
      setCurrentAnalysis(analysis);
      onAnalyzeTask(taskDescription);
      setIsAnalyzing(false);
    }, 2000);
  };

  const analyzeRnDQualification = (description: string): boolean => {
    // Keywords and phrases aligned with IRS Section 41 four-part test
    const rndCriteria = [
      // Permitted Purpose (weight: 2-3)
      { keyword: 'develop new', weight: 3 },
      { keyword: 'improve functionality', weight: 3 },
      { keyword: 'enhance performance', weight: 3 },
      { keyword: 'improve reliability', weight: 3 },
      { keyword: 'improve quality', weight: 3 },
      { keyword: 'new product', weight: 2 },
      { keyword: 'new process', weight: 2 },
      { keyword: 'prototype', weight: 2 },
      { keyword: 'innovation', weight: 2 },
      // Technological in Nature (weight: 2)
      { keyword: 'engineering', weight: 2 },
      { keyword: 'computer science', weight: 2 },
      { keyword: 'physics', weight: 2 },
      { keyword: 'chemistry', weight: 2 },
      { keyword: 'biological science', weight: 2 },
      { keyword: 'software development', weight: 2 },
      { keyword: 'algorithm', weight: 2 },
      { keyword: 'machine learning', weight: 2 },
      // Elimination of Uncertainty (weight: 3-4)
      { keyword: 'technical uncertainty', weight: 4 },
      { keyword: 'uncertainty', weight: 3 },
      { keyword: 'unknown capability', weight: 3 },
      { keyword: 'feasibility', weight: 3 },
      // Process of Experimentation (weight: 3-4)
      { keyword: 'process of experimentation', weight: 4 },
      { keyword: 'systematic experimentation', weight: 4 },
      { keyword: 'testing alternatives', weight: 3 },
      { keyword: 'trial and error', weight: 3 },
      { keyword: 'simulation', weight: 3 },
      { keyword: 'modeling', weight: 3 }
    ];

    // Non-qualifying keywords and phrases (negative weights)
    const nonRndCriteria = [
      { keyword: 'maintenance', weight: -3 },
      { keyword: 'bug fix', weight: -3 },
      { keyword: 'routine', weight: -3 },
      { keyword: 'post-production', weight: -4 },
      { keyword: 'commercial production', weight: -4 },
      { keyword: 'adaptation existing', weight: -3 },
      { keyword: 'reproduction existing', weight: -3 },
      { keyword: 'social science', weight: -3 },
      { keyword: 'arts', weight: -3 },
      { keyword: 'humanities', weight: -3 },
      { keyword: 'administrative', weight: -2 },
      { keyword: 'meeting', weight: -2 },
      { keyword: 'documentation', weight: -2 }
    ];

    const lowerDesc = description.toLowerCase();

    // Calculate scores for R&D and non-R&D criteria
    const rndScore = rndCriteria.reduce((sum, { keyword, weight }) => 
      sum + (lowerDesc.includes(keyword) ? weight : 0), 0);
    const nonRndScore = nonRndCriteria.reduce((sum, { keyword, weight }) => 
      sum + (lowerDesc.includes(keyword) ? weight : 0), 0);

    // Bonus for combinations indicating strong R&D alignment
    const comboBonus = [
      { keywords: ['develop', 'uncertainty'], bonus: 2 },
      { keywords: ['experiment', 'technical'], bonus: 2 },
      { keywords: ['prototype', 'testing'], bonus: 2 }
    ].reduce((sum, { keywords, bonus }) => 
      sum + (keywords.every(k => lowerDesc.includes(k)) ? bonus : 0), 0);

    // Total score with threshold for qualification
    const totalScore = rndScore + nonRndScore + comboBonus;
    return totalScore > 5 && rndScore > 0; // Require positive R&D score and high threshold
  };

  const generateReasoning = (description: string): string => {
    const isQualified = analyzeRnDQualification(description);
    
    if (isQualified) {
      return `This task likely qualifies for R&D tax credits under IRC Section 41. It appears to involve technological innovation, systematic experimentation, or addressing technical uncertainty, aligning with the IRS four-part test for qualified research. The activities suggest development or improvement of a business component with a scientific or technological basis.`;
    } else {
      return `This task may not qualify for R&D tax credits under IRC Section 41. It appears to involve routine development, maintenance, or non-technological activities, or lacks evidence of systematic experimentation or technical uncertainty required for qualified research.`;
    }
  };

  const generateTags = (description: string): string[] => {
    const tagMap: { [key: string]: string[] } = {
      'machine learning': ['ML', 'AI', 'algorithm', 'data-science'],
      'algorithm': ['optimization', 'performance', 'computational'],
      'database': ['data-management', 'storage', 'query-optimization'],
      'frontend': ['UI', 'UX', 'user-interface', 'web-development'],
      'backend': ['API', 'server', 'infrastructure', 'microservices'],
      'testing': ['QA', 'automation', 'validation', 'verification'],
      'security': ['cybersecurity', 'encryption', 'authentication'],
      'mobile': ['iOS', 'Android', 'mobile-development'],
      'cloud': ['AWS', 'Azure', 'cloud-computing', 'scalability'],
      'engineering': ['mechanical', 'electrical', 'systems'],
      'prototype': ['proof-of-concept', 'MVP', 'experimental'],
      'uncertainty': ['research', 'feasibility', 'exploration']
    };
    
    const lowerDesc = description.toLowerCase();
    const tags: string[] = [];
    
    Object.entries(tagMap).forEach(([keyword, relatedTags]) => {
      if (lowerDesc.includes(keyword)) {
        tags.push(...relatedTags);
      }
    });
    
    return [...new Set(tags)].slice(0, 5);
  };

  const generateUncertainty = (description: string): string => {
    const uncertaintyTemplates = [
      "Uncertainty exists regarding the optimal design or methodology to achieve the desired functionality or performance.",
      "The feasibility of integrating the proposed technology with existing systems is unknown.",
      "Technical uncertainty surrounds the ability to meet performance requirements within current constraints.",
      "Multiple technical approaches were evaluated due to uncertainty in achieving the desired outcome.",
      "The activity involves resolving uncertainties about the capability or method of development."
    ];
    
    return uncertaintyTemplates[Math.floor(Math.random() * uncertaintyTemplates.length)];
  };

  const generateDocumentation = (description: string): string[] => {
    return [
      "Detailed technical specifications and requirements",
      "Experimental methodology and test plans",
      "Documentation of alternative approaches evaluated",
      "Test results and performance benchmarks",
      "Records of technical uncertainties and resolutions"
    ];
  };

  const generateIRSAlignment = (description: string): string => {
    return "This activity aligns with IRC Section 41 requirements for qualified research, meeting the four-part test: permitted purpose, technological in nature, elimination of uncertainty, and process of experimentation.";
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getQualificationIcon = (isQualified: boolean) => {
    return isQualified ? (
      <CheckCircle className="h-5 w-5 text-green-600" />
    ) : (
      <XCircle className="h-5 w-5 text-red-600" />
    );
  };

  const recentAnalyses = analyses.slice(0, 5);
  const qualifiedCount = analyses.filter(a => a.isRnDQualified).length;
  const avgConfidence = analyses.length > 0 ? analyses.reduce((sum, a) => sum + a.confidence, 0) / analyses.length : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">AI R&D Qualification Analyzer</h1>
        <div className="flex items-center space-x-2">
          <Brain className="h-5 w-5 text-blue-600" />
          <span className="text-sm text-gray-600">AI-powered R&D qualification assessment</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Brain className="h-4 w-4 mr-1" />
            Total Analyses
          </h4>
          <p className="text-2xl font-bold text-blue-600">{analyses.length}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            R&D Qualified
          </h4>
          <p className="text-2xl font-bold text-green-600">{qualifiedCount}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Zap className="h-4 w-4 mr-1" />
            Avg Confidence
          </h4>
          <p className="text-2xl font-bold text-purple-600">{Math.round(avgConfidence * 100)}%</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <Brain className="h-5 w-5 mr-2" />
            Analyze New Task
          </h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Task Description
              </label>
              <textarea
                value={taskDescription}
                onChange={(e) => setTaskDescription(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={4}
                placeholder="Describe the task or activity you want to analyze for R&D qualification..."
              />
            </div>
            
            <button
              onClick={handleAnalyze}
              disabled={!taskDescription.trim() || isAnalyzing}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {isAnalyzing ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4" />
                  <span>Analyze R&D Qualification</span>
                </>
              )}
            </button>
          </div>

          {currentAnalysis && (
            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  {getQualificationIcon(currentAnalysis.isRnDQualified)}
                  <span className="font-medium text-gray-900">
                    {currentAnalysis.isRnDQualified ? 'Likely R&D Qualified' : 'Not R&D Qualified'}
                  </span>
                </div>
                <span className={`text-sm font-medium ${getConfidenceColor(currentAnalysis.confidence)}`}>
                  {Math.round(currentAnalysis.confidence * 100)}% confidence
                </span>
              </div>
              
              <p className="text-sm text-gray-700 mb-3">{currentAnalysis.reasoning}</p>
              
              {currentAnalysis.suggestedTags.length > 0 && (
                <div className="mb-3">
                  <p className="text-xs font-medium text-gray-700 mb-1">Suggested Tags:</p>
                  <div className="flex flex-wrap gap-1">
                    {currentAnalysis.suggestedTags.map((tag, index) => (
                      <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-100 text-blue-600">
                        <Tag className="h-3 w-3 mr-1" />
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              {currentAnalysis.isRnDQualified && (
                <div className="space-y-2">
                  <div>
                    <p className="text-xs font-medium text-gray-700 mb-1">Technical Uncertainty:</p>
                    <p className="text-xs text-gray-600">{currentAnalysis.technicalUncertainty}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-gray-700 mb-1">Recommended Documentation:</p>
                    <ul className="text-xs text-gray-600 list-disc list-inside">
                      {currentAnalysis.recommendedDocumentation.map((doc, index) => (
                        <li key={index}>{doc}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Analyses</h3>
          
          <div className="space-y-3">
            {recentAnalyses.map((analysis) => (
              <div key={analysis.id} className="border border-gray-200 rounded-lg p-3">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getQualificationIcon(analysis.isRnDQualified)}
                    <span className={`text-sm font-medium ${getConfidenceColor(analysis.confidence)}`}>
                      {Math.round(analysis.confidence * 100)}%
                    </span>
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(analysis.timestamp).toLocaleDateString()}
                  </span>
                </div>
                
                <p className="text-sm text-gray-900 mb-2 line-clamp-2">
                  {analysis.taskDescription}
                </p>
                
                {analysis.suggestedTags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {analysis.suggestedTags.slice(0, 3).map((tag, index) => (
                      <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                        {tag}
                      </span>
                    ))}
                    {analysis.suggestedTags.length > 3 && (
                      <span className="text-xs text-gray-500">+{analysis.suggestedTags.length - 3}</span>
                    )}
                  </div>
                )}
              </div>
            ))}
            
            {recentAnalyses.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Brain className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p className="text-sm">No analyses yet. Start by describing a task above.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="bg-blue-50 p-6 rounded-xl">
        <h3 className="text-lg font-semibold text-blue-900 mb-3 flex items-center">
          <Lightbulb className="h-5 w-5 mr-2" />
          How the AI Analyzer Works
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
          <div>
            <h4 className="font-medium mb-2">Analysis Criteria</h4>
            <ul className="space-y-1 list-disc list-inside">
              <li>Technological innovation keywords</li>
              <li>Technical uncertainty indicators</li>
              <li>Experimentation and research terms</li>
              <li>Novel approach descriptions</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium mb-2">R&D Qualification Factors</h4>
            <ul className="space-y-1 list-disc list-inside">
              <li>Technological in nature</li>
              <li>Technical uncertainty present</li>
              <li>Process of experimentation</li>
              <li>Qualified business purpose</li>
            </ul>
          </div>
        </div>
        <div className="mt-4 p-3 bg-blue-100 rounded-lg">
          <p className="text-sm text-blue-900">
            <strong>Note:</strong> This AI analysis provides guidance only. Final R&D qualification decisions should always be reviewed by qualified tax professionals and documented with proper supporting evidence.
          </p>
        </div>
      </div>
    </div>
  );
};