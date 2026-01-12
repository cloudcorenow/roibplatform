import React, { useState } from 'react';
import { AlertTriangle, Building2, Eye, RefreshCw, X } from 'lucide-react';

interface PlatformAdminBannerProps {
  tenantName: string;
  readOnly: boolean;
  onSwitchTenant: () => void;
  onClose?: () => void;
}

export const PlatformAdminBanner: React.FC<PlatformAdminBannerProps> = ({
  tenantName,
  readOnly,
  onSwitchTenant,
  onClose
}) => {
  const [isVisible, setIsVisible] = useState(true);

  if (!isVisible) return null;

  const handleClose = () => {
    setIsVisible(false);
    if (onClose) onClose();
  };

  return (
    <div className="bg-gradient-to-r from-amber-500 to-orange-500 border-b-2 border-amber-600 px-4 py-3 shadow-md relative">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-4 flex-1">
          <div className="flex items-center space-x-2 bg-white/20 backdrop-blur-sm px-3 py-1.5 rounded-lg">
            <AlertTriangle className="h-5 w-5 text-white animate-pulse" />
            <span className="text-white font-bold text-sm uppercase tracking-wide">
              Platform Admin Mode
            </span>
          </div>

          <div className="hidden sm:flex items-center space-x-2 bg-white/20 backdrop-blur-sm px-3 py-1.5 rounded-lg">
            <Building2 className="h-4 w-4 text-white" />
            <span className="text-white font-semibold text-sm">
              Acting as:
            </span>
            <span className="text-white font-bold text-sm">{tenantName}</span>
          </div>

          {readOnly && (
            <div className="hidden md:flex items-center space-x-2 bg-white/20 backdrop-blur-sm px-3 py-1.5 rounded-lg">
              <Eye className="h-4 w-4 text-white" />
              <span className="text-white font-semibold text-sm">Read-Only Mode</span>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={onSwitchTenant}
            className="flex items-center space-x-2 bg-white text-amber-700 hover:bg-amber-50 px-4 py-2 rounded-lg font-semibold text-sm transition-all duration-200 shadow-sm hover:shadow-md"
          >
            <RefreshCw className="h-4 w-4" />
            <span className="hidden sm:inline">Switch Tenant</span>
            <span className="sm:hidden">Switch</span>
          </button>

          <button
            onClick={handleClose}
            className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
            aria-label="Close banner"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      </div>

      <div className="sm:hidden mt-2 flex items-center space-x-2 max-w-7xl mx-auto">
        <div className="flex items-center space-x-2 bg-white/20 backdrop-blur-sm px-3 py-1.5 rounded-lg">
          <Building2 className="h-4 w-4 text-white" />
          <span className="text-white font-semibold text-sm">{tenantName}</span>
        </div>
        {readOnly && (
          <div className="flex items-center space-x-2 bg-white/20 backdrop-blur-sm px-3 py-1.5 rounded-lg">
            <Eye className="h-4 w-4 text-white" />
            <span className="text-white font-semibold text-sm">Read-Only</span>
          </div>
        )}
      </div>
    </div>
  );
};
