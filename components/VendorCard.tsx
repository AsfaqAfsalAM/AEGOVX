import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, ShieldQuestion } from 'lucide-react';
import { VendorResult } from '@/lib/types';
import { VendorLogo } from './VendorLogo';

interface VendorCardProps {
  vendor: VendorResult;
}

export const VendorCard: React.FC<VendorCardProps> = ({ vendor }) => {
  // Determine styles for the left colored block based on status
  const getStatusConfig = () => {
    switch (vendor.status) {
      case 'clean':
        return {
          pillBg: 'bg-emerald-600 dark:bg-emerald-700 text-white',
          badgeText: 'clean site',
          icon: <ShieldCheck className="w-4 h-4 flex-shrink-0" />,
          cardBorder: 'border-slate-200 dark:border-slate-800/80 hover:border-emerald-500/50',
          leftAccent: 'bg-emerald-500',
        };
      case 'malicious':
        return {
          pillBg: 'bg-rose-600 dark:bg-rose-700 text-white',
          badgeText: 'malicious site',
          icon: <ShieldX className="w-4 h-4 flex-shrink-0" />,
          cardBorder: 'border-rose-300 dark:border-rose-900/60 bg-rose-50/20 dark:bg-rose-950/20 hover:border-rose-500',
          leftAccent: 'bg-rose-600',
        };
      case 'suspicious':
        return {
          pillBg: 'bg-amber-600 dark:bg-amber-600 text-white',
          badgeText: 'suspicious site',
          icon: <ShieldAlert className="w-4 h-4 flex-shrink-0" />,
          cardBorder: 'border-amber-300 dark:border-amber-900/60 bg-amber-50/20 dark:bg-amber-950/20 hover:border-amber-500',
          leftAccent: 'bg-amber-500',
        };
      case 'unrated':
      default:
        return {
          pillBg: 'bg-slate-500 dark:bg-slate-700 text-slate-100',
          badgeText: 'unrated site',
          icon: <ShieldQuestion className="w-4 h-4 flex-shrink-0" />,
          cardBorder: 'border-slate-200 dark:border-slate-800/80 opacity-80 hover:opacity-100',
          leftAccent: 'bg-slate-400 dark:bg-slate-600',
        };
    }
  };

  const config = getStatusConfig();

  return (
    <div
      className={`group flex items-stretch rounded-xl border bg-white dark:bg-slate-900/90 shadow-sm transition-all duration-200 hover:shadow-md overflow-hidden ${config.cardBorder}`}
    >
      {/* Left colored block with shield icon and status label */}
      <div
        className={`flex flex-col items-center justify-center min-w-[110px] sm:min-w-[125px] px-2.5 py-3 ${config.pillBg} select-none transition-colors duration-200`}
      >
        <div className="mb-1 text-white">{config.icon}</div>
        <span className="text-[11px] font-bold uppercase tracking-wider text-center leading-tight">
          {config.badgeText}
        </span>
      </div>

      {/* Main card info: Vendor name, category, and detection details */}
      <div className="flex-1 flex items-center justify-between p-3.5 sm:p-4 min-w-0">
        <div className="min-w-0 pr-3">
          <div className="flex items-center gap-2">
            <h3 className="font-bold text-slate-900 dark:text-slate-100 text-sm sm:text-base truncate tracking-tight">
              {vendor.name}
            </h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate font-medium">
            {vendor.category}
          </p>
          {vendor.details && (
            <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-1 truncate">
              {vendor.details}
            </p>
          )}
        </div>

        {/* Brand logo / badge on right */}
        <div className="flex-shrink-0 flex items-center justify-center w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800/70 p-1">
          <VendorLogo logoKey={vendor.logoKey} name={vendor.name} className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
