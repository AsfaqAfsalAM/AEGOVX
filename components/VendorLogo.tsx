import React from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  FileCode,
  Calendar,
  Network,
  GitFork,
  Radio,
  Globe,
  Database,
  Eye,
  Server
} from 'lucide-react';

interface VendorLogoProps {
  logoKey?: string;
  name: string;
  className?: string;
}

export const VendorLogo: React.FC<VendorLogoProps> = ({ logoKey, name, className = 'w-5 h-5' }) => {
  switch (logoKey) {
    case 'google':
      return (
        <svg className={className} viewBox="0 0 24 24">
          <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.66v3.04h3.88c2.27-2.09 3.66-5.17 3.66-9.14z" />
          <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.04c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.26v3.13C3.25 21.31 7.31 24 12 24z" />
          <path fill="#FBBC05" d="M5.28 14.28c-.25-.72-.38-1.49-.38-2.28s.13-1.56.38-2.28V6.59H1.26C.46 8.19 0 9.99 0 12s.46 3.81 1.26 5.41l4.02-3.13z" />
          <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.25 2.69 1.26 6.59l4.02 3.13c.95-2.83 3.6-4.97 6.72-4.97z" />
        </svg>
      );
    case 'microsoft':
      return (
        <svg className={className} viewBox="0 0 24 24">
          <rect fill="#F25022" x="1" y="1" width="10" height="10" />
          <rect fill="#7FBA00" x="13" y="1" width="10" height="10" />
          <rect fill="#00A4EF" x="1" y="13" width="10" height="10" />
          <rect fill="#FFB900" x="13" y="13" width="10" height="10" />
        </svg>
      );
    case 'cloudflare':
      return (
        <svg className={className} viewBox="0 0 24 24" fill="#F38020">
          <path d="M18.3 12.8c-.2-1.8-1.7-3.2-3.6-3.2-.8 0-1.5.3-2.1.7-.6-1.5-2.1-2.5-3.8-2.5-2.2 0-4 1.7-4.1 3.9C2.1 12 0 14.2 0 16.9c0 2.8 2.3 5.1 5.1 5.1h13.1c3.2 0 5.8-2.6 5.8-5.8 0-2.8-2-5.1-4.7-5.6l-1-.2z" />
        </svg>
      );
    case 'kaspersky':
      return (
        <span className="flex items-center justify-center font-black text-xs px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
          K
        </span>
      );
    case 'bitdefender':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
          B
        </span>
      );
    case 'sophos':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
          S
        </span>
      );
    case 'eset':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
          ESET
        </span>
      );
    case 'avast':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800">
          AVAST
        </span>
      );
    case 'avg':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
          AVG
        </span>
      );
    case 'fortinet':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-red-900 text-white">
          FORTI
        </span>
      );
    case 'trendmicro':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-red-800 text-white">
          TM
        </span>
      );
    case 'sucuri':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-emerald-900 text-emerald-200">
          SUCURI
        </span>
      );
    case 'urlhaus':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
          URLhaus
        </span>
      );
    case 'spamhaus':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-slate-800 text-sky-400">
          SPAMHAUS
        </span>
      );
    case 'openphish':
      return (
        <span className="flex items-center justify-center font-bold text-xs px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300">
          PHISH
        </span>
      );
    case 'ssl':
      return <Lock className={`${className} text-emerald-400`} />;
    case 'headers':
      return <FileCode className={`${className} text-sky-400`} />;
    case 'whois':
      return <Calendar className={`${className} text-violet-400`} />;
    case 'dns':
      return <Network className={`${className} text-amber-400`} />;
    case 'redirect':
      return <GitFork className={`${className} text-cyan-400`} />;
    default:
      return <Shield className={`${className} text-slate-400 opacity-60`} />;
  }
};
