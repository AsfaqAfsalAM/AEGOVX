import React from 'react';
import Link from 'next/link';
import { Shield, Lock, ExternalLink, Code2, Award, History } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-slate-200 dark:border-slate-800/80 bg-slate-50 dark:bg-slate-950 py-12 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl overflow-hidden bg-slate-950 border border-slate-700 shadow flex-shrink-0">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src="/aegovx-logo.jpg" alt="AEGOVX Logo" className="w-full h-full object-cover" />
              </div>
              <div>
                <span className="font-black text-xl tracking-wider text-slate-900 dark:text-white uppercase font-mono">
                  AEGOV<span className="text-sky-400">X</span>
                </span>
                <p className="text-[10px] text-slate-400 font-semibold tracking-widest uppercase">Evidence Before Trust</p>
              </div>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-400 max-w-md leading-relaxed">
              AEGOVX aggregates telemetry from 90+ antivirus engines, security vendors, domain reputation
              lists, direct feeds (Google Safe Browsing, URLhaus, Spamhaus DBL), and cryptographic TLS audits.
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-3 italic">
              Scan results and detections are provided by independent third-party security vendors.
              AEGOVX delivers evidence before trust without altering raw findings.
            </p>
          </div>

          {/* Tools */}
          <div>
            <h4 className="font-semibold text-sm text-slate-900 dark:text-white mb-3 tracking-wide uppercase">
              Tools & Features
            </h4>
            <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
              <li>
                <Link href="/" className="hover:text-emerald-500 transition-colors flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" /> Multi-Engine URL Scanner
                </Link>
              </li>
              <li>
                <Link href="/history" className="hover:text-emerald-500 transition-colors flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5" /> Scan History
                </Link>
              </li>
              <li>
                <Link href="/badge" className="hover:text-emerald-500 transition-colors flex items-center gap-1.5">
                  <Award className="w-3.5 h-3.5" /> Embeddable Security Badge
                </Link>
              </li>
              <li>
                <Link href="/api-docs" className="hover:text-emerald-500 transition-colors flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5" /> Public REST API
                </Link>
              </li>
              <li>
                <a
                  href="https://www.virustotal.com"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-emerald-500 transition-colors inline-flex items-center gap-1"
                >
                  VirusTotal Telemetry <ExternalLink className="w-3 h-3" />
                </a>
              </li>
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h4 className="font-semibold text-sm text-slate-900 dark:text-white mb-3 tracking-wide uppercase">
              Legal & Safety
            </h4>
            <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
              <li>
                <Link href="/privacy" className="hover:text-emerald-500 transition-colors">
                  Privacy Policy
                </Link>
              </li>
              <li>
                <Link href="/terms" className="hover:text-emerald-500 transition-colors">
                  Terms of Service
                </Link>
              </li>
              <li className="pt-1">
                <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-300 dark:border-emerald-800">
                  <Lock className="w-3 h-3" /> SSRF Hardened
                </span>
              </li>
              <li>
                <span className="inline-flex items-center gap-1 text-sky-600 dark:text-sky-400 text-xs font-semibold bg-sky-50 dark:bg-sky-950/60 px-2 py-0.5 rounded border border-sky-300 dark:border-sky-800">
                  <Shield className="w-3 h-3" /> A-Grade Security Headers
                </span>
              </li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-slate-200 dark:border-slate-800/80 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 dark:text-slate-400 gap-4">
          <p>© {new Date().getFullYear()} AEGOVX. Evidence Before Trust. All rights reserved.</p>
          <p className="flex items-center gap-1">
            Real-time intelligence from 90+ security vendors worldwide
          </p>
        </div>
      </div>
    </footer>
  );
};
