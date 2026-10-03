'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { History, Trash2, ExternalLink, ShieldCheck, ShieldAlert, ShieldX, ShieldQuestion, Search, Clock } from 'lucide-react';

interface LocalScan {
  id: string;
  domain: string;
  verdict: string;
  totalChecks: number;
  positiveMatched: number;
  timestamp: number;
  scanDate: string;
}

const STORAGE_KEY = 'aegovx_scan_history';

export function saveToLocalHistory(scan: LocalScan) {
  try {
    const existing: LocalScan[] = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    const filtered = existing.filter((s) => s.id !== scan.id);
    const updated = [scan, ...filtered].slice(0, 50); // keep last 50
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch { /* ignore */ }
}

export function getLocalHistory(): LocalScan[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch { return []; }
}

function VerdictBadge({ verdict, count }: { verdict: string; count: number }) {
  if (verdict === 'MALICIOUS') return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400 border border-rose-300 dark:border-rose-900">
      <ShieldX className="w-3 h-3" /> {count} Flagged
    </span>
  );
  if (verdict === 'SUSPICIOUS') return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 dark:bg-amber-950 text-amber-600 dark:text-amber-400 border border-amber-300 dark:border-amber-900">
      <ShieldAlert className="w-3 h-3" /> Suspicious
    </span>
  );
  if (verdict === 'CLEAN') return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-900">
      <ShieldCheck className="w-3 h-3" /> Clean
    </span>
  );
  return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
      <ShieldQuestion className="w-3 h-3" /> Unknown
    </span>
  );
}

export default function HistoryPage() {
  const [history, setHistory] = useState<LocalScan[]>([]);
  const [search, setSearch] = useState('');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setHistory(getLocalHistory());
  }, []);

  const clearAll = () => {
    localStorage.removeItem(STORAGE_KEY);
    setHistory([]);
  };

  const removeOne = (id: string) => {
    const updated = history.filter((s) => s.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    setHistory(updated);
  };

  const filtered = history.filter((s) =>
    s.domain.toLowerCase().includes(search.toLowerCase())
  );

  if (!mounted) return null;

  return (
    <div className="flex-1 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <History className="w-5 h-5 text-emerald-500" />
            <h1 className="text-2xl font-extrabold text-slate-900 dark:text-white">Scan History</h1>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Your last {history.length} scans — stored locally in your browser
          </p>
        </div>
        {history.length > 0 && (
          <button
            onClick={clearAll}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 hover:bg-rose-100 dark:hover:bg-rose-950 transition-colors"
          >
            <Trash2 className="w-4 h-4" /> Clear All
          </button>
        )}
      </div>

      {history.length === 0 ? (
        /* Empty state */
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 text-slate-400" />
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">No scans yet</h2>
          <p className="text-slate-500 dark:text-slate-400 mb-6 max-w-sm mx-auto">
            Your scan history will appear here after you scan a website. History is stored locally in your browser.
          </p>
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm shadow-lg shadow-emerald-600/30 transition-all"
          >
            <Search className="w-4 h-4" />
            Start Scanning
          </Link>
        </div>
      ) : (
        <>
          {/* Search bar */}
          <div className="relative mb-6">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by domain..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>

          {/* Results grid */}
          {filtered.length === 0 ? (
            <p className="text-center text-slate-400 py-12">No results for "{search}"</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {filtered.map((scan) => (
                <div
                  key={scan.id}
                  className="group p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-emerald-500/50 shadow-sm transition-all hover:shadow"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold text-sm text-slate-900 dark:text-white truncate group-hover:text-emerald-500 transition-colors">
                        {scan.domain}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> {scan.scanDate}
                      </p>
                    </div>
                    <button
                      onClick={() => removeOne(scan.id)}
                      className="ml-2 p-1 rounded-lg text-slate-300 dark:text-slate-600 hover:text-rose-500 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors flex-shrink-0"
                      title="Remove from history"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <VerdictBadge verdict={scan.verdict} count={scan.positiveMatched} />
                    <span className="text-xs text-slate-400">{scan.totalChecks} checks</span>
                  </div>

                  <Link
                    href={`/report/${scan.id}`}
                    className="mt-3 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 hover:bg-emerald-100 dark:hover:bg-emerald-950 border border-emerald-200 dark:border-emerald-900 transition-colors"
                  >
                    <ExternalLink className="w-3 h-3" /> View Report
                  </Link>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
