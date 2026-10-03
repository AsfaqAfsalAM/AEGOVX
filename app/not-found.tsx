'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldQuestion, Home, Search, History } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center min-h-[60vh] px-4 text-center">
      {/* Background glow */}
      <div className="absolute inset-0 bg-gradient-to-b from-rose-500/5 via-transparent to-transparent pointer-events-none" />

      {/* Icon */}
      <div className="relative mb-6">
        <div className="w-24 h-24 rounded-3xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mx-auto">
          <ShieldQuestion className="w-12 h-12 text-rose-400" />
        </div>
        <div className="absolute -top-2 -right-2 w-8 h-8 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-center">
          <span className="text-xs font-black text-rose-400 font-mono">404</span>
        </div>
      </div>

      {/* Text */}
      <h1 className="text-4xl sm:text-5xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-3">
        Page Not Found
      </h1>
      <p className="text-slate-500 dark:text-slate-400 text-base sm:text-lg max-w-md mb-10 leading-relaxed">
        The page you're looking for doesn't exist or the scan report may have expired.
        Start a fresh scan from the homepage.
      </p>

      {/* Actions */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <Link
          href="/"
          className="flex items-center gap-2 px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm shadow-lg shadow-emerald-600/30 transition-all"
        >
          <Home className="w-4 h-4" />
          Back to Scanner
        </Link>
        <Link
          href="/history"
          className="flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-sm border border-slate-200 dark:border-slate-700 transition-all"
        >
          <History className="w-4 h-4" />
          View Scan History
        </Link>
      </div>

      {/* Quick scan */}
      <div className="mt-10 p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm max-w-sm w-full">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Quick Scan</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const input = (e.currentTarget.elements.namedItem('domain') as HTMLInputElement).value.trim();
            if (input) window.location.href = `/?scan=${encodeURIComponent(input)}`;
          }}
          className="flex gap-2"
        >
          <input
            name="domain"
            type="text"
            placeholder="example.com"
            className="flex-1 px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-sm text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500"
          />
          <button
            type="submit"
            className="px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
          >
            <Search className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
