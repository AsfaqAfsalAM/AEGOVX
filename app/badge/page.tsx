'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { Award, Copy, Check, ExternalLink, ShieldCheck } from 'lucide-react';

function BadgeContent() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get('domain') || 'example.com';
  const [domain, setDomain] = useState(initialDomain);
  const [copiedHtml, setCopiedHtml] = useState(false);
  const [copiedMd, setCopiedMd] = useState(false);

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const badgeUrl = `${origin}/api/public/badge?domain=${encodeURIComponent(domain.trim())}`;
  const reportUrl = `${origin}/`;

  const htmlSnippet = `<a href="${reportUrl}" target="_blank" rel="noopener noreferrer">\n  <img src="${badgeUrl}" alt="AEGOVX Website Security Badge" />\n</a>`;
  const markdownSnippet = `[![AEGOVX Security Badge](${badgeUrl})](${reportUrl})`;

  const handleCopy = (type: 'html' | 'md') => {
    const text = type === 'html' ? htmlSnippet : markdownSnippet;
    navigator.clipboard.writeText(text);
    if (type === 'html') {
      setCopiedHtml(true);
      setTimeout(() => setCopiedHtml(false), 2000);
    } else {
      setCopiedMd(true);
      setTimeout(() => setCopiedMd(false), 2000);
    }
  };

  return (
    <div className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="text-center max-w-2xl mx-auto mb-10">
        <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center mx-auto mb-4">
          <Award className="w-6 h-6" />
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Embeddable Security Badge
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-600 dark:text-slate-400">
          Show your website visitors that your domain has been scanned and verified clean against 90+ security engines.
        </p>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-sm">
        {/* Domain input */}
        <div className="mb-6">
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
            Target Domain
          </label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-sm text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500"
          />
        </div>

        {/* Live Preview */}
        <div className="p-6 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 mb-8 flex flex-col items-center justify-center">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4">Live Preview</span>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={badgeUrl}
            alt="AEGOVX Security Badge"
            className="h-8 shadow-sm"
          />
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-4">
            Direct SVG URL: <code className="text-emerald-500">{badgeUrl}</code>
          </p>
        </div>

        {/* Snippets */}
        <div className="space-y-6">
          {/* HTML Embed */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                HTML Embed Code
              </span>
              <button
                onClick={() => handleCopy('html')}
                className="text-xs text-emerald-500 hover:text-emerald-400 font-semibold flex items-center gap-1"
              >
                {copiedHtml ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedHtml ? 'Copied!' : 'Copy HTML'}
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 text-slate-300 text-xs font-mono overflow-x-auto border border-slate-800">
              {htmlSnippet}
            </pre>
          </div>

          {/* Markdown Embed */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                Markdown (README.md)
              </span>
              <button
                onClick={() => handleCopy('md')}
                className="text-xs text-emerald-500 hover:text-emerald-400 font-semibold flex items-center gap-1"
              >
                {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedMd ? 'Copied!' : 'Copy Markdown'}
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 text-slate-300 text-xs font-mono overflow-x-auto border border-slate-800">
              {markdownSnippet}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function BadgePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center">Loading badge studio...</div>}>
      <BadgeContent />
    </Suspense>
  );
}
