import React from 'react';
import { Code2, Key, Terminal, Shield, CheckCircle } from 'lucide-react';

export default function ApiDocsPage() {
  return (
    <div className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="mb-10 text-center sm:text-left">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 text-sky-500 text-xs font-semibold mb-3">
          <Code2 className="w-4 h-4" />
          <span>Developer Documentation</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Public REST API
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-600 dark:text-slate-400">
          Integrate automated multi-engine URL and domain reputation audits into your CI/CD pipelines, security bots, and applications.
        </p>
      </div>

      <div className="space-y-8">
        {/* Endpoint: Public Check */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <span className="px-2.5 py-1 rounded-md bg-emerald-600 text-white font-mono text-xs font-bold">
              GET
            </span>
            <code className="text-sm sm:text-base font-mono font-semibold text-slate-900 dark:text-white">
              /api/public/check?domain=example.com
            </code>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
            Queries the cached or live reputation analysis for any domain across 90+ security vendors.
          </p>

          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Query Parameters</h4>
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden mb-6 text-xs">
            <table className="w-full text-left">
              <thead className="bg-slate-50 dark:bg-slate-800/60 font-semibold text-slate-700 dark:text-slate-300">
                <tr>
                  <th className="p-3">Parameter</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Required</th>
                  <th className="p-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-slate-600 dark:text-slate-400 font-mono">
                <tr>
                  <td className="p-3 text-emerald-500 font-semibold">domain</td>
                  <td className="p-3">string</td>
                  <td className="p-3">Yes</td>
                  <td className="p-3 font-sans">The domain name or target URL to evaluate</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Example cURL Request</h4>
          <pre className="p-4 rounded-xl bg-slate-950 text-slate-300 text-xs font-mono overflow-x-auto border border-slate-800 mb-6">
            {`curl -X GET "https://your-domain.com/api/public/check?domain=github.com"`}
          </pre>

          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Example JSON Response</h4>
          <pre className="p-4 rounded-xl bg-slate-950 text-slate-300 text-xs font-mono overflow-x-auto border border-slate-800">
{`{
  "domain": "github.com",
  "targetUrl": "https://github.com",
  "verdict": "CLEAN",
  "verdictText": "No threats detected across all security vendors",
  "totalChecks": 96,
  "positiveMatched": 0,
  "suspiciousCount": 0,
  "cleanCount": 92,
  "unratedCount": 4,
  "scanDate": "Oct 1, 2026, 8:20 PM",
  "cached": true,
  "reportUrl": "https://your-domain.com/report/scan_1727803200_abc123",
  "badgeUrl": "https://your-domain.com/api/public/badge?domain=github.com"
}`}
          </pre>
        </div>

        {/* Rate Limiting Info */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-sm">
          <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <Key className="w-5 h-5 text-amber-500" /> Rate Limits & Quotas
          </h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed mb-4">
            To prevent resource exhaustion and comply with upstream provider policies, standard client IP
            addresses are limited to <strong>5 scans per minute</strong>.
          </p>
          <ul className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 space-y-2 list-disc list-inside">
            <li>Scans are automatically cached for <strong>1 hour</strong>. Subsequent queries return instantaneous cached results.</li>
            <li>HTTP 429 Too Many Requests is returned if request thresholds are breached.</li>
            <li>Private and internal IPs are strictly filtered by SSRF defense middleware.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
