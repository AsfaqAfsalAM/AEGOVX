import React from 'react';
import { Shield, Lock, Eye, AlertCircle } from 'lucide-react';

export default function PrivacyPage() {
  return (
    <div className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="mb-10 text-center sm:text-left">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Privacy Policy & Telemetry Notice
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-600 dark:text-slate-400">
          Last updated: October 2026
        </p>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-sm space-y-6 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <Eye className="w-5 h-5 text-emerald-500" /> 1. Third-Party Engine Telemetry
          </h2>
          <p>
            AEGOVX acts as an aggregator and auditor. When you submit a domain or URL for reputation scanning,
            the URL is evaluated using our cryptographic probes, direct threat intelligence feeds (such as URLhaus,
            Spamhaus DBL, Google Safe Browsing), and cloud reputation endpoints (such as VirusTotal v3).
          </p>
          <div className="mt-3 p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 text-amber-800 dark:text-amber-200 text-xs">
            <strong>Important Notice:</strong> Scan verdicts, categorizations, and malicious/clean flags originate
            from independent third-party security vendors. AEGOVX delivers evidence before trust without altering,
            falsifying, or censoring these independent vendor results.
          </div>
        </section>

        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <Lock className="w-5 h-5 text-sky-500" /> 2. Data We Retain
          </h2>
          <p>
            To conserve API quotas and provide instantaneous responses, scan results are cached in our database for
            <strong> 1 hour</strong>. Scan records contain the target domain, date, and vendor verdicts. No personal
            browsing history or private credentials are requested or stored.
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <Shield className="w-5 h-5 text-purple-500" /> 3. SSRF & Security Protection
          </h2>
          <p>
            To prevent Server-Side Request Forgery (SSRF) and abuse of internal network interfaces, all submitted
            targets are checked against RFC 1918 private ranges, loopback addresses (127.0.0.1, ::1), and cloud
            metadata servers (169.254.169.254). Any request targeting private infrastructure is immediately blocked.
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-amber-500" /> 4. Safety Disclaimer
          </h2>
          <p className="italic">
            Even if no positive matches are found across all vendors, this does not guarantee the website is 100% safe.
            Zero-day malware, fast-flux domains, and new phishing kits may evade detection during early deployment.
            Caution should always be exercised.
          </p>
        </section>
      </div>
    </div>
  );
}
