import React from 'react';

export default function TermsPage() {
  return (
    <div className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="mb-10 text-center sm:text-left">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Terms of Service
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-600 dark:text-slate-400">
          Last updated: October 2026
        </p>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-sm space-y-6 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2">1. Acceptable Use</h2>
          <p>
            You agree to use AEGOVX exclusively for authorized security audits, domain reputation monitoring, and
            legitimate defense purposes. You agree not to attempt to bypass rate limits, probe internal infrastructure,
            or conduct Denial-of-Service attacks against this service or upstream intelligence providers.
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2">2. Accuracy of Vendor Data</h2>
          <p>
            AEGOVX is an interface for security vendor intelligence. We do not control or modify the classification
            logic of third-party vendors. If you believe your domain was misclassified (false positive), please submit
            a false positive dispute directly to the respective antivirus vendor.
          </p>
        </section>

        <section>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2">3. Limitation of Liability</h2>
          <p>
            AEGOVX and its creators shall not be held liable for any damages, loss of business, or data corruption
            arising from relying on report ratings or detection telemetry.
          </p>
        </section>
      </div>
    </div>
  );
}
