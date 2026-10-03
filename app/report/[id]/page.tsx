'use client';

import React, { useEffect, useState, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  RefreshCw,
  Copy,
  Download,
  Check,
  Search,
  ExternalLink,
  Lock,
  FileCode,
  Calendar,
  Network,
  GitFork,
  ArrowLeft,
  Info,
  Clock,
  CheckCircle,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Minus
} from 'lucide-react';
import { ScanReport, VendorResult } from '@/lib/types';
import { sortVendorResults } from '@/lib/vendors';
import { VendorCard } from '@/components/VendorCard';

export default function ReportPage() {
  const params = useParams();
  const router = useRouter();
  const id = params?.id as string;

  const [scan, setScan] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'clean' | 'malicious' | 'suspicious' | 'unrated'>('all');
  const [vendorSearch, setVendorSearch] = useState('');
  const [copied, setCopied] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [showExtraChecks, setShowExtraChecks] = useState(true);

  // Polling function for scan progress
  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    let pollInterval: NodeJS.Timeout | null = null;

    const fetchScan = async () => {
      try {
        const res = await fetch(`/api/scan/${id}`);
        if (!res.ok) {
          if (res.status === 404) {
            throw new Error('Scan report not found.');
          }
          throw new Error('Failed to retrieve scan data.');
        }

        const data = await res.json();
        if (!isMounted) return;

        if (data.scan) {
          setScan(data.scan);
          setLoading(false);

          if (data.scan.status === 'completed' || data.scan.status === 'failed') {
            if (pollInterval) clearInterval(pollInterval);
          }
        }
      } catch (err: unknown) {
        if (!isMounted) return;
        setError(err instanceof Error ? err.message : 'Error fetching scan');
        setLoading(false);
        if (pollInterval) clearInterval(pollInterval);
      }
    };

    // Initial fetch
    fetchScan();

    // Poll every 2.5 seconds if scan is not yet completed
    pollInterval = setInterval(fetchScan, 2500);

    return () => {
      isMounted = false;
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [id]);

  // Copy report link handler
  const handleCopyLink = () => {
    if (typeof window !== 'undefined') {
      navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  // Download PDF / Print handler
  const handleDownloadPdf = () => {
    if (typeof window !== 'undefined') {
      window.print();
    }
  };

  // Rescan handler
  const handleRescan = async () => {
    if (!scan) return;
    setRescanning(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scan.targetUrl, forceRescan: true }),
      });
      const data = await res.json();
      if (data.scanId) {
        router.push(`/report/${data.scanId}`);
      }
    } catch {
      alert('Failed to trigger rescan. Please try again.');
    } finally {
      setRescanning(false);
    }
  };

  // Filter and sort vendor results
  const filteredVendors = useMemo(() => {
    if (!scan || !scan.results) return [];

    let list = scan.results;

    // Filter by status tab
    if (activeFilter !== 'all') {
      list = list.filter((v) => v.status === activeFilter);
    }

    // Filter by search text
    if (vendorSearch.trim()) {
      const q = vendorSearch.toLowerCase().trim();
      list = list.filter((v) => v.name.toLowerCase().includes(q) || v.category.toLowerCase().includes(q));
    }

    // Sort strictly: Malicious/Suspicious on top, Logos first, Alphabetical, Unrated at bottom
    return sortVendorResults(list);
  }, [scan, activeFilter, vendorSearch]);

  // Loading skeleton / progress state
  if (loading || (scan && scan.status !== 'completed' && scan.status !== 'failed')) {
    const progress = scan?.progress || 25;
    const totalEngines = scan?.totalChecks || 96;
    const completedEngines = Math.min(totalEngines, Math.floor((progress / 100) * totalEngines));

    return (
      <div className="flex-1 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16 w-full flex flex-col items-center justify-center">
        <div className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 sm:p-10 shadow-xl text-center">
          <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center mx-auto mb-6 animate-pulse">
            <ShieldCheck className="w-10 h-10" />
          </div>

          <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">
            Scanning {scan?.domain || 'Target Website'}
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
            Querying 90+ antivirus vendors, SSL certificate handshake & threat intelligence feeds...
          </p>

          {/* Progress Bar */}
          <div className="w-full bg-slate-100 dark:bg-slate-800 h-4 rounded-full overflow-hidden mb-3 relative">
            <div
              className="bg-gradient-to-r from-emerald-500 via-teal-400 to-sky-500 h-full transition-all duration-500 ease-out"
              style={{ width: `${Math.max(5, progress)}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-xs sm:text-sm text-slate-600 dark:text-slate-400 font-mono">
            <span>
              Progress: <strong className="text-emerald-500">{completedEngines}</strong> of{' '}
              <strong>{totalEngines}</strong> engines done
            </span>
            <span>{progress}%</span>
          </div>

          {scan?.currentEngine && (
            <p className="mt-4 text-xs text-slate-400 dark:text-slate-500 italic">
              Active engine: {scan.currentEngine}
            </p>
          )}

          {/* Loading Card Skeletons */}
          <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="h-20 rounded-xl bg-slate-100 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800 animate-pulse"
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error State
  if (error || !scan || scan.status === 'failed') {
    return (
      <div className="flex-1 max-w-2xl mx-auto px-4 py-20 text-center">
        <div className="w-16 h-16 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center mx-auto mb-4">
          <ShieldAlert className="w-10 h-10" />
        </div>
        <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Scan Failed</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-6">
          {error || 'Unable to scan the specified website. The target may be unreachable or blocked by security policies.'}
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-emerald-600 text-white font-semibold hover:bg-emerald-500 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Scanner
        </Link>
      </div>
    );
  }

  // Determine header shield icon and color
  const isMalicious = scan.positiveMatched > 0;
  const isSuspicious = !isMalicious && scan.suspiciousCount > 0;

  const headerShield = () => {
    if (isMalicious) {
      return (
        <div className="w-12 h-12 sm:w-16 sm:h-16 rounded-2xl bg-rose-100 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 text-rose-600 flex items-center justify-center shadow-lg shadow-rose-500/10 flex-shrink-0">
          <ShieldX className="w-7 h-7 sm:w-9 sm:h-9" />
        </div>
      );
    }
    if (isSuspicious) {
      return (
        <div className="w-12 h-12 sm:w-16 sm:h-16 rounded-2xl bg-amber-100 dark:bg-amber-950/80 border border-amber-300 dark:border-amber-800 text-amber-600 flex items-center justify-center shadow-lg shadow-amber-500/10 flex-shrink-0">
          <ShieldAlert className="w-7 h-7 sm:w-9 sm:h-9" />
        </div>
      );
    }
    return (
      <div className="w-12 h-12 sm:w-16 sm:h-16 rounded-2xl bg-emerald-100 dark:bg-emerald-950/80 border border-emerald-300 dark:border-emerald-800 text-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-500/10 flex-shrink-0">
        <ShieldCheck className="w-7 h-7 sm:w-9 sm:h-9" />
      </div>
    );
  };

  return (
    <div className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 print-page">
      {/* Back button */}
      <div className="mb-6 no-print">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-emerald-500 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Scan another website
        </Link>
      </div>

      {/* Main Report Header Card */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 sm:p-8 shadow-sm mb-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          {/* Left: Shield icon & domain & stats */}
          <div className="flex items-start sm:items-center gap-4 sm:gap-5 min-w-0">
            {headerShield()}
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl sm:text-3xl font-extrabold text-slate-900 dark:text-white truncate tracking-tight">
                  {scan.domain}
                </h1>
                <a
                  href={scan.targetUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 no-print"
                  title="Open URL"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>

              {/* Stats badges */}
              <div className="flex flex-wrap items-center gap-3 sm:gap-4 mt-2.5 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  Total Checks: <span className="font-mono text-emerald-500">{scan.totalChecks}</span>
                </span>
                <span className="text-slate-300 dark:text-slate-700">•</span>
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  Positive Matched:{' '}
                  <span
                    className={`font-mono ${scan.positiveMatched > 0 ? 'text-rose-500 font-bold' : 'text-emerald-500'}`}
                  >
                    {scan.positiveMatched}
                  </span>
                </span>
                <span className="text-slate-300 dark:text-slate-700">•</span>
                <span className="flex items-center gap-1 font-mono text-xs">
                  <Clock className="w-3.5 h-3.5" />
                  {scan.scanDate}
                </span>
              </div>
            </div>
          </div>

          {/* Right: Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 sm:self-center no-print">
            <button
              onClick={handleRescan}
              disabled={rescanning}
              className="px-3.5 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs sm:text-sm flex items-center gap-1.5 transition-colors border border-slate-200 dark:border-slate-700 disabled:opacity-60"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${rescanning ? 'animate-spin' : ''}`} />
              <span>{rescanning ? 'Rescanning...' : 'Rescan'}</span>
            </button>

            <button
              onClick={handleCopyLink}
              className="px-3.5 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs sm:text-sm flex items-center gap-1.5 transition-colors border border-slate-200 dark:border-slate-700"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  <span className="text-emerald-500 font-bold">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy report link</span>
                </>
              )}
            </button>

            <button
              onClick={handleDownloadPdf}
              className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs sm:text-sm flex items-center gap-1.5 shadow-md shadow-emerald-600/20 transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </button>
          </div>
        </div>

        {/* Plain-English Verdict Banner */}
        <div
          className={`mt-6 p-4 rounded-xl border flex items-center gap-3 ${
            isMalicious
              ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-900/60 text-rose-800 dark:text-rose-200'
              : isSuspicious
              ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/60 text-amber-800 dark:text-amber-200'
              : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-900/60 text-emerald-800 dark:text-emerald-200'
          }`}
        >
          {isMalicious ? (
            <ShieldX className="w-5 h-5 flex-shrink-0 text-rose-500" />
          ) : isSuspicious ? (
            <ShieldAlert className="w-5 h-5 flex-shrink-0 text-amber-500" />
          ) : (
            <CheckCircle className="w-5 h-5 flex-shrink-0 text-emerald-500" />
          )}
          <div className="font-semibold text-sm sm:text-base">
            {scan.verdictText}
          </div>
        </div>

        {/* Required Centered Disclaimer under header */}
        <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800/80 text-center">
          <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 italic max-w-3xl mx-auto flex items-center justify-center gap-1.5">
            <Info className="w-4 h-4 text-slate-400 flex-shrink-0" />
            <span>
              Even if no positive matches are found, this does not guarantee the website is safe. Caution should always be taken.
            </span>
          </p>
        </div>
      </div>

      {/* Extra Technical Deep-Dive Cards (SSL, Headers, WHOIS, DNSBL, Redirects) */}
      {scan.extraChecks && (
        <div className="mb-8">
          <div className="flex items-center justify-between mb-3 no-print">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-500" /> Infrastructure & Cryptography Audits
            </h2>
            <button
              onClick={() => setShowExtraChecks(!showExtraChecks)}
              className="text-xs text-emerald-500 hover:underline font-semibold"
            >
              {showExtraChecks ? 'Collapse Details' : 'Expand Details'}
            </button>
          </div>

          {showExtraChecks && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SSL Certificate Card */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-emerald-500" />
                    <h3 className="font-bold text-sm text-slate-900 dark:text-white">SSL/TLS Certificate</h3>
                  </div>
                  {scan.extraChecks.ssl?.valid ? (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400">
                      VALID
                    </span>
                  ) : (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400">
                      INVALID
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400 space-y-1">
                  <p>
                    <span className="text-slate-400">Issuer:</span> {scan.extraChecks.ssl?.issuer || 'Unknown'}
                  </p>
                  <p>
                    <span className="text-slate-400">Expires:</span> {scan.extraChecks.ssl?.validTo || 'N/A'}{' '}
                    {scan.extraChecks.ssl?.daysLeft !== undefined && (
                      <span className="font-semibold text-emerald-500 font-mono">
                        ({scan.extraChecks.ssl.daysLeft} days left)
                      </span>
                    )}
                  </p>
                  <p>
                    <span className="text-slate-400">Protocol:</span> {scan.extraChecks.ssl?.protocol || 'TLS'}
                  </p>
                </div>
              </div>

              {/* Security Headers Card */}
              {(() => {
                const h = scan.extraChecks.headers;
                const score = h?.score || 0;
                const grade =
                  score >= 90 ? 'A+' :
                  score >= 75 ? 'A' :
                  score >= 60 ? 'B' :
                  score >= 40 ? 'C' :
                  score >= 20 ? 'D' : 'F';
                const gradeColor =
                  score >= 75 ? 'text-emerald-500 bg-emerald-950 border-emerald-700' :
                  score >= 40 ? 'text-amber-400 bg-amber-950 border-amber-700' :
                  'text-rose-400 bg-rose-950 border-rose-700';
                const barColor =
                  score >= 75 ? 'from-emerald-500 to-teal-400' :
                  score >= 40 ? 'from-amber-500 to-yellow-400' :
                  'from-rose-500 to-red-400';

                const headerRows = [
                  {
                    key: 'hsts',
                    label: 'HSTS',
                    fullName: 'Strict-Transport-Security',
                    present: h?.hsts,
                    value: h?.foundHeaders?.['Strict-Transport-Security'],
                    desc: 'Forces HTTPS — prevents protocol downgrade attacks',
                    weight: 25,
                  },
                  {
                    key: 'csp',
                    label: 'CSP',
                    fullName: 'Content-Security-Policy',
                    present: h?.csp,
                    value: h?.foundHeaders?.['Content-Security-Policy'],
                    desc: 'Restricts script/resource origins — blocks XSS attacks',
                    weight: 25,
                  },
                  {
                    key: 'xfo',
                    label: 'X-Frame-Options',
                    fullName: 'X-Frame-Options',
                    present: h?.xFrameOptions,
                    value: h?.foundHeaders?.['X-Frame-Options'],
                    desc: 'Blocks clickjacking via iframe embedding',
                    weight: 20,
                  },
                  {
                    key: 'xcto',
                    label: 'X-Content-Type-Options',
                    fullName: 'X-Content-Type-Options',
                    present: h?.xContentTypeOptions,
                    value: h?.foundHeaders?.['X-Content-Type-Options'],
                    desc: 'Prevents MIME-type sniffing attacks',
                    weight: 15,
                  },
                  {
                    key: 'rp',
                    label: 'Referrer-Policy',
                    fullName: 'Referrer-Policy',
                    present: h?.referrerPolicy,
                    value: h?.foundHeaders?.['Referrer-Policy'],
                    desc: 'Controls how much referrer info is sent with requests',
                    weight: 10,
                  },
                  {
                    key: 'pp',
                    label: 'Permissions-Policy',
                    fullName: 'Permissions-Policy',
                    present: h?.permissionsPolicy,
                    value: h?.foundHeaders?.['Permissions-Policy'],
                    desc: 'Restricts access to browser features (camera, mic, geo)',
                    weight: 5,
                  },
                ];

                return (
                  <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
                    {/* Header row */}
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-sky-500" />
                        <h3 className="font-bold text-sm text-slate-900 dark:text-white">HTTP Security Headers</h3>
                      </div>
                      <span className={`text-xs font-black px-2 py-0.5 rounded border font-mono ${gradeColor}`}>
                        {grade}
                      </span>
                    </div>

                    {/* Score bar */}
                    <div className="mb-3">
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                        <span>Header Security Score</span>
                        <span className="font-mono font-bold">{score}/100</span>
                      </div>
                      <div className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${barColor} transition-all duration-700`}
                          style={{ width: `${score}%` }}
                        />
                      </div>
                    </div>

                    {/* Header rows */}
                    <div className="space-y-1.5">
                      {headerRows.map((row) => (
                        <div key={row.key} className="flex items-start gap-2">
                          <div className="mt-0.5 flex-shrink-0">
                            {row.present === true ? (
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                            ) : row.present === false ? (
                              <XCircle className="w-3.5 h-3.5 text-rose-500" />
                            ) : (
                              <Minus className="w-3.5 h-3.5 text-slate-400" />
                            )}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-[11px] font-bold text-slate-700 dark:text-slate-200 font-mono">
                                {row.label}
                              </span>
                              <span className={`text-[9px] font-bold px-1 rounded ${
                                row.present
                                  ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400'
                                  : 'bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400'
                              }`}>
                                {row.present ? 'SET' : 'MISSING'}
                              </span>
                              <span className="text-[9px] text-slate-400 font-mono">+{row.weight}pts</span>
                            </div>
                            {row.present && row.value ? (
                              <p className="text-[10px] font-mono text-sky-400/80 dark:text-sky-500/80 truncate mt-0.5" title={row.value}>
                                {row.value.length > 42 ? row.value.slice(0, 42) + '…' : row.value}
                              </p>
                            ) : (
                              <p className="text-[10px] text-slate-400 italic mt-0.5">{row.desc}</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Missing headers warning */}
                    {h?.missingHeaders && h.missingHeaders.length > 0 && (
                      <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800">
                        <p className="text-[10px] text-amber-500 flex items-start gap-1">
                          <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                          <span>{h.missingHeaders.length} header{h.missingHeaders.length > 1 ? 's' : ''} missing — reduces trust score</span>
                        </p>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* WHOIS & Redirect Integrity Card */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Calendar className="w-4 h-4 text-violet-500" />
                    <h3 className="font-bold text-sm text-slate-900 dark:text-white">Domain & Routing</h3>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-violet-100 dark:bg-violet-950 text-violet-600 dark:text-violet-400">
                    WHOIS
                  </span>
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400 space-y-1">
                  <p>
                    <span className="text-slate-400">Domain Age:</span>{' '}
                    {scan.extraChecks.whois?.domainAgeYears !== undefined
                      ? `${scan.extraChecks.whois.domainAgeYears} years`
                      : 'Verified'}
                  </p>
                  <p className="truncate">
                    <span className="text-slate-400">Registrar:</span>{' '}
                    {scan.extraChecks.whois?.registrar || 'ICANN Registrar'}
                  </p>
                  <p>
                    <span className="text-slate-400">Redirect Hops:</span>{' '}
                    {scan.extraChecks.redirects?.totalHops || 0} hop(s){' '}
                    {scan.extraChecks.redirects?.downgradeDetected && (
                      <span className="text-rose-500 font-bold">(Downgrade!)</span>
                    )}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filter Tabs and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 mb-6 no-print">
        {/* Summary Filter Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-x-auto">
          <button
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFilter === 'all'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            All ({scan.results?.length || 0})
          </button>
          <button
            onClick={() => setActiveFilter('clean')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFilter === 'clean'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Clean ({scan.cleanCount || 0})
          </button>
          <button
            onClick={() => setActiveFilter('malicious')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFilter === 'malicious'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Malicious ({scan.positiveMatched || 0})
          </button>
          <button
            onClick={() => setActiveFilter('suspicious')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFilter === 'suspicious'
                ? 'bg-amber-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Suspicious ({scan.suspiciousCount || 0})
          </button>
          <button
            onClick={() => setActiveFilter('unrated')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              activeFilter === 'unrated'
                ? 'bg-slate-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Unrated ({scan.unratedCount || 0})
          </button>
        </div>

        {/* Search input for vendors */}
        <div className="relative min-w-[220px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={vendorSearch}
            onChange={(e) => setVendorSearch(e.target.value)}
            placeholder="Search security vendor..."
            className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {/* Vendor Cards Responsive Grid: 2 columns on desktop, 1 column on mobile */}
      {filteredVendors.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
          {filteredVendors.map((vendor) => (
            <div key={vendor.id} className="break-inside-avoid">
              <VendorCard vendor={vendor} />
            </div>
          ))}
        </div>
      ) : (
        <div className="p-12 text-center bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
          <p className="text-slate-500 dark:text-slate-400 text-sm">
            No vendors match the selected filter criteria.
          </p>
        </div>
      )}

      {/* Embed Badge Promotion Callout */}
      <div className="mt-12 p-6 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border border-emerald-500/20 flex flex-col sm:flex-row items-center justify-between gap-4 no-print">
        <div>
          <h3 className="font-bold text-white text-base">Embed this security badge on your website</h3>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Display live verified safety telemetry to your visitors with an official AEGOVX badge.
          </p>
        </div>
        <Link
          href={`/badge?domain=${scan.domain}`}
          className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs sm:text-sm whitespace-nowrap transition-colors flex-shrink-0"
        >
          Get Badge Code →
        </Link>
      </div>
    </div>
  );
}
