'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldCheck,
  Search,
  AlertTriangle,
  Globe,
  Lock,
  ArrowRight,
  Sparkles,
  Layers,
  Activity,
  History,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Cpu
} from 'lucide-react';
import Link from 'next/link';
import { RecentScanItem } from '@/lib/types';

export default function HomePage() {
  const router = useRouter();
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScanItem[]>([]);

  useEffect(() => {
    // Fetch recent scans
    fetch('/api/recent')
      .then((res) => res.json())
      .then((data) => {
        if (data.scans) setRecentScans(data.scans);
      })
      .catch(() => {});
  }, []);

  const handleScanSubmit = async (target?: string) => {
    const rawTarget = target || urlInput;
    if (!rawTarget || !rawTarget.trim()) {
      setErrorMessage('Please enter a website URL or domain name.');
      return;
    }

    setLoading(true);
    setErrorMessage(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawTarget.trim() }),
      });

      const data = await res.json();

      if (!res.ok) {
        setErrorMessage(data.error || 'Failed to initiate scan.');
        setLoading(false);
        return;
      }

      if (data.scanId) {
        router.push(`/report/${data.scanId}`);
      } else {
        setErrorMessage('Unexpected response from server.');
        setLoading(false);
      }
    } catch {
      setErrorMessage('Unable to connect to scanner service. Please check your internet connection.');
      setLoading(false);
    }
  };

  const sampleTargets = [
    { label: 'google.com', domain: 'google.com', type: 'Safe' },
    { label: 'github.com', domain: 'github.com', type: 'Safe' },
    { label: 'cloudflare.com', domain: 'cloudflare.com', type: 'Safe' },
    { label: 'wikipedia.org', domain: 'wikipedia.org', type: 'Safe' },
  ];

  return (
    <div className="flex-1 flex flex-col items-center">
      {/* Background Glow */}
      <div className="absolute top-0 inset-x-0 h-96 bg-gradient-to-b from-emerald-500/10 via-sky-500/5 to-transparent pointer-events-none -z-10" />

      {/* Hero Section */}
      <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pt-10 sm:pt-16 pb-12 text-center">
        {/* Brand Banner with uploaded logo */}
        <div className="flex flex-col items-center justify-center mb-6">
          <div className="relative w-28 h-28 sm:w-36 sm:h-36 rounded-3xl overflow-hidden bg-slate-950 border border-slate-700/80 shadow-2xl shadow-sky-950/60 p-1 mb-4 group hover:border-sky-500/50 transition-all duration-300">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="/aegovx-logo.jpg"
              alt="AEGOVX - Evidence Before Trust"
              className="w-full h-full object-cover rounded-2xl"
            />
          </div>
          <div className="flex items-center gap-3">
            <h2 className="text-3xl sm:text-4xl font-black tracking-widest text-slate-900 dark:text-white uppercase font-mono">
              AEGOV<span className="text-sky-400">X</span>
            </h2>
          </div>
          <p className="mt-1 text-xs sm:text-sm font-semibold tracking-[0.25em] text-slate-500 dark:text-sky-400/80 uppercase">
            Evidence Before Trust
          </p>
        </div>

        {/* Badge Pill */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-sky-500/10 border border-sky-500/20 text-sky-600 dark:text-sky-400 text-xs sm:text-sm font-semibold mb-6 animate-fade-in">
          <Sparkles className="w-4 h-4" />
          <span>Real-time Multi-Engine Threat Intelligence & Cryptographic Scanner</span>
        </div>

        {/* Headline */}
        <h1 className="text-3xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white max-w-4xl mx-auto leading-[1.15]">
          Scan Any Website Against <span className="text-transparent bg-clip-text bg-gradient-to-r from-sky-400 via-teal-300 to-emerald-400">90+ Security Engines</span>
        </h1>

        {/* Subtitle */}
        <p className="mt-4 sm:mt-6 text-base sm:text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Verify URL reputation across Kaspersky, Bitdefender, Sophos, Microsoft Defender,
          direct feeds (URLhaus, Spamhaus DBL), TLS certificate integrity, and HTTP security policies.
        </p>

        {/* Scanner Form */}
        <div className="mt-8 sm:mt-10 max-w-2xl mx-auto">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScanSubmit();
            }}
            className="relative flex flex-col sm:flex-row items-center gap-2 p-2 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl shadow-slate-200/50 dark:shadow-emerald-950/20 focus-within:border-emerald-500 transition-all duration-200"
          >
            <div className="flex items-center flex-1 w-full pl-3 pr-2">
              <Globe className="w-5 h-5 text-slate-400 flex-shrink-0 mr-2" />
              <input
                type="text"
                id="target-url-input"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter domain or URL (e.g. example.com or https://...)"
                disabled={loading}
                className="w-full bg-transparent text-sm sm:text-base text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none py-2.5"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm sm:text-base flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/30 hover:shadow-emerald-500/40 transition-all duration-200 disabled:opacity-70 disabled:cursor-not-allowed flex-shrink-0"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Initiating...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Scan Website</span>
                </>
              )}
            </button>
          </form>

          {/* Error Message */}
          {errorMessage && (
            <div className="mt-4 p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300 text-sm flex items-start gap-2.5 text-left">
              <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-500 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Sample quick scans */}
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span className="font-medium">Try sample:</span>
            {sampleTargets.map((item) => (
              <button
                key={item.domain}
                type="button"
                onClick={() => {
                  setUrlInput(item.domain);
                  handleScanSubmit(item.domain);
                }}
                className="px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-mono transition-colors"
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        {/* Feature Highlights Grid */}
        <div className="mt-16 sm:mt-24 grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 text-left">
          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center mb-3">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-900 dark:text-white text-sm sm:text-base">90+ Security Vendors</h3>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1">
              Kaspersky, Bitdefender, Sophos, Defender, ESET, Avast, Fortinet & more.
            </p>
          </div>

          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="w-10 h-10 rounded-xl bg-sky-500/10 text-sky-500 flex items-center justify-center mb-3">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-900 dark:text-white text-sm sm:text-base">Direct Threat Feeds</h3>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1">
              Live queries to URLhaus, Spamhaus DBL, and Google Safe Browsing.
            </p>
          </div>

          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-500 flex items-center justify-center mb-3">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-900 dark:text-white text-sm sm:text-base">TLS & Security Headers</h3>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1">
              Cryptographic cert validity, days to expiry, HSTS, CSP, and X-Frame-Options.
            </p>
          </div>

          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-500 flex items-center justify-center mb-3">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-900 dark:text-white text-sm sm:text-base">SSRF Hardened</h3>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1">
              Blocks private subnets, cloud metadata (169.254.x), loopback and rebinding.
            </p>
          </div>
        </div>

        {/* Recent Scans Section */}
        {recentScans.length > 0 && (
          <div className="mt-16 sm:mt-20 text-left">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-emerald-500" />
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Recent Website Scans</h2>
              </div>
              <span className="text-xs text-slate-500 dark:text-slate-400">Cached for 1 hour</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/report/${scan.id}`}
                  className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-emerald-500/50 shadow-sm transition-all hover:shadow group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm text-slate-900 dark:text-white truncate max-w-[150px] group-hover:text-emerald-500 transition-colors">
                      {scan.domain}
                    </span>
                    {scan.verdict === 'MALICIOUS' ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400 border border-rose-300 dark:border-rose-900">
                        {scan.positiveMatched} Flagged
                      </span>
                    ) : scan.verdict === 'SUSPICIOUS' ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 dark:bg-amber-950 text-amber-600 dark:text-amber-400 border border-amber-300 dark:border-amber-900">
                        Suspicious
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-900">
                        Clean
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                    <span>{scan.totalChecks} Checks</span>
                    <span>{scan.scanDate}</span>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
