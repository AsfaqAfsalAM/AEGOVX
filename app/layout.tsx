import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '@/components/Navbar';
import { Footer } from '@/components/Footer';

export const metadata: Metadata = {
  title: 'AEGOVX — Evidence Before Trust | Multi-Engine Website Security Scanner',
  description:
    'AEGOVX scans websites and domains across 90+ antivirus and threat intelligence engines. Evidence before trust: real-time telemetry from VirusTotal v3, Google Safe Browsing, URLhaus, and cryptographic TLS audits.',
  keywords: [
    'AEGOVX',
    'AEGOVX security',
    'website security checker',
    'url scanner',
    'virustotal checker',
    'url reputation',
    'phishing detector',
    'malware scanner',
    'ssl certificate check',
  ],
  authors: [{ name: 'AEGOVX Security' }],
  verification: {
    google: '16C2uqzK4P9W7wQbDjuwuhAaBJhRVXEKHc0j9I_4pFo',
  },
  icons: {
    icon: '/aegovx-logo.jpg',
    apple: '/aegovx-logo.jpg',
  },
  viewport: 'width=device-width, initial-scale=1, maximum-scale=5',
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#020617' },
  ],
  openGraph: {
    title: 'AEGOVX — Evidence Before Trust',
    description: 'Instant multi-engine reputation scan across 90+ security vendors, antivirus engines, and threat feeds.',
    type: 'website',
    images: [{ url: '/aegovx-logo.jpg' }],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 antialiased selection:bg-emerald-500 selection:text-white">
        <Navbar />
        <main className="flex-1 flex flex-col">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
