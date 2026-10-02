export type EngineStatus = 'clean' | 'malicious' | 'suspicious' | 'unrated';

export type EngineCategory =
  | 'Malware/Antivirus Check'
  | 'Phishing Website Check'
  | 'Malicious Behavioral Analysis'
  | 'Infrastructure & SSL Check';

export interface VendorResult {
  id: string;
  name: string;
  category: EngineCategory;
  status: EngineStatus;
  details?: string;
  hasLogo: boolean;
  logoKey?: string;
  engineType?: string;
  detectionMethod?: string;
}

export interface ExtraChecks {
  ssl?: {
    valid: boolean;
    issuer?: string;
    subject?: string;
    validTo?: string;
    validFrom?: string;
    daysLeft?: number;
    protocol?: string;
    cipher?: string;
    error?: string;
  };
  headers?: {
    score: number;
    hsts: boolean;
    csp: boolean;
    xFrameOptions: boolean;
    xContentTypeOptions: boolean;
    referrerPolicy: boolean;
    permissionsPolicy: boolean;
    missingHeaders: string[];
    foundHeaders: Record<string, string>;
  };
  whois?: {
    domainAgeYears?: number;
    creationDate?: string;
    expirationDate?: string;
    registrar?: string;
    error?: string;
  };
  dnsbl?: {
    listed: boolean;
    provider?: string;
    details?: string;
  };
  redirects?: {
    chain: { url: string; status: number }[];
    finalUrl: string;
    totalHops: number;
    downgradeDetected: boolean;
  };
}

export interface ScanReport {
  id: string;
  targetUrl: string;
  domain: string;
  hostname: string;
  scanDate: string;
  timestamp: number;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  progress: number;
  currentEngine?: string;
  totalChecks: number;
  positiveMatched: number;
  suspiciousCount: number;
  cleanCount: number;
  unratedCount: number;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'ERROR';
  verdictText: string;
  results: VendorResult[];
  extraChecks?: ExtraChecks;
  sourceNote?: string;
  cached?: boolean;
}

export interface RecentScanItem {
  id: string;
  domain: string;
  targetUrl: string;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'ERROR';
  positiveMatched: number;
  totalChecks: number;
  timestamp: number;
  scanDate: string;
}
