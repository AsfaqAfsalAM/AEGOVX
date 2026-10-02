import dns from 'dns/promises';
import { URL } from 'url';

export interface ValidationResult {
  valid: boolean;
  error?: string;
  normalizedUrl?: string;
  domain?: string;
  hostname?: string;
  resolvedIp?: string;
}

// IP range validation helpers
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [a, b, c, d] = parts;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private)
  if (a === 10) return true;

  // 172.16.0.0/12 (Private)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;

  // 169.254.0.0/16 (Link-Local, AWS/Cloud metadata)
  if (a === 169 && b === 254) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Documentation / Test-net)
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  // Broadcast
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  // Loopback ::1
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // Unspecified ::
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  // Link-local fe80::/10
  if (lower.startsWith('fe80:') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  // Unique local fc00::/7
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  // IPv4 mapped
  if (lower.includes('::ffff:')) {
    const v4Part = lower.split('::ffff:')[1];
    if (v4Part && isPrivateIPv4(v4Part)) return true;
  }
  return false;
}

const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.lan$/i,
  /\.corp$/i,
  /\.test$/i,
  /\.example$/i,
  /\.invalid$/i,
  /^metadata\.google\.internal$/i,
  /^instance-data$/i,
  /^169\.254\.169\.254$/,
];

export async function validateAndNormalizeTarget(input: string): Promise<ValidationResult> {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'Target URL or domain is required.' };
  }

  const trimmed = input.trim();
  if (trimmed.length > 2048) {
    return { valid: false, error: 'Target exceeds maximum allowable length of 2048 characters.' };
  }

  // Prepend https:// if protocol is missing
  let candidate = trimmed;
  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Invalid URL or domain format.' };
  }

  // Only allow http: and https: protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Unsupported protocol. Only HTTP and HTTPS are permitted.' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Strip trailing dot if present
  const cleanHostname = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;

  // Domain name syntax check
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(cleanHostname)) {
    return { valid: false, error: 'Hostname contains illegal characters or invalid formatting.' };
  }

  // Check blocked domain patterns
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(cleanHostname)) {
      return { valid: false, error: 'SSRF Protection: Access to private, local, or cloud metadata domains is strictly blocked.' };
    }
  }

  // If input is an explicit IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleanHostname)) {
    if (isPrivateIPv4(cleanHostname)) {
      return { valid: false, error: 'SSRF Protection: Private and internal IPv4 addresses are prohibited.' };
    }
  }

  // Perform DNS resolution to check for DNS-rebinding / SSRF to private IP
  try {
    const lookupResult = await dns.lookup(cleanHostname, { all: true });
    if (!lookupResult || lookupResult.length === 0) {
      return { valid: false, error: `Could not resolve domain: ${cleanHostname}` };
    }

    for (const record of lookupResult) {
      if (record.family === 4 && isPrivateIPv4(record.address)) {
        return { valid: false, error: `SSRF Protection: Domain resolves to forbidden private IP address (${record.address}).` };
      }
      if (record.family === 6 && isPrivateIPv6(record.address)) {
        return { valid: false, error: `SSRF Protection: Domain resolves to forbidden internal IPv6 address (${record.address}).` };
      }
    }

    const primaryIp = lookupResult[0].address;

    // Extract base domain (e.g., sub.example.com -> example.com)
    const hostParts = cleanHostname.split('.');
    const domain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : cleanHostname;

    return {
      valid: true,
      normalizedUrl: parsed.toString(),
      domain: domain,
      hostname: cleanHostname,
      resolvedIp: primaryIp,
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'DNS lookup failed';
    return { valid: false, error: `DNS resolution failed for ${cleanHostname}: ${errorMsg}` };
  }
}
