import { NextRequest, NextResponse } from 'next/server';
import { validateAndNormalizeTarget } from '@/lib/ssrf';
import { checkRateLimit, getCachedScan, clearDomainCache } from '@/lib/db';
import { runScan } from '@/lib/scanner';

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
      req.headers.get('x-real-ip') ||
      '127.0.0.1';

    // 1. Rate Limiting (5 scans / min)
    const rateCheck = checkRateLimit(ip, 5);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded. Please wait a minute before starting another scan.',
          resetMs: rateCheck.resetMs,
        },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const target = body.url || body.target;
    const forceRescan = Boolean(body.forceRescan);

    if (!target) {
      return NextResponse.json({ error: 'Please enter a valid website URL or domain name.' }, { status: 400 });
    }

    // 2. SSRF Protection & Input Validation
    const validation = await validateAndNormalizeTarget(target);
    if (!validation.valid || !validation.normalizedUrl || !validation.domain || !validation.hostname) {
      return NextResponse.json(
        { error: validation.error || 'Invalid or forbidden domain/URL.' },
        { status: 400 }
      );
    }

    // 3. Cache Check (1-Hour TTL)
    if (forceRescan) {
      clearDomainCache(validation.domain);
    } else {
      const cached = getCachedScan(validation.domain);
      if (cached) {
        return NextResponse.json({
          scanId: cached.id,
          status: 'completed',
          cached: true,
          domain: cached.domain,
          totalChecks: cached.totalChecks,
          positiveMatched: cached.positiveMatched,
        });
      }
    }

    // 4. Create Scan and Trigger Scanning Pipeline
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    // Run in background
    runScan(scanId, validation.normalizedUrl, validation.domain, validation.hostname, ip).catch((err) => {
      console.error(`Error running scan ${scanId}:`, err);
    });

    return NextResponse.json({
      scanId,
      status: 'scanning',
      cached: false,
      domain: validation.domain,
      hostname: validation.hostname,
    });
  } catch (err: unknown) {
    console.error('API /api/scan error:', err);
    return NextResponse.json(
      { error: 'An unexpected internal error occurred while initiating the scan.' },
      { status: 500 }
    );
  }
}
