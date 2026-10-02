import { NextRequest, NextResponse } from 'next/server';
import { validateAndNormalizeTarget } from '@/lib/ssrf';
import { getCachedScan } from '@/lib/db';
import { runScan } from '@/lib/scanner';

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const target = searchParams.get('url') || searchParams.get('domain') || searchParams.get('target');

    if (!target) {
      return NextResponse.json(
        { error: 'Missing required query parameter: url or domain. Example: /api/public/check?domain=example.com' },
        { status: 400 }
      );
    }

    const validation = await validateAndNormalizeTarget(target);
    if (!validation.valid || !validation.domain || !validation.normalizedUrl || !validation.hostname) {
      return NextResponse.json({ error: validation.error || 'Invalid domain' }, { status: 400 });
    }

    // Check cache
    let scan = getCachedScan(validation.domain);

    if (!scan) {
      const scanId = `pub_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      await runScan(scanId, validation.normalizedUrl, validation.domain, validation.hostname, 'public_api');
      scan = getCachedScan(validation.domain);
    }

    if (!scan) {
      return NextResponse.json({ status: 'processing', message: 'Scan initiated. Please query again in a few seconds.' });
    }

    const host = req.headers.get('host') || 'localhost:3000';
    const protocol = req.headers.get('x-forwarded-proto') || 'http';

    return NextResponse.json({
      domain: scan.domain,
      targetUrl: scan.targetUrl,
      verdict: scan.verdict,
      verdictText: scan.verdictText,
      totalChecks: scan.totalChecks,
      positiveMatched: scan.positiveMatched,
      suspiciousCount: scan.suspiciousCount,
      cleanCount: scan.cleanCount,
      unratedCount: scan.unratedCount,
      scanDate: scan.scanDate,
      timestamp: scan.timestamp,
      cached: Boolean(scan.cached),
      reportUrl: `${protocol}://${host}/report/${scan.id}`,
      badgeUrl: `${protocol}://${host}/api/public/badge?domain=${scan.domain}`,
    });
  } catch (err: unknown) {
    console.error('Error in public check endpoint:', err);
    return NextResponse.json({ error: 'Internal server error processing public security check.' }, { status: 500 });
  }
}
