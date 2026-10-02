import { NextRequest, NextResponse } from 'next/server';
import { getCachedScan } from '@/lib/db';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const domain = searchParams.get('domain') || 'example.com';
  const cleanDomain = domain.toLowerCase().trim();

  const scan = getCachedScan(cleanDomain);

  let labelLeft = 'Scanned by AEGOVX';
  let labelRight = 'Clean (0/96)';
  let bgRight = '#10b981'; // Emerald

  if (!scan) {
    labelRight = 'Verified';
    bgRight = '#3b82f6'; // Blue
  } else if (scan.verdict === 'MALICIOUS') {
    labelRight = `Threat (${scan.positiveMatched} flagged)`;
    bgRight = '#ef4444'; // Red
  } else if (scan.verdict === 'SUSPICIOUS') {
    labelRight = `Caution (${scan.suspiciousCount} flags)`;
    bgRight = '#f59e0b'; // Amber
  } else {
    labelRight = `Clean (0/${scan.totalChecks || 96})`;
    bgRight = '#10b981'; // Emerald
  }

  // Calculate widths based on characters
  const widthLeft = Math.max(120, labelLeft.length * 7 + 24);
  const widthRight = Math.max(90, labelRight.length * 7 + 24);
  const totalWidth = widthLeft + widthRight;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="28" role="img" aria-label="${labelLeft}: ${labelRight}">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="${totalWidth}" height="28" rx="4" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <rect width="${widthLeft}" height="28" fill="#1e293b"/>
    <rect x="${widthLeft}" width="${widthRight}" height="28" fill="${bgRight}"/>
    <rect width="${totalWidth}" height="28" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="11" font-weight="600">
    <text x="${widthLeft / 2}" y="18" fill="#010101" fill-opacity=".3">${labelLeft}</text>
    <text x="${widthLeft / 2}" y="17" fill="#f8fafc">${labelLeft}</text>
    <text x="${widthLeft + widthRight / 2}" y="18" fill="#010101" fill-opacity=".3">${labelRight}</text>
    <text x="${widthLeft + widthRight / 2}" y="17" fill="#ffffff">${labelRight}</text>
  </g>
  <g transform="translate(6, 6)">
    <path fill="#38bdf8" d="M8 0L1 3v4c0 4.42 2.98 8.56 7 9.5 4.02-.94 7-5.08 7-9.5V3L8 0zm0 15.5C4.7 14.6 2.5 11.2 2.5 7.5V4.2L8 1.8l5.5 2.4v3.3c0 3.7-2.2 7.1-5.5 8z"/>
  </g>
</svg>`;

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=300, s-maxage=600',
    },
  });
}
