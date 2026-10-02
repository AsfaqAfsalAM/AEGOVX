import { NextResponse } from 'next/server';
import { getRecentScans } from '@/lib/db';

export async function GET() {
  try {
    const recent = getRecentScans(8);
    return NextResponse.json({ scans: recent });
  } catch (err: unknown) {
    return NextResponse.json({ scans: [] });
  }
}
