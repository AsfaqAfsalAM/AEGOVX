import { NextRequest, NextResponse } from 'next/server';
import { getScan } from '@/lib/db';

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!id) {
      return NextResponse.json({ error: 'Scan ID is required' }, { status: 400 });
    }

    const scan = getScan(id);
    if (!scan) {
      return NextResponse.json({ error: 'Scan report not found or has expired.' }, { status: 404 });
    }

    const totalEngines = scan.totalChecks || 96;
    const progressPercent = scan.progress || (scan.status === 'completed' ? 100 : 15);
    const enginesDone = Math.min(
      totalEngines,
      Math.floor((progressPercent / 100) * totalEngines)
    );

    return NextResponse.json({
      scan,
      status: scan.status,
      progress: progressPercent,
      enginesCompleted: enginesDone,
      totalEngines: totalEngines,
      currentEngine: scan.currentEngine,
    });
  } catch (err: unknown) {
    console.error('Error fetching scan by id:', err);
    return NextResponse.json(
      { error: 'An error occurred while fetching scan report.' },
      { status: 500 }
    );
  }
}
