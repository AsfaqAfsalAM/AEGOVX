import fs from 'fs';
import path from 'path';
import { ScanReport, RecentScanItem } from './types';

// Detect or initialize SQLite database
// Node.js 22+ & 24 include native `node:sqlite`
let dbInstance: any = null;

function getDb() {
  if (dbInstance) return dbInstance;

  try {
    // Ensure ./data directory exists
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'scanner.db');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { DatabaseSync } = require('node:sqlite');
    const db = new DatabaseSync(dbPath);

    // Initialize Schema
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        domain TEXT NOT NULL,
        hostname TEXT NOT NULL,
        status TEXT NOT NULL,
        progress INTEGER DEFAULT 0,
        current_engine TEXT,
        total_checks INTEGER DEFAULT 0,
        positive_matched INTEGER DEFAULT 0,
        suspicious_count INTEGER DEFAULT 0,
        clean_count INTEGER DEFAULT 0,
        unrated_count INTEGER DEFAULT 0,
        verdict TEXT NOT NULL,
        verdict_text TEXT,
        results_json TEXT NOT NULL,
        extra_checks_json TEXT,
        source_note TEXT,
        ip_address TEXT,
        created_at INTEGER NOT NULL,
        completed_at INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
      CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

      CREATE TABLE IF NOT EXISTS scan_cache (
        domain TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS rate_limits (
        ip TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_time ON rate_limits(ip, timestamp);
    `);

    dbInstance = db;
    return dbInstance;
  } catch (error) {
    console.error('Failed to initialize node:sqlite database, falling back to memory store:', error);
    // In-memory fallback if needed
    return null;
  }
}

// In-memory fallback if file system / SQLite has unexpected issues
const memoryStore = {
  scans: new Map<string, ScanReport>(),
  cache: new Map<string, { scanId: string; expiresAt: number }>(),
  rateLimits: [] as { ip: string; timestamp: number }[],
};

export function saveScan(scan: ScanReport, ipAddress?: string): void {
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`
        INSERT INTO scans (
          id, target_url, domain, hostname, status, progress, current_engine,
          total_checks, positive_matched, suspicious_count, clean_count, unrated_count,
          verdict, verdict_text, results_json, extra_checks_json, source_note,
          ip_address, created_at, completed_at
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?
        )
        ON CONFLICT(id) DO UPDATE SET
          status = excluded.status,
          progress = excluded.progress,
          current_engine = excluded.current_engine,
          total_checks = excluded.total_checks,
          positive_matched = excluded.positive_matched,
          suspicious_count = excluded.suspicious_count,
          clean_count = excluded.clean_count,
          unrated_count = excluded.unrated_count,
          verdict = excluded.verdict,
          verdict_text = excluded.verdict_text,
          results_json = excluded.results_json,
          extra_checks_json = excluded.extra_checks_json,
          source_note = excluded.source_note,
          completed_at = excluded.completed_at
      `);

      stmt.run(
        scan.id,
        scan.targetUrl,
        scan.domain,
        scan.hostname,
        scan.status,
        scan.progress,
        scan.currentEngine || '',
        scan.totalChecks,
        scan.positiveMatched,
        scan.suspiciousCount,
        scan.cleanCount,
        scan.unratedCount,
        scan.verdict,
        scan.verdictText,
        JSON.stringify(scan.results),
        scan.extraChecks ? JSON.stringify(scan.extraChecks) : null,
        scan.sourceNote || null,
        ipAddress || '127.0.0.1',
        scan.timestamp,
        scan.status === 'completed' ? Date.now() : null
      );
      return;
    } catch (err) {
      console.error('Error in saveScan (SQLite):', err);
    }
  }

  // Fallback to memory
  memoryStore.scans.set(scan.id, scan);
}

export function updateScanProgress(
  id: string,
  progress: number,
  currentEngine?: string,
  status: 'pending' | 'scanning' | 'completed' | 'failed' = 'scanning'
): void {
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`
        UPDATE scans
        SET progress = ?, current_engine = ?, status = ?
        WHERE id = ?
      `);
      stmt.run(progress, currentEngine || '', status, id);
      return;
    } catch (err) {
      console.error('Error in updateScanProgress:', err);
    }
  }

  const existing = memoryStore.scans.get(id);
  if (existing) {
    existing.progress = progress;
    existing.currentEngine = currentEngine;
    existing.status = status;
  }
}

export function getScan(id: string): ScanReport | null {
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`SELECT * FROM scans WHERE id = ?`);
      const row: any = stmt.get(id);
      if (row) {
        return {
          id: row.id,
          targetUrl: row.target_url,
          domain: row.domain,
          hostname: row.hostname,
          scanDate: new Date(row.created_at).toLocaleString('en-US', {
            dateStyle: 'medium',
            timeStyle: 'short',
          }),
          timestamp: row.created_at,
          status: row.status,
          progress: row.progress,
          currentEngine: row.current_engine,
          totalChecks: row.total_checks,
          positiveMatched: row.positive_matched,
          suspiciousCount: row.suspicious_count,
          cleanCount: row.clean_count,
          unratedCount: row.unrated_count,
          verdict: row.verdict,
          verdictText: row.verdict_text,
          results: JSON.parse(row.results_json || '[]'),
          extraChecks: row.extra_checks_json ? JSON.parse(row.extra_checks_json) : undefined,
          sourceNote: row.source_note,
        };
      }
    } catch (err) {
      console.error('Error in getScan (SQLite):', err);
    }
  }

  return memoryStore.scans.get(id) || null;
}

export function setScanCache(domain: string, scanId: string, ttlHours: number = 1): void {
  const expiresAt = Date.now() + ttlHours * 60 * 60 * 1000;
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`
        INSERT INTO scan_cache (domain, scan_id, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
          scan_id = excluded.scan_id,
          expires_at = excluded.expires_at
      `);
      stmt.run(domain.toLowerCase(), scanId, expiresAt);
      return;
    } catch (err) {
      console.error('Error in setScanCache:', err);
    }
  }

  memoryStore.cache.set(domain.toLowerCase(), { scanId, expiresAt });
}

export function getCachedScan(domain: string): ScanReport | null {
  const now = Date.now();
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`
        SELECT scan_id, expires_at FROM scan_cache
        WHERE domain = ? AND expires_at > ?
      `);
      const row: any = stmt.get(domain.toLowerCase(), now);
      if (row && row.scan_id) {
        const scan = getScan(row.scan_id);
        if (scan && scan.status === 'completed') {
          return { ...scan, cached: true };
        }
      }
    } catch (err) {
      console.error('Error in getCachedScan:', err);
    }
  }

  const cached = memoryStore.cache.get(domain.toLowerCase());
  if (cached && cached.expiresAt > now) {
    const scan = memoryStore.scans.get(cached.scanId);
    if (scan && scan.status === 'completed') {
      return { ...scan, cached: true };
    }
  }

  return null;
}

export function clearDomainCache(domain: string): void {
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`DELETE FROM scan_cache WHERE domain = ?`);
      stmt.run(domain.toLowerCase());
    } catch (err) {
      console.error('Error clearing cache:', err);
    }
  }
  memoryStore.cache.delete(domain.toLowerCase());
}

export function getRecentScans(limit: number = 10): RecentScanItem[] {
  const db = getDb();
  if (db) {
    try {
      const stmt = db.prepare(`
        SELECT id, domain, target_url, verdict, positive_matched, total_checks, created_at
        FROM scans
        WHERE status = 'completed'
        ORDER BY created_at DESC
        LIMIT ?
      `);
      const rows: any[] = stmt.all(limit);
      return rows.map((r) => ({
        id: r.id,
        domain: r.domain,
        targetUrl: r.target_url,
        verdict: r.verdict,
        positiveMatched: r.positive_matched,
        totalChecks: r.total_checks,
        timestamp: r.created_at,
        scanDate: new Date(r.created_at).toLocaleString('en-US', {
          dateStyle: 'medium',
          timeStyle: 'short',
        }),
      }));
    } catch (err) {
      console.error('Error in getRecentScans:', err);
    }
  }

  const scans = Array.from(memoryStore.scans.values())
    .filter((s) => s.status === 'completed')
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, limit)
    .map((s) => ({
      id: s.id,
      domain: s.domain,
      targetUrl: s.targetUrl,
      verdict: s.verdict,
      positiveMatched: s.positiveMatched,
      totalChecks: s.totalChecks,
      timestamp: s.timestamp,
      scanDate: s.scanDate,
    }));

  return scans;
}

export function checkRateLimit(
  ip: string,
  maxPerMin: number = 5
): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const cutoff = now - windowMs;

  const db = getDb();
  if (db) {
    try {
      // Clean old entries
      db.prepare(`DELETE FROM rate_limits WHERE timestamp < ?`).run(cutoff);

      // Count recent
      const countRow: any = db
        .prepare(`SELECT COUNT(*) as count FROM rate_limits WHERE ip = ? AND timestamp >= ?`)
        .get(ip, cutoff);

      const count = countRow?.count || 0;
      if (count >= maxPerMin) {
        return { allowed: false, remaining: 0, resetMs: windowMs };
      }

      // Record this hit
      db.prepare(`INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)`).run(ip, now);
      return { allowed: true, remaining: maxPerMin - count - 1, resetMs: windowMs };
    } catch (err) {
      console.error('Error in checkRateLimit:', err);
    }
  }

  // Memory fallback
  memoryStore.rateLimits = memoryStore.rateLimits.filter((r) => r.timestamp >= cutoff);
  const count = memoryStore.rateLimits.filter((r) => r.ip === ip).length;
  if (count >= maxPerMin) {
    return { allowed: false, remaining: 0, resetMs: windowMs };
  }
  memoryStore.rateLimits.push({ ip, timestamp: now });
  return { allowed: true, remaining: maxPerMin - count - 1, resetMs: windowMs };
}
