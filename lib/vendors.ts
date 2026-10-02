import { VendorResult, EngineCategory } from './types';

export interface VendorDefinition {
  id: string;
  name: string;
  category: EngineCategory;
  hasLogo: boolean;
  logoKey?: string;
  defaultStatus?: 'clean' | 'unrated';
}

export const SECURITY_VENDORS: VendorDefinition[] = [
  // Top-tier famous antivirus / cyber security vendors (with logos)
  { id: 'kaspersky', name: 'Kaspersky', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'kaspersky' },
  { id: 'google_safe_browsing', name: 'Google Safe Browsing', category: 'Phishing Website Check', hasLogo: true, logoKey: 'google' },
  { id: 'microsoft_defender', name: 'Microsoft Defender SmartScreen', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'microsoft' },
  { id: 'bitdefender', name: 'Bitdefender', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'bitdefender' },
  { id: 'sophos', name: 'Sophos', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'sophos' },
  { id: 'eset', name: 'ESET NOD32', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'eset' },
  { id: 'avast', name: 'Avast Software', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'avast' },
  { id: 'avg', name: 'AVG Antivirus', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'avg' },
  { id: 'fortinet', name: 'Fortinet', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'fortinet' },
  { id: 'trend_micro', name: 'Trend Micro', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'trendmicro' },
  { id: 'webroot', name: 'Webroot', category: 'Phishing Website Check', hasLogo: true, logoKey: 'webroot' },
  { id: 'sucuri', name: 'Sucuri SiteCheck', category: 'Malicious Behavioral Analysis', hasLogo: true, logoKey: 'sucuri' },
  { id: 'urlhaus', name: 'URLhaus (abuse.ch)', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'urlhaus' },
  { id: 'openphish', name: 'OpenPhish', category: 'Phishing Website Check', hasLogo: true, logoKey: 'openphish' },
  { id: 'phishtank', name: 'PhishTank', category: 'Phishing Website Check', hasLogo: true, logoKey: 'phishtank' },
  { id: 'spamhaus', name: 'Spamhaus DBL', category: 'Phishing Website Check', hasLogo: true, logoKey: 'spamhaus' },
  { id: 'malwarebytes', name: 'Malwarebytes hpHosts', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'malwarebytes' },
  { id: 'mcafee', name: 'McAfee SiteAdvisor', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'mcafee' },
  { id: 'palo_alto', name: 'Palo Alto Networks', category: 'Malicious Behavioral Analysis', hasLogo: true, logoKey: 'paloalto' },
  { id: 'symantec', name: 'Broadcom / Symantec', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'symantec' },
  { id: 'cloudflare', name: 'Cloudflare Radar Intelligence', category: 'Malicious Behavioral Analysis', hasLogo: true, logoKey: 'cloudflare' },
  { id: 'cisco_talos', name: 'Cisco Talos Intelligence', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'cisco' },
  { id: 'avira', name: 'Avira Safe Browsing', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'avira' },
  { id: 'f_secure', name: 'F-Secure ThreatShield', category: 'Malware/Antivirus Check', hasLogo: true, logoKey: 'fsecure' },
  { id: 'yandex', name: 'Yandex Safebrowsing', category: 'Phishing Website Check', hasLogo: true, logoKey: 'yandex' },
  { id: 'netcraft', name: 'Netcraft Anti-Phishing', category: 'Phishing Website Check', hasLogo: true, logoKey: 'netcraft' },
  { id: 'sentinelone', name: 'SentinelOne Autonomous AI', category: 'Malicious Behavioral Analysis', hasLogo: true, logoKey: 'sentinelone' },
  { id: 'crowdstrike', name: 'CrowdStrike Falcon', category: 'Malicious Behavioral Analysis', hasLogo: true, logoKey: 'crowdstrike' },

  // Dedicated own checks (Custom cards as requested)
  { id: 'ssl_certificate', name: 'SSL/TLS Certificate Validity & Chain', category: 'Infrastructure & SSL Check', hasLogo: true, logoKey: 'ssl' },
  { id: 'security_headers', name: 'HTTP Security Headers (HSTS, CSP)', category: 'Infrastructure & SSL Check', hasLogo: true, logoKey: 'headers' },
  { id: 'whois_domain_age', name: 'Domain Age & WHOIS Authenticity', category: 'Infrastructure & SSL Check', hasLogo: true, logoKey: 'whois' },
  { id: 'dns_blacklist', name: 'DNSBL Reputation (Spamhaus, SURBL)', category: 'Infrastructure & SSL Check', hasLogo: true, logoKey: 'dns' },
  { id: 'redirect_chain', name: 'Hop-by-Hop Redirect Integrity', category: 'Infrastructure & SSL Check', hasLogo: true, logoKey: 'redirect' },

  // Remaining engines from standard 90+ security roster
  { id: 'acronis', name: 'Acronis Cloud Security', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'alienvault', name: 'AlienVault OTX', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'alpha_soc', name: 'AlphaSOC Threat Stream', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'antiy_avl', name: 'Antiy-AVL', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'ahnlab', name: 'AhnLab Smart Defense', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'arcabit', name: 'Arcabit Engine', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'auto_shun', name: 'AutoShun Suspicious IPs', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'bfore_ai', name: 'Bfore.Ai PreCrime Network', category: 'Phishing Website Check', hasLogo: false },
  { id: 'bkav', name: 'Bkav Pro Enterprise', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'blocklist_de', name: 'BlockList.de Attack Monitor', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'certly', name: 'Certly Anti-Phishing', category: 'Phishing Website Check', hasLogo: false },
  { id: 'chong_rong', name: 'Chong Rong Token Sentinel', category: 'Phishing Website Check', hasLogo: false },
  { id: 'clamav', name: 'ClamAV Gateway Filter', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'clean_browsing', name: 'CleanBrowsing DNS Security', category: 'Phishing Website Check', hasLogo: false },
  { id: 'cmc_threat', name: 'CMC Threat Intelligence', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'comodo_valkyrie', name: 'Comodo Valkyrie Verdict', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'crdf', name: 'CRDF Threat Center', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'cynet', name: 'Cynet 360 AutoX', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'cyren', name: 'Cyren Web Security', category: 'Phishing Website Check', hasLogo: false },
  { id: 'deep_instinct', name: 'Deep Instinct Deep Learning', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'dr_web', name: 'Dr.Web CureIt', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'elastic', name: 'Elastic Security Intelligence', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'emsisoft', name: 'Emsisoft Anti-Malware', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'forcepoint', name: 'Forcepoint ThreatSeeker', category: 'Phishing Website Check', hasLogo: false },
  { id: 'g_data', name: 'G-Data CyberDefense', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'gridinsoft', name: 'Gridinsoft Anti-Malware', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'hunt_io', name: 'HUNT.io Infrastructure Scan', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'ikarus', name: 'Ikarus Security Software', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'infinet', name: 'InfiNet Web Shield', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'jiangmin', name: 'Jiangmin KV Antivirus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'k7_antivirus', name: 'K7 AntiVirus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'k7_gateway', name: 'K7GW Web Gateway', category: 'Phishing Website Check', hasLogo: false },
  { id: 'lionic', name: 'Lionic Threat Engine', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'malwaredomainlist', name: 'MalwareDomainList', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'malpatrol', name: 'MalPatrol Threat Feed', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'max_security', name: 'MAX Secure Anti-Virus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'my_wp_guard', name: 'MyWpGuard Security', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'nano_antivirus', name: 'NANO Antivirus Pro', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'palevo', name: 'Palevo Tracker Botnet Feed', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'panda', name: 'Panda Dome Security', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'precision_sec', name: 'PrecisionSec Feed', category: 'Phishing Website Check', hasLogo: false },
  { id: 'quick_heal', name: 'Quick Heal Technologies', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'quttera', name: 'Quttera Web Malware Scanner', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'rising', name: 'Rising Antivirus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'sangfor', name: 'Sangfor Engine Zero', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'scantitan', name: 'ScanTitan Web Engine', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'seclookup', name: 'SecLookup Threat Core', category: 'Phishing Website Check', hasLogo: false },
  { id: 'securebrain', name: 'SecureBrain PhishWall', category: 'Phishing Website Check', hasLogo: false },
  { id: 'spameatingmonkey', name: 'SpamEatingMonkey URIBL', category: 'Phishing Website Check', hasLogo: false },
  { id: 'superantispyware', name: 'SUPERAntiSpyware', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'tachyion', name: 'Tachyon Cyber Security', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'tencent', name: 'Tencent Threat Intelligence', category: 'Phishing Website Check', hasLogo: false },
  { id: 'threat_miner', name: 'ThreatMiner Engine', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'threat_stop', name: 'ThreatSTOP Cloud Defense', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'trellix', name: 'Trellix ENS (McAfee/FireEye)', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'trustlook', name: 'Trustlook Mobile & Web', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'url_query', name: 'URLQuery Sandboxed Engine', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'varist', name: 'Varist Web Protection', category: 'Phishing Website Check', hasLogo: false },
  { id: 'virobot', name: 'ViRobot IS Engine', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'virustracker', name: 'VirusTracker Threat Index', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'watchguard', name: 'WatchGuard EPDR', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'xcitium', name: 'Xcitium Verdict Cloud', category: 'Malicious Behavioral Analysis', hasLogo: false },
  { id: 'zillya', name: 'Zillya! Antivirus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'zoner', name: 'Zoner AntiVirus', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'zonealarm', name: 'ZoneAlarm by Check Point', category: 'Malware/Antivirus Check', hasLogo: false },
  { id: 'zerocert', name: 'ZeroCERT Fraud Prevention', category: 'Phishing Website Check', hasLogo: false },
];

/**
 * Sorts vendors strictly according to specifications:
 * - Malicious / Suspicious always on top
 * - Vendors with logos first, then rest alphabetically
 * - Unrated at the bottom
 */
export function sortVendorResults(vendors: VendorResult[]): VendorResult[] {
  return [...vendors].sort((a, b) => {
    // 1. Threat priority: Malicious/Suspicious on top, Unrated at bottom
    const threatScore = (status: VendorResult['status']) => {
      if (status === 'malicious') return 0;
      if (status === 'suspicious') return 1;
      if (status === 'clean') return 2;
      return 3; // unrated
    };

    const scoreA = threatScore(a.status);
    const scoreB = threatScore(b.status);

    if (scoreA !== scoreB) {
      return scoreA - scoreB;
    }

    // 2. If same threat level, vendors with logos first
    if (a.hasLogo !== b.hasLogo) {
      return a.hasLogo ? -1 : 1;
    }

    // 3. Alphabetical by vendor name
    return a.name.localeCompare(b.name);
  });
}
