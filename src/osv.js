const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function inferSeverity(vuln) {
  const dbSev = vuln?.database_specific?.severity;
  if (typeof dbSev === 'string') {
    const norm = dbSev.toUpperCase();
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW'].includes(norm)) {
      return norm === 'MODERATE' ? 'MEDIUM' : norm;
    }
  }
  const sevArr = Array.isArray(vuln?.severity) ? vuln.severity : [];
  for (const s of sevArr) {
    const scoreStr = String(s?.score || '');
    const numMatch = scoreStr.match(/(\d+(?:\.\d+)?)/);
    if (numMatch && s.type === 'CVSS_V3' && !scoreStr.startsWith('CVSS:')) {
      const score = Number(numMatch[1]);
      if (score >= 9.0) return 'CRITICAL';
      if (score >= 7.0) return 'HIGH';
      if (score >= 4.0) return 'MEDIUM';
      return 'LOW';
    }
  }
  return 'MEDIUM';
}

export async function fetchCisaKevSet(options = {}) {
  if (options.offline) {
    return { checked: false, kevSet: new Set() };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || 8000);
  try {
    const res = await fetch(CISA_KEV_URL, {
      headers: { 'user-agent': 'cra-audit/0.2.0' },
      signal: controller.signal,
    });
    if (!res.ok) return { checked: false, kevSet: new Set() };
    const data = await res.json();
    const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const kevSet = new Set();
    for (const item of list) {
      if (typeof item?.cveID === 'string') kevSet.add(item.cveID.toUpperCase());
    }
    return { checked: true, kevSet };
  } catch {
    return { checked: false, kevSet: new Set() };
  } finally {
    clearTimeout(timer);
  }
}

export async function queryOsvVulnerabilities(components, options = {}) {
  if (options.offline) {
    return {
      queried: false,
      kevChecked: false,
      offline: true,
      vulnerabilities: [],
      summary: { total: 0, kev: 0, critical: 0, high: 0, medium: 0, low: 0 },
    };
  }

  const queryable = components.filter(
    (c) =>
      c.version &&
      c.version !== 'unknown' &&
      ['npm', 'PyPI', 'Go', 'crates.io', 'Packagist', 'Hex'].includes(c.ecosystem),
  );

  if (queryable.length === 0) {
    return {
      queried: true,
      kevChecked: false,
      offline: false,
      vulnerabilities: [],
      summary: { total: 0, kev: 0, critical: 0, high: 0, medium: 0, low: 0 },
    };
  }

  const capped = queryable.slice(0, options.maxPackages || 250);
  const rawMatches = [];
  const chunkSize = 100;

  const [kevResult] = await Promise.all([fetchCisaKevSet(options)]);

  for (let i = 0; i < capped.length; i += chunkSize) {
    const batch = capped.slice(i, i + chunkSize);
    const queries = batch.map((c) => ({
      package: { name: c.name, ecosystem: c.ecosystem },
      version: c.version,
    }));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs || 10000);
    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`OSV querybatch HTTP ${res.status}`);
      }
      const data = await res.json();
      const results = Array.isArray(data?.results) ? data.results : [];
      results.forEach((entry, idx) => {
        const vulns = Array.isArray(entry?.vulns) ? entry.vulns : [];
        for (const v of vulns) {
          rawMatches.push({ component: batch[idx], id: v.id, modified: v.modified });
        }
      });
    } catch (err) {
      return {
        queried: false,
        kevChecked: kevResult.checked,
        offline: false,
        error: err instanceof Error ? err.message : String(err),
        vulnerabilities: [],
        summary: { total: 0, kev: 0, critical: 0, high: 0, medium: 0, low: 0 },
      };
    } finally {
      clearTimeout(timer);
    }
  }

  const uniqueIds = Array.from(new Set(rawMatches.map((m) => m.id))).slice(0, 20);
  const detailsMap = new Map();
  await Promise.all(
    uniqueIds.map(async (id) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const r = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, { signal: controller.signal });
        if (r.ok) detailsMap.set(id, await r.json());
      } catch {
        // graceful fallback
      } finally {
        clearTimeout(timer);
      }
    }),
  );

  const vulnerabilities = rawMatches.map((m) => {
    const detail = detailsMap.get(m.id);
    const aliases = Array.isArray(detail?.aliases) ? detail.aliases : [];
    const cve = aliases.find((a) => a.startsWith('CVE-')) || (m.id.startsWith('CVE-') ? m.id : null);
    const isCisaKev = Boolean(cve && kevResult.kevSet.has(cve.toUpperCase()));
    const severity = detail ? inferSeverity(detail) : 'MEDIUM';
    return {
      id: m.id,
      cve,
      isCisaKev,
      packageName: m.component.name,
      packageVersion: m.component.version,
      ecosystem: m.component.ecosystem,
      purl: m.component.purl,
      severity,
      summary: detail?.summary || detail?.details?.slice(0, 140) || 'Known vulnerability reported in OSV database',
      references: [`https://osv.dev/vulnerability/${m.id}`],
    };
  });

  const summary = { total: vulnerabilities.length, kev: 0, critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulnerabilities) {
    if (v.isCisaKev) summary.kev += 1;
    if (v.severity === 'CRITICAL') summary.critical += 1;
    else if (v.severity === 'HIGH') summary.high += 1;
    else if (v.severity === 'LOW') summary.low += 1;
    else summary.medium += 1;
  }

  return {
    queried: true,
    kevChecked: kevResult.checked,
    offline: false,
    checkedCount: capped.length,
    vulnerabilities,
    summary,
  };
}
