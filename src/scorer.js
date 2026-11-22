export function scoreCraReadiness(meta, components, osvResult) {
  const breakdown = [];
  const annexIGaps = [];
  const annexVIIGaps = [];

  // 1. SBOM & Lockfile Pinning (25 pts)
  let sbomScore = 0;
  if (meta.manifests.length > 0) sbomScore += 10;
  else annexVIIGaps.push('No recognized dependency manifest found (package.json, mix.exs, requirements.txt, pyproject.toml, go.mod, Cargo.toml, composer.json).');

  if (meta.hasLockfile) sbomScore += 10;
  else annexVIIGaps.push('Missing deterministic lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, mix.lock, go.sum, Cargo.lock, composer.lock) — cannot guarantee reproducible SBOM.');

  if (components.length > 0) sbomScore += 5;
  breakdown.push({ area: 'SBOM & Dependency Pinning', score: sbomScore, max: 25 });

  // 2. Vulnerability & Article 14 Exposure (25 pts)
  let vulnScore = 25;
  const s = osvResult?.summary || { total: 0, kev: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const kevCount = Number(s.kev || 0);
  if (!osvResult?.queried && !osvResult?.offline) {
    vulnScore = 15;
    annexIGaps.push('OSV vulnerability lookup failed/timed out; verify known vulnerabilities prior to release.');
  } else {
    vulnScore -= Math.min(25, kevCount * 15 + s.critical * 10 + s.high * 5 + s.medium * 2 + s.low * 1);
    vulnScore = Math.max(0, vulnScore);
    if (kevCount > 0) {
      annexIGaps.push(
        `URGENT: ${kevCount} CISA KEV actively exploited vulnerability match(es) detected — triggers immediate 24-hour ENISA SRP Article 14 assessment if deployed in EU products.`,
      );
    }
    if (s.critical > 0 || s.high > 0) {
      annexIGaps.push(
        `Detected ${s.critical} critical and ${s.high} high OSV vulnerabilities — Annex I Part I forbids placing products with known exploitable vulnerabilities on the EU market.`,
      );
    }
  }
  breakdown.push({ area: 'Known Vulnerability & Art. 14 Posture', score: vulnScore, max: 25 });

  // 3. Article 13/14 VDP & Security Contact (20 pts)
  let vdpScore = 0;
  if (meta.hasSecurityMd) vdpScore += 10;
  else annexIGaps.push('Missing SECURITY.md / Coordinated Vulnerability Disclosure policy (Article 13(6) & Annex I Part II).');

  if (meta.securityEmail) vdpScore += 6;
  else annexIGaps.push('No public vulnerability reporting email address detected for EU single point of contact.');

  if (meta.hasSlaMention) vdpScore += 4;
  else annexIGaps.push('No explicit vulnerability acknowledgement/triage SLA documented.');
  breakdown.push({ area: 'Coordinated VDP & Contact (Art. 13/14)', score: vdpScore, max: 20 });

  // 4. Support Period, License & Provenance (15 pts)
  let docScore = 0;
  if (meta.hasLicenseFile) docScore += 5;
  else annexVIIGaps.push('Missing top-level LICENSE file for third-party component provenance.');

  if (meta.hasSupportPeriodMention) docScore += 6;
  else annexVIIGaps.push('No explicit EU CRA support period (typically 5 years or product lifetime) published in SECURITY.md or cra.json (Article 13(8)).');

  if (meta.productVersion && meta.productVersion !== '0.1.0') docScore += 4;
  else docScore += 2;
  breakdown.push({ area: 'Support Period & Technical File Baseline', score: docScore, max: 15 });

  // 5. CI/CD Release & Security Automation (15 pts)
  let ciScore = 0;
  if (meta.hasCiWorkflows) ciScore += 8;
  else annexVIIGaps.push('No automated CI pipeline (.github/workflows) generating release SBOMs and build provenance.');

  if (meta.hasAutomatedSecurityCi) ciScore += 7;
  else annexVIIGaps.push('No automated dependency update or security scan CI workflow detected (Dependabot, Renovate, CodeQL, or cra-audit Action).');
  breakdown.push({ area: 'CI/CD Security & Update Automation', score: ciScore, max: 15 });

  const score = breakdown.reduce((acc, item) => acc + item.score, 0);
  const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'D';
  const readinessLevel =
    score >= 85
      ? 'Strong Baseline (Finalize Annex VII & Declaration)'
      : score >= 65
        ? 'Partial Readiness (Close VDP, SBOM & Support Gaps)'
        : 'At Risk (Missing Core CRA Article 13/14/Annex VII Controls)';

  const article14Status =
    kevCount > 0
      ? `URGENT_24H_ENISA_CHECK: ${kevCount} CISA KEV active-exploit match(es) detected — verify reachability & file ENISA SRP within 24h if affected.`
      : s.critical > 0 || s.high > 0
        ? 'ACTION_REQUIRED: Triage high/critical vulnerabilities in CSAF VEX & verify against ENISA SRP 24h clock if actively exploited.'
        : 'MONITORING: Keep continuous CI + KEV monitoring live for 24h ENISA SRP window (live since Sept 11, 2026).';

  return {
    score,
    grade,
    readinessLevel,
    breakdown,
    annexIGaps,
    annexVIIGaps,
    article14Status,
  };
}
