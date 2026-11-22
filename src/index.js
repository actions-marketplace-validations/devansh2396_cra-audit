import fs from 'node:fs';
import path from 'node:path';
import { scanRepositoryDir } from './parsers.js';
import { queryOsvVulnerabilities } from './osv.js';
import { generateCycloneDX, generateCsafVex } from './sbom.js';
import { scoreCraReadiness } from './scorer.js';
import {
  renderCraReportMarkdown,
  renderAnnexViiStarterMarkdown,
  renderDeclarationOfConformityDraft,
  generateEnisaSrpTemplate,
  renderSecurityMdDraft,
} from './generators.js';

export async function runAudit(targetDir, options = {}) {
  const { meta, components } = scanRepositoryDir(targetDir, {
    productName: options.productName,
    productVersion: options.productVersion,
    supportYears: options.supportYears,
  });

  const osv = await queryOsvVulnerabilities(components, {
    offline: Boolean(options.offline),
    maxPackages: options.maxPackages || 200,
    timeoutMs: options.timeoutMs || 10000,
  });

  const scoring = scoreCraReadiness(meta, components, osv);
  const scan = { meta, components, osv, scoring };

  const sbom = generateCycloneDX(meta, components);
  const vex = generateCsafVex(meta, osv.vulnerabilities);
  const reportMd = renderCraReportMarkdown(scan);
  const annexViiMd = renderAnnexViiStarterMarkdown(scan);
  const declarationMd = renderDeclarationOfConformityDraft(meta);
  const enisaTemplate = generateEnisaSrpTemplate(meta, osv);
  const securityMdDraft = renderSecurityMdDraft(meta);

  const reportJson = {
    schema: 'craops.audit-report.v1',
    generatedAt: new Date().toISOString(),
    meta,
    componentCount: components.length,
    osvSummary: osv.summary,
    vulnerabilities: osv.vulnerabilities,
    scoring,
  };

  if (options.outDir) {
    const out = path.resolve(options.outDir);
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'cra-report.md'), reportMd, 'utf8');
    fs.writeFileSync(path.join(out, 'cra-report.json'), JSON.stringify(reportJson, null, 2), 'utf8');
    fs.writeFileSync(path.join(out, 'sbom.cdx.json'), JSON.stringify(sbom, null, 2), 'utf8');
    fs.writeFileSync(path.join(out, 'vex.csaf.json'), JSON.stringify(vex, null, 2), 'utf8');
    fs.writeFileSync(path.join(out, 'annex-vii-technical-file-starter.md'), annexViiMd, 'utf8');
    fs.writeFileSync(path.join(out, 'eu-declaration-of-conformity-draft.md'), declarationMd, 'utf8');
    fs.writeFileSync(path.join(out, 'enisa-srp-24h-template.json'), JSON.stringify(enisaTemplate, null, 2), 'utf8');
    fs.writeFileSync(path.join(out, 'SECURITY.cra-draft.md'), securityMdDraft, 'utf8');
  }

  return {
    reportJson,
    reportMd,
    sbom,
    vex,
    annexViiMd,
    declarationMd,
    enisaTemplate,
    securityMdDraft,
  };
}

export {
  scanRepositoryDir,
  queryOsvVulnerabilities,
  generateCycloneDX,
  generateCsafVex,
  scoreCraReadiness,
  renderSecurityMdDraft,
};
