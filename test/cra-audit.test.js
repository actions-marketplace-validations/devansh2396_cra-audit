import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  parsePackageJson,
  parsePnpmLock,
  parseYarnLock,
  parseMixLock,
  parseRequirementsTxt,
  parseGoMod,
  parseCargoToml,
  parseComposerJson,
  scanRepositoryDir,
} from '../src/parsers.js';
import { generateCycloneDX, generateCsafVex } from '../src/sbom.js';
import { scoreCraReadiness } from '../src/scorer.js';
import { runAudit } from '../src/index.js';

test('parses npm, PyPI, Go, Rust, PHP, pnpm, yarn, and Elixir mix.lock accurately', () => {
  const npmRes = parsePackageJson(
    JSON.stringify({
      name: 'demo-cli',
      version: '1.4.2',
      license: 'MIT',
      bin: { demo: './cli.js' },
      dependencies: { express: '^4.19.2', '@acme/sdk': '~2.0.1' },
    }),
  );
  assert.equal(npmRes.components.length, 2);
  assert.equal(npmRes.components[1].purl, 'pkg:npm/%40acme/sdk@2.0.1');

  const pnpmComps = parsePnpmLock(`lockfileVersion: '9.0'\npackages:\n  '@scope/lib@2.1.4':\n    resolution: {}\n  zod@3.23.8:\n    resolution: {}`);
  assert.equal(pnpmComps.length, 2);
  assert.equal(pnpmComps[0].name, '@scope/lib');

  const yarnComps = parseYarnLock(`"@acme/ui@^1.0.0":\n  version "1.2.3"\n\nlodash@^4.17.21:\n  version "4.17.21"\n`);
  assert.equal(yarnComps.length, 2);
  assert.equal(yarnComps[1].purl, 'pkg:npm/lodash@4.17.21');

  const mixComps = parseMixLock(`%{\n  "phoenix": {:hex, :phoenix, "1.7.14", "hash", [:mix], [], "hexpm", "hash2"},\n  "jason": {:hex, :jason, "1.4.4", "hash", [:mix], [], "hexpm", "hash2"}\n}`);
  assert.equal(mixComps.length, 2);
  assert.equal(mixComps[0].ecosystem, 'Hex');
  assert.equal(mixComps[0].purl, 'pkg:hex/phoenix@1.7.14');

  const pyComps = parseRequirementsTxt('fastapi==0.115.0\nuvicorn[standard]>=0.30.0 # server');
  assert.equal(pyComps.length, 2);

  const goComps = parseGoMod('module example.com/app\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n)');
  assert.equal(goComps.length, 1);

  const rustComps = parseCargoToml('[dependencies]\nserde = { version = "1.0.210", features = ["derive"] }');
  assert.equal(rustComps.length, 1);

  const phpComps = parseComposerJson(JSON.stringify({ require: { php: '^8.2', 'laravel/framework': '^11.0.0' } }));
  assert.equal(phpComps.length, 1);
});

test('discovers workspace monorepo manifests when root package.json has zero deps', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-monorepo-'));
  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'mono-root', private: true, workspaces: ['apps/*'] }));
  fs.mkdirSync(path.join(tmpDir, 'apps', 'web'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'apps', 'web', 'package.json'), JSON.stringify({ name: 'web', dependencies: { next: '15.1.0', zod: '3.23.8' } }));

  const scan = scanRepositoryDir(tmpDir);
  assert.equal(scan.components.length, 2);
  assert.ok(scan.meta.manifests.some((m) => m.startsWith('workspace-manifests')));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('generates valid CycloneDX 1.6 SBOM and CSAF 2.0 VEX structures', () => {
  const meta = { productName: 'widget-agent', productVersion: '2.1.0', license: 'Apache-2.0', supportYears: 5 };
  const comps = [{ name: 'zod', version: '3.23.8', ecosystem: 'npm', purl: 'pkg:npm/zod@3.23.8', direct: true }];
  const sbom = generateCycloneDX(meta, comps);
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, '1.6');
  assert.equal(sbom.components.length, 1);
  assert.ok(sbom.serialNumber.startsWith('urn:uuid:'));

  const vex = generateCsafVex(meta, [
    {
      id: 'GHSA-test-1234',
      cve: 'CVE-2026-0001',
      packageName: 'zod',
      packageVersion: '3.23.8',
      ecosystem: 'npm',
      severity: 'HIGH',
      summary: 'Sample advisory',
      references: ['https://osv.dev/vulnerability/GHSA-test-1234'],
    },
  ]);
  assert.equal(vex.document.category, 'csaf_vex');
  assert.equal(vex.document.csaf_version, '2.0');
  assert.equal(vex.vulnerabilities.length, 1);
});

test('triggers URGENT_24H_ENISA_CHECK and penalizes score when CISA KEV match exists', () => {
  const kevRes = scoreCraReadiness(
    {
      manifests: ['package.json'],
      lockfiles: ['package-lock.json'],
      hasLockfile: true,
      hasSecurityMd: true,
      securityEmail: 'security@example.com',
      hasSlaMention: true,
      hasLicenseFile: true,
      hasSupportPeriodMention: true,
      productVersion: '2.0.0',
      hasCiWorkflows: true,
      hasAutomatedSecurityCi: true,
    },
    [{ name: 'a', version: '1.0.0' }],
    { queried: true, offline: false, summary: { total: 1, kev: 1, critical: 1, high: 0, medium: 0, low: 0 } },
  );
  assert.ok(kevRes.article14Status.startsWith('URGENT_24H_ENISA_CHECK'));
  assert.equal(kevRes.score, 75);
});

test('runAudit writes all 7 artifacts in offline mode for fixture directory', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-audit-fixture-'));
  const outDir = path.join(tmpDir, 'out');
  fs.writeFileSync(
    path.join(tmpDir, 'package.json'),
    JSON.stringify({ name: 'fixture-desktop-app', version: '1.2.0', license: 'MIT', dependencies: { lodash: '4.17.21' } }),
  );
  fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
  fs.writeFileSync(
    path.join(tmpDir, 'SECURITY.md'),
    'Report vulnerabilities to security@fixture.example within 48 hours. Supported for 5 years.',
  );
  fs.writeFileSync(path.join(tmpDir, 'LICENSE'), 'MIT License');

  const res = await runAudit(tmpDir, { offline: true, outDir });
  assert.ok(res.reportJson.scoring.score >= 60);

  for (const fname of [
    'cra-report.md',
    'cra-report.json',
    'sbom.cdx.json',
    'vex.csaf.json',
    'annex-vii-technical-file-starter.md',
    'eu-declaration-of-conformity-draft.md',
    'enisa-srp-24h-template.json',
  ]) {
    assert.ok(fs.existsSync(path.join(outDir, fname)), `Missing ${fname}`);
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
