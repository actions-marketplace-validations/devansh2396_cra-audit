#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { runAudit } from '../src/index.js';

function parseArgs(argv) {
  const args = argv.slice(2);
  let command = 'scan';
  let targetDir = '.';
  const flags = {
    outDir: null,
    offline: false,
    json: false,
    productName: null,
    productVersion: null,
    supportYears: 5,
    failUnder: null,
    help: false,
  };

  let idx = 0;
  if (args[0] && !args[0].startsWith('-') && ['scan', 'help'].includes(args[0])) {
    command = args[0];
    idx = 1;
  }

  for (; idx < args.length; idx += 1) {
    const a = args[idx];
    if (a === '-h' || a === '--help') flags.help = true;
    else if (a === '--offline') flags.offline = true;
    else if (a === '--json') flags.json = true;
    else if (a === '--out' && args[idx + 1]) {
      flags.outDir = args[++idx];
    } else if (a === '--product-name' && args[idx + 1]) {
      flags.productName = args[++idx];
    } else if (a === '--product-version' && args[idx + 1]) {
      flags.productVersion = args[++idx];
    } else if (a === '--support-years' && args[idx + 1]) {
      flags.supportYears = Number(args[++idx]) || 5;
    } else if (a === '--fail-under' && args[idx + 1]) {
      flags.failUnder = Number(args[++idx]);
    } else if (!a.startsWith('-')) {
      targetDir = a;
    }
  }

  return { command, targetDir, flags };
}

function printHelp() {
  console.log(`craops v0.2.0 — EU Cyber Resilience Act (CRA) Compliance-as-Code CLI

Usage:
  npx craops scan [dir] [options]

Options:
  --out <dir>              Write 7 CRA evidence artifacts (SBOM, CSAF VEX, Annex VII, ENISA SRP)
  --offline                Skip live OSV.dev vulnerability lookups
  --json                   Output machine-readable JSON summary to stdout
  --product-name <name>    Override detected product name
  --product-version <ver>  Override detected product version
  --support-years <n>      CRA support commitment in years (default: 5)
  --fail-under <score>     Exit with code 2 if score < threshold
  -h, --help               Show this help
`);
}

async function main() {
  const { command, targetDir, flags } = parseArgs(process.argv);
  if (command === 'help' || flags.help) {
    printHelp();
    process.exit(0);
  }

  const absTarget = path.resolve(targetDir);
  if (!fs.existsSync(absTarget)) {
    console.error(`Error: target directory not found: ${absTarget}`);
    process.exit(1);
  }

  const result = await runAudit(absTarget, flags);
  const { reportJson } = result;
  const { meta, scoring, osvSummary, componentCount } = reportJson;

  if (flags.json) {
    console.log(JSON.stringify(reportJson, null, 2));
  } else {
    console.log(`\nEU CRA Readiness Audit — ${meta.productName} (${meta.productVersion})`);
    console.log(`Score: ${scoring.score}/100 [Grade ${scoring.grade}] — ${scoring.readinessLevel}`);
    console.log(`Manifests: ${meta.manifests.join(', ') || 'None'} | Components: ${componentCount} | Lockfile: ${meta.hasLockfile ? meta.lockfiles.join(', ') : 'MISSING'}`);
    console.log(
      `OSV Vulnerabilities: ${flags.offline ? 'OFFLINE' : `${osvSummary.total} (Critical: ${osvSummary.critical}, High: ${osvSummary.high}, Medium: ${osvSummary.medium})`}`,
    );
    console.log(`Article 14 (ENISA SRP Live Sept 11, 2026): ${scoring.article14Status}`);
    if (scoring.annexIGaps.length || scoring.annexVIIGaps.length) {
      console.log('\nPriority Gaps:');
      for (const gap of [...scoring.annexIGaps, ...scoring.annexVIIGaps]) {
        console.log(`  - ${gap}`);
      }
    }
    if (flags.outDir) {
      console.log(`\nWrote 7 CRA artifacts to ${path.resolve(flags.outDir)}`);
    }
  }

  if (process.env.GITHUB_OUTPUT) {
    const outLines = [
      `score=${scoring.score}`,
      `grade=${scoring.grade}`,
      `vuln-count=${osvSummary.total}`,
      `component-count=${componentCount}`,
      ...(flags.outDir
        ? [
            `sbom-path=${path.join(path.resolve(flags.outDir), 'sbom.cdx.json')}`,
            `report-path=${path.join(path.resolve(flags.outDir), 'cra-report.md')}`,
          ]
        : []),
    ];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${outLines.join('\n')}\n`, 'utf8');
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${result.reportMd}\n`, 'utf8');
  }

  if (typeof flags.failUnder === 'number' && !Number.isNaN(flags.failUnder) && scoring.score < flags.failUnder) {
    console.error(`\nFailed threshold: CRA score ${scoring.score} < ${flags.failUnder}`);
    process.exit(2);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
