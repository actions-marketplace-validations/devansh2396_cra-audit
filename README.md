# `craops` (`cra-audit`) — Open-Source EU Cyber Resilience Act (CRA) Compliance-as-Code CLI & GitHub Action

Zero-dependency Node.js 20+ CLI and GitHub Action that turns your repository into **EU Cyber Resilience Act (Regulation (EU) 2024/2847)** technical evidence in seconds:

- **CycloneDX 1.6 SBOM** (`sbom.cdx.json`) across npm (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, workspace sub-manifests), PyPI, Go, Rust (`Cargo.lock`), PHP (`composer.lock`), and Elixir (`mix.exs` / `mix.lock`)
- **Live OSV.dev + CISA KEV Check** mapped to **Article 14 ENISA Single Reporting Platform (live since Sept 11, 2026)**
- **CSAF 2.0 VEX Dossier** (`vex.csaf.json`) ready for exploitability triage
- **Annex VII Technical File Starter** (`annex-vii-technical-file-starter.md`), **Module A EU Declaration of Conformity Draft** (`eu-declaration-of-conformity-draft.md`), and **Article 13(6)/13(8) VDP Draft** (`SECURITY.cra-draft.md`)
- **Container Base-Image Check** (`Dockerfile` floating `:latest` & EOL OS detection)
- **24h / 72h / 14d ENISA SRP Incident Template** (`enisa-srp-24h-template.json`)
- **Deterministic 0–100 CRA Readiness Score**

## Quickstart (CLI)

```bash
npx craops scan . --out ./cra-artifacts
```

Or run locally without network calls:

```bash
node ./bin/cra-audit.js scan . --offline --out ./cra-artifacts
```

## GitHub Actions Integration

```yaml
name: EU CRA Readiness Check
on:
  push:
    branches: [main]
  pull_request:

jobs:
  cra-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run CRAOps cra-audit
        uses: devansh2396/cra-audit@v0.2.0
        with:
          out-dir: ./cra-artifacts
          support-years: '5'
      - uses: actions/upload-artifact@v4
        with:
          name: eu-cra-evidence-pack
          path: ./cra-artifacts
```

## July 2026 EC Guidance (`C(2026) 5252`) Scope Reminder

Pure browser-only SaaS with no distributed client software generally sits outside CRA (under NIS2), **while** commercial desktop/Electron/mobile apps, browser/IDE/Shopify/Jira plugins, CLIs/SDKs, self-hosted/on-prem software, connected IoT firmware, custom APIs powering client apps ("Remote Data Processing Solutions"), and monetized open-source fall **in scope** with full CE-marking due **December 11, 2027**.

## Need Continuous ENISA 24h Triage, Hosted VDP & 10-Year Archive?
Run the live browser diagnostic, public GitHub scanner, and 24h ENISA SRP Dossier Builder at **https://craops.dev** (`futurewealth.ailab@gmail.com`).

> *Legal Notice: `craops` (`cra-audit`) provides engineering automation and technical evidence templates. It does not constitute legal advice or a Notified Body conformity assessment.*
