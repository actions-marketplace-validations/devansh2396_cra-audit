import fs from 'node:fs';
import path from 'node:path';

function safeReadText(filePath, maxBytes = 2_000_000) {
  try {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const fd = fs.openSync(filePath, 'r');
      try {
        const size = Math.min(fs.fstatSync(fd).size, maxBytes);
        const buf = Buffer.alloc(size);
        fs.readSync(fd, buf, 0, size, 0);
        return buf.toString('utf8');
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch {
    return null;
  }
  return null;
}

function cleanSemver(raw) {
  if (!raw || typeof raw !== 'string') return 'unknown';
  const trimmed = raw.trim().replace(/^[~^>=<\s]+/, '');
  const match = trimmed.match(/^\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?/);
  return match ? match[0] : trimmed.split(/\s+/)[0] || 'unknown';
}

function encodeNpmPurl(name, version) {
  const ver = version && version !== 'unknown' ? `@${version}` : '';
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/');
    return `pkg:npm/${encodeURIComponent(scope)}/${pkg}${ver}`;
  }
  return `pkg:npm/${name}${ver}`;
}

export function parsePackageJson(content) {
  try {
    const pkg = JSON.parse(content);
    const comps = [];
    for (const section of ['dependencies', 'optionalDependencies']) {
      const deps = pkg[section];
      if (deps && typeof deps === 'object') {
        for (const [name, rawVer] of Object.entries(deps)) {
          const version = cleanSemver(String(rawVer));
          comps.push({
            name,
            version,
            ecosystem: 'npm',
            purl: encodeNpmPurl(name, version),
            direct: true,
          });
        }
      }
    }
    return {
      meta: {
        name: pkg.name || null,
        version: pkg.version || null,
        license: typeof pkg.license === 'string' ? pkg.license : pkg.license?.type || null,
        description: pkg.description || null,
        hasBin: Boolean(pkg.bin),
        hasWorkspaces: Boolean(pkg.workspaces),
        keywords: Array.isArray(pkg.keywords) ? pkg.keywords : [],
      },
      components: comps,
    };
  } catch {
    return { meta: {}, components: [] };
  }
}

export function parsePackageLockJson(content) {
  try {
    const lock = JSON.parse(content);
    const comps = [];
    const seen = new Set();

    if (lock.packages && typeof lock.packages === 'object') {
      for (const [pkgPath, info] of Object.entries(lock.packages)) {
        if (!pkgPath || pkgPath === '') continue;
        const idx = pkgPath.lastIndexOf('node_modules/');
        const name = idx >= 0 ? pkgPath.slice(idx + 'node_modules/'.length) : pkgPath;
        if (!name || !info?.version) continue;
        const key = `${name}@${info.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        comps.push({
          name,
          version: String(info.version),
          ecosystem: 'npm',
          purl: encodeNpmPurl(name, String(info.version)),
          direct: !pkgPath.includes('node_modules/', idx + 1),
        });
      }
    } else if (lock.dependencies && typeof lock.dependencies === 'object') {
      const walk = (deps, isDirect) => {
        for (const [name, info] of Object.entries(deps)) {
          if (!info?.version) continue;
          const key = `${name}@${info.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            comps.push({
              name,
              version: String(info.version),
              ecosystem: 'npm',
              purl: encodeNpmPurl(name, String(info.version)),
              direct: isDirect,
            });
          }
          if (info.dependencies) walk(info.dependencies, false);
        }
      };
      walk(lock.dependencies, true);
    }
    return comps;
  } catch {
    return [];
  }
}

export function parsePnpmLock(content) {
  const comps = [];
  const seen = new Set();
  for (const line of content.split(/\r?\n/)) {
    // Support pnpm v5-v9 lockfile formats: '/pkg@1.2.3:' or '  pkg@1.2.3:' or "  '@scope/pkg@1.2.3':"
    const m = line.match(/^\s{2,4}['"]?\/?(@?[^@:\s'"]+(?:\/[^@:\s'"]+)?)@(\d+\.\d+\.\d+[^('"\s:]*)/);
    if (m) {
      const [, name, version] = m;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name,
        version,
        ecosystem: 'npm',
        purl: encodeNpmPurl(name, version),
        direct: false,
      });
    }
  }
  return comps;
}

export function parseYarnLock(content) {
  const comps = [];
  const seen = new Set();
  let currentNames = [];
  for (const rawLine of content.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith('#') || rawLine.startsWith('__metadata')) continue;
    if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t')) {
      currentNames = [];
      const header = rawLine.replace(/:$/, '');
      for (const spec of header.split(',')) {
        const s = spec.trim().replace(/^['"]|['"]$/g, '');
        const atIdx = s.lastIndexOf('@');
        if (atIdx > 0) {
          const pkgName = s.slice(0, atIdx).replace(/@npm:.*$/, '');
          if (pkgName && !pkgName.startsWith('workspace:')) currentNames.push(pkgName);
        }
      }
      continue;
    }
    const verMatch = rawLine.match(/^\s+version(?::\s*|\s+)["']?(\d+\.\d+\.\d+[^"'\s]*)["']?/);
    if (verMatch && currentNames.length > 0) {
      const version = verMatch[1];
      for (const name of currentNames) {
        const key = `${name}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          comps.push({
            name,
            version,
            ecosystem: 'npm',
            purl: encodeNpmPurl(name, version),
            direct: false,
          });
        }
      }
      currentNames = [];
    }
  }
  return comps;
}

export function parseMixLock(content) {
  const comps = [];
  const seen = new Set();
  for (const rawLine of content.split(/\r?\n/)) {
    const m = rawLine.match(/^\s*"([a-z0-9_]+)":\s*\{:hex,\s*:([a-z0-9_]+),\s*"([^"]+)"/);
    if (m) {
      const name = m[2] || m[1];
      const version = m[3];
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name,
        version,
        ecosystem: 'Hex',
        purl: `pkg:hex/${name}@${version}`,
        direct: false,
      });
    }
  }
  return comps;
}

export function parseMixExs(content) {
  const comps = [];
  const seen = new Set();
  const matches = content.matchAll(/\{:([a-z0-9_]+),\s*"([^"]+)"/g);
  for (const m of matches) {
    const name = m[1];
    const version = cleanSemver(m[2]);
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    comps.push({
      name,
      version,
      ecosystem: 'Hex',
      purl: `pkg:hex/${name}${version !== 'unknown' ? `@${version}` : ''}`,
      direct: true,
    });
  }
  return comps;
}

export function parseRequirementsTxt(content) {
  const comps = [];
  const seen = new Set();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0].trim();
    if (!line || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===?|~=|>=|<=)?\s*([A-Za-z0-9.*+-]+)?/);
    if (!m) continue;
    const name = m[1];
    const version = m[2] ? cleanSemver(m[2]) : 'unknown';
    const key = `${name.toLowerCase()}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    comps.push({
      name,
      version,
      ecosystem: 'PyPI',
      purl: `pkg:pypi/${name.toLowerCase()}${version !== 'unknown' ? `@${version}` : ''}`,
      direct: true,
    });
  }
  return comps;
}

export function parsePyprojectToml(content) {
  const comps = [];
  const seen = new Set();
  const depBlock = content.match(/dependencies\s*=\s*\[([\s\S]*?)\]/m);
  if (depBlock) {
    const matches = depBlock[1].matchAll(/['"]([^'"]+)['"]/g);
    for (const m of matches) {
      const parsed = parseRequirementsTxt(m[1]);
      for (const c of parsed) {
        const key = `${c.name.toLowerCase()}@${c.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          comps.push(c);
        }
      }
    }
  }
  return comps;
}

export function parseGoMod(content) {
  const comps = [];
  const seen = new Set();
  let inBlock = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split('//')[0].trim();
    if (!line) continue;
    if (line.startsWith('require (')) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    const target = line.startsWith('require ') ? line.slice('require '.length).trim() : inBlock ? line : null;
    if (!target) continue;
    const m = target.match(/^([^\s]+)\s+(v[^\s]+)/);
    if (m) {
      const [, name, version] = m;
      const cleanVer = version.replace(/^v/, '');
      const key = `${name}@${cleanVer}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name,
        version: cleanVer,
        ecosystem: 'Go',
        purl: `pkg:golang/${name}@${version}`,
        direct: !rawLine.includes('// indirect'),
      });
    }
  }
  return comps;
}

export function parseCargoToml(content) {
  const comps = [];
  let inDeps = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    if (line.startsWith('[')) {
      inDeps = /^\[(?:dependencies|workspace\.dependencies)\]$/.test(line);
      continue;
    }
    if (!inDeps) continue;
    const simple = line.match(/^([A-Za-z0-9_-]+)\s*=\s*["']([^"']+)["']/);
    const obj = line.match(/^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*["']([^"']+)["']/);
    const m = simple || obj;
    if (m) {
      const version = cleanSemver(m[2]);
      comps.push({
        name: m[1],
        version,
        ecosystem: 'crates.io',
        purl: `pkg:cargo/${m[1]}${version !== 'unknown' ? `@${version}` : ''}`,
        direct: true,
      });
    }
  }
  return comps;
}

export function parseCargoLock(content) {
  const comps = [];
  const blocks = content.split(/\[\[package\]\]/);
  for (const blk of blocks.slice(1)) {
    const nameMatch = blk.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
    const verMatch = blk.match(/^\s*version\s*=\s*["']([^"']+)["']/m);
    if (nameMatch && verMatch) {
      comps.push({
        name: nameMatch[1],
        version: verMatch[1],
        ecosystem: 'crates.io',
        purl: `pkg:cargo/${nameMatch[1]}@${verMatch[1]}`,
        direct: false,
      });
    }
  }
  return comps;
}

export function parseComposerJson(content) {
  try {
    const comp = JSON.parse(content);
    const comps = [];
    if (comp.require && typeof comp.require === 'object') {
      for (const [name, rawVer] of Object.entries(comp.require)) {
        if (name === 'php' || name.startsWith('ext-')) continue;
        const version = cleanSemver(String(rawVer));
        comps.push({
          name,
          version,
          ecosystem: 'Packagist',
          purl: `pkg:composer/${name}${version !== 'unknown' ? `@${version}` : ''}`,
          direct: true,
        });
      }
    }
    return comps;
  } catch {
    return [];
  }
}

export function parseComposerLock(content) {
  try {
    const lock = JSON.parse(content);
    const pkgs = Array.isArray(lock.packages) ? lock.packages : [];
    return pkgs
      .filter((p) => p?.name && p?.version)
      .map((p) => ({
        name: p.name,
        version: String(p.version).replace(/^v/, ''),
        ecosystem: 'Packagist',
        purl: `pkg:composer/${p.name}@${String(p.version).replace(/^v/, '')}`,
        direct: false,
      }));
  } catch {
    return [];
  }
}

export function parsePomXml(content) {
  const comps = [];
  const seen = new Set();
  const props = {};
  const propsBlock = content.match(/<properties>([\s\S]*?)<\/properties>/i);
  if (propsBlock) {
    for (const pm of propsBlock[1].matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) {
      props[pm[1].trim()] = pm[2].trim();
    }
  }
  const depMatches = content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi);
  for (const dm of depMatches) {
    const block = dm[1];
    const scopeMatch = block.match(/<scope>\s*([^<]+?)\s*<\/scope>/i);
    if (scopeMatch && scopeMatch[1].trim().toLowerCase() === 'test') continue;
    const gMatch = block.match(/<groupId>\s*([^<]+?)\s*<\/groupId>/i);
    const aMatch = block.match(/<artifactId>\s*([^<]+?)\s*<\/artifactId>/i);
    if (!gMatch || !aMatch) continue;
    const groupId = gMatch[1].trim();
    const artifactId = aMatch[1].trim();
    const vMatch = block.match(/<version>\s*([^<]+?)\s*<\/version>/i);
    let version = vMatch ? vMatch[1].trim() : 'unknown';
    const propRef = version.match(/^\$\{([^}]+)\}$/);
    if (propRef && props[propRef[1]]) version = props[propRef[1]];
    if (version.startsWith('${')) version = 'unknown';
    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    comps.push({
      name,
      version,
      ecosystem: 'Maven',
      purl: `pkg:maven/${groupId}/${artifactId}${version !== 'unknown' ? `@${version}` : ''}`,
      direct: true,
    });
  }
  return comps;
}

export function parseGradle(content) {
  const comps = [];
  const seen = new Set();
  const re =
    /\b(?:implementation|api|compileOnly|runtimeOnly|classpath)\s*(?:\(\s*)?["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"')\s]+)["']\s*\)?/g;
  for (const m of content.matchAll(re)) {
    const [, groupId, artifactId, rawVer] = m;
    const version = rawVer.startsWith('$') ? 'unknown' : rawVer;
    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    comps.push({
      name,
      version,
      ecosystem: 'Maven',
      purl: `pkg:maven/${groupId}/${artifactId}${version !== 'unknown' ? `@${version}` : ''}`,
      direct: true,
    });
  }
  return comps;
}

function mergeComponents(primary, secondary) {
  const map = new Map();
  for (const item of [...secondary, ...primary]) {
    const key = `${item.ecosystem}:${item.name.toLowerCase()}@${item.version}`;
    if (!map.has(key)) {
      map.set(key, item);
    } else if (item.direct) {
      map.get(key).direct = true;
    }
  }
  return Array.from(map.values());
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'build', 'dist', '.next', 'vendor', '.venv']);
const NESTED_MANIFEST_NAMES = [
  'package.json',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'go.mod',
  'Cargo.toml',
  'requirements.txt',
  'pyproject.toml',
  'composer.json',
  'mix.exs',
];

function discoverNestedManifests(absDir, limit = 30) {
  const found = [];
  function walk(dir, depth) {
    if (depth > 2 || found.length >= limit) return;
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (found.length >= limit) return;
      if (!ent.isDirectory() || ent.name.startsWith('.') || SKIP_DIRS.has(ent.name)) continue;
      const subDir = path.join(dir, ent.name);
      for (const fileName of NESTED_MANIFEST_NAMES) {
        const candidate = path.join(subDir, fileName);
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          found.push({ filePath: candidate, fileName, relPath: path.relative(absDir, candidate) });
          if (found.length >= limit) return;
        }
      }
      walk(subDir, depth + 1);
    }
  }
  walk(absDir, 1);
  return found;
}

export function scanRepositoryDir(targetDir, overrides = {}) {
  const absDir = path.resolve(targetDir);
  const manifests = [];
  const lockfiles = [];
  let components = [];
  let pkgMeta = {};

  const pkgJsonPath = path.join(absDir, 'package.json');
  const pkgLockPath = path.join(absDir, 'package-lock.json');
  const pnpmLockPath = path.join(absDir, 'pnpm-lock.yaml');
  const yarnLockPath = path.join(absDir, 'yarn.lock');

  const pkgJsonText = safeReadText(pkgJsonPath);
  if (pkgJsonText) {
    manifests.push('package.json');
    const parsed = parsePackageJson(pkgJsonText);
    pkgMeta = parsed.meta;
    components = mergeComponents(components, parsed.components);
  }

  const pkgLockText = safeReadText(pkgLockPath);
  if (pkgLockText) {
    lockfiles.push('package-lock.json');
    components = mergeComponents(components, parsePackageLockJson(pkgLockText));
  }
  const pnpmLockText = safeReadText(pnpmLockPath);
  if (pnpmLockText) {
    lockfiles.push('pnpm-lock.yaml');
    components = mergeComponents(components, parsePnpmLock(pnpmLockText));
  }
  const yarnLockText = safeReadText(yarnLockPath);
  if (yarnLockText) {
    lockfiles.push('yarn.lock');
    components = mergeComponents(components, parseYarnLock(yarnLockText));
  }

  const mixExsText = safeReadText(path.join(absDir, 'mix.exs'));
  if (mixExsText) {
    manifests.push('mix.exs');
    components = mergeComponents(components, parseMixExs(mixExsText));
  }
  const mixLockText = safeReadText(path.join(absDir, 'mix.lock'));
  if (mixLockText) {
    lockfiles.push('mix.lock');
    components = mergeComponents(components, parseMixLock(mixLockText));
  }

  const reqText = safeReadText(path.join(absDir, 'requirements.txt'));
  if (reqText) {
    manifests.push('requirements.txt');
    components = mergeComponents(components, parseRequirementsTxt(reqText));
  }
  const pyprojText = safeReadText(path.join(absDir, 'pyproject.toml'));
  if (pyprojText) {
    manifests.push('pyproject.toml');
    components = mergeComponents(components, parsePyprojectToml(pyprojText));
  }
  if (fs.existsSync(path.join(absDir, 'poetry.lock')) || fs.existsSync(path.join(absDir, 'uv.lock'))) {
    lockfiles.push(fs.existsSync(path.join(absDir, 'uv.lock')) ? 'uv.lock' : 'poetry.lock');
  }

  const goModText = safeReadText(path.join(absDir, 'go.mod'));
  if (goModText) {
    manifests.push('go.mod');
    components = mergeComponents(components, parseGoMod(goModText));
    if (fs.existsSync(path.join(absDir, 'go.sum'))) lockfiles.push('go.sum');
  }

  const cargoTomlText = safeReadText(path.join(absDir, 'Cargo.toml'));
  if (cargoTomlText) {
    manifests.push('Cargo.toml');
    components = mergeComponents(components, parseCargoToml(cargoTomlText));
  }
  const cargoLockText = safeReadText(path.join(absDir, 'Cargo.lock'));
  if (cargoLockText) {
    lockfiles.push('Cargo.lock');
    components = mergeComponents(components, parseCargoLock(cargoLockText));
  }

  const composerJsonText = safeReadText(path.join(absDir, 'composer.json'));
  if (composerJsonText) {
    manifests.push('composer.json');
    components = mergeComponents(components, parseComposerJson(composerJsonText));
  }
  const composerLockText = safeReadText(path.join(absDir, 'composer.lock'));
  if (composerLockText) {
    lockfiles.push('composer.lock');
    components = mergeComponents(components, parseComposerLock(composerLockText));
  }

  const pomXmlText = safeReadText(path.join(absDir, 'pom.xml'));
  if (pomXmlText) {
    manifests.push('pom.xml');
    components = mergeComponents(components, parsePomXml(pomXmlText));
  }
  for (const gradleName of ['build.gradle', 'build.gradle.kts']) {
    const gradleText = safeReadText(path.join(absDir, gradleName));
    if (gradleText) {
      manifests.push(gradleName);
      components = mergeComponents(components, parseGradle(gradleText));
    }
  }
  if (fs.existsSync(path.join(absDir, 'gradle.lockfile'))) {
    lockfiles.push('gradle.lockfile');
  }

  const isMonorepoOrSparse =
    Boolean(pkgMeta.hasWorkspaces || fs.existsSync(path.join(absDir, 'pnpm-workspace.yaml'))) || components.length === 0;
  if (isMonorepoOrSparse) {
    const nested = discoverNestedManifests(absDir, 30);
    let nestedCount = 0;
    for (const item of nested) {
      const txt = safeReadText(item.filePath);
      if (!txt) continue;
      let parsedComps = [];
      if (item.fileName === 'package.json') parsedComps = parsePackageJson(txt).components;
      else if (item.fileName === 'pom.xml') parsedComps = parsePomXml(txt);
      else if (item.fileName === 'build.gradle' || item.fileName === 'build.gradle.kts') parsedComps = parseGradle(txt);
      else if (item.fileName === 'go.mod') parsedComps = parseGoMod(txt);
      else if (item.fileName === 'Cargo.toml') parsedComps = parseCargoToml(txt);
      else if (item.fileName === 'requirements.txt') parsedComps = parseRequirementsTxt(txt);
      else if (item.fileName === 'pyproject.toml') parsedComps = parsePyprojectToml(txt);
      else if (item.fileName === 'composer.json') parsedComps = parseComposerJson(txt);
      else if (item.fileName === 'mix.exs') parsedComps = parseMixExs(txt);
      if (parsedComps.length > 0) {
        nestedCount += 1;
        components = mergeComponents(components, parsedComps);
      }
    }
    if (nestedCount > 0 && !manifests.some((m) => m.startsWith('workspace-manifests'))) {
      manifests.push(`workspace-manifests(${nestedCount})`);
    }
  }

  const securityCandidates = [
    path.join(absDir, 'SECURITY.md'),
    path.join(absDir, '.github', 'SECURITY.md'),
    path.join(absDir, 'docs', 'SECURITY.md'),
  ];
  let securityMdPath = null;
  let securityMdText = null;
  for (const p of securityCandidates) {
    const txt = safeReadText(p);
    if (txt) {
      securityMdPath = path.relative(absDir, p);
      securityMdText = txt;
      break;
    }
  }

  const licenseFile = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING'].find((f) =>
    fs.existsSync(path.join(absDir, f)),
  );
  const craConfigText = safeReadText(path.join(absDir, 'cra.json'));
  let craConfig = null;
  if (craConfigText) {
    try {
      craConfig = JSON.parse(craConfigText);
    } catch {
      craConfig = null;
    }
  }

  const workflowsDir = path.join(absDir, '.github', 'workflows');
  let workflowFiles = [];
  try {
    if (fs.existsSync(workflowsDir) && fs.statSync(workflowsDir).isDirectory()) {
      workflowFiles = fs.readdirSync(workflowsDir).filter((f) => /\.ya?ml$/i.test(f));
    }
  } catch {
    workflowFiles = [];
  }

  const hasAutomatedSecurityCi =
    fs.existsSync(path.join(absDir, '.github', 'dependabot.yml')) ||
    fs.existsSync(path.join(absDir, '.github', 'dependabot.yaml')) ||
    fs.existsSync(path.join(absDir, 'renovate.json')) ||
    workflowFiles.some((f) => /security|codeql|sbom|trivy|audit|snyk|cra/i.test(f));

  const securityEmailMatch = securityMdText?.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
  const hasSlaMention = Boolean(
    securityMdText && /\b(\d+\s*(hours?|days?|business days?)|sla|response time|acknowledge)\b/i.test(securityMdText),
  );
  const hasSupportPeriodMention = Boolean(
    craConfig?.supportYears ||
      (securityMdText && /\b(supported versions|support period|end[- ]of[- ]life|eol|\d+\s+years?)\b/i.test(securityMdText)),
  );

  const hasDockerfile =
    fs.existsSync(path.join(absDir, 'Dockerfile')) ||
    fs.existsSync(path.join(absDir, 'docker-compose.yml')) ||
    fs.existsSync(path.join(absDir, 'docker-compose.yaml'));

  const productName = overrides.productName || pkgMeta.name || path.basename(absDir);
  const productVersion = overrides.productVersion || pkgMeta.version || '0.1.0';
  const supportYears = Number(overrides.supportYears || craConfig?.supportYears || 5);

  return {
    meta: {
      productName,
      productVersion,
      license: pkgMeta.license || (licenseFile ? `Declared (${licenseFile})` : null),
      hasLicenseFile: Boolean(licenseFile || pkgMeta.license),
      hasDockerfile,
      hasCliOrBinary: Boolean(pkgMeta.hasBin),
      manifests,
      lockfiles,
      hasLockfile: lockfiles.length > 0,
      hasSecurityMd: Boolean(securityMdText),
      securityMdPath,
      securityEmail: securityEmailMatch ? securityEmailMatch[0] : null,
      hasSlaMention,
      hasSupportPeriodMention,
      supportYears,
      hasCiWorkflows: workflowFiles.length > 0,
      workflowCount: workflowFiles.length,
      hasAutomatedSecurityCi,
      hasCraConfig: Boolean(craConfig),
    },
    components,
  };
}
