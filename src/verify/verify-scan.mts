// Scores scanner output against the ground truth planted in src/fixtures.
//
//   npm run verify -- --sarif sast.sarif --sarif secrets.sarif --sarif iac.sarif --sarif sca.sarif --sbom bom.json
//   npm run verify -- --list
//
// Code findings come from line markers in src/fixtures:
//   // tg-expect: <ID> <rule> [advanced]   the scanner must report this line
//   // tg-expect-next: <ID> <rule>          same, for the following line
//   // tg-clean: <ID>                       the scanner must NOT report this line
// Package findings come from src/fixtures/expected-packages.ts.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { EXPECTED_PACKAGES, type ExpectedPackage } from '../fixtures/expected-packages.ts';

type Category = 'sast' | 'secrets' | 'iac' | 'sca';

interface Marker {
  id: string;
  kind: 'expect' | 'clean';
  category: Category;
  rule: string;
  advanced: boolean;
  file: string;
  line: number;
  // First line of the enclosing IaC construct; IaC scanners often report the resource, not the property.
  anchor: number;
}

interface ScanResult {
  tool: string;
  ruleId: string;
  file: string;
  startLine: number;
  endLine: number;
  haystack: string;
}

interface Options {
  sarif: string[];
  sbom?: string;
  tolerance: number;
  json: boolean;
  list: boolean;
  noFail: boolean;
}

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const FIXTURES = path.join(ROOT, 'src', 'fixtures');
const MARKER = /\/\/\s*tg-(expect-next|expect|clean):\s*([A-Z0-9-]+)(?:\s+(\S+))?(?:\s+(advanced))?/;
const CONSTRUCT_START = /new\s+[\w.]+\(\s*this\b|\.add\w+\(/;
const IAC_NEGATIVE_SPAN = 6;

const CATEGORY_BY_PREFIX: Record<string, Category> = { SAST: 'sast', SECRET: 'secrets', IAC: 'iac', SCA: 'sca' };

const parseArgs = (argv: string[]): Options => {
  const opts: Options = { sarif: [], tolerance: 2, json: false, list: false, noFail: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--sarif') opts.sarif.push(argv[++i]);
    else if (arg === '--sbom') opts.sbom = argv[++i];
    else if (arg === '--tolerance') opts.tolerance = Number(argv[++i]);
    else if (arg === '--json') opts.json = true;
    else if (arg === '--list') opts.list = true;
    else if (arg === '--no-fail') opts.noFail = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.list && opts.sarif.length === 0 && !opts.sbom) throw new Error('Pass at least one --sarif or --sbom, or use --list');
  return opts;
};

const walk = (dir: string): string[] =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    return /\.m?ts$/.test(entry.name) ? [full] : [];
  });

const categoryOf = (id: string): Category => {
  const prefix = id.replace(/^NEG-/, '').split('-')[0];
  const category = CATEGORY_BY_PREFIX[prefix];
  if (!category) throw new Error(`Marker ${id} has an unknown category prefix`);
  return category;
};

const collectMarkers = (): Marker[] => {
  const markers: Marker[] = [];
  for (const file of walk(FIXTURES)) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const relative = path.relative(ROOT, file).split(path.sep).join('/');
    let anchor = 1;
    lines.forEach((text, index) => {
      if (CONSTRUCT_START.test(text)) anchor = index + 1;
      const match = MARKER.exec(text);
      if (!match) return;
      const [, kind, id, rule = '', advanced] = match;
      const line = kind === 'expect-next' ? index + 2 : index + 1;
      const category = categoryOf(id);
      markers.push({
        id,
        kind: kind === 'clean' ? 'clean' : 'expect',
        category,
        rule,
        // Reachability needs call-graph analysis, so it is never a baseline requirement.
        advanced: Boolean(advanced) || category === 'sca',
        file: relative,
        line,
        anchor: kind === 'expect-next' ? line : anchor,
      });
    });
  }
  const seen = new Set<string>();
  for (const marker of markers) {
    if (seen.has(marker.id)) throw new Error(`Duplicate marker id ${marker.id} in ${marker.file}:${marker.line}`);
    seen.add(marker.id);
  }
  return markers;
};

const normalizeUri = (uri: string): string => {
  let value = decodeURIComponent(uri).replace(/^file:\/\//, '');
  if (path.isAbsolute(value)) value = path.relative(ROOT, value);
  return value.split(path.sep).join('/').replace(/^\.\//, '');
};

const loadSarif = (file: string): ScanResult[] => {
  const log = JSON.parse(fs.readFileSync(file, 'utf8'));
  const results: ScanResult[] = [];
  for (const run of log.runs ?? []) {
    const tool = run.tool?.driver?.name ?? path.basename(file);
    const rules = new Map<string, unknown>((run.tool?.driver?.rules ?? []).map((rule: { id: string }) => [rule.id, rule]));
    for (const result of run.results ?? []) {
      const ruleId = result.ruleId ?? result.rule?.id ?? '';
      const haystack = JSON.stringify([ruleId, result.message, result.properties, rules.get(ruleId)]).toLowerCase();
      const locations = result.locations?.length ? result.locations : [{}];
      for (const location of locations) {
        const physical = location.physicalLocation ?? {};
        const startLine = physical.region?.startLine ?? 0;
        results.push({
          tool,
          ruleId,
          file: normalizeUri(physical.artifactLocation?.uri ?? ''),
          startLine,
          endLine: physical.region?.endLine ?? startLine,
          haystack,
        });
      }
    }
  }
  return results;
};

const sameFile = (result: ScanResult, marker: Marker): boolean =>
  result.file === marker.file || result.file.endsWith(`/${marker.file}`) || marker.file.endsWith(`/${result.file}`);

const covers = (result: ScanResult, line: number): boolean => result.startLine <= line && result.endLine >= line;

// A result that lands exactly on one marker must not also count, via tolerance, for its neighbours.
const hitsMarker = (result: ScanResult, marker: Marker, tolerance: number, markers: Marker[]): boolean => {
  if (!sameFile(result, marker) || result.startLine === 0) return false;
  if (marker.kind === 'clean') {
    const last = marker.category === 'iac' ? marker.line + IAC_NEGATIVE_SPAN : marker.line;
    return result.startLine >= marker.line && result.startLine <= last;
  }
  if (covers(result, marker.line)) return true;
  if (markers.some((other) => other !== marker && sameFile(result, other) && covers(result, other.line))) return false;
  // IaC scanners commonly report the resource declaration rather than the offending property.
  if (marker.category === 'iac' && Math.abs(result.startLine - marker.anchor) <= tolerance) return true;
  return result.startLine <= marker.line + tolerance && result.endLine >= marker.line - tolerance;
};

const MANIFEST_FILE = /(^|\/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$/;

interface CategoryScore {
  expected: number;
  detected: number;
  baselineMissed: Marker[];
  advancedMissed: Marker[];
  controls: number;
  falsePositives: Array<{ marker: Marker; results: ScanResult[] }>;
}

const scoreCode = (markers: Marker[], results: ScanResult[], tolerance: number) => {
  const scores = {} as Record<Category, CategoryScore>;
  const matched = new Set<ScanResult>();
  for (const marker of markers) {
    const score = (scores[marker.category] ??= { expected: 0, detected: 0, baselineMissed: [], advancedMissed: [], controls: 0, falsePositives: [] });
    const hits = results.filter((result) => hitsMarker(result, marker, tolerance, markers));
    hits.forEach((hit) => matched.add(hit));
    if (marker.kind === 'clean') {
      score.controls++;
      if (hits.length) score.falsePositives.push({ marker, results: hits });
      continue;
    }
    score.expected++;
    if (hits.length) score.detected++;
    else (marker.advanced ? score.advancedMissed : score.baselineMissed).push(marker);
  }
  const unmapped = results.filter((result) => !matched.has(result) && !MANIFEST_FILE.test(result.file));
  return { scores, unmapped };
};

interface PackageScore {
  pkg: ExpectedPackage;
  advisoriesFound: string[];
  advisoriesMissed: string[];
  cleanPackageFlagged: boolean;
}

const scoreSca = (results: ScanResult[]): PackageScore[] =>
  EXPECTED_PACKAGES.map((pkg) => {
    const found = pkg.advisories.filter((advisory) => results.some((r) => r.haystack.includes(advisory.toLowerCase())));
    const manifestHit = results.some((r) => MANIFEST_FILE.test(r.file) && r.haystack.includes(`"${pkg.name}`));
    return {
      pkg,
      advisoriesFound: found,
      advisoriesMissed: pkg.advisories.filter((advisory) => !found.includes(advisory)),
      cleanPackageFlagged: pkg.advisories.length === 0 && manifestHit,
    };
  });

interface SbomComponent {
  name: string;
  version: string;
  dev: boolean | undefined;
  // SPDX ids or expressions; empty when the SBOM records no licence.
  licenses: string[];
}

const NO_LICENSE = new Set(['', 'NOASSERTION', 'NONE', 'UNKNOWN', 'UNLICENSED']);

const cyclonedxLicenses = (entries: any[] = []): string[] =>
  entries.map((entry) => entry.expression ?? entry.license?.id ?? entry.license?.name ?? '').filter((id: string) => !NO_LICENSE.has(id));

const loadSbom = (file: string): { format: string; components: SbomComponent[] } => {
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (doc.bomFormat === 'CycloneDX') {
    const components: SbomComponent[] = [];
    const visit = (list: any[] = []) =>
      list.forEach((c) => {
        const devProperty = (c.properties ?? []).find((p: { name: string }) => p.name === 'cdx:npm:package:development');
        components.push({
          name: c.group ? `${c.group}/${c.name}` : c.name,
          version: c.version,
          dev: devProperty ? devProperty.value === 'true' : c.scope ? c.scope !== 'required' : undefined,
          licenses: cyclonedxLicenses(c.licenses),
        });
        visit(c.components);
      });
    visit(doc.components);
    return { format: `CycloneDX ${doc.specVersion ?? ''}`.trim(), components };
  }
  if (typeof doc.spdxVersion === 'string') {
    const components = (doc.packages ?? []).map((p: { name: string; versionInfo: string; licenseDeclared?: string; licenseConcluded?: string }) => ({
      name: p.name,
      version: p.versionInfo,
      dev: undefined,
      licenses: [p.licenseDeclared, p.licenseConcluded].filter((id): id is string => !NO_LICENSE.has(id ?? '')),
    }));
    return { format: doc.spdxVersion, components };
  }
  throw new Error(`${file} is neither CycloneDX JSON nor SPDX JSON`);
};

const scoreSbom = (file: string) => {
  const { format, components } = loadSbom(file);
  const checks = EXPECTED_PACKAGES.map((pkg) => {
    const byName = components.filter((c) => c.name === pkg.name);
    const exact = byName.find((c) => c.version === pkg.version);
    return {
      pkg,
      present: Boolean(exact),
      wrongVersions: exact ? [] : byName.map((c) => c.version),
      scopeCorrect: exact?.dev === undefined ? null : exact.dev === (pkg.scope === 'dev'),
      // Matches the id alone or inside an expression such as "(MIT OR Apache-2.0)".
      licenseFound: exact?.licenses ?? [],
      licenseCorrect: Boolean(exact?.licenses.some((id) => id.split(/[\s()]+/).includes(pkg.license))),
    };
  });
  const licensed = components.filter((c) => c.licenses.length > 0).length;
  return { format, componentCount: components.length, licensed, checks };
};

const packageLabel = (pkg: ExpectedPackage): string => {
  const origin = pkg.via ? ` (via ${pkg.via}${pkg.bundled ? ', bundled' : ''})` : '';
  return `${pkg.name}@${pkg.version}`.padEnd(22) + origin;
};

const pct = (part: number, whole: number): string => (whole === 0 ? 'n/a' : `${Math.round((part / whole) * 100)}%`);

const main = (): void => {
  const opts = parseArgs(process.argv.slice(2));
  const markers = collectMarkers();

  if (opts.list) {
    for (const m of markers) {
      const tag = m.kind === 'clean' ? 'CLEAN ' : m.advanced ? 'EXPECT*' : 'EXPECT ';
      console.log(`${tag} ${m.id.padEnd(22)} ${`${m.file}:${m.line}`.padEnd(52)} ${m.rule}`);
    }
    for (const p of EXPECTED_PACKAGES) {
      console.log(`PACKAGE ${packageLabel(p).padEnd(42)} ${p.scope.padEnd(4)} ${p.license.padEnd(13)} ${p.advisories.join(', ') || '(clean)'}`);
    }
    console.log('\n* = advanced: reported separately, does not fail the run');
    return;
  }

  const results = opts.sarif.flatMap(loadSarif);
  // Without SARIF there is nothing to score code markers against; an SBOM-only run must not report them as misses.
  const { scores, unmapped } = opts.sarif.length
    ? scoreCode(markers, results, opts.tolerance)
    : { scores: {} as Record<Category, CategoryScore>, unmapped: [] as ScanResult[] };
  const sca = opts.sarif.length ? scoreSca(results) : [];
  const sbom = opts.sbom ? scoreSbom(opts.sbom) : undefined;

  const baselineMisses = Object.values(scores).reduce((n, s) => n + s.baselineMissed.length, 0);
  const falsePositives = Object.values(scores).reduce((n, s) => n + s.falsePositives.length, 0) + sca.filter((s) => s.cleanPackageFlagged).length;
  // An SBOM with no licence data at all is "empty", not "clean", and counts as a single gap.
  const licenseDataEmpty = Boolean(sbom && sbom.componentCount > 0 && sbom.licensed === 0);
  const licenseGaps = licenseDataEmpty ? 1 : (sbom?.checks.filter((c) => c.present && !c.licenseCorrect && !c.pkg.legacyLicenseField).length ?? 0);
  const sbomMissing = (sbom?.checks.filter((c) => !c.present).length ?? 0) + licenseGaps;
  const failed = baselineMisses + falsePositives + sbomMissing > 0;

  if (opts.json) {
    console.log(JSON.stringify({ results: results.length, scores, sca, sbom, unmapped, failed }, null, 2));
  } else {
    if (opts.sarif.length) console.log(`Loaded ${results.length} result location(s) from ${opts.sarif.length} SARIF file(s)\n`);
    for (const category of ['sast', 'secrets', 'iac', 'sca'] as Category[]) {
      const s = scores[category];
      if (!s || results.length === 0) continue;
      const title = category === 'sca' ? 'SCA reachability (call sites)' : category.toUpperCase();
      const fpSummary = s.controls ? `, false positives ${s.falsePositives.length}/${s.controls} controls` : '';
      console.log(`== ${title}: detected ${s.detected}/${s.expected} (${pct(s.detected, s.expected)})${fpSummary}`);
      s.baselineMissed.forEach((m) => console.log(`   MISSED     ${m.id.padEnd(22)} ${m.file}:${m.line}  ${m.rule}`));
      s.advancedMissed.forEach((m) => console.log(`   missed*    ${m.id.padEnd(22)} ${m.file}:${m.line}  ${m.rule}`));
      s.falsePositives.forEach(({ marker, results: hits }) =>
        console.log(`   FALSE POS  ${marker.id.padEnd(22)} ${marker.file}:${marker.line}  <- ${hits.map((h) => `${h.tool}:${h.ruleId}`).join(', ')}`),
      );
    }
    if (sca.length) {
      const total = sca.reduce((n, s) => n + s.pkg.advisories.length, 0);
      const found = sca.reduce((n, s) => n + s.advisoriesFound.length, 0);
      console.log(`== SCA advisories: detected ${found}/${total} (${pct(found, total)})`);
      for (const s of sca) {
        if (s.cleanPackageFlagged) console.log(`   FALSE POS  ${packageLabel(s.pkg)} has no known advisories but was flagged`);
        if (s.advisoriesMissed.length) console.log(`   missed     ${packageLabel(s.pkg).padEnd(42)} ${s.advisoriesMissed.join(', ')}`);
      }
      const transitive = sca.filter((s) => s.pkg.via && s.pkg.advisories.length);
      const transitiveFound = transitive.filter((s) => s.advisoriesFound.length).length;
      console.log(`   transitive packages with at least one advisory reported: ${transitiveFound}/${transitive.length}`);
    }
    if (sbom) {
      const present = sbom.checks.filter((c) => c.present).length;
      console.log(`== SBOM (${sbom.format}, ${sbom.componentCount} components): ${present}/${sbom.checks.length} expected packages at exact version`);
      console.log(`   licences: ${sbom.licensed}/${sbom.componentCount} components carry one${licenseDataEmpty ? '  <- EMPTY licence data, not a clean result' : ''}`);
      for (const c of sbom.checks) {
        const label = packageLabel(c.pkg).padEnd(42);
        if (!c.present) console.log(`   MISSING    ${label} ${c.wrongVersions.length ? `found ${c.wrongVersions.join(', ')}` : 'not listed'}`);
        else {
          if (c.scopeCorrect === false) console.log(`   scope      ${label} expected ${c.pkg.scope}`);
          if (!licenseDataEmpty && !c.licenseCorrect) {
            const tag = c.pkg.legacyLicenseField ? 'licence*  ' : 'LICENCE   ';
            console.log(`   ${tag} ${label} expected ${c.pkg.license}, found ${c.licenseFound.join(', ') || 'none'}`);
          }
        }
      }
    }
    if (unmapped.length) {
      console.log(`\n${unmapped.length} result location(s) did not map to any marker (legacy fixtures, synthesized IaC templates, or noise):`);
      unmapped.slice(0, 15).forEach((r) => console.log(`   ${r.tool}:${r.ruleId}  ${r.file}:${r.startLine}`));
      if (unmapped.length > 15) console.log(`   ... ${unmapped.length - 15} more (use --json)`);
    }
    console.log(`\n${failed ? 'FAIL' : 'PASS'}: ${baselineMisses} baseline miss(es), ${falsePositives} false positive(s), ${sbomMissing} SBOM gap(s). * = advanced, informational`);
  }

  if (failed && !opts.noFail) process.exitCode = 1;
};

main();
