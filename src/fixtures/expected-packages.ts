// Ground truth for SCA and SBOM checks. Direct versions must match package.json exactly;
// transitive versions must match package-lock.json (they are pinned exactly by their parents).
export type DependencyScope = 'prod' | 'dev';

export interface ExpectedPackage {
  name: string;
  version: string;
  scope: DependencyScope;
  // True when src/fixtures actually calls the vulnerable code path.
  reachable: boolean;
  // Advisories an SCA scanner is expected to report. Empty = clean control package.
  advisories: string[];
  // SPDX licence id the SBOM should carry.
  license: string;
  // Parent package for transitive dependencies; absent for direct ones.
  via?: string;
  // Shipped inside the parent's tarball (bundleDependencies) rather than resolved from the registry.
  bundled?: boolean;
  // Licence only declared through the deprecated `licenses: [...]` array, which lockfiles do not record.
  legacyLicenseField?: boolean;
}

export const EXPECTED_PACKAGES: ExpectedPackage[] = [
  { name: 'lodash', version: '4.17.15', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2020-8203', 'CVE-2021-23337', 'CVE-2020-28500'] },
  { name: 'minimist', version: '1.2.5', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2021-44906'] },
  { name: 'moment', version: '2.29.1', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2022-24785', 'CVE-2022-31129'] },
  { name: 'marked', version: '0.3.6', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2017-1000427', 'CVE-2022-21680', 'CVE-2022-21681'] },
  { name: 'xml2js', version: '0.4.23', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2023-0842'] },
  { name: 'shelljs', version: '0.8.4', scope: 'prod', reachable: true, license: 'BSD-3-Clause', advisories: ['CVE-2022-0144'] },
  { name: 'axios', version: '0.21.1', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2021-3749', 'CVE-2023-45857'] },
  { name: 'node-fetch', version: '2.6.0', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2020-15168', 'CVE-2022-0235'] },
  { name: 'jsonwebtoken', version: '8.5.1', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2022-23529', 'CVE-2022-23539', 'CVE-2022-23540', 'CVE-2022-23541'] },
  { name: 'node-serialize', version: '0.0.4', scope: 'prod', reachable: true, license: 'MIT', legacyLicenseField: true, advisories: ['CVE-2017-5941'] },
  { name: 'js-yaml', version: '3.12.0', scope: 'prod', reachable: true, license: 'MIT', advisories: ['GHSA-8j8c-7jfh-h6hx', 'GHSA-2pr6-76vf-7546'] },
  { name: 'ejs', version: '3.1.6', scope: 'prod', reachable: true, license: 'Apache-2.0', advisories: ['CVE-2022-29078', 'CVE-2024-33883'] },
  { name: 'express', version: '4.17.1', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2024-29041', 'CVE-2024-43796'] },
  { name: 'mongodb', version: '3.6.0', scope: 'prod', reachable: true, license: 'Apache-2.0', advisories: ['CVE-2021-32050'] },
  { name: 'libxmljs', version: '0.19.7', scope: 'prod', reachable: true, license: 'MIT', advisories: ['CVE-2024-34391', 'CVE-2024-34392'] },
  { name: 'aws-cdk-lib', version: '2.79.0', scope: 'prod', reachable: false, license: 'Apache-2.0', advisories: ['CVE-2023-35165'] },
  // Declared but never imported: vulnerable yet unreachable.
  { name: 'handlebars', version: '4.5.1', scope: 'prod', reachable: false, license: 'MIT', advisories: ['CVE-2021-23369', 'CVE-2021-23383'] },
  // Vulnerable dev-only dependency: checks dev/prod scope classification.
  { name: 'jquery', version: '3.4.1', scope: 'dev', reachable: false, license: 'MIT', advisories: ['CVE-2020-11022', 'CVE-2020-11023'] },

  // Transitive: pinned exactly by express@4.17.1, so they stay vulnerable. Only visible with a lockfile.
  { name: 'qs', version: '6.7.0', scope: 'prod', reachable: true, license: 'BSD-3-Clause', via: 'express', advisories: ['CVE-2022-24999'] },
  { name: 'body-parser', version: '1.19.0', scope: 'prod', reachable: true, license: 'MIT', via: 'express', advisories: ['CVE-2024-45590'] },
  { name: 'path-to-regexp', version: '0.1.7', scope: 'prod', reachable: true, license: 'MIT', via: 'express', advisories: ['CVE-2024-45296', 'CVE-2024-52798'] },
  { name: 'cookie', version: '0.4.0', scope: 'prod', reachable: true, license: 'MIT', via: 'express', advisories: ['CVE-2024-47764'] },
  { name: 'send', version: '0.17.1', scope: 'prod', reachable: true, license: 'MIT', via: 'express', advisories: ['CVE-2024-43799'] },
  { name: 'serve-static', version: '1.14.1', scope: 'prod', reachable: true, license: 'MIT', via: 'express', advisories: ['CVE-2024-43800'] },
  // Bundled inside the cdk8s tarball; a second, patched follow-redirects@1.16.0 is also in the tree.
  { name: 'follow-redirects', version: '1.15.2', scope: 'prod', reachable: false, license: 'MIT', via: 'cdk8s', bundled: true, advisories: ['CVE-2023-26159', 'CVE-2024-28849'] },
  // Transitive licence edge case: MIT only via the legacy `licenses` array.
  { name: 'rechoir', version: '0.6.2', scope: 'prod', reachable: false, license: 'MIT', via: 'shelljs', legacyLicenseField: true, advisories: [] },

  // Clean control packages: must appear in the SBOM but carry no advisories.
  { name: 'mysql', version: '2.18.1', scope: 'prod', reachable: true, license: 'MIT', advisories: [] },
  { name: 'constructs', version: '10.2.0', scope: 'prod', reachable: true, license: 'Apache-2.0', advisories: [] },
  { name: 'cdk8s', version: '2.30.0', scope: 'prod', reachable: true, license: 'Apache-2.0', advisories: [] },
];
