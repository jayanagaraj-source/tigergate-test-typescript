// SCA reachability fixture: calls the specific vulnerable functions of pinned dependencies.
// Packages listed in expected-packages.ts with `reachable: false` are declared but never imported,
// so a reachability-aware scanner should rank them below the ones exercised here.
import type { Request, Response } from 'express';
import * as _ from 'lodash';
import minimist from 'minimist';
import moment from 'moment';
import { marked } from 'marked';
import * as shell from 'shelljs';
import * as xml2js from 'xml2js';

// lodash < 4.17.21, CVE-2021-23337: command injection through template().
export const renderInvoice = (req: Request, res: Response): void => {
  res.send(_.template(req.body.template)({ total: 42 })); // tg-expect: SCA-REACH-001 CVE-2021-23337
};

// lodash < 4.17.19, CVE-2020-8203: prototype pollution through zipObjectDeep().
export const buildObject = (req: Request, res: Response): void => {
  res.json(_.zipObjectDeep(req.body.paths, req.body.values)); // tg-expect: SCA-REACH-002 CVE-2020-8203
};

// minimist < 1.2.6, CVE-2021-44906: prototype pollution while parsing arguments.
export const parseCliArgs = (argv: string[]): Record<string, unknown> => minimist(argv); // tg-expect: SCA-REACH-003 CVE-2021-44906

// moment < 2.29.2, CVE-2022-24785: path traversal via user-controlled locale.
export const localizedDate = (req: Request, res: Response): void => {
  moment.locale(req.query.lang as string); // tg-expect: SCA-REACH-004 CVE-2022-24785
  res.send(moment().format('LLLL'));
};

// marked 0.3.6, CVE-2017-1000427: XSS through crafted links.
export const renderMarkdown = (req: Request, res: Response): void => {
  res.send(marked(req.body.markdown)); // tg-expect: SCA-REACH-005 CVE-2017-1000427
};

// xml2js < 0.5.0, CVE-2023-0842: prototype pollution while parsing.
export const parseFeed = async (req: Request, res: Response): Promise<void> => {
  res.json(await xml2js.parseStringPromise(req.body.xml)); // tg-expect: SCA-REACH-006 CVE-2023-0842
};

// shelljs < 0.8.5, CVE-2022-0144: improper privilege management in exec().
export const shellStatus = (): string => shell.exec('git status', { silent: true }).stdout; // tg-expect: SCA-REACH-007 CVE-2022-0144
