// Deliberately insecure SAST fixture: web, deserialization and transport issues.
import * as https from 'https';
import type { NextFunction, Request, Response } from 'express';
import axios from 'axios';
import fetch from 'node-fetch';
import * as ejs from 'ejs';
import * as _ from 'lodash';
import * as yaml from 'js-yaml';
import * as serialize from 'node-serialize';
import * as libxmljs from 'libxmljs';

export const greet = (req: Request, res: Response): void => {
  res.send(`<h1>Hello ${req.query.name}</h1>`); // tg-expect: SAST-XSS-001 CWE-79
};

export const afterLogin = (req: Request, res: Response): void => {
  res.redirect(req.query.next as string); // tg-expect: SAST-REDIRECT-001 CWE-601
};

export const preview = async (req: Request, res: Response): Promise<void> => {
  const page = await axios.get(req.query.url as string); // tg-expect: SAST-SSRF-001 CWE-918
  res.send(page.data);
};

export const notify = async (req: Request, res: Response): Promise<void> => {
  await fetch(req.body.webhookUrl, { method: 'POST', body: JSON.stringify(req.body.event) }); // tg-expect: SAST-SSRF-002 CWE-918
  res.sendStatus(202);
};

export const updateSettings = (req: Request, res: Response): void => {
  const settings = _.merge({}, req.body); // tg-expect: SAST-PROTO-001 CWE-1321
  res.json(settings);
};

export const setPath = (req: Request, res: Response): void => {
  const target: Record<string, any> = {};
  const { section, key, value } = req.body;
  target[section] = target[section] || {};
  target[section][key] = value; // tg-expect: SAST-PROTO-002 CWE-1321 advanced
  res.json(target);
};

export const filter = (req: Request, res: Response): void => {
  const matcher = new RegExp(req.query.pattern as string); // tg-expect: SAST-REDOS-001 CWE-1333
  res.json({ match: matcher.test(req.query.text as string) });
};

export const validateSku = (req: Request, res: Response): void => {
  res.json({ valid: /^([a-zA-Z0-9]+)*-sku$/.test(req.query.sku as string) }); // tg-expect: SAST-REDOS-002 CWE-1333 advanced
};

export const renderTemplate = (req: Request, res: Response): void => {
  res.send(ejs.render(req.body.template, { user: req.body.user })); // tg-expect: SAST-SSTI-001 CWE-1336
};

export const createSession = (_req: Request, res: Response): void => {
  res.cookie('session', 'opaque-session-id', { httpOnly: false, secure: false, sameSite: 'none' }); // tg-expect: SAST-COOKIE-001 CWE-614
  res.sendStatus(204);
};

export const cors = (req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*'); // tg-expect: SAST-CORS-001 CWE-942
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
};

export const importXml = (req: Request, res: Response): void => {
  const doc = libxmljs.parseXml(req.body.xml, { noent: true, dtdload: true }); // tg-expect: SAST-XXE-001 CWE-611
  res.send(doc.toString());
};

export const restoreProfile = (req: Request, res: Response): void => {
  const raw = Buffer.from(req.headers['x-profile'] as string, 'base64').toString();
  res.json(serialize.unserialize(raw)); // tg-expect: SAST-DESER-001 CWE-502
};

export const loadConfig = (req: Request, res: Response): void => {
  res.json(yaml.load(req.body.config)); // tg-expect: SAST-DESER-002 CWE-502
};

export const disableTlsGlobally = (): void => {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // tg-expect: SAST-TLS-001 CWE-295
};

export const insecureAgent = new https.Agent({ rejectUnauthorized: false }); // tg-expect: SAST-TLS-002 CWE-295

export const errorHandler = (err: Error, _req: Request, res: Response, _next: NextFunction): void => {
  res.status(500).send(err.stack); // tg-expect: SAST-INFOLEAK-001 CWE-209
};
