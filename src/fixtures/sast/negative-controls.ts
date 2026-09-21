// SAST negative controls: safe code that resembles the vulnerable fixtures.
// Every `tg-clean` line must produce NO finding; a hit here is a false positive.
import { execFile } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { Request, Response } from 'express';
import * as mysql from 'mysql';

const db = mysql.createConnection({ host: 'localhost', user: 'app', database: 'shop' });
const UPLOAD_ROOT = path.resolve('/var/app/uploads');
const ALLOWED_HOSTS = new Set(['status.internal', 'db.internal']);
const ALLOWED_REDIRECTS = new Set(['/dashboard', '/settings']);

export const findAccountSafe = (req: Request, res: Response): void => {
  db.query('SELECT * FROM accounts WHERE id = ?', [req.query.id], (_err, rows) => res.json(rows)); // tg-clean: NEG-SAST-001
};

export const pingSafe = (req: Request, res: Response): void => {
  const host = String(req.query.host);
  if (!ALLOWED_HOSTS.has(host)) return void res.sendStatus(400);
  execFile('/usr/bin/ping', ['-c', '1', host], (_err, stdout) => res.send(stdout)); // tg-clean: NEG-SAST-002
};

export const downloadSafe = (req: Request, res: Response): void => {
  const target = path.resolve(UPLOAD_ROOT, path.basename(String(req.query.file)));
  if (!target.startsWith(UPLOAD_ROOT + path.sep)) return void res.sendStatus(400);
  res.send(fs.readFileSync(target)); // tg-clean: NEG-SAST-003
};

export const resetTokenSafe = (): string => crypto.randomBytes(32).toString('hex'); // tg-clean: NEG-SAST-004

export const fileChecksum = (contents: Buffer): string => crypto.createHash('sha256').update(contents).digest('hex'); // tg-clean: NEG-SAST-005

export const afterLoginSafe = (req: Request, res: Response): void => {
  const next = String(req.query.next);
  res.redirect(ALLOWED_REDIRECTS.has(next) ? next : '/dashboard'); // tg-clean: NEG-SAST-006
};

export const describeRule = (): string => 'Never call eval(userInput) or new Function(body) on request data'; // tg-clean: NEG-SAST-007

export const greetSafe = (req: Request, res: Response): void => {
  res.json({ message: `Hello ${req.query.name}` }); // tg-clean: NEG-SAST-008
};

export const verifyWebhookSafe = (body: string, signature: string, secret: string): boolean => {
  const expected = Buffer.from(crypto.createHmac('sha256', secret).update(body).digest('hex'));
  const given = Buffer.from(signature);
  return expected.length === given.length && crypto.timingSafeEqual(expected, given); // tg-clean: NEG-SAST-009
};

export const encryptSafe = (key: Buffer, plaintext: string): Buffer => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); // tg-clean: NEG-SAST-010
  return Buffer.concat([iv, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
};
