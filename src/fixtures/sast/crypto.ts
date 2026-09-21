// Deliberately insecure SAST fixture: weak cryptography, randomness and token handling.
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import type { Request, Response } from 'express';

export const hashPasswordMd5 = (password: string): string =>
  crypto.createHash('md5').update(password).digest('hex'); // tg-expect: SAST-CRYPTO-001 CWE-328

export const hashPasswordSha1 = (password: string): string =>
  crypto.createHash('sha1').update(password).digest('hex'); // tg-expect: SAST-CRYPTO-002 CWE-328

export const encryptLegacy = (key: Buffer, plaintext: string): Buffer => {
  const cipher = crypto.createCipheriv('des-ecb', key, null); // tg-expect: SAST-CRYPTO-003 CWE-327
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
};

export const encryptStaticIv = (key: Buffer, plaintext: string): Buffer => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0)); // tg-expect: SAST-CRYPTO-004 CWE-329
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
};

export const deriveKey = (password: string): Buffer =>
  crypto.pbkdf2Sync(password, 'static-salt', 1, 32, 'sha256'); // tg-expect: SAST-CRYPTO-005 CWE-916

export const weakRsaKeys = () => crypto.generateKeyPairSync('rsa', { modulusLength: 512 }); // tg-expect: SAST-CRYPTO-006 CWE-326

export const resetToken = (): string => Math.random().toString(36).slice(2); // tg-expect: SAST-RAND-001 CWE-338

export const verifyAnyAlgorithm = (token: string): unknown =>
  jwt.verify(token, 'shared-secret', { algorithms: ['none', 'HS256'] }); // tg-expect: SAST-JWT-001 CWE-347

export const currentUser = (req: Request, res: Response): void => {
  const claims = jwt.decode(req.headers.authorization as string) as { role?: string } | null; // tg-expect: SAST-JWT-002 CWE-345
  res.json({ admin: claims?.role === 'admin' });
};

export const issueToken = (userId: string): string =>
  jwt.sign({ sub: userId }, 'tigergate-jwt-signing-secret', { expiresIn: '365d' }); // tg-expect: SAST-JWT-003 CWE-798

export const verifyWebhook = (body: string, signature: string, secret: string): boolean => {
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return expected === signature; // tg-expect: SAST-TIMING-001 CWE-208 advanced
};
