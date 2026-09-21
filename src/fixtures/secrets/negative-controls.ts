// Secret-scanning negative controls: values that look sensitive but are not secrets.
// Every `tg-clean` line must produce NO finding; a hit here is a false positive.
export const awsSecretFromEnv = process.env.AWS_SECRET_ACCESS_KEY ?? ''; // tg-clean: NEG-SECRET-001
export const apiKeyPlaceholder = 'YOUR_API_KEY_HERE'; // tg-clean: NEG-SECRET-002
export const maskedPassword = '********'; // tg-clean: NEG-SECRET-003
export const passwordFieldLabel = 'password'; // tg-clean: NEG-SECRET-004
export const requestId = '3f2c9a1e-7b4d-4e8f-9a2c-1d5e7f9b3c6a'; // tg-clean: NEG-SECRET-005
export const commitSha = '7cf67b9e4d2a1c8f5b3e9d7a6c4f2e1b8a9d0c3e'; // tg-clean: NEG-SECRET-006
export const releaseChecksum = 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'; // tg-clean: NEG-SECRET-007
export const passwordPolicy = { minLength: 12, requireSymbol: true }; // tg-clean: NEG-SECRET-008
export const connectionTemplate = 'postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/app'; // tg-clean: NEG-SECRET-009
export const exampleDocsKey = 'sk_test_xxxxxxxxxxxxxxxxxxxxxxxx'; // tg-clean: NEG-SECRET-010
