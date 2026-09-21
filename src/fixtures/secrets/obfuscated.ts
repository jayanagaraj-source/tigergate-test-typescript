// Harder secret-detection cases: encoded, split, or indirectly assigned FAKE credentials.
// All are tagged `advanced`, so misses are reported separately from baseline misses.

// Base64 of the fake AWS secret access key used in credentials.ts.
export const encodedAwsSecret = 'cThWZDNMbTJSdDdZeDFCbjVLcDlaczRIYzZXZjBKYTJVZThHaTNNbw=='; // tg-expect: SECRET-ENC-001 base64-encoded-secret advanced

// Hex of the fake GitHub token used in credentials.ts.
export const hexGithubToken = '6768705f52376b51326d58397642346e4c38705433775a36794331644635684a30734732614b3765'; // tg-expect: SECRET-ENC-002 hex-encoded-secret advanced

// Token split across concatenation so no single literal matches the full pattern.
export const splitStripeKey = 'sk_live_' + '51Hq8ZkT3v' + 'N7mR2xP9wL4bYc'; // tg-expect: SECRET-SPLIT-001 concatenated-secret advanced

// High-entropy value whose variable name gives no hint.
export const cfgValue7 = 'Zp4#Lw9!Qm2$Tx7&Rv3*Kb8@'; // tg-expect: SECRET-ENTROPY-001 high-entropy-string advanced

// Credentials embedded in a JSON blob.
export const embeddedJson = '{"client_id":"billing-svc","client_secret":"Tq8vLm3Xp9Rz2Kw7Yb4Nc6Hd"}'; // tg-expect: SECRET-JSON-001 client-secret-in-json advanced

// Credentials in a URL used for an HTTP call.
export const artifactRepo = 'https://deploy-bot:Wm5Rq8Zt2Lx7Vp4K@artifacts.internal.example/npm/'; // tg-expect: SECRET-URL-001 url-embedded-credentials

// Secret assigned through an object key that is not literally named "password".
export const vendorSettings: Record<string, string> = { ['api' + 'Key']: 'Jr6Nw2Qe9Tz4Lk7Xp3Vb8Mc' }; // tg-expect: SECRET-DYNKEY-001 dynamic-key-secret advanced
