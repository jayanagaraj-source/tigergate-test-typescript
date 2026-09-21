// Deliberately leaked FAKE credentials for secret-scanner validation.
// None of these are valid; they only match each provider's token format.
export const awsAccessKeyId = 'AKIA2E0A8F3B4C5D6E7F'; // tg-expect: SECRET-AWS-001 aws-access-key-id
export const awsSecretAccessKey = 'q8Vd3Lm2Rt7Yx1Bn5Kp9Zs4Hc6Wf0Ja2Ue8Gi3Mo'; // tg-expect: SECRET-AWS-002 aws-secret-access-key

export const githubToken = 'ghp_R7kQ2mX9vB4nL8pT3wZ6yC1dF5hJ0sG2aK7e'; // tg-expect: SECRET-GITHUB-001 github-pat
export const npmToken = 'npm_Kx8Pq2Lm7Vn4Rt9Yb3Zc6Hd1Wf5Js0Ga8Ue2'; // tg-expect: SECRET-NPM-001 npm-access-token

export const slackBotToken = 'xoxb-482915730264-5028371946152-Qm7Rt2Yx9Bn4Kp1Zs6Hc3Wf8'; // tg-expect: SECRET-SLACK-001 slack-bot-token
export const slackWebhook = 'https://hooks.slack.com/services/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'; // tg-expect: SECRET-SLACK-002 slack-webhook-url

export const stripeSecretKey = 'sk_live_51Hq8ZkT3vN7mR2xP9wL4bYc'; // tg-expect: SECRET-STRIPE-001 stripe-secret-key
export const googleApiKey = 'AIzaSyD4f8K2mQ9xR7vT3nL6pW1bZ5cH0jE8gUs'; // tg-expect: SECRET-GCP-001 gcp-api-key
export const sendgridApiKey = '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'; // tg-expect: SECRET-SENDGRID-001 sendgrid-api-key
export const twilioAuth = { accountSid: 'AC7d3f9a1c5e2b8046d9a3c7e1b5f2d804', authToken: 'f3a9c1e7b5d2084619ae3c7b1d5f9024' }; // tg-expect: SECRET-TWILIO-001 twilio-credentials
export const openAiApiKey = 'sk-proj-K6q6PxaW3w5CIZEo4C6aR9oCiqMi4O6sA4TckYtOfhWXkKeJ'; // tg-expect: SECRET-OPENAI-001 openai-api-key

export const azureStorageConnection =
  'DefaultEndpointsProtocol=https;AccountName=tigergatefixture;AccountKey=CNQc43jxsLDkbTIRiFATzKcijmxSvsMyeoKoQeFTiaqSBuDpQG0iyG9irFWqvE6MbyEqbxV85mK56xbXnpJxCA==;EndpointSuffix=core.windows.net'; // tg-expect: SECRET-AZURE-001 azure-storage-key

export const postgresUrl = 'postgres://billing_admin:Vq7!mZ2#rT9xLp4@billing-db.internal:5432/billing'; // tg-expect: SECRET-DBURL-001 connection-string-password
export const mongoUrl = 'mongodb+srv://root:Hk9$wQ3vN7pX2zR@cluster0.x7k2p.mongodb.net/prod?retryWrites=true'; // tg-expect: SECRET-DBURL-002 connection-string-password

export const serviceJwt =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZyIsInJvbGUiOiJhZG1pbiJ9.xe_3fq5AHoht3bY10nSmNXIyU8_tWMQvYBpD_apelKg'; // tg-expect: SECRET-JWT-001 jwt

// tg-expect-next: SECRET-PEM-001 private-key
export const deployKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA06T8GtIp2eQ07tOm0U0x7pH/fVIHnvcXdzdfMx/6EMeq1VnJ
bKPahwUejUZFoLOKMdA6lCybj3rrVFStNaxU2ug+PGmDL3xnWrC0C6HUyHtv1hZ0
SaY4mRRuqRE2asCC7+u9EXc3dp5yIjGnAEtllFr+MlE6IXEXJhWbhzY6E9NJzSBH
R3igpcQrfI8i3FoS5a96QhhYW3WKmaKZ5NILd0oJkWb09TYAXuXJt+a2F3zaTgT3
-----END RSA PRIVATE KEY-----`;

export const databaseConfig = {
  host: 'orders-db.internal',
  user: 'orders_rw',
  password: 'Xk9#mP2$vL7@qR4!zT8w', // tg-expect: SECRET-GENERIC-001 hardcoded-password
};

export const basicAuthHeader = { Authorization: 'Basic c3ZjLWRlcGxveTpQcjBkLURlcGwweSEyMDI2' }; // tg-expect: SECRET-BASIC-001 basic-auth-credentials
