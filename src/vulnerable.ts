// Intentional security-test fixture.
export const unsafeQuery = (input: string): string => `SELECT * FROM users WHERE name = '${input}'`;
