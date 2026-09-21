import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { login } from './app.ts';

const isTTY = Boolean(process.stdin.isTTY);
let muted = false;

// Swallows the echo while a password is being typed.
const output = new Writable({
  write(chunk, _encoding, callback) {
    if (!muted) process.stdout.write(chunk);
    callback();
  },
});

const rl = createInterface({ input: process.stdin, output, terminal: isTTY });

// Buffer lines as they arrive: on piped input the stream can end while we are
// still awaiting an earlier answer, which would drop any unread lines.
const pending: string[] = [];
const waiting: Array<(line: string | null) => void> = [];
let closed = false;

rl.on('line', (line) => {
  const next = waiting.shift();
  if (next) next(line);
  else pending.push(line);
});

rl.on('close', () => {
  closed = true;
  while (waiting.length) waiting.shift()!(null);
});

const nextLine = (): Promise<string | null> =>
  new Promise((resolve) => {
    if (pending.length) return resolve(pending.shift()!);
    if (closed) return resolve(null);
    waiting.push(resolve);
  });

const ask = async (query: string, secret = false): Promise<string> => {
  process.stdout.write(query);
  muted = secret && isTTY;
  const line = await nextLine();
  muted = false;
  if (secret) process.stdout.write('\n');
  if (line === null) throw new Error('input closed');
  return line.trim();
};

const main = async (): Promise<void> => {
  const username = await ask('Username: ');
  const password = await ask('Password: ', true);
  rl.close();

  const ok = login(username, password);
  process.stdout.write(ok ? 'Login successful\n' : 'Invalid username or password\n');
  process.exitCode = ok ? 0 : 1;
};

main().catch((err: Error) => {
  process.stdout.write(`\nAborted: ${err.message}\n`);
  process.exitCode = 1;
});
