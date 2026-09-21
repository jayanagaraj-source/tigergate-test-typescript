// Deliberately insecure SAST fixture: injection sinks fed directly by HTTP input.
// Each vulnerable sink carries a `tg-expect` marker read by src/verify/verify-scan.mts.
import { exec, execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vm from 'vm';
import type { Request, Response } from 'express';
import * as mysql from 'mysql';
import { MongoClient } from 'mongodb';

const db = mysql.createConnection({ host: 'localhost', user: 'app', database: 'shop' });
const mongo = new MongoClient('mongodb://localhost:27017');

export const findAccount = (req: Request, res: Response): void => {
  const id = req.query.id as string;
  db.query(`SELECT * FROM accounts WHERE id = '${id}'`, (_err, rows) => res.json(rows)); // tg-expect: SAST-SQLI-001 CWE-89
};

export const findOrders = (req: Request, res: Response): void => {
  const sql = 'SELECT * FROM orders WHERE customer = "' + req.body.customer + '" ORDER BY ' + req.body.sort;
  db.query(sql, (_err, rows) => res.json(rows)); // tg-expect: SAST-SQLI-002 CWE-89
};

export const searchUsers = async (req: Request, res: Response): Promise<void> => {
  const users = mongo.db('app').collection('users');
  const byWhere = await users.find({ $where: `this.name == '${req.query.name}'` }).toArray(); // tg-expect: SAST-NOSQLI-001 CWE-943
  const byLogin = await users.findOne({ username: req.body.username, password: req.body.password }); // tg-expect: SAST-NOSQLI-002 CWE-943
  res.json({ byWhere, byLogin });
};

export const ping = (req: Request, res: Response): void => {
  exec(`ping -c 1 ${req.query.host}`, (_err, stdout) => res.send(stdout)); // tg-expect: SAST-CMDI-001 CWE-78
};

export const backup = (req: Request, res: Response): void => {
  const out = execSync('tar -czf /tmp/backup.tgz ' + req.body.dir); // tg-expect: SAST-CMDI-002 CWE-78
  res.send(out.toString());
};

export const runTool = (req: Request, res: Response): void => {
  const child = spawn('sh', ['-c', req.query.cmd as string]); // tg-expect: SAST-CMDI-003 CWE-78
  child.stdout.pipe(res);
};

export const calculate = (req: Request, res: Response): void => {
  res.json({ result: eval(req.body.expression) }); // tg-expect: SAST-CODEI-001 CWE-95
};

export const compileRule = (req: Request, res: Response): void => {
  const rule = new Function('input', req.body.ruleSource); // tg-expect: SAST-CODEI-002 CWE-95
  res.json({ allowed: rule(req.body.input) });
};

export const sandbox = (req: Request, res: Response): void => {
  res.json({ value: vm.runInNewContext(req.query.script as string, {}) }); // tg-expect: SAST-CODEI-003 CWE-95
};

export const download = (req: Request, res: Response): void => {
  const data = fs.readFileSync(path.join('/var/app/uploads', req.query.file as string)); // tg-expect: SAST-PATH-001 CWE-22
  res.send(data);
};

export const upload = (req: Request, res: Response): void => {
  req.pipe(fs.createWriteStream(`/var/app/uploads/${req.body.filename}`)); // tg-expect: SAST-PATH-002 CWE-22
  res.sendStatus(201);
};
