import { execSync } from 'child_process';
import * as mysql from 'mysql';

const pool = mysql.createPool({ host: 'localhost', user: 'reports', database: 'analytics' });

const run = (sql: string): Promise<unknown[]> =>
  new Promise((resolve, reject) => pool.query(sql, (err, rows) => (err ? reject(err) : resolve(rows))));

export class ReportRepository {
  // Reached from reportByRegion (normalize) and reportByTitle (broken escapeQuotes).
  rawQuery(column: string, value: string): Promise<unknown[]> {
    return run(`SELECT * FROM reports WHERE ${column} = '${value}'`); // tg-expect: SAST-TAINT-001 CWE-89 advanced
  }

  byNumericYear(year: number): Promise<unknown[]> {
    return run(`SELECT * FROM reports WHERE year = ${year}`); // tg-clean: NEG-SAST-TAINT-001
  }

  async runExport(format: string, owner: string): Promise<string> {
    return execSync(`report-cli export --format ${format} --owner ${owner}`).toString(); // tg-expect: SAST-TAINT-002 CWE-78 advanced
  }
}
