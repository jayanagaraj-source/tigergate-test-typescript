// Inter-procedural taint fixture: sources live here, sinks live in repository.ts.
// A scanner only passes these cases if it tracks data across files, classes and awaits.
import type { Request, Response } from 'express';
import { ReportService } from './service';

const service = new ReportService();

// Source -> service.normalize (no sanitizing) -> repository SQL sink. Expect a finding.
export const reportByRegion = async (req: Request, res: Response): Promise<void> => {
  res.json(await service.byRegion(req.query.region as string));
};

// Source -> destructured object -> repository command sink. Expect a finding.
export const exportReport = async (req: Request, res: Response): Promise<void> => {
  const { format, ...rest } = req.body;
  res.send(await service.export({ format, owner: rest.owner }));
};

// Source -> broken sanitizer (replaces only the first quote) -> SQL sink. Expect a finding.
export const reportByTitle = async (req: Request, res: Response): Promise<void> => {
  res.json(await service.byTitle(req.query.title as string));
};

// Source -> Number.parseInt -> numeric SQL fragment. Sanitized: must NOT be flagged.
export const reportByYear = async (req: Request, res: Response): Promise<void> => {
  res.json(await service.byYear(req.query.year as string));
};
