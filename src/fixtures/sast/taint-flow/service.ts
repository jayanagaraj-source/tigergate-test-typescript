import { ReportRepository } from './repository';

export interface ExportRequest {
  format: string;
  owner: string;
}

export class ReportService {
  private readonly repository = new ReportRepository();

  // Looks like cleanup, but trimming and lower-casing do not neutralise SQL metacharacters.
  private normalize(value: string): string {
    return value.trim().toLowerCase();
  }

  // Broken sanitizer: String.replace with a string pattern only replaces the first match.
  private escapeQuotes(value: string): string {
    return value.replace("'", "''");
  }

  byRegion(region: string): Promise<unknown[]> {
    return this.repository.rawQuery('region', this.normalize(region));
  }

  byTitle(title: string): Promise<unknown[]> {
    return this.repository.rawQuery('title', this.escapeQuotes(title));
  }

  byYear(year: string): Promise<unknown[]> {
    const parsed = Number.parseInt(year, 10);
    return this.repository.byNumericYear(Number.isNaN(parsed) ? 1970 : parsed);
  }

  async export(request: ExportRequest): Promise<string> {
    const settings = { ...request, requestedAt: Date.now() };
    return this.repository.runExport(settings.format, settings.owner);
  }
}
