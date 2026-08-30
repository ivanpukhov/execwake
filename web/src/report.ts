export interface CoverageReport {
  category: string;
  state: 'complete' | 'partial' | 'unavailable';
  lostEvents: number;
}

export interface ProcessReport {
  processId: number;
  parentProcessId: number | null;
  executable: string;
  startedAtMs: number;
  endedAtMs: number | null;
  exitCode: number | null;
  terminationSignal: number | null;
  evidence: 'observed' | 'inferred' | 'derived';
}

export interface EventReport {
  eventId: number;
  category: string;
  operation: string;
  target: string;
  processId: number | null;
  occurredAtMs: number;
  evidence: 'observed' | 'inferred' | 'derived';
}

export interface SessionReport {
  id: string;
  schemaVersion: number;
  mode: 'observe';
  state: 'running' | 'finalized' | 'interrupted';
  finalized: boolean;
  commandName: string;
  argumentCount: number;
  startedAtMs: number;
  endedAtMs: number | null;
  exitCode: number | null;
  terminationSignal: number | null;
  interruption: string | null;
  coverage: CoverageReport[];
  processes: ProcessReport[];
  events: EventReport[];
}

export async function loadReport(): Promise<SessionReport> {
  const sessionId = window.location.pathname.split('/').filter(Boolean).at(-1);
  if (!sessionId) {
    throw new Error('Session id is missing.');
  }

  const response = await fetch(`/api/session/${encodeURIComponent(sessionId)}`);
  if (!response.ok) {
    throw new Error(`Report request failed (${response.status}).`);
  }
  return response.json() as Promise<SessionReport>;
}

export function durationMs(report: SessionReport): number | null {
  return report.endedAtMs === null ? null : Math.max(0, report.endedAtMs - report.startedAtMs);
}
