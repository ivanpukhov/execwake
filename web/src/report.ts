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

export interface FindingReport {
  findingId: number;
  ruleId: string;
  ruleVersion: number;
  severity: 'low' | 'medium' | 'high';
  processId: number;
  subject: string;
  evidenceEventIds: number[];
  evidenceTruncated: boolean;
}

export interface NodeEnrichmentReport {
  enrichmentId: number;
  kind: 'http' | 'environment';
  method: string | null;
  host: string | null;
  path: string | null;
  environmentName: string | null;
  processId: number;
  monotonicNs: string;
  evidence: 'observed';
}

export interface SessionReport {
  id: string;
  schemaVersion: number;
  mode: 'observe' | 'instrumented';
  state: 'running' | 'finalized' | 'interrupted';
  finalized: boolean;
  commandName: string;
  argumentCount: number;
  collectorRequested: 'auto' | 'ebpf' | 'ptrace';
  collectorBackend: 'ebpf' | 'ptrace' | null;
  collectorFallbackReason:
    | 'cgroup_unavailable'
    | 'permission_denied'
    | 'platform_incompatible'
    | 'initialization_failed'
    | null;
  startedAtMs: number;
  endedAtMs: number | null;
  exitCode: number | null;
  terminationSignal: number | null;
  interruption: string | null;
  coverage: CoverageReport[];
  processCount: number;
  processes: ProcessReport[];
  eventCount: number;
  timelineEvents: EventReport[];
  nodeEnrichmentCount: number;
  nodeEnrichment: NodeEnrichmentReport[];
  findingCount: number;
  findings: FindingReport[];
}

export interface EventPage {
  offset: number;
  total: number;
  events: EventReport[];
}

export type DiffStatus = 'NEW' | 'REMOVED' | 'CHANGED' | 'UNCHANGED';
export type BehaviorCategory = 'filesystem' | 'network' | 'process' | 'environment';

export type BehaviorKey =
  | { category: 'filesystem'; path: string; process: string | null }
  | { category: 'network'; endpoint: string; process: string | null }
  | { category: 'process'; role: string }
  | { category: 'environment'; name: string; process: string | null };

export interface BehaviorValue {
  operations: string[];
  evidence: string[];
  attributes: string[];
}

export interface BehaviorSide {
  value: BehaviorValue;
  evidenceEventIds: number[];
}

export interface BehaviorChange {
  status: DiffStatus;
  key: BehaviorKey;
  before: BehaviorSide | null;
  after: BehaviorSide | null;
}

export interface DiffFinding {
  findingId: number;
  ruleId: string;
  ruleVersion: number;
  severity: 'low' | 'medium' | 'high';
  process: string;
  subject: string;
  evidenceEventIds: number[];
}

export interface FindingChange {
  status: DiffStatus;
  before: DiffFinding | null;
  after: DiffFinding | null;
}

export type CompatibilityIssue =
  | 'schema_mismatch'
  | 'unsupported_schema'
  | 'backend_unavailable'
  | 'backend_mismatch'
  | 'privacy_profile_unavailable'
  | 'privacy_profile_mismatch'
  | 'unsupported_privacy_profile'
  | 'coverage_unavailable'
  | 'coverage_mismatch'
  | 'lost_events';

export interface DiffCoverage {
  state: string;
  lostEvents: number;
}

export interface CategoryCompatibility {
  category: BehaviorCategory;
  comparable: boolean;
  issues: CompatibilityIssue[];
  before: DiffCoverage | null;
  after: DiffCoverage | null;
}

export interface DiffSessionInfo {
  id: string;
  schemaVersion: number;
  backend: string | null;
  privacyProfile: string | null;
  commandName: string;
}

export interface SemanticDiff {
  before: DiffSessionInfo;
  after: DiffSessionInfo;
  compatibility: CategoryCompatibility[];
  behavior: BehaviorChange[];
  findings: FindingChange[];
  whatChanged: string[];
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

export async function loadEventPage(
  sessionId: string,
  offset: number,
  category: string,
  search: string
): Promise<EventPage> {
  const query = new URLSearchParams({ offset: String(offset) });
  if (category !== 'all') query.set('category', category);
  if (search.length > 0) query.set('search', search);
  const response = await fetch(
    `/api/session/${encodeURIComponent(sessionId)}/events?${query.toString()}`
  );
  if (!response.ok) {
    throw new Error(`Event request failed (${response.status}).`);
  }
  return response.json() as Promise<EventPage>;
}

export async function loadDiff(): Promise<SemanticDiff> {
  const response = await fetch('/api/diff');
  if (!response.ok) {
    throw new Error(`Comparison request failed (${response.status}).`);
  }
  return response.json() as Promise<SemanticDiff>;
}

export function durationMs(report: SessionReport): number | null {
  return report.endedAtMs === null ? null : Math.max(0, report.endedAtMs - report.startedAtMs);
}
