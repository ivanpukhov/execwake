import { expect, test } from '@playwright/test';

const session = {
  id: 'test-session',
  schemaVersion: 1,
  mode: 'observe',
  state: 'finalized',
  finalized: true,
  commandName: '<img src=x onerror="window.reportInjected=true">',
  argumentCount: 2,
  collectorRequested: 'auto',
  collectorBackend: 'ptrace',
  collectorFallbackReason: 'permission_denied',
  startedAtMs: 1_000,
  endedAtMs: 2_500,
  exitCode: 0,
  terminationSignal: null,
  interruption: null,
  coverage: [
    { category: 'processes', state: 'complete', lostEvents: 0 },
    { category: 'filesystem', state: 'partial', lostEvents: 0 },
    { category: 'network', state: 'partial', lostEvents: 0 },
    { category: 'environment', state: 'partial', lostEvents: 0 },
  ],
  processCount: 2,
  processes: [
    {
      processId: 1,
      parentProcessId: null,
      executable: '/usr/bin/node',
      startedAtMs: 1_000,
      endedAtMs: 2_500,
      exitCode: 0,
      terminationSignal: null,
      evidence: 'observed',
    },
    {
      processId: 2,
      parentProcessId: 1,
      executable: '/usr/bin/git',
      startedAtMs: 1_400,
      endedAtMs: 1_900,
      exitCode: 0,
      terminationSignal: null,
      evidence: 'observed',
    },
  ],
  eventCount: 1_000_000,
  timelineEvents: [
    {
      eventId: 1,
      category: 'process',
      operation: 'exec',
      target: '/usr/bin/node',
      processId: 1,
      occurredAtMs: 1_000,
      evidence: 'observed',
    },
    {
      eventId: 2,
      category: 'network',
      operation: 'connect',
      target: '127.0.0.1:443',
      processId: 2,
      occurredAtMs: 1_700,
      evidence: 'observed',
    },
  ],
  nodeEnrichmentCount: 0,
  nodeEnrichment: [],
  findingCount: 1,
  findings: [
    {
      findingId: 1,
      ruleId: 'sensitive-path-read',
      ruleVersion: 1,
      severity: 'high',
      processId: 2,
      subject: '~/.ssh/config',
      evidenceEventIds: [3],
      evidenceTruncated: false,
    },
  ],
};

test('renders a large session without inserting report text as markup', async ({ page }) => {
  await page.route('**/api/session/test-session/events?**', async (route) => {
    const offset = Number(new URL(route.request().url()).searchParams.get('offset') ?? '0');
    const events = Array.from({ length: 500 }, (_, index) => ({
      eventId: offset + index + 1,
      category: index % 2 === 0 ? 'filesystem' : 'network',
      operation: index % 2 === 0 ? 'read' : 'connect',
      target:
        index === 0
          ? '<script>window.reportInjected=true</script>\u001b]8;;https://invalid.example\u0007link'
          : `/workspace/file-${offset + index}`,
      processId: index % 2 === 0 ? 1 : 2,
      occurredAtMs: 1_000 + offset + index,
      evidence: 'observed',
    }));
    await route.fulfill({ json: { offset, total: 1_000_000, events } });
  });
  await page.route('**/api/session/test-session', (route) => route.fulfill({ json: session }));

  await page.goto('/session/test-session');

  await expect(page.getByRole('heading', { level: 1 })).toHaveText(session.commandName);
  await expect(page.locator('h1 img')).toHaveCount(0);
  await expect(page.getByLabel('Process hierarchy')).toContainText('/usr/bin/node');
  await expect(page.getByLabel('Process hierarchy')).toContainText('/usr/bin/git');
  await expect(page.getByText('sensitive-path-read v1')).toBeVisible();
  const collector = page.getByLabel('Collector selection');
  await expect(collector).toContainText('Requestedauto');
  await expect(collector).toContainText('Selectedptrace');
  await expect(collector).toContainText('Fallback permission denied');

  const timeline = page.getByLabel('Process and event timeline');
  await expect(timeline).toBeVisible();
  expect(
    await timeline.evaluate((element: HTMLCanvasElement) => element.width > 0 && element.height > 0),
  ).toBe(true);

  const grid = page.getByRole('grid', { name: 'Session events' });
  await expect(grid).toHaveAttribute('aria-rowcount', '1000001');
  await expect(grid.getByText('<script>window.reportInjected=true</script>', { exact: false })).toBeVisible();
  await expect(grid.locator('.event-target script')).toHaveCount(0);
  expect(await grid.locator('[role="row"]').count()).toBeLessThan(100);
  expect(await page.evaluate(() => Boolean((window as Window & { reportInjected?: boolean }).reportInjected))).toBe(
    false,
  );
});

test('renders deterministic diff sections and comparison scope', async ({ page }) => {
  await page.route('**/api/diff', (route) =>
    route.fulfill({
      json: {
        before: {
          id: 'before',
          schemaVersion: 1,
          backend: 'ebpf',
          privacyProfile: 'default-v1',
          commandName: 'package@1.4.0',
        },
        after: {
          id: 'after',
          schemaVersion: 1,
          backend: 'ebpf',
          privacyProfile: 'default-v1',
          commandName: 'package@1.5.0',
        },
        compatibility: ['filesystem', 'network', 'process', 'environment'].map((category) => ({
          category,
          comparable: true,
          issues: [],
          before: { state: category === 'process' ? 'complete' : 'partial', lostEvents: 0 },
          after: { state: category === 'process' ? 'complete' : 'partial', lostEvents: 0 },
        })),
        behavior: [
          {
            status: 'NEW',
            key: { category: 'network', endpoint: 'telemetry.example:443', process: 'install.js' },
            before: null,
            after: {
              value: { operations: ['connect'], evidence: ['observed'], attributes: [] },
              evidenceEventIds: [8],
            },
          },
          {
            status: 'UNCHANGED',
            key: { category: 'filesystem', path: '$WORKSPACE/package.json', process: 'npm' },
            before: {
              value: { operations: ['read'], evidence: ['observed'], attributes: [] },
              evidenceEventIds: [2],
            },
            after: {
              value: { operations: ['read'], evidence: ['observed'], attributes: [] },
              evidenceEventIds: [3],
            },
          },
        ],
        findings: [],
        whatChanged: ['This version connects to telemetry.example:443.'],
      },
    }),
  );

  await page.goto('/diff');

  await expect(page.getByRole('heading', { level: 1 })).toContainText('package@1.4.0 to package@1.5.0');
  await expect(page.getByText('This version connects to telemetry.example:443.')).toBeVisible();
  await expect(page.getByRole('table', { name: 'NEW behavior' })).toContainText(
    'telemetry.example:443',
  );
  await expect(page.getByRole('table', { name: 'UNCHANGED behavior' })).toContainText(
    '$WORKSPACE/package.json',
  );
  await expect(page.getByText('comparable', { exact: true })).toHaveCount(4);
});
