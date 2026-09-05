<script lang="ts">
  import { onMount } from 'svelte';
  import DiffView from './DiffView.svelte';
  import Findings from './Findings.svelte';
  import NodeEnrichment from './NodeEnrichment.svelte';
  import ProcessTree from './ProcessTree.svelte';
  import Timeline from './Timeline.svelte';
  import VirtualEventTable from './VirtualEventTable.svelte';
  import {
    durationMs,
    loadDiff,
    loadReport,
    type CoverageReport,
    type SemanticDiff,
    type SessionReport,
  } from './report';

  let report: SessionReport | null = null;
  let diff: SemanticDiff | null = null;
  let error = '';
  const timelineProcessLimit = 128;
  const isDiff = window.location.pathname === '/diff';

  onMount(async () => {
    try {
      if (isDiff) diff = await loadDiff();
      else report = await loadReport();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Report could not be loaded.';
    }
  });

  function formatDuration(value: number | null): string {
    if (value === null) return 'Running';
    if (value < 1000) return `${value} ms`;
    return `${(value / 1000).toFixed(2)} s`;
  }

  function coverageStatus(coverage: CoverageReport): string {
    if (coverage.lostEvents === 0) return coverage.state;
    return `${coverage.state} · ${coverage.lostEvents} lost`;
  }

  function collectorReason(reason: string): string {
    return reason.replaceAll('_', ' ');
  }
</script>

<svelte:head>
  <title>{diff ? 'ExecWake comparison' : report ? `${report.commandName} — ExecWake` : 'ExecWake report'}</title>
</svelte:head>

<main class="page-shell">
  {#if error}
    <section class="message error" role="alert">
      <h1>Report unavailable</h1>
      <p>{error}</p>
    </section>
  {:else if diff}
    <DiffView report={diff} />
  {:else if report}
    <header class="report-header">
      <div>
        <p class="eyebrow">ExecWake session</p>
        <h1>{report.commandName}</h1>
      </div>
      <div class="session-labels">
        {#if report.mode === 'instrumented'}<span class="state mode">instrumented</span>{/if}
        <span class:interrupted={report.state === 'interrupted'} class="state">{report.state}</span>
      </div>
    </header>

    <section class="metrics" aria-label="Session summary">
      <article><span>Duration</span><strong>{formatDuration(durationMs(report))}</strong></article>
      <article><span>Processes</span><strong>{report.processCount}</strong></article>
      <article><span>Events</span><strong>{report.eventCount}</strong></article>
      <article><span>Findings</span><strong>{report.findingCount}</strong></article>
    </section>

    <section class="panel">
      <div class="panel-heading"><div><p class="eyebrow">Findings</p><h2>Deterministic rules</h2></div></div>
      <Findings findings={report.findings} total={report.findingCount} />
    </section>

    {#if report.mode === 'instrumented'}
      <section class="panel">
        <div class="panel-heading">
          <div><p class="eyebrow">Node enrichment</p><h2>Runtime evidence</h2></div>
          <span class="section-count">{report.nodeEnrichmentCount} events</span>
        </div>
        <p class="evidence-note">Runtime evidence is separate from kernel socket events. Coverage is partial.</p>
        <NodeEnrichment events={report.nodeEnrichment} total={report.nodeEnrichmentCount} />
      </section>
    {/if}

    <section class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Coverage</p><h2>Observation status</h2></div>
      </div>
      <dl class="collector-status" aria-label="Collector selection">
        <div><dt>Requested</dt><dd>{report.collectorRequested}</dd></div>
        <div><dt>Selected</dt><dd>{report.collectorBackend ?? 'unavailable'}</dd></div>
        {#if report.collectorFallbackReason}
          <div>
            <dt>Fallback</dt>
            <dd>{collectorReason(report.collectorFallbackReason)}</dd>
          </div>
        {/if}
      </dl>
      <div class="coverage-grid">
        {#each report.coverage as coverage}
          <div class="coverage-row">
            <span>{coverage.category}</span>
            <strong class:unavailable={coverage.state === 'unavailable'}>{coverageStatus(coverage)}</strong>
          </div>
        {/each}
      </div>
    </section>

    <div class="content-grid">
      <section class="panel">
        <div class="panel-heading"><h2>Process tree</h2></div>
        <ProcessTree processes={report.processes} total={report.processCount} />
      </section>
      <section class="panel">
        <div class="panel-heading"><h2>Timeline</h2></div>
        {#if report.processCount > timelineProcessLimit}
          <p class="truncation-note">Timeline shows the first {timelineProcessLimit} of {report.processCount} processes.</p>
        {/if}
        <Timeline
          processes={report.processes.slice(0, timelineProcessLimit)}
          events={report.timelineEvents}
          startedAtMs={report.startedAtMs}
          endedAtMs={report.endedAtMs}
        />
      </section>
    </div>

    <section class="panel">
      <div class="panel-heading"><h2>Events</h2></div>
      <VirtualEventTable
        sessionId={report.id}
        eventCount={report.eventCount}
        startedAtMs={report.startedAtMs}
      />
    </section>
  {:else}
    <section class="message" aria-live="polite"><p>Loading report…</p></section>
  {/if}
</main>
