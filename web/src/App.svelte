<script lang="ts">
  import { onMount } from 'svelte';
  import DiffView from './DiffView.svelte';
  import Findings from './Findings.svelte';
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
      <span class:interrupted={report.state === 'interrupted'} class="state">{report.state}</span>
    </header>

    <section class="metrics" aria-label="Session summary">
      <article><span>Duration</span><strong>{formatDuration(durationMs(report))}</strong></article>
      <article><span>Processes</span><strong>{report.processes.length}</strong></article>
      <article><span>Events</span><strong>{report.events.length}</strong></article>
      <article><span>Findings</span><strong>{report.findings.length}</strong></article>
    </section>

    <section class="panel">
      <div class="panel-heading"><div><p class="eyebrow">Findings</p><h2>Deterministic rules</h2></div></div>
      <Findings findings={report.findings} />
    </section>

    <section class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Coverage</p><h2>Observation status</h2></div>
      </div>
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
        <ProcessTree processes={report.processes} />
      </section>
      <section class="panel">
        <div class="panel-heading"><h2>Timeline</h2></div>
        <Timeline
          processes={report.processes}
          events={report.events}
          startedAtMs={report.startedAtMs}
          endedAtMs={report.endedAtMs}
        />
      </section>
    </div>

    <section class="panel">
      <div class="panel-heading"><h2>Events</h2></div>
      <VirtualEventTable events={report.events} startedAtMs={report.startedAtMs} />
    </section>
  {:else}
    <section class="message" aria-live="polite"><p>Loading report…</p></section>
  {/if}
</main>
