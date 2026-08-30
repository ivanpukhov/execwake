<script lang="ts">
  import { onMount } from 'svelte';
  import { durationMs, loadReport, type SessionReport } from './report';

  let report: SessionReport | null = null;
  let error = '';

  onMount(async () => {
    try {
      report = await loadReport();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Report could not be loaded.';
    }
  });

  function formatDuration(value: number | null): string {
    if (value === null) return 'Running';
    if (value < 1000) return `${value} ms`;
    return `${(value / 1000).toFixed(2)} s`;
  }
</script>

<svelte:head>
  <title>{report ? `${report.commandName} — ExecWake` : 'ExecWake report'}</title>
</svelte:head>

<main class="page-shell">
  {#if error}
    <section class="message error" role="alert">
      <h1>Report unavailable</h1>
      <p>{error}</p>
    </section>
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
      <article><span>Arguments</span><strong>{report.argumentCount}</strong></article>
    </section>

    <section class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Coverage</p><h2>Observation status</h2></div>
      </div>
      <div class="coverage-grid">
        {#each report.coverage as coverage}
          <div class="coverage-row">
            <span>{coverage.category}</span>
            <strong class:unavailable={coverage.state === 'unavailable'}>{coverage.state}</strong>
          </div>
        {/each}
      </div>
    </section>

    <div class="content-grid">
      <section class="panel"><div class="panel-heading"><h2>Process tree</h2></div><p class="muted">Process details load here.</p></section>
      <section class="panel"><div class="panel-heading"><h2>Timeline</h2></div><p class="muted">Execution timing loads here.</p></section>
    </div>

    <section class="panel"><div class="panel-heading"><h2>Events</h2></div><p class="muted">Observed events load here.</p></section>
  {:else}
    <section class="message" aria-live="polite"><p>Loading report…</p></section>
  {/if}
</main>
