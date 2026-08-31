<script lang="ts">
  import type { NodeEnrichmentReport } from './report';

  export let events: NodeEnrichmentReport[];
  export let total: number;

  const firstByProcess = new Map<number, bigint>();
  for (const event of events) {
    const timestamp = BigInt(event.monotonicNs);
    const current = firstByProcess.get(event.processId);
    if (current === undefined || timestamp < current) {
      firstByProcess.set(event.processId, timestamp);
    }
  }

  function time(event: NodeEnrichmentReport): string {
    const timestamp = BigInt(event.monotonicNs);
    const first = firstByProcess.get(event.processId) ?? timestamp;
    const elapsed = timestamp - first;
    const milliseconds = elapsed / 1_000_000n;
    const microseconds = (elapsed % 1_000_000n) / 1_000n;
    return `+${milliseconds}.${microseconds.toString().padStart(3, '0')} ms`;
  }

  function fact(event: NodeEnrichmentReport): string {
    if (event.kind === 'environment') return event.environmentName ?? '';
    return `${event.method ?? ''} ${event.host ?? ''}${event.path ?? ''}`.trim();
  }
</script>

{#if events.length === 0}
  <p class="empty-state">No Node runtime evidence was recorded.</p>
{:else}
  <div class="enrichment-table" role="table" aria-label="Node runtime evidence">
    <div class="enrichment-row enrichment-head" role="row">
      <span role="columnheader">Process time</span>
      <span role="columnheader">Kind</span>
      <span role="columnheader">Fact</span>
      <span role="columnheader">Process</span>
      <span role="columnheader">Evidence</span>
    </div>
    {#each events as event (event.enrichmentId)}
      <div class="enrichment-row" role="row">
        <span class="event-time" role="cell">{time(event)}</span>
        <span role="cell">{event.kind}</span>
        <span role="cell" title={fact(event)}><code>{fact(event)}</code></span>
        <span class="process-id" role="cell">P{event.processId}</span>
        <span role="cell">{event.evidence}</span>
      </div>
    {/each}
  </div>
  {#if events.length < total}
    <p class="truncation-note">Showing {events.length} of {total} runtime events.</p>
  {/if}
{/if}
