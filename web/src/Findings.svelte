<script lang="ts">
  import type { FindingReport } from './report';

  export let findings: FindingReport[];
</script>

{#if findings.length === 0}
  <p class="empty-state">No findings recorded.</p>
{:else}
  <div class="finding-list">
    {#each findings as finding (finding.findingId)}
      <article class={`finding severity-${finding.severity}`}>
        <div class="finding-heading">
          <strong>{finding.severity}</strong>
          <code>{finding.ruleId} v{finding.ruleVersion}</code>
        </div>
        <p class="finding-subject">{finding.subject}</p>
        <p class="finding-meta">
          Process {finding.processId} · Evidence {finding.evidenceEventIds.join(', ')}
        </p>
      </article>
    {/each}
  </div>
{/if}
