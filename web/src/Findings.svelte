<script lang="ts">
  import type { FindingReport } from './report';

  export let findings: FindingReport[];
  export let total: number;
</script>

{#if findings.length === 0}
  <p class="empty-state">No findings recorded.</p>
{:else}
  {#if total > findings.length}
    <p class="truncation-note">Showing {findings.length} of {total} findings.</p>
  {/if}
  <div class="finding-list">
    {#each findings as finding (finding.findingId)}
      <article class={`finding severity-${finding.severity}`}>
        <div class="finding-heading">
          <strong>{finding.severity}</strong>
          <code>{finding.ruleId} v{finding.ruleVersion}</code>
        </div>
        <p class="finding-subject">{finding.subject}</p>
        <p class="finding-meta">
          Process {finding.processId} · Evidence {finding.evidenceEventIds.join(', ')}{finding.evidenceTruncated ? ', …' : ''}
        </p>
      </article>
    {/each}
  </div>
{/if}
