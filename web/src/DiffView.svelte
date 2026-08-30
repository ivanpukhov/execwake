<script lang="ts">
  import type {
    BehaviorChange,
    BehaviorKey,
    BehaviorSide,
    DiffFinding,
    DiffStatus,
    FindingChange,
    SemanticDiff,
  } from './report';

  export let report: SemanticDiff;

  const statuses: DiffStatus[] = ['NEW', 'REMOVED', 'CHANGED', 'UNCHANGED'];

  function subject(key: BehaviorKey): string {
    if (key.category === 'filesystem') return key.path;
    if (key.category === 'network') return key.endpoint;
    if (key.category === 'environment') return key.name;
    return key.role;
  }

  function process(key: BehaviorKey): string {
    return key.category === 'process' ? key.role : key.process ?? 'session';
  }

  function sideDetail(side: BehaviorSide | null): string {
    if (!side) return '';
    return [...side.value.operations, ...side.value.attributes].join(', ');
  }

  function detail(change: BehaviorChange): string {
    if (change.status === 'CHANGED') {
      return `${sideDetail(change.before)} to ${sideDetail(change.after)}`;
    }
    return sideDetail(change.after ?? change.before);
  }

  function evidence(change: BehaviorChange): string {
    const before = change.before?.evidenceEventIds ?? [];
    const after = change.after?.evidenceEventIds ?? [];
    if (before.length > 0 && after.length > 0) {
      return `before ${before.join(', ')}; after ${after.join(', ')}`;
    }
    const ids = after.length > 0 ? after : before;
    return ids.length > 0 ? ids.join(', ') : 'not linked';
  }

  function issueLabel(issue: string): string {
    return issue.replaceAll('_', ' ');
  }

  function changedFinding(change: FindingChange): DiffFinding {
    return (change.after ?? change.before) as DiffFinding;
  }

  $: counts = Object.fromEntries(
    statuses.map((status) => [status, report.behavior.filter((change) => change.status === status).length]),
  ) as Record<DiffStatus, number>;
</script>

<header class="report-header diff-header">
  <div>
    <p class="eyebrow">ExecWake comparison</p>
    <h1>{report.before.commandName} <span>to</span> {report.after.commandName}</h1>
  </div>
  <span class="state">diff</span>
</header>

<section class="metrics" aria-label="Comparison summary">
  {#each statuses as status}
    <article><span>{status}</span><strong>{counts[status]}</strong></article>
  {/each}
</section>

<section class="panel">
  <div class="panel-heading"><div><p class="eyebrow">What changed</p><h2>Finding summary</h2></div></div>
  <ul class="summary-list">
    {#each report.whatChanged as line}<li>{line}</li>{/each}
  </ul>
  {#if report.findings.some((change) => change.status !== 'UNCHANGED')}
    <div class="finding-list diff-findings">
      {#each report.findings.filter((change) => change.status !== 'UNCHANGED') as change}
        {@const finding = changedFinding(change)}
        <article class={`finding severity-${finding.severity}`}>
          <div class="finding-heading">
            <strong>{change.status} · {finding.severity}</strong>
            <code>{finding.ruleId} v{finding.ruleVersion}</code>
          </div>
          <p class="finding-subject">{finding.subject}</p>
          <p class="finding-meta">
            {finding.process} · Evidence {finding.evidenceEventIds.join(', ')}
          </p>
        </article>
      {/each}
    </div>
  {/if}
</section>

<section class="panel">
  <div class="panel-heading"><div><p class="eyebrow">Compatibility</p><h2>Comparison scope</h2></div></div>
  <div class="compatibility-grid">
    {#each report.compatibility as entry}
      <article class:incomparable={!entry.comparable}>
        <strong>{entry.category}</strong>
        <span>{entry.comparable ? 'comparable' : entry.issues.map(issueLabel).join(', ')}</span>
      </article>
    {/each}
  </div>
</section>

{#each statuses as status}
  {@const changes = report.behavior.filter((change) => change.status === status)}
  <section class={`panel diff-section status-${status.toLowerCase()}`}>
    <div class="panel-heading"><h2>{status}</h2><span class="section-count">{changes.length}</span></div>
    {#if changes.length === 0}
      <p class="empty-state">0 entries in this section.</p>
    {:else}
      <div class="diff-table" role="table" aria-label={`${status} behavior`}>
        <div class="diff-row diff-table-head" role="row">
          <span>Category</span><span>Behavior</span><span>Process</span><span>Details</span><span>Evidence</span>
        </div>
        {#each changes as change}
          <div class="diff-row" role="row">
            <span>{change.key.category}</span>
            <code title={subject(change.key)}>{subject(change.key)}</code>
            <code title={process(change.key)}>{process(change.key)}</code>
            <span title={detail(change)}>{detail(change)}</span>
            <span title={evidence(change)}>{evidence(change)}</span>
          </div>
        {/each}
      </div>
    {/if}
  </section>
{/each}
