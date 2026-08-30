<script lang="ts">
  import type { ProcessReport } from './report';

  export let processes: ProcessReport[];

  interface ProcessRow {
    process: ProcessReport;
    depth: number;
  }

  function flatten(input: ProcessReport[]): ProcessRow[] {
    const byId = new Map(input.map((process) => [process.processId, process]));
    const children = new Map<number, ProcessReport[]>();
    const roots: ProcessReport[] = [];

    for (const process of input) {
      if (process.parentProcessId === null || !byId.has(process.parentProcessId)) {
        roots.push(process);
      } else {
        const siblings = children.get(process.parentProcessId) ?? [];
        siblings.push(process);
        children.set(process.parentProcessId, siblings);
      }
    }

    const order = (left: ProcessReport, right: ProcessReport) =>
      left.startedAtMs - right.startedAtMs || left.processId - right.processId;
    roots.sort(order);
    for (const siblings of children.values()) siblings.sort(order);

    const rows: ProcessRow[] = [];
    const visited = new Set<number>();
    const visit = (process: ProcessReport, depth: number) => {
      if (visited.has(process.processId)) return;
      visited.add(process.processId);
      rows.push({ process, depth });
      for (const child of children.get(process.processId) ?? []) visit(child, depth + 1);
    };

    for (const root of roots) visit(root, 0);
    for (const process of [...input].sort(order)) visit(process, 0);
    return rows;
  }

  function processResult(process: ProcessReport): string {
    if (process.terminationSignal !== null) return `signal ${process.terminationSignal}`;
    if (process.exitCode !== null) return `exit ${process.exitCode}`;
    return 'running';
  }

  $: rows = flatten(processes);
</script>

{#if rows.length === 0}
  <p class="empty-state">No process events.</p>
{:else}
  <div class="process-tree" aria-label="Process hierarchy">
    {#each rows as row (row.process.processId)}
      <div
        class="process-row"
        style:--tree-depth={row.depth}
      >
        <span class="tree-mark" aria-hidden="true">{row.depth === 0 ? '●' : '└'}</span>
        <span class="process-name" title={row.process.executable}>{row.process.executable}</span>
        <span class="process-id">{row.process.processId}</span>
        <span class="process-result">{processResult(row.process)}</span>
      </div>
    {/each}
  </div>
{/if}
