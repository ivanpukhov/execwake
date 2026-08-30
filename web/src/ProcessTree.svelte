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
    const append = (root: ProcessReport) => {
      const pending: ProcessRow[] = [{ process: root, depth: 0 }];
      while (pending.length > 0) {
        const row = pending.pop();
        if (!row || visited.has(row.process.processId)) continue;
        visited.add(row.process.processId);
        rows.push(row);

        const descendants = children.get(row.process.processId) ?? [];
        for (let index = descendants.length - 1; index >= 0; index -= 1) {
          pending.push({ process: descendants[index], depth: row.depth + 1 });
        }
      }
    };

    for (const root of roots) append(root);
    for (const process of [...input].sort(order)) append(process);
    return rows;
  }

  function processResult(process: ProcessReport): string {
    if (process.endedAtMs === null) return 'incomplete';
    if (process.terminationSignal !== null) return `signal ${process.terminationSignal}`;
    if (process.exitCode !== null) return `exit ${process.exitCode}`;
    return 'unknown';
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
