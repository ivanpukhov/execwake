<script lang="ts">
  import { onMount } from 'svelte';
  import type { EventReport, ProcessReport } from './report';

  export let processes: ProcessReport[];
  export let events: EventReport[];
  export let startedAtMs: number;
  export let endedAtMs: number | null;

  let canvas: HTMLCanvasElement;
  let width = 0;

  const axisHeight = 30;
  const rowHeight = 32;
  const labelWidth = 126;
  const rightPadding = 14;
  const eventColors: Record<string, string> = {
    process: '#385d46',
    filesystem: '#98692d',
    network: '#316b81',
    environment: '#80506e'
  };

  onMount(() => {
    const observer = new ResizeObserver(([entry]) => {
      width = Math.floor(entry.contentRect.width);
    });
    observer.observe(canvas);
    return () => observer.disconnect();
  });

  function elapsedLabel(milliseconds: number): string {
    if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
    return `${(milliseconds / 1000).toFixed(milliseconds < 10000 ? 1 : 0)} s`;
  }

  function shortName(executable: string): string {
    const parts = executable.split(/[\\/]/);
    return parts.at(-1) || executable;
  }

  function draw() {
    if (!canvas || width === 0) return;

    const rows = Math.max(1, processes.length);
    const cssHeight = axisHeight + rows * rowHeight + 10;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(cssHeight * ratio);
    canvas.style.height = `${cssHeight}px`;

    const context = canvas.getContext('2d');
    if (!context) return;
    context.scale(ratio, ratio);
    context.clearRect(0, 0, width, cssHeight);
    context.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
    context.textBaseline = 'middle';

    let observedEnd = endedAtMs ?? startedAtMs;
    for (const process of processes) {
      observedEnd = Math.max(observedEnd, process.endedAtMs ?? process.startedAtMs);
    }
    for (const event of events) {
      observedEnd = Math.max(observedEnd, event.occurredAtMs);
    }
    const duration = Math.max(1, observedEnd - startedAtMs);
    const plotWidth = Math.max(1, width - labelWidth - rightPadding);
    const xFor = (timestamp: number) =>
      labelWidth + (Math.max(0, timestamp - startedAtMs) / duration) * plotWidth;

    context.strokeStyle = '#d9e0db';
    context.fillStyle = '#68766d';
    context.lineWidth = 1;
    for (let tick = 0; tick <= 4; tick += 1) {
      const x = labelWidth + (plotWidth * tick) / 4;
      const label = elapsedLabel((duration * tick) / 4);
      context.beginPath();
      context.moveTo(x + 0.5, axisHeight - 4);
      context.lineTo(x + 0.5, cssHeight - 6);
      context.stroke();
      context.textAlign = tick === 0 ? 'left' : tick === 4 ? 'right' : 'center';
      context.fillText(label, tick === 0 ? x + 4 : tick === 4 ? x - 2 : x, 11);
    }

    const processRows = new Map<number, number>();
    context.textAlign = 'left';
    processes.forEach((process, index) => {
      processRows.set(process.processId, index);
      const y = axisHeight + index * rowHeight + rowHeight / 2;
      context.fillStyle = '#354139';
      context.fillText(shortName(process.executable), 0, y);
      context.fillStyle = '#aebbb2';
      context.fillRect(labelWidth, y - 4, plotWidth, 8);
      context.fillStyle = '#385d46';
      const start = xFor(process.startedAtMs);
      const end = xFor(process.endedAtMs ?? observedEnd);
      context.fillRect(start, y - 4, Math.max(2, end - start), 8);
    });

    const markers = new Set<string>();
    for (const event of events) {
      if (event.processId !== null && !processRows.has(event.processId)) continue;
      const row = event.processId === null ? 0 : (processRows.get(event.processId) ?? 0);
      const x = xFor(event.occurredAtMs);
      const marker = `${row}:${Math.round(x)}:${event.category}`;
      if (markers.has(marker)) continue;
      markers.add(marker);
      const y = axisHeight + row * rowHeight + rowHeight / 2;
      context.fillStyle = eventColors[event.category] ?? '#7b8580';
      context.fillRect(x - 1, y - 8, 2, 16);
    }
  }

  $: if (canvas && width) {
    processes;
    events;
    startedAtMs;
    endedAtMs;
    draw();
  }
</script>

<canvas bind:this={canvas} class="timeline" aria-label="Process and event timeline"></canvas>

<div class="timeline-legend" aria-label="Event categories">
  {#each Object.entries(eventColors) as [category, color]}
    <span><i style:background={color}></i>{category}</span>
  {/each}
</div>
