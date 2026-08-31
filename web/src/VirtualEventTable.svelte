<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { loadEventPage, type EventReport } from './report';

  export let sessionId: string;
  export let eventCount: number;
  export let startedAtMs: number;

  const rowHeight = 30;
  const pageSize = 500;
  const cachedPageLimit = 12;
  const overscan = 8;
  const categories = ['all', 'process', 'filesystem', 'network', 'environment'];

  let viewport: HTMLDivElement;
  let scrollTop = 0;
  let viewportHeight = 360;
  let selectedCategory = 'all';
  let searchInput = '';
  let search = '';
  let total = eventCount;
  let pages = new Map<number, EventReport[]>();
  let pending = new Set<number>();
  let requestGeneration = 0;
  let error = '';
  let searchTimer: ReturnType<typeof setTimeout> | undefined;

  onMount(() => {
    const observer = new ResizeObserver(([entry]) => {
      viewportHeight = entry.contentRect.height;
    });
    observer.observe(viewport);
    return () => observer.disconnect();
  });

  onDestroy(() => {
    if (searchTimer) clearTimeout(searchTimer);
  });

  function selectCategory(category: string) {
    selectedCategory = category;
    resetQuery();
  }

  function searchEvents(event: Event) {
    searchInput = (event.currentTarget as HTMLInputElement).value;
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      search = searchInput.trim();
      resetQuery();
    }, 250);
  }

  function resetQuery() {
    requestGeneration += 1;
    pages = new Map();
    pending = new Set();
    total = eventCount;
    error = '';
    scrollTop = 0;
    viewport?.scrollTo({ top: 0 });
    void loadVisible(0, visibleRowCount);
  }

  function scrollEvents(event: Event) {
    scrollTop = (event.currentTarget as HTMLDivElement).scrollTop;
    const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
    void loadVisible(first, Math.min(total, first + visibleRowCount));
  }

  async function loadPage(offset: number, generation: number) {
    if (pages.has(offset) || pending.has(offset)) return;
    pending.add(offset);
    pending = new Set(pending);
    try {
      const page = await loadEventPage(sessionId, offset, selectedCategory, search);
      if (generation !== requestGeneration) return;
      total = page.total;
      const updated = new Map(pages);
      updated.set(page.offset, page.events);
      while (updated.size > cachedPageLimit) {
        const oldest = updated.keys().next().value as number | undefined;
        if (oldest === undefined) break;
        updated.delete(oldest);
      }
      pages = updated;
      if (page.offset === 0) markFirstPageRendered();
      error = '';
    } catch (cause) {
      if (generation !== requestGeneration) return;
      error = cause instanceof Error ? cause.message : 'Events could not be loaded.';
    } finally {
      if (generation === requestGeneration) {
        pending.delete(offset);
        pending = new Set(pending);
      }
    }
  }

  async function loadVisible(first: number, last: number) {
    const generation = requestGeneration;
    const firstPage = Math.floor(first / pageSize) * pageSize;
    const lastPage = Math.floor(Math.max(first, last - 1) / pageSize) * pageSize;
    const requests: Promise<void>[] = [];
    for (let offset = firstPage; offset <= lastPage; offset += pageSize) {
      requests.push(loadPage(offset, generation));
    }
    await Promise.all(requests);
  }

  function eventAt(index: number, source: Map<number, EventReport[]>): EventReport | undefined {
    const pageOffset = Math.floor(index / pageSize) * pageSize;
    return source.get(pageOffset)?.[index - pageOffset];
  }

  function markFirstPageRendered() {
    if (performance.getEntriesByName('execwake-first-page-rendered').length > 0) return;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (performance.getEntriesByName('execwake-first-page-rendered').length > 0) return;
        performance.mark('execwake-first-page-rendered');
        performance.measure(
          'execwake-report-ready',
          'execwake-app-start',
          'execwake-first-page-rendered'
        );
        const measurement = performance.getEntriesByName('execwake-report-ready')[0];
        if (measurement) {
          document.documentElement.dataset.reportReadyMs = measurement.duration.toFixed(1);
        }
      });
    });
  }

  function elapsed(timestamp: number): string {
    const value = Math.max(0, timestamp - startedAtMs);
    return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(2)} s`;
  }

  $: visibleRowCount = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  $: firstRow = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  $: lastRow = Math.min(total, firstRow + visibleRowCount);
  $: visibleIndexes = Array.from({ length: Math.max(0, lastRow - firstRow) }, (_, index) =>
    firstRow + index
  );
  $: void loadVisible(firstRow, lastRow);
</script>

<div class="event-controls">
  <div class="category-filter" aria-label="Filter event category">
    {#each categories as category}
      <button
        type="button"
        class:active={selectedCategory === category}
        aria-pressed={selectedCategory === category}
        on:click={() => selectCategory(category)}
      >{category}</button>
    {/each}
  </div>
  <label class="event-search">
    <span class="visually-hidden">Search events</span>
    <input
      value={searchInput}
      on:input={searchEvents}
      type="search"
      maxlength="1024"
      placeholder="Search target or operation"
    />
  </label>
</div>

<div
  class="event-table"
  bind:this={viewport}
  role="grid"
  aria-label="Session events"
  aria-rowcount={total + 1}
  tabindex="0"
  on:scroll={scrollEvents}
>
  <div class="event-table-head" role="row" aria-rowindex="1">
    <span role="columnheader">Time</span>
    <span role="columnheader">Category</span>
    <span role="columnheader">Operation</span>
    <span role="columnheader">Target</span>
    <span role="columnheader">Process</span>
    <span role="columnheader">Evidence</span>
  </div>
  {#if error}
    <p class="empty-state" role="alert">{error}</p>
  {:else if total === 0}
    <p class="empty-state">No matching events.</p>
  {:else}
    <div class="event-spacer" role="rowgroup" style:height={`${total * rowHeight}px`}>
      {#each visibleIndexes as rowIndex (rowIndex)}
        {@const event = eventAt(rowIndex, pages)}
        <div
          class="event-row"
          role="row"
          aria-rowindex={rowIndex + 2}
          style:transform={`translateY(${rowIndex * rowHeight}px)`}
        >
          {#if event}
            <span role="gridcell" class="event-time">{elapsed(event.occurredAtMs)}</span>
            <span role="gridcell"><i class={`category-dot category-${event.category}`}></i>{event.category}</span>
            <span role="gridcell">{event.operation}</span>
            <span role="gridcell" class="event-target" title={event.target}>{event.target}</span>
            <span role="gridcell">{event.processId ?? '—'}</span>
            <span role="gridcell">{event.evidence}</span>
          {:else}
            <span role="gridcell" class="event-time">Loading…</span>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<p class="event-count">{total} events</p>
