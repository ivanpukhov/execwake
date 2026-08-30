<script lang="ts">
  import { onMount } from 'svelte';
  import type { EventReport } from './report';

  export let events: EventReport[];
  export let startedAtMs: number;

  const rowHeight = 36;
  const overscan = 5;
  let viewport: HTMLDivElement;
  let scrollTop = 0;
  let viewportHeight = 360;
  let selectedCategory = 'all';
  let search = '';

  onMount(() => {
    const observer = new ResizeObserver(([entry]) => {
      viewportHeight = entry.contentRect.height;
    });
    observer.observe(viewport);
    return () => observer.disconnect();
  });

  function selectCategory(category: string) {
    selectedCategory = category;
    resetViewport();
  }

  function searchEvents(event: Event) {
    search = (event.currentTarget as HTMLInputElement).value;
    resetViewport();
  }

  function resetViewport() {
    scrollTop = 0;
    viewport?.scrollTo({ top: 0 });
  }

  function elapsed(timestamp: number): string {
    const value = Math.max(0, timestamp - startedAtMs);
    return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(2)} s`;
  }

  $: categories = ['all', ...new Set(events.map((event) => event.category))];
  $: query = search.trim().toLocaleLowerCase();
  $: filtered = events.filter((event) => {
    const categoryMatches = selectedCategory === 'all' || event.category === selectedCategory;
    const searchMatches =
      query.length === 0 ||
      event.target.toLocaleLowerCase().includes(query) ||
      event.operation.toLocaleLowerCase().includes(query);
    return categoryMatches && searchMatches;
  });
  $: firstRow = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  $: visibleRows = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  $: lastRow = Math.min(filtered.length, firstRow + visibleRows);
  $: visible = filtered.slice(firstRow, lastRow);
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
    <input value={search} on:input={searchEvents} type="search" placeholder="Search target or operation" />
  </label>
</div>

<div
  class="event-table"
  bind:this={viewport}
  role="grid"
  aria-label="Session events"
  aria-rowcount={filtered.length}
  tabindex="0"
  on:scroll={(event) => (scrollTop = event.currentTarget.scrollTop)}
>
  <div class="event-table-head" role="row">
    <span role="columnheader">Time</span>
    <span role="columnheader">Category</span>
    <span role="columnheader">Operation</span>
    <span role="columnheader">Target</span>
    <span role="columnheader">Process</span>
    <span role="columnheader">Evidence</span>
  </div>
  {#if filtered.length === 0}
    <p class="empty-state">No matching events.</p>
  {:else}
    <div class="event-spacer" role="rowgroup" style:height={`${filtered.length * rowHeight}px`}>
      {#each visible as event, index (event.eventId)}
        <div
          class="event-row"
          role="row"
          aria-rowindex={firstRow + index + 1}
          style:transform={`translateY(${(firstRow + index) * rowHeight}px)`}
        >
          <span role="gridcell" class="event-time">{elapsed(event.occurredAtMs)}</span>
          <span role="gridcell"><i class={`category-dot category-${event.category}`}></i>{event.category}</span>
          <span role="gridcell">{event.operation}</span>
          <span role="gridcell" class="event-target" title={event.target}>{event.target}</span>
          <span role="gridcell">{event.processId ?? '—'}</span>
          <span role="gridcell">{event.evidence}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<p class="event-count">{filtered.length} of {events.length} events</p>
