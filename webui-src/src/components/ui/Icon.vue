<script setup lang="ts">
export type IconName =
  | 'overview'
  | 'strategies'
  | 'sweep'
  | 'domains'
  | 'custom-strats'
  | 'blobs'
  | 'settings'
  | 'more'
  | 'refresh'
  | 'logout'
  | 'check'
  | 'pencil'
  | 'trash'
  | 'plus'
  | 'upload'
  | 'download'
  | 'chevron-down'
  | 'arrow-right'
  | 'arrow-left'
  | 'arrow-up'
  | 'arrow-down'
  | 'cross'
  | 'play'
  | 'stop'
  | 'shield'
  | 'external'
  | 'sliders'
  | 'info'
  | 'warning'

defineProps<{ name: IconName }>()
</script>

<template>
  <svg
    class="icon-svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.65"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <template v-if="name === 'overview'">
      <path d="M3 10.5 12 3l9 7.5V20a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 20z" />
      <path d="M9 21.5V14h6v7.5" />
    </template>

    <template v-else-if="name === 'strategies'">
      <path d="M4 6h16M4 12h16M4 18h16" />
      <circle cx="9" cy="6" r="1.8" fill="var(--surface, #fff)" />
      <circle cx="15" cy="12" r="1.8" fill="var(--surface, #fff)" />
      <circle cx="10" cy="18" r="1.8" fill="var(--surface, #fff)" />
    </template>

    <template v-else-if="name === 'sweep'">
      <path d="M12 3a9 9 0 1 0 9 9" />
      <path d="M12 7v5l3 2" />
      <path d="M17 3h4v4" />
    </template>

    <template v-else-if="name === 'domains'">
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3a14.5 14.5 0 0 1 0 18" />
      <path d="M12 3a14.5 14.5 0 0 0 0 18" />
    </template>

    <template v-else-if="name === 'custom-strats'">
      <path d="m8 8-4 4 4 4" />
      <path d="m16 8 4 4-4 4" />
      <path d="m13.5 5.5-3 13" />
    </template>

    <template v-else-if="name === 'blobs'">
      <path d="M12 3 3.5 7.5 12 12l8.5-4.5z" />
      <path d="m3.5 12 8.5 4.5 8.5-4.5" />
      <path d="m3.5 16.5 8.5 4.5 8.5-4.5" />
    </template>

    <template v-else-if="name === 'settings'">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </template>

    <template v-else-if="name === 'more'">
      <circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </template>

    <template v-else-if="name === 'refresh'">
      <path d="M20 11a8 8 0 0 0-14.5-4.5L4 8" />
      <path d="M4 4v4h4" />
      <path d="M4 13a8 8 0 0 0 14.5 4.5L20 16" />
      <path d="M20 20v-4h-4" />
    </template>

    <template v-else-if="name === 'logout'">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5" />
      <path d="M21 12H9" />
    </template>

    <template v-else-if="name === 'check'">
      <path d="m5 12.5 4.5 4.5L19 7.5" />
    </template>

    <template v-else-if="name === 'pencil'">
      <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
      <path d="m14.5 5.5 4 4" />
    </template>

    <template v-else-if="name === 'trash'">
      <path d="M4 7h16" />
      <path d="M9 7V4.5A1.5 1.5 0 0 1 10.5 3h3A1.5 1.5 0 0 1 15 4.5V7" />
      <path d="M6.5 7 7.5 19.5A1.5 1.5 0 0 0 9 21h6a1.5 1.5 0 0 0 1.5-1.5L17.5 7" />
      <path d="M10 11v6M14 11v6" />
    </template>

    <template v-else-if="name === 'plus'">
      <path d="M12 5v14M5 12h14" />
    </template>

    <template v-else-if="name === 'upload'">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m17 8-5-5-5 5" />
      <path d="M12 3v12" />
    </template>

    <template v-else-if="name === 'download'">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m7 10 5 5 5-5" />
      <path d="M12 15V3" />
    </template>

    <template v-else-if="name === 'chevron-down'">
      <path d="m6 9 6 6 6-6" />
    </template>

    <template v-else-if="name === 'arrow-right'">
      <path d="M5 12h14" />
      <path d="m13 6 6 6-6 6" />
    </template>

    <template v-else-if="name === 'arrow-left'">
      <path d="M19 12H5" />
      <path d="m11 6-6 6 6 6" />
    </template>

    <template v-else-if="name === 'arrow-up'">
      <path d="M12 19V5" />
      <path d="m6 11 6-6 6 6" />
    </template>

    <template v-else-if="name === 'arrow-down'">
      <path d="M12 5v14" />
      <path d="m6 13 6 6 6-6" />
    </template>

    <template v-else-if="name === 'cross'">
      <path d="M17 7 7 17M7 7l10 10" />
    </template>

    <template v-else-if="name === 'play'">
      <path d="M7 5.5v13l11-6.5z" />
    </template>

    <template v-else-if="name === 'stop'">
      <rect x="6" y="6" width="12" height="12" rx="2" />
    </template>

    <template v-else-if="name === 'shield'">
      <path d="M12 3 4.5 6.5v5.2c0 4.6 3.2 8.8 7.5 9.8 4.3-1 7.5-5.2 7.5-9.8V6.5z" />
      <path d="m9 12 2 2 4-4" />
    </template>

    <template v-else-if="name === 'external'">
      <path d="M14 5h5v5" />
      <path d="M10 14 19 5" />
      <path d="M19 13.5V19a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 4 19V7.5A1.5 1.5 0 0 1 5.5 6H11" />
    </template>

    <template v-else-if="name === 'sliders'">
      <path d="M4 7h16M4 17h16" />
      <circle cx="9" cy="7" r="2.2" fill="var(--surface, #fff)" />
      <circle cx="15" cy="17" r="2.2" fill="var(--surface, #fff)" />
    </template>

    <template v-else-if="name === 'warning'">
      <path d="M12 3.5 2.8 19.5h18.4z" />
      <path d="M12 10v4" />
      <circle cx="12" cy="17" r="0.6" fill="currentColor" stroke="none" />
    </template>

    <template v-else>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5" />
      <circle cx="12" cy="8" r="0.6" fill="currentColor" stroke="none" />
    </template>
  </svg>
</template>
