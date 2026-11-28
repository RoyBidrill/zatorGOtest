<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { busyActive, busyButton } from '../../stores/busy'
import { versionInfo } from '../../stores/status'
import {
  actionLabelForRelease, compareZapretVersion, installZapretRelease, loadZapretReleases,
  zapretBranchLabel, zapretBranchShort, zapretReleases, zapretReleasesError, zapretReleasesState,
  type ZapretSource,
} from '../../stores/zapretReleases'
import Icon from './Icon.vue'

defineProps<{ compact?: boolean }>()

const installedVersion = computed(
  () => zapretReleases.value?.installed.version || versionInfo.value?.zapret2_version || '',
)
const installedSource = computed<ZapretSource | ''>(
  () => (zapretReleases.value?.installed.source || versionInfo.value?.zapret2_source || '') as ZapretSource | '',
)
const installedArch = computed(
  () => zapretReleases.value?.installed.arch || versionInfo.value?.zapret2_arch || zapretReleases.value?.platform_arch || '',
)

const selectedSource = ref<ZapretSource>('fork')
const userPickedSource = ref(false)
watch(installedSource, (src) => {
  if (!userPickedSource.value && (src === 'fork' || src === 'official')) {
    selectedSource.value = src
  }
}, { immediate: true })

function selectBranch(src: ZapretSource) {
  userPickedSource.value = true
  selectedSource.value = src
}

const forkList = computed(() => zapretReleases.value?.fork || [])
const officialList = computed(() => zapretReleases.value?.official || [])
const activeList = computed(() => (selectedSource.value === 'official' ? officialList.value : forkList.value))
const branchError = computed(() => zapretReleases.value?.errors?.[selectedSource.value] || '')

const latestForInstalledBranch = computed(() => {
  const curVer = installedVersion.value
  const src = installedSource.value
  if (!curVer || curVer === 'self-built' || (src !== 'fork' && src !== 'official')) return ''
  const list = src === 'official' ? officialList.value : forkList.value
  if (!list.length) return ''
  const top = list[0].version
  return compareZapretVersion(top, curVer) > 0 ? top : ''
})

const selectedVersion = ref('')
watch([selectedSource, activeList], () => {
  const list = activeList.value
  if (!list.length) {
    selectedVersion.value = ''
    return
  }
  if (!list.some((r) => r.version === selectedVersion.value)) {
    selectedVersion.value = list[0].version
  }
}, { immediate: true })

const compactActionLabel = computed(() => {
  if (!selectedVersion.value) return 'Установить'
  return actionLabelForRelease(selectedSource.value, selectedVersion.value, installedSource.value, installedVersion.value)
})

function shortDate(iso?: string): string {
  return iso ? iso.slice(0, 10) : ''
}

function isCurrent(src: ZapretSource, ver: string): boolean {
  return installedSource.value === src && installedVersion.value === ver
}

function rowAction(src: ZapretSource, ver: string): string {
  return actionLabelForRelease(src, ver, installedSource.value, installedVersion.value)
}

function installCompact() {
  if (!selectedVersion.value) return
  void installZapretRelease(selectedSource.value, selectedVersion.value)
}
</script>

<template>
  <div v-if="compact" class="zapret-compact">
    <div class="zapret-compact-head">
      <div class="seg-group seg-sm" role="tablist" aria-label="Ветка zapret2">
        <button
          type="button"
          role="tab"
          :aria-selected="selectedSource === 'fork'"
          :class="{ active: selectedSource === 'fork' }"
          :disabled="busyActive"
          @click="selectBranch('fork')"
        >
          reasm-fix ({{ forkList.length }})
        </button>
        <button
          type="button"
          role="tab"
          :aria-selected="selectedSource === 'official'"
          :class="{ active: selectedSource === 'official' }"
          :disabled="busyActive"
          @click="selectBranch('official')"
        >
          Обычная ({{ officialList.length }})
        </button>
      </div>
      <button
        type="button"
        class="icon-btn ghost"
        title="Обновить список релизов"
        aria-label="Обновить список релизов"
        :disabled="busyActive || zapretReleasesState === 'loading'"
        @click="loadZapretReleases(true)"
      >
        <Icon name="refresh" class="icon-sm" />
      </button>
    </div>

    <p v-if="latestForInstalledBranch" class="zapret-hint">
      Доступно обновление: <strong>v{{ latestForInstalledBranch }}</strong>
    </p>
    <p v-if="zapretReleasesState === 'loading' && !activeList.length" class="panel-d">Загружаем релизы с GitHub...</p>
    <p v-else-if="zapretReleasesState === 'error' && !activeList.length" class="error-text">{{ zapretReleasesError }}</p>
    <p v-else-if="branchError && !activeList.length" class="error-text">{{ branchError }}</p>

    <div v-if="activeList.length" class="zapret-compact-controls">
      <select v-model="selectedVersion" :disabled="busyActive" aria-label="Доступные версии zapret2">
        <option v-for="rel in activeList" :key="`${rel.source}-${rel.version}`" :value="rel.version">
          {{ rel.tag }}{{ shortDate(rel.published_at) ? ` · ${shortDate(rel.published_at)}` : '' }}{{ isCurrent(rel.source, rel.version) ? ' (установлена)' : '' }}
        </option>
      </select>
      <button
        type="button"
        class="primary"
        :disabled="busyActive || !selectedVersion"
        :class="{ 'is-busy': busyButton === 'zapret-version' }"
        @click="installCompact"
      >
        {{ compactActionLabel }}
      </button>
    </div>
    <div v-else-if="zapretReleasesState === 'idle'" class="actions">
      <button type="button" class="secondary-button compact-btn" :disabled="busyActive" @click="loadZapretReleases(false)">
        Загрузить версии
      </button>
    </div>
  </div>

  <div v-else class="zapret-full">
    <div class="panel-h">
      <h2>Версия zapret2</h2>
      <span v-if="installedVersion" class="chip on">
        {{ installedVersion === 'self-built' ? 'self-built' : `v${installedVersion}` }}
        <template v-if="installedSource"> · {{ zapretBranchShort(installedSource) }}</template>
      </span>
      <span v-else class="chip">не определена</span>
    </div>

    <p class="panel-d">
      Установлено:
      <strong>{{ installedVersion ? (installedVersion === 'self-built' ? 'self-built' : `v${installedVersion}`) : '-' }}</strong>
      <template v-if="installedSource"> · {{ zapretBranchLabel(installedSource) }}</template>
      <template v-if="installedArch"> · <code>{{ installedArch }}</code></template>
      <template v-if="zapretReleases?.embedded"> · openwrt-embedded</template>
      <span v-if="latestForInstalledBranch" class="chip on zapret-inline-badge">
        Доступна v{{ latestForInstalledBranch }}
      </span>
    </p>

    <div class="zapret-toolbar">
      <div class="seg-group" role="tablist" aria-label="Ветка zapret2">
        <button
          type="button"
          role="tab"
          :aria-selected="selectedSource === 'fork'"
          :class="{ active: selectedSource === 'fork' }"
          :disabled="busyActive"
          @click="selectBranch('fork')"
        >
          reasm-fix · MarkinAlexander ({{ forkList.length }})
        </button>
        <button
          type="button"
          role="tab"
          :aria-selected="selectedSource === 'official'"
          :class="{ active: selectedSource === 'official' }"
          :disabled="busyActive"
          @click="selectBranch('official')"
        >
          Обычная · bol-van ({{ officialList.length }})
        </button>
      </div>
      <button
        type="button"
        class="ghost"
        :disabled="busyActive || zapretReleasesState === 'loading'"
        :class="{ 'is-busy': zapretReleasesState === 'loading' }"
        @click="loadZapretReleases(true)"
      >
        <Icon name="refresh" class="icon-sm" />
        <span>{{ zapretReleasesState === 'loading' ? 'Обновление...' : 'Проверить релизы' }}</span>
      </button>
    </div>

    <p v-if="zapretReleasesError" class="error-text">{{ zapretReleasesError }}</p>
    <p v-if="branchError" class="error-text">{{ branchError }}</p>

    <div class="list-stack zapret-releases-list">
      <div v-for="rel in activeList" :key="`${rel.source}-${rel.version}`" class="list-row zapret-release-row">
        <div class="zapret-release-meta">
          <code>{{ rel.tag }}</code>
          <span v-if="shortDate(rel.published_at)" class="zapret-release-date">{{ shortDate(rel.published_at) }}</span>
          <span v-if="rel.prerelease" class="chip is-warn">pre-release</span>
          <span v-if="isCurrent(rel.source, rel.version)" class="chip on">установлена</span>
          <a
            v-if="rel.url"
            :href="rel.url"
            target="_blank"
            rel="noopener noreferrer"
            class="zapret-ext-link"
          >
            <span>GitHub</span>
            <Icon name="external" class="icon-sm" />
          </a>
        </div>
        <button
          type="button"
          class="compact-btn"
          :class="[rowAction(rel.source, rel.version) === 'Обновить' || rowAction(rel.source, rel.version) === 'Переключить' ? 'primary' : 'ghost', { 'is-busy': busyButton === 'zapret-version' }]"
          :disabled="busyActive"
          @click="installZapretRelease(rel.source, rel.version)"
        >
          {{ rowAction(rel.source, rel.version) }}
        </button>
      </div>
      <p v-if="zapretReleasesState === 'loading' && !activeList.length" class="panel-d">Загружаем доступные релизы...</p>
      <p v-else-if="!activeList.length && !branchError && !zapretReleasesError" class="panel-d">
        Релизы не загружены. Нажмите «Проверить релизы».
      </p>
    </div>
  </div>
</template>

<style scoped>
.zapret-compact {
  display: grid;
  gap: 0.55rem;
  margin: 0.75rem 0;
  padding: 0.75rem 0;
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}
.zapret-compact-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.zapret-hint {
  margin: 0;
  font-size: 0.78rem;
  color: var(--accent);
}
.zapret-compact-controls {
  display: flex;
  gap: 0.45rem;
  align-items: center;
}
.zapret-compact-controls select {
  flex: 1;
  min-width: 0;
  font-size: 0.78rem;
}
.zapret-inline-badge { margin-left: 0.45rem; }
.zapret-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.6rem;
  margin-bottom: 0.8rem;
}
.zapret-releases-list {
  max-height: 360px;
  overflow-y: auto;
}
.zapret-release-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem 0.75rem;
}
.zapret-release-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem;
  min-width: 0;
}
.zapret-release-date {
  color: var(--muted);
  font-size: 0.78rem;
  font-family: var(--font-mono);
}
.zapret-ext-link {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 500;
}
.zapret-ext-link:hover { text-decoration: underline; }
</style>
