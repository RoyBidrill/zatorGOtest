<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { customBlobs } from '../api/endpoints'
import { busyActive, busyButton, withBusy } from '../stores/busy'
import { confirmDialog } from '../stores/confirm'
import { refreshTlsBlobSettings } from '../stores/settings'
import { customBlobsPayload, refreshSniState, sniSets } from '../stores/sni'
import { refreshAll } from '../stores/status'
import { announceRestart, restartSuffix, showToast } from '../stores/toast'
import ProfilesBlobSniPanel from '../components/blobs/ProfilesBlobSniPanel.vue'
import CustomBlobsPanel from '../components/blobs/CustomBlobsPanel.vue'
import SniSetsPanel from '../components/blobs/SniSetsPanel.vue'
import Icon from '../components/ui/Icon.vue'

type TabId = 'profiles' | 'blobs' | 'sets'

const route = useRoute()
const activeTab = ref<TabId>(route.path === '/custom-blobs' ? 'blobs' : 'profiles')
const loaded = ref(false)
const needsApply = ref(false)

const blobsCount = computed(() => customBlobsPayload.value?.blobs?.length || 0)
const setsCount = computed(() => sniSets.value.length)
const configDirty = computed(() => needsApply.value || !!customBlobsPayload.value?.config_dirty)

async function load() {
  // Один комбинированный запрос /api/blobs + /api/settings на всю страницу.
  const [data] = await Promise.all([refreshSniState(), refreshTlsBlobSettings()])
  needsApply.value = !!data.config_dirty
  loaded.value = true
}

async function refresh() {
  try {
    await withBusy('refresh-blobs-sni', load)
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

onMounted(refresh)

async function applyBlobs() {
  const ok = await confirmDialog({
    title: 'Применить блобы к конфигу?',
    message: 'Декларации --blob= запишутся в секцию #Z2R_CUSTOM_BLOBS конфига zapret2, ссылки пользовательских стратегий переинжектятся, служба перезапустится.',
    confirmText: 'Применить',
  })
  if (!ok) return
  try {
    await withBusy('custom-blob-apply', async () => {
      announceRestart()
      const res = await customBlobs.apply()
      needsApply.value = false
      showToast(`Блобы применены к конфигу.${restartSuffix(res)}`)
      await Promise.all([load(), refreshAll()])
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}
</script>

<template>
  <section class="page-stack">
    <div class="page-head">
      <div>
        <span class="eyebrow">Фейки и маскировка</span>
        <h1>Блобы и SNI</h1>
        <p>Настройка TLS/QUIC-блобов по профилям, ротация SNI-пулов и загрузка собственных бинарных файлов.</p>
      </div>
      <div class="actions">
        <button
          id="refresh-custom-blobs"
          type="button"
          :class="{ 'is-busy': busyButton === 'refresh-blobs-sni' }"
          :disabled="busyActive"
          @click="refresh"
        >
          <Icon name="refresh" class="icon-sm" />
          <span>Обновить</span>
        </button>
      </div>
    </div>

    <div v-if="loaded && configDirty" class="notice-banner is-warn" role="region" aria-label="Неприменённые изменения блобов">
      <span>Есть неприменённые изменения своих блобов: запишите их в конфиг zapret2.</span>
      <button
        id="custom-blob-apply-btn"
        type="button"
        class="primary"
        :class="{ 'is-busy': busyButton === 'custom-blob-apply' }"
        :disabled="busyActive"
        @click="applyBlobs"
      >
        Применить к конфигу
      </button>
    </div>

    <div class="tabs-bar" role="tablist" aria-label="Разделы блобов и SNI">
      <button
        type="button"
        role="tab"
        :aria-selected="activeTab === 'profiles'"
        class="tab-pill"
        :class="{ active: activeTab === 'profiles' }"
        @click="activeTab = 'profiles'"
      >
        Профили и блобы <span class="tab-count">6</span>
      </button>
      <button
        type="button"
        role="tab"
        :aria-selected="activeTab === 'blobs'"
        class="tab-pill"
        :class="{ active: activeTab === 'blobs' }"
        @click="activeTab = 'blobs'"
      >
        Свои блобы <span class="tab-count">{{ blobsCount }}</span>
        <span v-if="configDirty" class="dirty-dot" title="Требуется применение к конфигу" />
      </button>
      <button
        type="button"
        role="tab"
        :aria-selected="activeTab === 'sets'"
        class="tab-pill"
        :class="{ active: activeTab === 'sets' }"
        @click="activeTab = 'sets'"
      >
        Наборы SNI <span class="tab-count">{{ setsCount }}</span>
      </button>
    </div>

    <div v-if="!loaded" class="skeleton-list" aria-label="Загрузка настроек блобов и SNI">
      <div class="skeleton-row is-tall" />
      <div v-for="i in 4" :key="i" class="skeleton-row" />
    </div>
    <template v-else>
      <ProfilesBlobSniPanel v-show="activeTab === 'profiles'" />
      <CustomBlobsPanel v-show="activeTab === 'blobs'" @dirty="needsApply = true" @reload="load" />
      <SniSetsPanel v-show="activeTab === 'sets'" />
    </template>
  </section>
</template>
