<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { applySetting, sni } from '../../api/endpoints'
import type { SniProfileInfo } from '../../api/types'
import { busyActive, busyButton, withBusy } from '../../stores/busy'
import { refreshTlsBlobSettings, tlsBlobSettings } from '../../stores/settings'
import { refreshSniState, sniProfiles, sniSets, sniUnavailable } from '../../stores/sni'
import { refreshAll } from '../../stores/status'
import { announceRestart, restartSuffix, showToast } from '../../stores/toast'
import Icon from '../ui/Icon.vue'

type SniSource = 'set' | 'pin' | 'custom' | 'default'

interface TlsProfileDraft {
  mode: 'classic' | 'clone'
  blob: string
  sizePreset: string
  sizeCustom: string
  sniSource: SniSource
  pinPick: string
  pinCustom: string
  set: string
  policy: 'rr' | 'rand'
  customList: string
}

const DEFAULT_TITLES: Record<string, string> = {
  '1': 'YouTube',
  '2': 'Googlevideo',
  '3': 'Blocked Sites / RKN',
  '4': 'Discord',
  '8': 'Fallback TLS',
}
const TLS_IDS = ['1', '2', '3', '4', '8'] as const
const CLONE_SIZE_PRESETS = ['256', '512', '768', '1024', '1200']
const PIN_PRESETS = ['300.ya.ru', 'www.google.com', 'max.ru', 'hcaptcha.com']
const PIN_CUSTOM = '__custom__'

const tls = computed(() => tlsBlobSettings.value)
const availableBlobs = computed(() => tls.value?.available_blobs || [])
const quicOptions = computed(() => tls.value?.quic_blobs || [])
const sets = sniSets

const savedGlobalBlob = computed(() =>
  tls.value?.current_mode === 'fake_default_tls'
    ? 'fake_default_tls'
    : (tls.value?.current_blob || 'fake_default_tls'),
)
const savedGlobalCloneSize = computed(() => tls.value?.global_clone_size || '')
const savedQuicBlob = computed(() => tls.value?.profile_blobs?.['5'] || '')

const globalBlobDraft = ref('fake_default_tls')
const globalSizeDraft = ref('')
const quicBlobDraft = ref('')
const expandedId = ref<string | null>(null)

const drafts = reactive<Record<string, TlsProfileDraft>>({})
const snapshots = reactive<Record<string, TlsProfileDraft>>({})

function profileInfo(id: string): SniProfileInfo | undefined {
  return sniProfiles.value.find((p) => p.id === id)
}

function buildDraftFromStore(id: string): TlsProfileDraft {
  const t = tls.value
  const p = profileInfo(id)
  const mode = (t?.profile_modes?.[id] === 'clone' ? 'clone' : 'classic') as 'classic' | 'clone'
  const blob = t?.profile_blobs?.[id] ?? ''
  const rawSize = t?.profile_sizes?.[id] || ''
  const sizeKnown = !rawSize || CLONE_SIZE_PRESETS.includes(rawSize)
  const pin = p?.pin || ''
  const set = p?.set || ''
  const eff = p?.effective || []

  let sniSource: SniSource = 'default'
  if (pin) sniSource = 'pin'
  else if (set) sniSource = 'set'
  else if (eff.length > 0) sniSource = 'custom'

  const defaultPin = pin || PIN_PRESETS[0]
  return {
    mode,
    blob,
    sizePreset: sizeKnown ? rawSize : 'custom',
    sizeCustom: sizeKnown ? (rawSize || '1200') : rawSize,
    sniSource,
    pinPick: PIN_PRESETS.includes(defaultPin) ? defaultPin : PIN_CUSTOM,
    pinCustom: PIN_PRESETS.includes(defaultPin) ? '' : defaultPin,
    set: set || sets.value[0]?.name || '',
    policy: p?.policy === 'rand' ? 'rand' : 'rr',
    customList: eff.join('\n'),
  }
}

function cloneDraft(d: TlsProfileDraft): TlsProfileDraft {
  return { ...d }
}

function draftsEqual(a?: TlsProfileDraft, b?: TlsProfileDraft): boolean {
  if (!a || !b) return false
  return a.mode === b.mode
    && a.blob === b.blob
    && a.sizePreset === b.sizePreset
    && a.sizeCustom === b.sizeCustom
    && a.sniSource === b.sniSource
    && a.pinPick === b.pinPick
    && a.pinCustom === b.pinCustom
    && a.set === b.set
    && a.policy === b.policy
    && a.customList === b.customList
}

function syncAll(force = false) {
  globalBlobDraft.value = savedGlobalBlob.value
  globalSizeDraft.value = savedGlobalCloneSize.value
  quicBlobDraft.value = savedQuicBlob.value
  for (const id of TLS_IDS) {
    const fresh = buildDraftFromStore(id)
    snapshots[id] = cloneDraft(fresh)
    if (force || expandedId.value !== id || !drafts[id]) {
      drafts[id] = cloneDraft(fresh)
    }
  }
}

watch([tls, sniProfiles, sets], () => syncAll(false), { immediate: true, deep: true })

const globalDirty = computed(() => globalBlobDraft.value !== savedGlobalBlob.value)
const globalSizeDirty = computed(() => String(globalSizeDraft.value ?? '').trim() !== savedGlobalCloneSize.value)
const quicDirty = computed(() => quicBlobDraft.value !== savedQuicBlob.value)

function isProfileDirty(id: string): boolean {
  if (id === '5') return quicDirty.value
  return !draftsEqual(drafts[id], snapshots[id])
}

const rows = computed(() => TLS_IDS.map((id) => {
  const p = profileInfo(id)
  const mode = (tls.value?.profile_modes?.[id] === 'clone' ? 'clone' : 'classic') as 'classic' | 'clone'
  const blob = tls.value?.profile_blobs?.[id] || ''
  const eff = p?.effective || []
  const tag = mode !== 'clone'
    ? 'blob'
    : (p?.pin ? 'clone-solo' : (p?.set || eff.length > 0 ? 'clone-pool' : 'clone-solo'))

  let sniLabel = '-'
  if (sniUnavailable.value) sniLabel = 'SNI недоступен'
  else if (p?.pin) sniLabel = `пин: ${p.pin}`
  else if (p?.set) sniLabel = `@${p.set} (${p.policy === 'rand' ? 'rand' : 'rr'})`
  else if (eff.length > 0) sniLabel = `свой (${eff.length}, ${p?.policy === 'rand' ? 'rand' : 'rr'})`
  else if (mode === 'clone') sniLabel = 'www.google.com (дефолт)'

  const size = tls.value?.profile_sizes?.[id]
  return {
    id,
    title: DEFAULT_TITLES[id],
    mode,
    tag,
    blobLabel: blob || 'глобальный',
    sniLabel,
    sizeLabel: size ? `${size} Б` : '',
  }
}))

function toggleRow(id: string) {
  if (expandedId.value === id) {
    expandedId.value = null
    return
  }
  if (id === '5') quicBlobDraft.value = savedQuicBlob.value
  else {
    const fresh = buildDraftFromStore(id)
    snapshots[id] = cloneDraft(fresh)
    drafts[id] = cloneDraft(fresh)
  }
  expandedId.value = id
}

function resetRow(id: string) {
  if (id === '5') {
    quicBlobDraft.value = savedQuicBlob.value
    return
  }
  const snap = snapshots[id]
  if (snap) drafts[id] = cloneDraft(snap)
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && expandedId.value) {
    expandedId.value = null
  }
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown))

function selectedSetDomains(setName: string): string[] {
  return sets.value.find((s) => s.name === setName)?.domains || []
}

function effectiveSizeValue(d: TlsProfileDraft): string {
  return d.sizePreset === 'custom' ? String(d.sizeCustom || '').trim() : d.sizePreset
}

function effectivePinValue(d: TlsProfileDraft): string {
  return d.pinPick === PIN_CUSTOM ? d.pinCustom.trim().toLowerCase() : d.pinPick
}

async function saveGlobalTls() {
  try {
    await withBusy('tls-global', async () => {
      announceRestart()
      const res = await applySetting.tls_blob(globalBlobDraft.value)
      showToast(`Глобальный TLS blob сохранён.${restartSuffix(res)}`)
      await Promise.all([refreshTlsBlobSettings(), refreshAll()])
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveGlobalCloneSize() {
  const raw = String(globalSizeDraft.value ?? '').trim()
  if (raw !== '') {
    const n = Number(raw)
    if (!Number.isInteger(n) || n < 64 || n > 1200) {
      showToast('Лимит клона должен быть 64-1200 байт или пусто', 'error')
      return
    }
  }
  try {
    await withBusy('clone-size-global', async () => {
      const res = await applySetting.clone_size_global(raw)
      showToast(`Глобальный лимит клонов сохранён.${restartSuffix(res)}`)
      await refreshTlsBlobSettings()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveQuicProfile() {
  try {
    await withBusy('prof-save-5', async () => {
      if (quicBlobDraft.value) announceRestart()
      const res = await applySetting.tls_blob_profile('5', quicBlobDraft.value)
      showToast(`Профиль 5 (QUIC) сохранён.${restartSuffix(res)}`)
      await refreshTlsBlobSettings()
      expandedId.value = null
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveTlsProfile(id: string) {
  const d = drafts[id]
  const orig = snapshots[id]
  if (!d || !orig) return

  const sizeVal = effectiveSizeValue(d)
  const origSizeVal = effectiveSizeValue(orig)
  if (sizeVal !== origSizeVal && sizeVal !== '') {
    const n = Number(sizeVal)
    if (!Number.isInteger(n) || n < 64 || n > 1200) {
      showToast('Лимит клона должен быть целым числом 64-1200 Б', 'error')
      return
    }
  }
  if (d.sniSource === 'pin' && !effectivePinValue(d)) {
    showToast('Укажите домен для SNI-пина', 'error')
    return
  }
  if (d.sniSource === 'set' && !d.set) {
    showToast('Выберите набор SNI для пула', 'error')
    return
  }
  if (d.sniSource === 'custom' && !d.customList.trim()) {
    showToast('Укажите хотя бы один домен в списке', 'error')
    return
  }

  try {
    await withBusy(`prof-save-${id}`, async () => {
      let restarted = false
      let restartNeeded = false

      if (d.mode !== orig.mode) {
        const res = await applySetting.fake_mode(id, d.mode)
        if (res.restarted) restarted = true
      }
      if (d.blob !== orig.blob) {
        if (d.blob) announceRestart()
        const res = await applySetting.tls_blob_profile(id, d.blob)
        if (res.restarted) restarted = true
        else if (res.restart_required) restartNeeded = true
      }
      if (sizeVal !== origSizeVal) {
        await applySetting.clone_size(id, sizeVal)
      }

      const sniChanged = !sniUnavailable.value && (
        d.sniSource !== orig.sniSource
        || (d.sniSource === 'pin' && effectivePinValue(d) !== effectivePinValue(orig))
        || (d.sniSource === 'set' && (d.set !== orig.set || d.policy !== orig.policy))
        || (d.sniSource === 'custom' && (d.customList !== orig.customList || d.policy !== orig.policy))
      )
      if (sniChanged) {
        const hadPin = orig.sniSource === 'pin'
        const hadPool = orig.sniSource === 'set' || orig.sniSource === 'custom'
        if (d.sniSource === 'pin') {
          await sni.pin(id, effectivePinValue(d))
        } else if (d.sniSource === 'set') {
          if (hadPin) await sni.pin(id, '')
          if (d.set !== orig.set || orig.sniSource !== 'set') await sni.assignSet(id, d.set)
          if (d.policy !== orig.policy || orig.sniSource !== 'set') await sni.policy(id, d.policy)
        } else if (d.sniSource === 'custom') {
          if (hadPin) await sni.pin(id, '')
          if (d.customList !== orig.customList || orig.sniSource !== 'custom') await sni.customList(id, d.customList)
          if (d.policy !== orig.policy || orig.sniSource !== 'custom') await sni.policy(id, d.policy)
        } else {
          if (hadPin) await sni.pin(id, '')
          if (hadPool) await sni.clearPool(id)
        }
      }

      await Promise.all([refreshSniState(), refreshTlsBlobSettings()])
      syncAll(true)
      const tail = restarted
        ? ' zapret2 перезапущен.'
        : restartNeeded ? ' Применится при следующем запуске zapret2.' : ' Изменения применены на лету.'
      showToast(`Профиль ${id} сохранён.${tail}`)
      expandedId.value = null
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}
</script>

<template>
  <div class="profiles-wrap">
    <section class="panel defaults-bar" aria-label="Глобальные значения по умолчанию">
      <div class="default-item">
        <label class="field">
          <span>Глобальный TLS blob</span>
          <select id="tls-global-blob" v-model="globalBlobDraft" :disabled="busyActive">
            <option value="fake_default_tls">fake_default_tls (встроенный)</option>
            <optgroup v-if="availableBlobs.length" label="Файлы (maxru)">
              <option v-for="b in availableBlobs" :key="b" :value="b">{{ b }}</option>
            </optgroup>
          </select>
        </label>
        <button
          id="tls-global-save"
          type="button"
          class="primary"
          :disabled="busyActive || !globalDirty"
          :class="{ 'is-busy': busyButton === 'tls-global' }"
          @click="saveGlobalTls"
        >
          Сохранить
        </button>
      </div>

      <div class="default-item">
        <label class="field">
          <span>Глобальный лимит клона (Б)</span>
          <input
            id="clone-size-global-input"
            v-model="globalSizeDraft"
            type="number"
            min="64"
            max="1200"
            placeholder="1200"
            :disabled="busyActive"
          >
        </label>
        <button
          type="button"
          :disabled="busyActive || !globalSizeDirty"
          :class="{ 'is-busy': busyButton === 'clone-size-global' }"
          @click="saveGlobalCloneSize"
        >
          Сохранить
        </button>
      </div>
    </section>

    <section class="panel" aria-label="Матрица профилей">
      <div class="panel-h">
        <div>
          <h2>Профили</h2>
          <p class="panel-hint">Нажмите на профиль, чтобы изменить режим, блоб или SNI</p>
        </div>
      </div>

      <div class="list-stack">
        <div
          v-for="row in rows"
          :id="`profile-row-${row.id}`"
          :key="row.id"
          class="matrix-item"
          :class="{ 'is-open': expandedId === row.id }"
        >
          <button
            type="button"
            class="matrix-summary"
            :aria-expanded="expandedId === row.id"
            @click="toggleRow(row.id)"
          >
            <span class="prof-id">{{ row.id }}</span>
            <strong class="prof-title">{{ row.title }}</strong>
            <span class="matrix-badges">
              <span class="chip mode-pill" :class="row.mode === 'clone' ? 'on' : ''">{{ row.tag }}</span>
              <span v-if="row.sizeLabel" class="chip size-pill">{{ row.sizeLabel }}</span>
            </span>
            <span class="meta-col">
              <span class="meta-k">блоб:</span>
              <code :class="{ accent: row.blobLabel !== 'глобальный' }">{{ row.blobLabel }}</code>
            </span>
            <span class="meta-col sni-col">
              <span class="meta-k">SNI:</span>
              <span>{{ row.sniLabel }}</span>
            </span>
            <span class="row-caret">
              <span>{{ expandedId === row.id ? 'Свернуть' : 'Настроить' }}</span>
              <Icon name="chevron-down" class="icon-sm row-caret-icon" :class="{ 'is-open': expandedId === row.id }" />
            </span>
          </button>

          <div v-if="expandedId === row.id && drafts[row.id]" class="matrix-editor">
            <div class="editor-block">
              <span class="field-caption">Режим фейков</span>
              <div class="seg-group" role="radiogroup" aria-label="Режим фейков">
                <button
                  type="button"
                  :class="{ active: drafts[row.id].mode === 'classic' }"
                  :disabled="busyActive"
                  @click="drafts[row.id].mode = 'classic'"
                >
                  Классика (blob)
                </button>
                <button
                  type="button"
                  :class="{ active: drafts[row.id].mode === 'clone' }"
                  :disabled="busyActive"
                  @click="drafts[row.id].mode = 'clone'"
                >
                  Клон (ClientHello + SNI)
                </button>
              </div>
            </div>

            <template v-if="drafts[row.id].mode === 'classic'">
              <label class="field">
                <span>TLS-блоб профиля</span>
                <select :id="`tls-blob-${row.id}`" v-model="drafts[row.id].blob" :disabled="busyActive">
                  <option value="">Как глобальный ({{ savedGlobalBlob }})</option>
                  <option value="fake_default_tls">fake_default_tls (встроенный)</option>
                  <option v-for="b in availableBlobs" :key="b" :value="b">{{ b }}</option>
                </select>
              </label>

              <details v-if="!sniUnavailable" class="extra-fold">
                <summary>SNI и размер клона (для встроенных клон-стратегий конфига)</summary>
                <div class="fold-body editor-block">
                  <div class="seg-group seg-sm" role="radiogroup" aria-label="Источник SNI">
                    <button type="button" :class="{ active: drafts[row.id].sniSource === 'set' }" @click="drafts[row.id].sniSource = 'set'">
                      Набор (пул)
                    </button>
                    <button type="button" :class="{ active: drafts[row.id].sniSource === 'pin' }" @click="drafts[row.id].sniSource = 'pin'">
                      Один SNI
                    </button>
                    <button type="button" :class="{ active: drafts[row.id].sniSource === 'custom' }" @click="drafts[row.id].sniSource = 'custom'">
                      Свой список
                    </button>
                    <button type="button" :class="{ active: drafts[row.id].sniSource === 'default' }" @click="drafts[row.id].sniSource = 'default'">
                      По умолчанию
                    </button>
                  </div>

                  <div v-if="drafts[row.id].sniSource === 'set'" class="sni-source-body">
                    <div class="grid-2">
                      <label class="field">
                        <span>Набор SNI</span>
                        <select :id="`sni-set-select-${row.id}`" v-model="drafts[row.id].set" :disabled="busyActive">
                          <option v-for="s in sets" :key="s.name" :value="s.name">
                            {{ s.name }} ({{ s.domains.length }} им., {{ s.origin === 'user' ? 'ваш' : 'zator' }})
                          </option>
                        </select>
                      </label>
                      <label class="field">
                        <span>Чередование</span>
                        <select :id="`sni-policy-${row.id}`" v-model="drafts[row.id].policy" :disabled="busyActive">
                          <option value="rr">По кругу (rr)</option>
                          <option value="rand">Случайно без повторов (rand)</option>
                        </select>
                      </label>
                    </div>
                    <div v-if="selectedSetDomains(drafts[row.id].set).length" class="preview-chips">
                      <span v-for="d in selectedSetDomains(drafts[row.id].set).slice(0, 8)" :key="d" class="chip">{{ d }}</span>
                      <span v-if="selectedSetDomains(drafts[row.id].set).length > 8" class="chip">
                        +{{ selectedSetDomains(drafts[row.id].set).length - 8 }}
                      </span>
                    </div>
                  </div>

                  <div v-else-if="drafts[row.id].sniSource === 'pin'" class="grid-2 sni-source-body">
                    <label class="field">
                      <span>Закреплённый SNI</span>
                      <select :id="`sni-pin-${row.id}`" v-model="drafts[row.id].pinPick" :disabled="busyActive">
                        <option v-for="preset in PIN_PRESETS" :key="preset" :value="preset">{{ preset }}</option>
                        <option :value="PIN_CUSTOM">Свой домен...</option>
                      </select>
                    </label>
                    <label v-if="drafts[row.id].pinPick === PIN_CUSTOM" class="field">
                      <span>Домен</span>
                      <input v-model.trim="drafts[row.id].pinCustom" type="text" placeholder="example.com" :disabled="busyActive">
                    </label>
                  </div>

                  <div v-else-if="drafts[row.id].sniSource === 'custom'" class="grid-2 sni-source-body">
                    <label class="field">
                      <span>Домены (до 32, по одному в строке)</span>
                      <textarea :id="`sni-custom-${row.id}`" v-model="drafts[row.id].customList" rows="3" :disabled="busyActive" />
                    </label>
                    <label class="field">
                      <span>Чередование</span>
                      <select v-model="drafts[row.id].policy" :disabled="busyActive">
                        <option value="rr">По кругу (rr)</option>
                        <option value="rand">Случайно без повторов (rand)</option>
                      </select>
                    </label>
                  </div>

                  <p v-else class="panel-d sni-default-note">
                    Используется невинный SNI по умолчанию (<code>www.google.com</code>).
                  </p>
                </div>
              </details>
            </template>

            <template v-else>
              <div v-if="!sniUnavailable" class="editor-block">
                <span class="field-caption">Источник SNI для клона</span>
                <div class="seg-group seg-sm" role="radiogroup" aria-label="Источник SNI">
                  <button type="button" :class="{ active: drafts[row.id].sniSource === 'set' }" @click="drafts[row.id].sniSource = 'set'">
                    Набор (пул)
                  </button>
                  <button type="button" :class="{ active: drafts[row.id].sniSource === 'pin' }" @click="drafts[row.id].sniSource = 'pin'">
                    Один SNI
                  </button>
                  <button type="button" :class="{ active: drafts[row.id].sniSource === 'custom' }" @click="drafts[row.id].sniSource = 'custom'">
                    Свой список
                  </button>
                  <button type="button" :class="{ active: drafts[row.id].sniSource === 'default' }" @click="drafts[row.id].sniSource = 'default'">
                    По умолчанию
                  </button>
                </div>

                <div v-if="drafts[row.id].sniSource === 'set'" class="sni-source-body">
                  <div class="grid-2">
                    <label class="field">
                      <span>Набор SNI</span>
                      <select :id="`sni-set-select-${row.id}`" v-model="drafts[row.id].set" :disabled="busyActive">
                        <option v-for="s in sets" :key="s.name" :value="s.name">
                          {{ s.name }} ({{ s.domains.length }} им., {{ s.origin === 'user' ? 'ваш' : 'zator' }})
                        </option>
                      </select>
                    </label>
                    <label class="field">
                      <span>Чередование</span>
                      <select :id="`sni-policy-${row.id}`" v-model="drafts[row.id].policy" :disabled="busyActive">
                        <option value="rr">По кругу (rr)</option>
                        <option value="rand">Случайно без повторов (rand)</option>
                      </select>
                    </label>
                  </div>
                  <div v-if="selectedSetDomains(drafts[row.id].set).length" class="preview-chips">
                    <span v-for="d in selectedSetDomains(drafts[row.id].set).slice(0, 8)" :key="d" class="chip">{{ d }}</span>
                    <span v-if="selectedSetDomains(drafts[row.id].set).length > 8" class="chip">
                      +{{ selectedSetDomains(drafts[row.id].set).length - 8 }}
                    </span>
                  </div>
                </div>

                <div v-else-if="drafts[row.id].sniSource === 'pin'" class="grid-2 sni-source-body">
                  <label class="field">
                    <span>Закреплённый SNI</span>
                    <select :id="`sni-pin-${row.id}`" v-model="drafts[row.id].pinPick" :disabled="busyActive">
                      <option v-for="preset in PIN_PRESETS" :key="preset" :value="preset">{{ preset }}</option>
                      <option :value="PIN_CUSTOM">Свой домен...</option>
                    </select>
                  </label>
                  <label v-if="drafts[row.id].pinPick === PIN_CUSTOM" class="field">
                    <span>Домен</span>
                    <input v-model.trim="drafts[row.id].pinCustom" type="text" placeholder="example.com" :disabled="busyActive">
                  </label>
                </div>

                <div v-else-if="drafts[row.id].sniSource === 'custom'" class="grid-2 sni-source-body">
                  <label class="field">
                    <span>Домены (до 32, по одному в строке)</span>
                    <textarea :id="`sni-custom-${row.id}`" v-model="drafts[row.id].customList" rows="3" :disabled="busyActive" />
                  </label>
                  <label class="field">
                    <span>Чередование</span>
                    <select v-model="drafts[row.id].policy" :disabled="busyActive">
                      <option value="rr">По кругу (rr)</option>
                      <option value="rand">Случайно без повторов (rand)</option>
                    </select>
                  </label>
                </div>

                <p v-else class="panel-d sni-default-note">
                  Используется невинный SNI по умолчанию (<code>www.google.com</code>).
                </p>
              </div>

              <details class="extra-fold">
                <summary>Дополнительно: размер клона и запасной TLS-блоб</summary>
                <div class="grid-2 fold-body">
                  <label class="field">
                    <span>Лимит клона (Б)</span>
                    <div class="size-pair">
                      <select :id="`clone-size-${row.id}`" v-model="drafts[row.id].sizePreset" :disabled="busyActive">
                        <option value="">По глобальному ({{ savedGlobalCloneSize || '1200' }} Б)</option>
                        <option v-for="preset in CLONE_SIZE_PRESETS" :key="preset" :value="preset">{{ preset }} Б</option>
                        <option value="custom">Свой (64-1200 Б)</option>
                      </select>
                      <input
                        v-if="drafts[row.id].sizePreset === 'custom'"
                        v-model="drafts[row.id].sizeCustom"
                        type="number"
                        min="64"
                        max="1200"
                        :disabled="busyActive"
                        placeholder="768"
                      >
                    </div>
                  </label>
                  <label class="field">
                    <span>Запасной TLS-блоб (fallback классики)</span>
                    <select v-model="drafts[row.id].blob" :disabled="busyActive">
                      <option value="">Как глобальный ({{ savedGlobalBlob }})</option>
                      <option value="fake_default_tls">fake_default_tls</option>
                      <option v-for="b in availableBlobs" :key="b" :value="b">{{ b }}</option>
                    </select>
                  </label>
                </div>
              </details>
            </template>

            <div class="actions editor-actions">
              <button
                type="button"
                class="primary"
                :disabled="busyActive || !isProfileDirty(row.id)"
                :class="{ 'is-busy': busyButton === `prof-save-${row.id}` }"
                @click="saveTlsProfile(row.id)"
              >
                Сохранить профиль
              </button>
              <button type="button" class="ghost" :disabled="busyActive || !isProfileDirty(row.id)" @click="resetRow(row.id)">
                Сбросить
              </button>
              <button type="button" class="ghost" @click="expandedId = null">Свернуть</button>
            </div>
          </div>
        </div>

        <div id="profile-row-5" class="matrix-item" :class="{ 'is-open': expandedId === '5' }">
          <button
            type="button"
            class="matrix-summary"
            :aria-expanded="expandedId === '5'"
            @click="toggleRow('5')"
          >
            <span class="prof-id">5</span>
            <strong class="prof-title">YouTube QUIC (UDP 443)</strong>
            <span class="matrix-badges">
              <span class="chip mode-pill">quic</span>
            </span>
            <span class="meta-col">
              <span class="meta-k">блоб:</span>
              <code :class="{ accent: !!savedQuicBlob }">{{ savedQuicBlob || 'как в конфиге' }}</code>
            </span>
            <span class="meta-col sni-col">
              <span class="meta-k">SNI:</span>
              <span>-</span>
            </span>
            <span class="row-caret">
              <span>{{ expandedId === '5' ? 'Свернуть' : 'Настроить' }}</span>
              <Icon name="chevron-down" class="icon-sm row-caret-icon" :class="{ 'is-open': expandedId === '5' }" />
            </span>
          </button>

          <div v-if="expandedId === '5'" class="matrix-editor">
            <label class="field">
              <span>QUIC-блоб профиля 5 (UDP 443)</span>
              <select id="tls-blob-quic-5" v-model="quicBlobDraft" :disabled="busyActive">
                <option value="">Как в стратегиях конфига</option>
                <option v-for="b in quicOptions" :key="b" :value="b">{{ b }}</option>
              </select>
            </label>
            <div class="actions editor-actions">
              <button
                id="tls-blob-quic-5-save"
                type="button"
                class="primary"
                :disabled="busyActive || !quicDirty"
                :class="{ 'is-busy': busyButton === 'prof-save-5' }"
                @click="saveQuicProfile"
              >
                Сохранить профиль
              </button>
              <button type="button" class="ghost" :disabled="busyActive || !quicDirty" @click="resetRow('5')">Сбросить</button>
              <button type="button" class="ghost" @click="expandedId = null">Свернуть</button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.profiles-wrap { display: grid; gap: 0.9rem; }
.defaults-bar {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.9rem;
  align-items: end;
}
.default-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.5rem;
  align-items: end;
}
.matrix-item {
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  background: var(--surface-2);
  transition: border-color 150ms var(--ease), background-color 150ms var(--ease);
}
.matrix-item.is-open {
  border-color: color-mix(in srgb, var(--accent) 46%, var(--line));
  background: var(--surface);
}
.matrix-summary {
  width: 100%;
  display: grid;
  grid-template-columns: 1.85rem minmax(8.5rem, 10.5rem) minmax(5.8rem, auto) minmax(8rem, 1fr) minmax(8rem, 1fr) auto;
  align-items: center;
  gap: 0.65rem;
  padding: 0.68rem 0.85rem;
  border: 0;
  background: transparent;
  text-align: left;
  border-radius: var(--radius-md);
  font-weight: 400;
}
.matrix-summary:hover:not(:disabled) {
  background: var(--surface-hover);
  border-color: transparent;
}
.prof-title {
  font-size: 0.88rem;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.matrix-badges {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
}
.mode-pill,
.size-pill { font-size: 0.72rem; }
.meta-col {
  min-width: 0;
  font-size: 0.8rem;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.meta-k { margin-right: 0.25rem; opacity: 0.85; }
.meta-col code {
  background: transparent;
  padding: 0;
  color: var(--ink);
  font-size: 0.78rem;
}
.meta-col code.accent { color: var(--accent); font-weight: 600; }
.row-caret {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  color: var(--muted);
  font-size: 0.78rem;
  white-space: nowrap;
  justify-self: end;
}
.row-caret-icon {
  transition: transform 180ms var(--ease);
}
.row-caret-icon.is-open {
  transform: rotate(180deg);
}

.matrix-editor {
  display: grid;
  gap: 0.85rem;
  padding: 0.9rem 0.95rem 1rem;
  border-top: 1px solid var(--line);
}
.editor-block { display: grid; gap: 0.45rem; }
.sni-source-body { margin-top: 0.2rem; }
.sni-default-note { margin: 0.35rem 0 0; }
.preview-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.5rem; }
.extra-fold summary { cursor: pointer; color: var(--muted); font-size: 0.8rem; }
.fold-body { margin-top: 0.55rem; }
.size-pair { display: flex; gap: 0.45rem; }
.size-pair > input { max-width: 6.5rem; }
.editor-actions { padding-top: 0.25rem; }

@media (max-width: 960px) {
  .defaults-bar { grid-template-columns: 1fr; }
  .matrix-summary {
    grid-template-columns: 1.85rem minmax(0, 1fr) auto;
    grid-auto-rows: auto;
  }
  .matrix-badges,
  .meta-col { grid-column: 2 / -1; }
  .row-caret { grid-column: 3; grid-row: 1; }
}
</style>
