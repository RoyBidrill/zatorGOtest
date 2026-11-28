<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { customStrats } from '../api/endpoints'
import type { CustomBlockInfo, CustomStrategy } from '../api/types'
import { busyActive, busyButton, withBusy } from '../stores/busy'
import { confirmDialog } from '../stores/confirm'
import { customBlocks, customStrategies, customStratsLoaded, refreshCustomStrats } from '../stores/customStrats'
import { refreshAll } from '../stores/status'
import { announceRestart, restartSuffix, showToast } from '../stores/toast'
import Icon from '../components/ui/Icon.vue'

const filter = ref('')
const hasDirty = ref(false)
const importOpen = ref(false)
const formOpen = ref(false)
const modalVisible = ref(false)
const editId = ref<number | null>(null)
const formBlock = ref('p5')
const formSpec = ref('')
const formComment = ref('')
const formError = ref('')
const specField = ref<HTMLTextAreaElement | null>(null)
const original = ref({ block: '', spec: '', comment: '' })

const importBlock = ref('tpl')
const importText = ref('')
const importErrors = ref<{ line: string; reason: string }[]>([])
const importNotes = ref<string[]>([])

const EXAMPLES: Record<string, { single: string; combo: string }> = {
  tcp: {
    single: 'fake:blob=maxru:tcp_md5:pos=2:repeats=2',
    combo: 'multisplit:blob=maxru:tcp_md5:pos=2:nodrop --lua-desync=fakeddisorder:pos=midsld:tcp_md5:nofake3',
  },
  udp: {
    single: 'fake:blob=quic_google:ipfrag:ipfrag_pos_udp=8:ipfrag_disorder:repeats=6:out_range=-d10',
    combo: 'send:repeats=2:ip_autottl=1,3-20 --lua-desync=fake:blob=0x00:repeats=4:out_range=-d10',
  },
}

const filtered = computed(() =>
  filter.value ? customStrategies.value.filter((s) => s.block === filter.value) : customStrategies.value)

const pendingCount = computed(() =>
  customStrategies.value.filter((s) => s.enabled && !s.assigned).length)

const needsApplyBanner = computed(() => pendingCount.value > 0 || hasDirty.value)

function blockCount(block: string): number {
  return customStrategies.value.filter((s) => s.block === block).length
}

function blockInfo(block: string): CustomBlockInfo | undefined {
  return customBlocks.value.find((b) => b.block === block)
}

const formExamples = computed(() => {
  const tr = blockInfo(formBlock.value)?.transport
  return EXAMPLES[tr === 'udp' ? 'udp' : 'tcp']
})

const saveDisabled = computed(() => {
  const spec = formSpec.value.trim()
  if (busyActive.value) return true
  if (editId.value === null) return !spec
  return formBlock.value === original.value.block
    && spec === original.value.spec
    && formComment.value.trim() === original.value.comment
})

async function load() {
  await refreshCustomStrats('')
}

async function refresh() {
  try {
    await withBusy('refresh-custom-strats', load)
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

onMounted(refresh)

function highlightRow(id: number) {
  nextTick(() => {
    const el = document.getElementById(`custom-strat-row-${id}`)
    if (!el) return
    el.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    el.classList.add('is-target')
    window.setTimeout(() => el.classList.remove('is-target'), 5000)
  })
}

function openAdd() {
  editId.value = null
  formBlock.value = filter.value || customBlocks.value[0]?.block || 'p5'
  formSpec.value = ''
  formComment.value = ''
  formError.value = ''
  original.value = { block: formBlock.value, spec: '', comment: '' }
  formOpen.value = true
}

function openEdit(item: CustomStrategy) {
  editId.value = item.id
  formBlock.value = item.block
  formSpec.value = item.spec
  formComment.value = item.comment
  formError.value = ''
  original.value = { block: item.block, spec: item.spec, comment: item.comment }
  formOpen.value = true
}

function cancelForm() {
  formOpen.value = false
  formError.value = ''
}

watch(formOpen, (open) => {
  if (!open) return
  modalVisible.value = false
  requestAnimationFrame(() => {
    modalVisible.value = true
    nextTick(() => specField.value?.focus())
  })
})

function onKeydown(event: KeyboardEvent) {
  if (!formOpen.value) return
  if (event.key === 'Escape') {
    event.preventDefault()
    cancelForm()
  }
}
onMounted(() => document.addEventListener('keydown', onKeydown, true))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown, true))

async function saveForm() {
  const spec = formSpec.value.trim()
  if (!spec) {
    formError.value = 'Пустая стратегия.'
    return
  }
  formError.value = ''
  const wasEdit = editId.value !== null
  const targetId = editId.value
  try {
    await withBusy(wasEdit ? `custom-edit-${targetId}` : 'custom-add', async () => {
      let newId: number | null = null
      if (wasEdit) {
        await customStrats.edit(String(targetId), formBlock.value, spec, formComment.value.trim())
      } else {
        const res = await customStrats.add(formBlock.value, spec, formComment.value.trim())
        newId = typeof res?.id === 'number' ? res.id : null
      }
      formOpen.value = false
      hasDirty.value = true
      if (!wasEdit && filter.value && filter.value !== formBlock.value) filter.value = ''
      showToast(wasEdit
        ? `Запись #${targetId} изменена. Нажмите «Применить к конфигу».`
        : 'Стратегия добавлена. Нажмите «Применить к конфигу».')
      await load()
      if (wasEdit) highlightRow(targetId as number)
      else if (newId !== null) highlightRow(newId)
    })
  } catch (e) {
    formError.value = (e as Error).message
  }
}

async function toggleEnabled(item: CustomStrategy) {
  try {
    await withBusy(`custom-enable-${item.id}`, async () => {
      await customStrats.enable(String(item.id), !item.enabled)
      hasDirty.value = true
      showToast(item.enabled
        ? `Запись #${item.id} выключена.`
        : `Запись #${item.id} включена. Нажмите «Применить к конфигу».`)
      await load()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function removeItem(item: CustomStrategy) {
  const ok = await confirmDialog({
    title: `Удалить стратегию #${item.id}?`,
    message: 'При следующем применении номера оставшихся записей будут переназначены, а локи перенесены.',
    confirmText: 'Удалить',
    danger: true,
  })
  if (!ok) return
  try {
    await withBusy(`custom-delete-${item.id}`, async () => {
      await customStrats.remove(String(item.id))
      hasDirty.value = true
      showToast('Удалено. Нажмите «Применить к конфигу».')
      await load()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function importLines() {
  if (!importText.value.trim()) {
    showToast('Вставьте строки для импорта.', 'warning')
    return
  }
  try {
    await withBusy('custom-import', async () => {
      const res = await customStrats.import(importBlock.value, importText.value)
      importErrors.value = Array.isArray(res?.errors) ? res.errors : []
      importNotes.value = Array.isArray(res?.notes) ? res.notes : []
      if ((res?.added ?? 0) > 0) hasDirty.value = true
      if (importErrors.value.length || importNotes.value.length) importOpen.value = true
      showToast(
        `Импорт: добавлено ${res?.added ?? 0}, дубликатов ${res?.dups ?? 0}, пропущено ${res?.skipped ?? 0}.`
        + (importNotes.value.length ? ` Замен блобов: ${importNotes.value.length}.` : ''),
      )
      const total = res?.total ?? 0
      const limit = res?.limit ?? 256
      if (total > limit) {
        showToast(`Обработаны первые ${limit} из ${total} строк; остальные импортируйте отдельно.`, 'warning')
      }
      importText.value = ''
      await load()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function applyToConfig() {
  const ok = await confirmDialog({
    title: 'Применить свои стратегии к конфигу?',
    message: 'Стратегии будут встроены в config zapret2 с автоматической нумерацией, активные локи перенесены, служба перезапустится.',
    confirmText: 'Применить',
  })
  if (!ok) return
  try {
    await withBusy('custom-apply', async () => {
      announceRestart()
      const res = await customStrats.apply()
      hasDirty.value = false
      const remapBits: string[] = []
      if (res?.moved) remapBits.push(`перенесено локов: ${res.moved}`)
      if (res?.dropped) remapBits.push(`сброшено локов: ${res.dropped}`)
      const extra = remapBits.length ? ` (${remapBits.join(', ')})` : ''
      showToast(`Применено${extra}.${restartSuffix(res)}`)
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
        <span class="eyebrow">Конструктор zapret2</span>
        <h1>Свои стратегии</h1>
        <p>Добавление, редактирование, пакетный импорт из blockcheck2 и безопасный инжект в конфиг с сохранением локов.</p>
      </div>
      <div class="actions">
        <button
          id="custom-strat-add-btn"
          type="button"
          :class="{ primary: !needsApplyBanner }"
          :disabled="busyActive"
          @click="openAdd"
        >
          <Icon name="plus" class="icon-sm" />
          <span>Добавить стратегию</span>
        </button>
        <button
          id="refresh-custom-strats"
          type="button"
          :class="{ 'is-busy': busyButton === 'refresh-custom-strats' }"
          :disabled="busyActive"
          @click="refresh"
        >
          <Icon name="refresh" class="icon-sm" />
          <span>Обновить</span>
        </button>
      </div>
    </div>

    <div
      v-if="customStratsLoaded && needsApplyBanner"
      class="notice-banner is-warn"
      role="region"
      aria-label="Неприменённые изменения стратегий"
    >
      <span>Есть неприменённые изменения своих стратегий: запишите их в конфиг zapret2.</span>
      <button
        id="custom-apply-btn"
        type="button"
        class="primary"
        :class="{ 'is-busy': busyButton === 'custom-apply' }"
        :disabled="busyActive || (!customStrategies.length && !hasDirty)"
        @click="applyToConfig"
      >
        Применить к конфигу{{ pendingCount ? ` (${pendingCount})` : '' }}
      </button>
    </div>

    <div class="tabs-bar" role="tablist" aria-label="Фильтр по блокам">
      <button
        type="button"
        role="tab"
        :aria-selected="filter === ''"
        class="tab-pill"
        :class="{ active: filter === '' }"
        @click="filter = ''"
      >
        Все <span class="tab-count">{{ customStrategies.length }}</span>
      </button>
      <button
        v-for="b in customBlocks"
        :key="b.block"
        type="button"
        role="tab"
        :aria-selected="filter === b.block"
        class="tab-pill"
        :class="{ active: filter === b.block }"
        :title="`${b.label} (профили ${b.profiles})`"
        @click="filter = b.block"
      >
        {{ b.block }} <span class="tab-count">{{ blockCount(b.block) }}</span>
      </button>
    </div>

    <div v-if="!customStratsLoaded" class="skeleton-list" aria-label="Загрузка пользовательских стратегий">
      <div v-for="i in 4" :key="i" class="skeleton-row" />
    </div>
    <template v-else>
      <section id="custom-strats-panel" class="panel">
        <div class="panel-h">
          <div class="panel-title-group">
            <h2>Список пользовательских стратегий</h2>
            <span class="chip" :class="{ on: customStrategies.length > 0 }">{{ filtered.length }}</span>
          </div>
          <div class="actions">
            <button
              v-if="!needsApplyBanner"
              id="custom-apply-btn"
              type="button"
              class="ghost compact-btn"
              :class="{ 'is-busy': busyButton === 'custom-apply' }"
              :disabled="busyActive || (!customStrategies.length && !hasDirty)"
              @click="applyToConfig"
            >
              Применить к конфигу
            </button>
            <button
              type="button"
              class="ghost compact-btn"
              :disabled="busyActive"
              @click="importOpen = !importOpen"
            >
              {{ importOpen ? 'Скрыть импорт' : 'Импорт списком' }}
            </button>
          </div>
        </div>

        <section v-show="importOpen" id="custom-import-panel" class="import-drawer" aria-label="Пакетный импорт">
          <div class="panel-h">
            <div>
              <h3>Пакетный импорт (blockcheck2 / nfqws2)</h3>
              <p class="panel-sub">Вставьте строки из SUMMARY blockcheck2, команды nfqws2 или готовые <code>--lua-desync=...</code>.</p>
            </div>
            <span class="chip">до 256 записей</span>
          </div>

          <div class="grid-2 import-block-row">
            <label class="field">
              <span>Целевой блок</span>
              <select id="custom-import-block" v-model="importBlock" :disabled="busyActive">
                <option v-for="b in customBlocks" :key="b.block" :value="b.block">
                  {{ b.block }} - {{ b.label }} (профили {{ b.profiles }})
                </option>
              </select>
            </label>
          </div>

          <label class="field">
            <span>Строки стратегий</span>
            <textarea
              id="custom-import-text"
              v-model="importText"
              rows="5"
              :disabled="busyActive"
              placeholder="nfqws2 --lua-desync=fake:blob=fake_default_tls:repeats=2 --lua-desync=multisplit:pos=1,midsld"
            />
          </label>

          <div class="actions">
            <button
              id="custom-import-btn"
              type="button"
              class="primary compact-btn"
              :class="{ 'is-busy': busyButton === 'custom-import' }"
              :disabled="busyActive || !importText.trim()"
              @click="importLines"
            >
              Импортировать
            </button>
            <button type="button" class="ghost compact-btn" :disabled="busyActive" @click="importOpen = false">Скрыть</button>
          </div>

          <div v-if="importNotes.length" class="import-feedback">
            <strong>Замены блобов:</strong>
            <ul>
              <li v-for="(n, i) in importNotes" :key="i">{{ n }}</li>
            </ul>
          </div>
          <div v-if="importErrors.length" class="import-feedback is-error">
            <strong>Отклонённые строки ({{ importErrors.length }}):</strong>
            <ul>
              <li v-for="(err, i) in importErrors" :key="i">
                <code>{{ err.line }}</code> - {{ err.reason }}
              </li>
            </ul>
          </div>
        </section>

        <div v-if="!filtered.length" class="empty-state">
          <strong>Стратегий пока нет</strong>
          <p>В выбранном фильтре нет записей. Нажмите «Добавить стратегию» или откройте «Импорт списком».</p>
        </div>
        <div v-else class="list-stack">
          <article
            v-for="item in filtered"
            :id="`custom-strat-row-${item.id}`"
            :key="item.id"
            class="list-row strat-row"
            :class="{ 'is-muted': !item.enabled }"
          >
            <div class="strat-row-top">
              <div class="strat-head">
                <span class="chip">ID {{ item.id }}</span>
                <span class="chip is-info">{{ item.block }}</span>
                <span v-if="!item.enabled" class="chip">выкл</span>
                <span v-else-if="item.assigned" class="chip on">#{{ item.assigned }}</span>
                <span v-else class="chip is-pending">не применена</span>
                <span v-if="item.comment" class="strat-comment">{{ item.comment }}</span>
              </div>
              <div class="actions">
                <button
                  type="button"
                  class="ghost compact-btn"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === `custom-enable-${item.id}` }"
                  @click="toggleEnabled(item)"
                >
                  {{ item.enabled ? 'Выключить' : 'Включить' }}
                </button>
                <button
                  type="button"
                  class="ghost icon-btn"
                  aria-label="Изменить"
                  title="Изменить"
                  :disabled="busyActive"
                  @click="openEdit(item)"
                >
                  <Icon name="pencil" class="icon-sm" />
                </button>
                <button
                  type="button"
                  class="ghost danger icon-btn"
                  aria-label="Удалить"
                  title="Удалить"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === `custom-delete-${item.id}` }"
                  @click="removeItem(item)"
                >
                  <Icon name="trash" class="icon-sm" />
                </button>
              </div>
            </div>
            <pre class="code-block">{{ item.spec }}</pre>
          </article>
        </div>
      </section>

      <div
        v-if="formOpen"
        :class="['modal-overlay', { 'is-visible': modalVisible }]"
        role="dialog"
        aria-modal="true"
        @click.self="cancelForm"
      >
        <form id="custom-strat-form" class="modal-card modal-wide" @submit.prevent="saveForm">
          <h3 class="modal-title">{{ editId === null ? 'Новая стратегия' : `Стратегия #${editId}` }}</h3>
          <div class="modal-fields">
            <label class="field">
              <span>Блок</span>
              <select id="custom-strat-block" v-model="formBlock" :disabled="busyActive">
                <option v-for="b in customBlocks" :key="b.block" :value="b.block">
                  {{ b.block }} - {{ b.label }} ({{ b.transport.toUpperCase() }})
                </option>
              </select>
            </label>
            <label class="field">
              <span>Спецификация desync</span>
              <textarea
                id="custom-strat-spec"
                ref="specField"
                v-model="formSpec"
                rows="4"
                :disabled="busyActive"
                placeholder="fake:blob=maxru:tcp_md5:pos=2:repeats=2"
              />
            </label>
            <div class="example-box">
              <span>Пример: <code>{{ formExamples.single }}</code></span>
              <button
                type="button"
                class="ghost compact-btn example-btn"
                :disabled="busyActive"
                @click="formSpec = formExamples.single; formError = ''"
              >
                Вставить пример
              </button>
              <div>Комбо: <code>{{ formExamples.combo }}</code></div>
            </div>
            <label class="field">
              <span>Комментарий (необязательно)</span>
              <input id="custom-strat-comment" v-model="formComment" type="text" maxlength="64" :disabled="busyActive">
            </label>
            <p v-if="formError" id="custom-strat-error" class="err-hint" role="alert">{{ formError }}</p>
          </div>
          <div class="modal-actions">
            <button id="custom-strat-cancel" type="button" class="ghost" :disabled="busyActive" @click="cancelForm">Отмена</button>
            <button
              id="custom-strat-save"
              type="submit"
              class="primary"
              :class="{ 'is-busy': busyButton === (editId === null ? 'custom-add' : `custom-edit-${editId}`) }"
              :disabled="saveDisabled"
            >
              {{ editId === null ? 'Добавить' : 'Сохранить' }}
            </button>
          </div>
        </form>
      </div>
    </template>
  </section>
</template>

<style scoped>
.panel-title-group {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}
.import-drawer {
  display: grid;
  gap: 0.75rem;
  margin-bottom: 0.95rem;
  padding: 0.9rem 0.95rem;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius-md);
  background: var(--surface-2);
}
.import-drawer h3 {
  margin: 0;
  font-size: 0.95rem;
  font-weight: 700;
}
.import-block-row { margin-bottom: 0; }
.strat-row-top {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.45rem 0.75rem;
}
.strat-head { display: flex; flex-wrap: wrap; gap: 0.35rem; align-items: center; }
.strat-comment { color: var(--muted); font-size: 0.84rem; }
.import-feedback {
  padding: 0.65rem 0.78rem;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line);
  background: var(--surface);
  font-size: 0.82rem;
}
.import-feedback.is-error {
  border-color: color-mix(in srgb, var(--danger) 42%, var(--line));
}
.import-feedback ul { margin: 0.35rem 0 0; padding-left: 1.2rem; }
.example-box {
  font-size: 0.78rem;
  color: var(--muted);
  display: grid;
  gap: 0.35rem;
}
.example-box code { overflow-wrap: anywhere; }
.example-btn { width: fit-content; }
</style>
