<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { domains } from '../api/endpoints'
import type { DomainItem } from '../api/types'
import { busyActive, busyButton, withBusy } from '../stores/busy'
import {
  DOMAIN_LISTS, DOMAIN_META, MAIN_DOMAIN_LISTS, domainChecks, domainLists, domainsLoaded,
  refreshDomainList, refreshDomains, type DomainListName,
} from '../stores/domains'
import { modeSettings } from '../stores/settings'
import { scope, scopes } from '../stores/status'
import { confirmDialog } from '../stores/confirm'
import { showToast } from '../stores/toast'
import Icon from '../components/ui/Icon.vue'

const route = useRoute()
const router = useRouter()

const input = ref('')
const bulk = ref('')
const importOpen = ref(false)
const searchInput = ref('')
const searchTerm = ref('')
const page = ref(1)
const strategyDraft = ref<Record<string, string>>({})
const renaming = ref('')
const renameValue = ref('')
let searchTimer: number | undefined

const labels: Record<DomainListName, string> = {
  netrogat: 'Исключения',
  custom_rkn: 'TCP Custom',
  substring: 'Подстроки RKN',
  netrogat_substring: 'Искл. подстрок',
  googlevideo: 'Googlevideo',
}

const active = computed<DomainListName>(() => {
  const p = String(route.params.list || 'netrogat')
  return (DOMAIN_LISTS as readonly string[]).includes(p) ? p as DomainListName : 'netrogat'
})
const isGooglevideo = computed(() => active.value === 'googlevideo')
const list = computed(() => domainLists[active.value])
const meta = computed(() => DOMAIN_META[active.value])
const hostlistAuto = computed(() => !!modeSettings.hostlist?.auto)
const autoLocked = computed(() => hostlistAuto.value && (active.value === 'custom_rkn' || active.value === 'substring'))
const scopeOptions = computed(() => scopes.value.scopes || ['default'])

const pageSize = 100
const filteredItems = computed(() => {
  const needle = searchTerm.value.trim().toLocaleLowerCase()
  const items = list.value?.items || []
  return needle ? items.filter((item) => item.value.toLocaleLowerCase().includes(needle)) : items
})
const pageCount = computed(() => Math.max(1, Math.ceil(filteredItems.value.length / pageSize)))
const visibleItems = computed(() => filteredItems.value.slice((page.value - 1) * pageSize, page.value * pageSize))

onMounted(() => {
  if (!domainsLoaded.value) void refreshDomains()
})
onUnmounted(() => {
  if (searchTimer !== undefined) window.clearTimeout(searchTimer)
})

watch(active, (name) => {
  page.value = 1
  renaming.value = ''
  importOpen.value = false
  if (!domainLists[name]) void refreshDomainList(name)
})
watch(searchInput, (value) => {
  if (searchTimer !== undefined) window.clearTimeout(searchTimer)
  searchTimer = window.setTimeout(() => {
    searchTerm.value = value
    page.value = 1
  }, 160)
})
watch(pageCount, (count) => { if (page.value > count) page.value = count })
watch(scope, () => {
  void refreshDomainList('custom_rkn')
  if (isGooglevideo.value) void refreshDomainList('googlevideo')
})

watch(list, (payload) => {
  if (!payload?.items) return
  const next: Record<string, string> = { ...strategyDraft.value }
  const alive = new Set(payload.items.map((i) => i.value))
  for (const key of Object.keys(next)) {
    if (!alive.has(key)) delete next[key]
  }
  for (const item of payload.items) {
    if (next[item.value] === undefined) {
      next[item.value] = item.strategy != null ? String(item.strategy) : ''
    } else if (!String(next[item.value] ?? '').trim() && item.strategy != null) {
      next[item.value] = String(item.strategy)
    }
  }
  strategyDraft.value = next
}, { deep: true, immediate: true })

function listCount(name: DomainListName): number {
  return domainLists[name]?.items?.length ?? 0
}

function go(name: DomainListName) {
  void router.push({ path: `/domains/${name}`, query: route.query })
}

function changeScope(v: string) {
  scope.value = v || 'default'
  void router.replace({ query: { ...route.query, scope: scope.value } })
}

function strategyDirty(item: DomainItem): boolean {
  const cur = item.strategy != null ? String(item.strategy) : ''
  const raw = String(strategyDraft.value[item.value] ?? '').trim()
  return raw !== cur
}

function beginRename(domain: string) {
  renaming.value = domain
  renameValue.value = domain
}

async function rename(domain: string) {
  const value = renameValue.value.trim()
  if (!value || value === domain) {
    renaming.value = ''
    return
  }
  try {
    await withBusy(`domain-rename-${domain}`, async () => {
      await domains.rename(active.value, domain, value, scope.value)
      renaming.value = ''
      await refreshDomainList(active.value)
    })
    showToast('Запись переименована')
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function add() {
  const d = input.value.trim()
  if (!d) return
  try {
    await withBusy('domain-add', async () => {
      await domains.add(active.value, d, scope.value)
      input.value = ''
      await refreshDomainList(active.value)
    })
    showToast('Добавлено')
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function remove(domain: string) {
  if (autoLocked.value) return
  const ok = await confirmDialog({
    title: 'Удалить запись?',
    message: `Удалить «${domain}» из списка?`,
    danger: true,
    confirmText: 'Удалить',
  })
  if (!ok) return
  try {
    await withBusy('domain-rm', async () => {
      const res = await domains.remove(active.value, domain, scope.value)
      delete strategyDraft.value[domain]
      await refreshDomainList(active.value)
      const warn = String((res as { warning?: string }).warning || '')
      if (warn) showToast(warn, 'warning')
      else showToast('Удалено')
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function importList() {
  if (!bulk.value.trim()) return
  try {
    await withBusy('domain-import', async () => {
      const res = await domains.import(active.value, bulk.value, scope.value)
      bulk.value = ''
      importOpen.value = false
      await refreshDomainList(active.value)
      showToast(`Импорт: +${res.added || 0}`)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function refreshLists() {
  try {
    await withBusy('domains-refresh', async () => {
      if (isGooglevideo.value) {
        await domains.refresh('googlevideo', scope.value)
        await refreshDomainList('googlevideo')
      } else {
        await refreshDomains()
      }
    })
    if (isGooglevideo.value) showToast('Список googlevideo обновлён')
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function setStrategy(domain: string) {
  const raw = String(strategyDraft.value[domain] ?? '').trim()
  if (raw && (!/^\d+$/.test(raw) || Number(raw) < 0)) {
    showToast('Некорректный номер стратегии', 'error')
    return
  }
  try {
    await withBusy(`domain-st-${domain}`, async () => {
      if (!raw || raw === '0') {
        await domains.clear_strategy(domain, scope.value)
        strategyDraft.value[domain] = ''
      } else {
        await domains.set_strategy(domain, raw, scope.value)
        strategyDraft.value[domain] = raw
      }
      await refreshDomainList(active.value)
      showToast((!raw || raw === '0') ? `Стратегия снята с ${domain}` : `Стратегия #${raw} для ${domain}`)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function clearStrategy(domain: string) {
  try {
    await withBusy(`domain-st-clear-${domain}`, async () => {
      await domains.clear_strategy(domain, scope.value)
      strategyDraft.value[domain] = ''
      await refreshDomainList(active.value)
      showToast(`Стратегия снята с ${domain}`)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function clearAll() {
  if (autoLocked.value) return
  const ok = await confirmDialog({
    title: 'Очистить список?',
    message: isGooglevideo.value
      ? 'Все собранные googlevideo-хосты будут удалены.'
      : 'Все записи этого списка будут удалены.',
    danger: true,
    confirmText: 'Очистить',
  })
  if (!ok) return
  try {
    await withBusy('domain-clear', async () => {
      const res = await domains.clear(active.value, scope.value)
      strategyDraft.value = {}
      await refreshDomainList(active.value)
      const warn = String((res as { warning?: string }).warning || '')
      showToast(warn || 'Список очищен', warn ? 'warning' : undefined)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function checkDomain(domain: string) {
  try {
    await withBusy(`domain-check-${domain}`, async () => {
      const res = await domains.check(domain)
      if (res.check) domainChecks[domain] = res.check
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

function checkSummary(domain: string): { verdict: string; text: string } | null {
  const c = domainChecks[domain]
  if (!c) return null
  const first = c.results?.[0]
  const verdict = first?.verdict || ''
  const text = (c.results || []).map((r) => r.text || r.verdict).filter(Boolean).join(' · ') || c.message || 'Готово'
  return { verdict, text }
}
</script>

<template>
  <section class="page-stack">
    <div class="page-head">
      <div>
        <span class="eyebrow">Списки трафика</span>
        <h1>Домены и списки</h1>
        <p>Исключения, собственные правила RKN, подстроки и автоматически собранные узлы Googlevideo.</p>
      </div>
      <div class="actions">
        <label v-if="scopes.enabled" class="field scope-picker">
          <span>Scope</span>
          <select :value="scope" :disabled="busyActive" @change="changeScope(($event.target as HTMLSelectElement).value)">
            <option v-for="s in scopeOptions" :key="s" :value="s">{{ s }}</option>
          </select>
        </label>
        <button type="button" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'domains-refresh' }" @click="refreshLists">
          <Icon name="refresh" class="icon-sm" />
          <span>Обновить</span>
        </button>
      </div>
    </div>

    <div class="tabs-bar" role="tablist" aria-label="Списки доменов">
      <button
        v-for="name in MAIN_DOMAIN_LISTS"
        :key="name"
        type="button"
        role="tab"
        :aria-selected="active === name"
        class="tab-pill"
        :class="{ active: active === name }"
        :disabled="busyActive"
        @click="go(name)"
      >
        {{ labels[name] }} <span class="tab-count">{{ listCount(name) }}</span>
      </button>
      <span class="tabs-sep" aria-hidden="true" />
      <button
        type="button"
        role="tab"
        :aria-selected="active === 'googlevideo'"
        class="tab-pill"
        :class="{ active: active === 'googlevideo' }"
        :disabled="busyActive"
        @click="go('googlevideo')"
      >
        {{ labels.googlevideo }} <span class="tab-count">{{ listCount('googlevideo') }}</span>
      </button>
    </div>

    <div v-if="autoLocked" class="notice-banner is-warn" role="status">
      <span>Autohostlist включён: ручное изменение этого списка заблокировано.</span>
      <router-link class="btn-link compact-link" to="/settings/modes">
        <span>Режимы</span>
        <Icon name="arrow-right" class="icon-sm" />
      </router-link>
    </div>

    <section v-if="isGooglevideo" class="panel gv-strip">
      <div class="gv-meta">
        <span>Сбор CDN: <strong>{{ list?.collection || '-' }}</strong></span>
        <span>
          Seed:
          <template v-if="list?.seed?.state === 'probing'">
            <strong class="mono">probing {{ list.seed.host_key }} -> #{{ list.seed.strategy }}</strong>
          </template>
          <template v-else-if="list?.seed?.last_result">
            <strong>{{ list.seed.state || 'idle' }}</strong>
            · {{ list.seed.last_host }} #{{ list.seed.last_strategy }} = {{ list.seed.last_result }}
            <span v-if="list.seed.pending"> · в очереди {{ list.seed.pending }}</span>
          </template>
          <template v-else><strong>{{ list?.seed?.state || '-' }}</strong></template>
        </span>
      </div>
      <details v-if="(list?.auto_locks || []).length" class="pop-fold">
        <summary>POP-автолоки ({{ list?.auto_locks?.length }})</summary>
        <div class="pop-list">
          <div v-for="lock in (list?.auto_locks || [])" :key="lock.host + ':' + lock.strategy" class="pop-row">
            <code class="mono">{{ lock.host }}</code>
            <span class="chip on">#{{ lock.strategy }}</span>
            <span class="chip">{{ lock.source === 'seed' ? 'seed' : 'learned' }}</span>
            <span v-if="lock.scope && lock.scope !== 'default'" class="chip">{{ lock.scope }}</span>
          </div>
        </div>
      </details>
    </section>

    <section class="panel" aria-label="Содержимое списка">
      <div class="panel-h">
        <div>
          <h2>{{ list?.title || labels[active] }}</h2>
          <p v-if="!isGooglevideo" class="panel-sub">{{ list?.description || meta.addLabel }}</p>
        </div>
        <div class="actions">
          <span class="chip mono">{{ filteredItems.length }} / {{ list?.items?.length ?? 0 }}</span>
          <button
            v-if="!autoLocked"
            type="button"
            class="ghost compact-btn"
            :disabled="busyActive"
            @click="importOpen = !importOpen"
          >
            {{ importOpen ? 'Скрыть импорт' : 'Импорт списком' }}
          </button>
          <button
            v-if="!autoLocked && (list?.items?.length ?? 0) > 0"
            type="button"
            class="ghost danger compact-btn"
            :disabled="busyActive"
            @click="clearAll"
          >
            Очистить
          </button>
        </div>
      </div>

      <div class="toolbar-grid">
        <input
          v-model="searchInput"
          type="search"
          :placeholder="`Поиск: ${meta.itemName.toLocaleLowerCase()}...`"
          aria-label="Поиск по списку"
        >
        <form class="add-inline" @submit.prevent="add">
          <input
            v-model="input"
            :placeholder="meta.placeholder"
            :disabled="busyActive || autoLocked"
            :aria-label="meta.addLabel"
          >
          <button
            type="submit"
            class="primary"
            :disabled="busyActive || autoLocked || !input.trim()"
            :class="{ 'is-busy': busyButton === 'domain-add' }"
          >
            <Icon name="plus" class="icon-sm" />
            <span>Добавить</span>
          </button>
        </form>
      </div>

      <div v-if="importOpen && !autoLocked" class="import-drawer">
        <label class="field">
          <span>Импорт нескольких записей (по одной на строку)</span>
          <textarea v-model="bulk" rows="4" :disabled="busyActive" placeholder="example.com&#10;cdn.example.org" />
        </label>
        <div class="actions">
          <button
            type="button"
            class="primary compact-btn"
            :disabled="busyActive || !bulk.trim()"
            :class="{ 'is-busy': busyButton === 'domain-import' }"
            @click="importList"
          >
            Импортировать
          </button>
          <button type="button" class="ghost compact-btn" :disabled="busyActive" @click="importOpen = false">Скрыть</button>
        </div>
      </div>

      <div v-if="!domainsLoaded && !(list?.items || []).length" class="skeleton-list" aria-label="Загрузка списка">
        <div v-for="i in 5" :key="i" class="skeleton-row" />
      </div>
      <div v-else-if="domainsLoaded && !(list?.items || []).length" class="empty-state">
        <strong>Список пуст</strong>
        <p>{{ isGooglevideo ? 'Узлы появятся после просмотра YouTube.' : 'Добавьте первую запись через поле выше или импорт.' }}</p>
      </div>
      <div v-else-if="filteredItems.length === 0" class="empty-state">
        <strong>Ничего не найдено</strong>
        <p>По вашему поисковому запросу записей нет.</p>
      </div>

      <div v-else class="list-stack">
        <article v-for="item in visibleItems" :key="item.value" class="list-row dom-row">
          <div class="dom-top">
            <div class="dom-main">
              <div v-if="renaming === item.value" class="rename-inline">
                <input
                  v-model="renameValue"
                  :disabled="busyActive"
                  aria-label="Новое имя записи"
                  @keydown.enter.prevent="rename(item.value)"
                  @keydown.esc.prevent="renaming = ''"
                >
                <button
                  type="button"
                  class="primary compact-btn"
                  :disabled="busyActive || !renameValue.trim()"
                  @click="rename(item.value)"
                >
                  Сохранить
                </button>
                <button type="button" class="ghost compact-btn" :disabled="busyActive" @click="renaming = ''">Отмена</button>
              </div>
              <template v-else>
                <code class="mono dom-name">{{ item.value }}</code>
                <span v-if="active === 'custom_rkn'" class="chip mono" :class="{ on: item.strategy != null }">
                  {{ item.strategy != null ? `#${item.strategy}` : 'авто' }}
                </span>
                <span v-if="isGooglevideo && item.ip" class="dom-ip mono">{{ item.ip }}</span>
                <span v-if="isGooglevideo && item.source" class="chip">{{ item.source }}</span>
              </template>
            </div>

            <div class="dom-actions">
              <template v-if="active === 'custom_rkn'">
                <input
                  class="dom-strat-input mono"
                  :value="strategyDraft[item.value] ?? ''"
                  type="number"
                  min="0"
                  placeholder="№"
                  :disabled="busyActive"
                  aria-label="Номер стратегии для домена"
                  @input="strategyDraft[item.value] = ($event.target as HTMLInputElement).value"
                  @keydown.enter.prevent="setStrategy(item.value)"
                >
                <button
                  type="button"
                  class="compact-btn"
                  :class="[strategyDirty(item) ? 'primary' : 'ghost', { 'is-busy': busyButton === `domain-st-${item.value}` }]"
                  :disabled="busyActive || !strategyDirty(item)"
                  @click="setStrategy(item.value)"
                >
                  Лок
                </button>
                <button
                  v-if="item.strategy != null"
                  type="button"
                  class="ghost icon-btn"
                  aria-label="Снять стратегию"
                  title="Снять стратегию"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === `domain-st-clear-${item.value}` }"
                  @click="clearStrategy(item.value)"
                >
                  <Icon name="cross" class="icon-sm" />
                </button>
                <button
                  type="button"
                  class="ghost compact-btn"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === `domain-check-${item.value}` }"
                  @click="checkDomain(item.value)"
                >
                  Проверить
                </button>
              </template>
              <button
                v-if="renaming !== item.value && !autoLocked"
                type="button"
                class="ghost icon-btn"
                aria-label="Переименовать"
                title="Переименовать"
                :disabled="busyActive"
                @click="beginRename(item.value)"
              >
                <Icon name="pencil" class="icon-sm" />
              </button>
              <button
                v-if="!autoLocked"
                type="button"
                class="ghost danger icon-btn"
                aria-label="Удалить"
                title="Удалить"
                :disabled="busyActive"
                @click="remove(item.value)"
              >
                <Icon name="trash" class="icon-sm" />
              </button>
            </div>
          </div>

          <div v-if="checkSummary(item.value)" class="dom-check">
            <span :class="checkSummary(item.value)!.verdict === 'ok' ? 'ok' : checkSummary(item.value)!.verdict === 'warn' ? 'warn' : 'bad'">
              {{ checkSummary(item.value)!.text }}
            </span>
            <button type="button" class="ghost compact-btn" @click="delete domainChecks[item.value]">Скрыть</button>
          </div>
        </article>
      </div>

      <div v-if="filteredItems.length > pageSize" class="pager" aria-live="polite">
        <button type="button" class="ghost compact-btn" :disabled="page <= 1" @click="page--">
          <Icon name="arrow-left" class="icon-sm" />
          <span>Назад</span>
        </button>
        <span class="mono">Страница {{ page }} / {{ pageCount }}</span>
        <button type="button" class="ghost compact-btn" :disabled="page >= pageCount" @click="page++">
          <span>Дальше</span>
          <Icon name="arrow-right" class="icon-sm" />
        </button>
      </div>
    </section>
  </section>
</template>

<style scoped>
.gv-strip { display: grid; gap: 0.6rem; }
.gv-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 1.25rem;
  font-size: 0.84rem;
  color: var(--muted);
}
.gv-meta strong { color: var(--ink); }
.pop-fold summary { cursor: pointer; font-size: 0.8rem; color: var(--muted); }
.pop-list { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.5rem; }
.pop-row {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.3rem 0.52rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  font-size: 0.78rem;
}

.toolbar-grid {
  display: grid;
  grid-template-columns: minmax(14rem, 1fr) minmax(16rem, 1.15fr);
  gap: 0.6rem;
  margin-bottom: 0.8rem;
}
.add-inline { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0.45rem; }
.import-drawer {
  display: grid;
  gap: 0.6rem;
  margin-bottom: 0.8rem;
  padding: 0.85rem;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius-md);
  background: var(--surface-2);
}
.import-drawer textarea { min-height: 5.5rem; }

.dom-row { padding: 0.55rem 0.8rem; }
.dom-top {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.45rem 0.75rem;
}
.dom-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem;
  min-width: 0;
  flex: 1 1 16rem;
}
.dom-name { font-size: 0.86rem; overflow-wrap: anywhere; }
.dom-ip { color: var(--muted); font-size: 0.78rem; }
.rename-inline { display: flex; flex-wrap: wrap; gap: 0.35rem; align-items: center; flex: 1; }
.rename-inline input { max-width: 18rem; min-height: 1.9rem; padding: 0.28rem 0.55rem; }

.dom-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.3rem; }
.dom-strat-input {
  width: 4.3rem;
  min-height: 1.9rem;
  padding: 0.25rem 0.45rem;
  text-align: center;
  font-size: 0.82rem;
}

.dom-check {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.45rem;
  padding-top: 0.45rem;
  border-top: 1px solid var(--line);
  font-size: 0.8rem;
}
.pager {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  margin-top: 0.85rem;
  color: var(--muted);
  font-size: 0.82rem;
}

@media (max-width: 780px) {
  .toolbar-grid { grid-template-columns: 1fr; }
}
</style>
