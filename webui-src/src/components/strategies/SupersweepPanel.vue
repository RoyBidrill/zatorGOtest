<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fetchSupersweep, supersweepCancel, supersweepStart } from '../../api/endpoints'
import type { SupersweepPayload } from '../../api/types'
import { busyActive, busyButton, withBusy } from '../../stores/busy'
import { confirmDialog } from '../../stores/confirm'
import { refreshAll } from '../../stores/status'
import { showToast } from '../../stores/toast'
import Icon from '../ui/Icon.vue'

const props = withDefaults(defineProps<{
  scope?: string
  scopes?: string[]
}>(), {
  scope: 'default',
  scopes: () => ['default'],
})

const emit = defineEmits<{ started: []; cancelled: [] }>()

type SweepMode = 'full' | 'quick'

const sweepMode = ref<SweepMode>('full')
const data = ref<SupersweepPayload | null>(null)
const loading = ref(false)
const error = ref('')
const runScope = ref(props.scope || 'default')
const domainsText = ref('')
const tlsPref = ref('any')
const includeQuic = ref(false)
const quicRounds = ref(2)
const quickProfile = ref(1)
const quickAddressDefaults: Record<number, string> = {
  1: 'www.youtube.com',
  2: 'rr2---sn-4g5ednly.googlevideo.com',
  3: 'xhamster.com',
  4: 'discord.com',
  5: '',
}
const showQuicOptions = computed(() =>
  (sweepMode.value === 'full' && includeQuic.value) || (sweepMode.value === 'quick' && quickProfile.value === 5))
const quickAddress = ref(quickAddressDefaults[quickProfile.value])
const states = {
  idle: 'Нет прогона', starting: 'Подготовка', running: 'Выполняется', applying: 'Применение результатов',
  done: 'Завершён', cancelled: 'Отменён', interrupted: 'Прерван',
}
const verdicts = { ok: 'Работает', warn: 'С предупреждением', fail: 'Не работает', unknown: 'Не проверено' }
const stateLabel = computed(() => data.value ? states[data.value.state] : 'Загрузка...')
const active = computed(() => !!data.value?.active)
const scopeOptions = computed(() => {
  const list = props.scopes?.length ? [...props.scopes] : ['default']
  if (!list.includes(runScope.value)) list.unshift(runScope.value)
  return list
})

const stateChipClass = computed(() => {
  const st = data.value?.state
  if (st === 'done') return 'on'
  if (st === 'running' || st === 'starting' || st === 'applying') return 'is-info'
  if (st === 'cancelled' || st === 'interrupted') return 'is-warn'
  return ''
})

function progressPct(done: number, total: number): number {
  if (!total || total <= 0) return 0
  return Math.min(100, Math.max(0, Math.round((done / total) * 100)))
}

let mounted = false
let timer: number | undefined
let controller: AbortController | null = null
let wasActive = false

watch(() => props.scope, (v) => {
  if (v && !active.value) runScope.value = v
}, { immediate: true })
watch(quickProfile, (next, previous) => {
  const current = quickAddress.value.trim()
  if (!current || current === quickAddressDefaults[previous]) {
    quickAddress.value = quickAddressDefaults[next] || ''
  }
})

const count = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 0
const strategy = (value: unknown) => value === null || count(value)
const text = (value: unknown) => typeof value === 'string'
function valid(value: SupersweepPayload) {
  return value && typeof value.available === 'boolean' && typeof value.active === 'boolean' &&
    Object.prototype.hasOwnProperty.call(states, value.state) && ['none', 'live', 'saved'].includes(value.source) &&
    [value.started, value.updated, value.completed, value.total].every(count) &&
    text(value.scope) && text(value.phase) &&
    (value.error === undefined || text(value.error)) &&
    Array.isArray(value.workers) && value.workers.every((worker) => worker &&
      [worker.name, worker.label, worker.current_target, worker.greens, worker.warns, worker.applied].every(text) &&
      [worker.profile, worker.completed, worker.total, worker.ok, worker.warn, worker.fail].every(count) &&
      strategy(worker.current_strategy)) &&
    Array.isArray(value.applied) && value.applied.every((row) => row &&
      ['profile', 'domain'].includes(row.kind) && text(row.target) && count(row.strategy)) &&
    Array.isArray(value.domains) && value.domains.every((row) => row && text(row.domain) &&
      Object.prototype.hasOwnProperty.call(verdicts, row.verdict) && strategy(row.best_strategy) && strategy(row.applied))
}
function date(value: number) {
  return value > 0 ? new Date(value * 1000).toLocaleString('ru-RU') : '-'
}
function stopTimer() {
  window.clearTimeout(timer)
  timer = undefined
}
async function refresh() {
  if (!mounted || document.hidden || loading.value) return
  stopTimer()
  loading.value = true
  const request = new AbortController()
  controller = request
  const timeout = window.setTimeout(() => request.abort(), 12000)
  try {
    const result = await fetchSupersweep(request.signal)
    if (!valid(result)) throw new Error('Некорректный ответ сервера')
    if (mounted) {
      if (wasActive && !result.active) {
        if (result.error) {
          showToast(result.error, 'error')
        }
        refreshAll().catch(() => undefined)
      }
      wasActive = result.active
      data.value = result
      error.value = ''
    }
  } catch (cause) {
    if (mounted) error.value = request.signal.aborted ? 'Превышено время ожидания ответа.'
      : cause instanceof Error ? cause.message : 'Не удалось получить данные.'
  } finally {
    window.clearTimeout(timeout)
    controller = null
    loading.value = false
    if (mounted && !document.hidden) timer = window.setTimeout(refresh, data.value?.active ? 5000 : 15000)
  }
}
function visibilityChanged() {
  stopTimer()
  if (!document.hidden) void refresh()
}

async function startRun() {
  const ok = await confirmDialog({
    title: 'Запустить суперсвип?',
    message: includeQuic.value
      ? 'Прогон подберёт стратегии для профилей 1-4, доменов РКН и в конце протестирует профиль 5 (QUIC) на живом nfqws2. Требуется h3-curl.'
      : 'Прогон подберёт стратегии для профилей и доменов РКН, затем применит победителей. Это может занять несколько минут.',
  })
  if (!ok) return
  try {
    await withBusy('ss-start', async () => {
      await supersweepStart({
        scope: runScope.value || 'default',
        domain: domainsText.value,
        tls_pref: tlsPref.value,
        include_quic: includeQuic.value,
        quic_rounds: includeQuic.value ? quicRounds.value : undefined,
      })
      showToast('Суперсвип запущен')
      emit('started')
      wasActive = true
      await refresh()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function startQuickRun() {
  if (quickProfile.value !== 5 && !quickAddress.value.trim()) {
    showToast('Укажите адрес для быстрого подбора', 'error')
    return
  }
  const ok = await confirmDialog({
    title: 'Запустить быстрый подбор?',
    message: quickProfile.value === 5
      ? `Будут проверены QUIC/HTTP3-стратегии профиля 5 на живом nfqws2 (раундов: ${quicRounds.value}); победитель применится автоматически.`
      : `Будут проверены стратегии профиля ${quickProfile.value} для ${quickAddress.value.trim()}; зелёный победитель будет применён автоматически.`,
  })
  if (!ok) return
  try {
    await withBusy('quick-start', async () => {
      await supersweepStart({
        scope: runScope.value || 'default',
        tls_pref: tlsPref.value,
        quick_profile: quickProfile.value,
        address: quickAddress.value,
        quic_rounds: quickProfile.value === 5 ? quicRounds.value : undefined,
      })
      showToast('Быстрый подбор запущен')
      emit('started')
      wasActive = true
      await refresh()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function cancelRun() {
  const ok = await confirmDialog({
    title: 'Остановить суперсвип?',
    message: 'Текущий прогон будет отменён. Уже применённые локи останутся.',
    danger: true,
  })
  if (!ok) return
  try {
    await withBusy('ss-cancel', async () => {
      await supersweepCancel()
      showToast('Суперсвип отменён')
      emit('cancelled')
      await refresh()
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

onMounted(() => {
  mounted = true
  document.addEventListener('visibilitychange', visibilityChanged)
  void refresh()
})
onUnmounted(() => {
  mounted = false
  stopTimer()
  controller?.abort()
  document.removeEventListener('visibilitychange', visibilityChanged)
})

defineExpose({ refresh })
</script>

<template>
  <div id="supersweep-panel" class="sweep-stack" aria-labelledby="supersweep-title">
    <div v-if="active" class="notice-banner is-info" role="status">
      <span>
        Идёт подбор: <strong>{{ stateLabel }}</strong>
        <template v-if="data?.phase"> · {{ data.phase }}</template>
        <span class="mono"> ({{ data?.completed ?? 0 }} / {{ data?.total ?? 0 }})</span>
      </span>
      <button
        type="button"
        class="danger compact-btn"
        :disabled="busyActive"
        :class="{ 'is-busy': busyButton === 'ss-cancel' }"
        @click="cancelRun"
      >
        <Icon name="stop" class="icon-sm" />
        <span>Остановить</span>
      </button>
    </div>

    <div v-if="error" class="notice-banner is-danger" role="alert">
      <span>
        Не удалось обновить суперсвип: {{ error }}
        <template v-if="data"> Показаны последние полученные данные, они могут быть устаревшими.</template>
      </span>
    </div>

    <div v-if="data?.error" class="notice-banner is-warn" role="alert">
      <span><strong>Прогон остановлен:</strong> {{ data.error }}</span>
    </div>

    <section class="panel">
      <div class="panel-h">
        <div>
          <h2 id="supersweep-title">Параметры запуска</h2>
          <p class="panel-sub">Автоподбор для всех профилей и доменов РКН или точечный тест одного профиля.</p>
        </div>
        <div class="seg-group" role="tablist" aria-label="Режим подбора">
          <button
            type="button"
            role="tab"
            :aria-selected="sweepMode === 'full'"
            :class="{ active: sweepMode === 'full' }"
            @click="sweepMode = 'full'"
          >
            Полный прогон
          </button>
          <button
            type="button"
            role="tab"
            :aria-selected="sweepMode === 'quick'"
            :class="{ active: sweepMode === 'quick' }"
            @click="sweepMode = 'quick'"
          >
            Быстрый подбор
          </button>
        </div>
      </div>

      <template v-if="sweepMode === 'full'">
        <div class="grid-2 sweep-form">
          <label class="field">
            <span>Scope</span>
            <select v-model="runScope" :disabled="busyActive || active">
              <option v-for="s in scopeOptions" :key="s" :value="s">{{ s }}</option>
            </select>
          </label>
          <label class="field">
            <span>TLS preference</span>
            <select v-model="tlsPref" :disabled="busyActive || active">
              <option value="any">any</option>
              <option value="12">TLS 1.2</option>
              <option value="13">TLS 1.3</option>
              <option value="both">both</option>
            </select>
          </label>
          <label class="field field-full">
            <span>Домены РКН (по одному в строке, пусто - эталонный набор)</span>
            <textarea
              v-model="domainsText"
              rows="3"
              :disabled="busyActive || active"
              placeholder="xhamster.com&#10;anidub.com&#10;amnezia.org"
            />
          </label>
          <label class="toggle-row" :class="{ 'field-full': !showQuicOptions }">
            <span>Включить QUIC (профиль 5, live-режим)</span>
            <input v-model="includeQuic" type="checkbox" :disabled="busyActive || active">
          </label>
          <label v-if="showQuicOptions" class="field">
            <span>Раунды QUIC (1-5)</span>
            <select v-model.number="quicRounds" :disabled="busyActive || active">
              <option v-for="n in [1, 2, 3, 4, 5]" :key="n" :value="n">{{ n }}</option>
            </select>
          </label>
        </div>

        <p v-if="showQuicOptions" class="notice-banner is-warn quic-live-warn" role="note">
          <span>
            QUIC-подбор (профиль 5) временно переключает реальный лок на живом nfqws2 и требует установленный <code>h3-curl</code> (см. карточку Профиля 5 во вкладке «Стратегии»).
          </span>
        </p>

        <div class="actions sweep-actions">
          <button
            type="button"
            class="primary"
            :disabled="busyActive || active"
            :class="{ 'is-busy': busyButton === 'ss-start' }"
            @click="startRun"
          >
            <Icon name="play" class="icon-sm" />
            <span>Запустить полный прогон</span>
          </button>
        </div>
      </template>

      <template v-else>
        <div class="grid-2 sweep-form">
          <label class="field">
            <span>Scope</span>
            <select v-model="runScope" :disabled="busyActive || active">
              <option v-for="s in scopeOptions" :key="s" :value="s">{{ s }}</option>
            </select>
          </label>
          <label class="field">
            <span>Профиль</span>
            <select v-model.number="quickProfile" :disabled="busyActive || active">
              <option :value="1">YouTube (1)</option>
              <option :value="2">Googlevideo media (2)</option>
              <option :value="3">Домен РКН (3)</option>
              <option :value="4">Discord (4)</option>
              <option :value="5">YouTube QUIC / HTTP3 (5)</option>
            </select>
          </label>
          <label v-if="quickProfile !== 5" class="field">
            <span>TLS preference</span>
            <select v-model="tlsPref" :disabled="busyActive || active">
              <option value="any">any</option>
              <option value="12">TLS 1.2</option>
              <option value="13">TLS 1.3</option>
              <option value="both">both</option>
            </select>
          </label>
          <label v-else class="field">
            <span>Раунды QUIC (1-5)</span>
            <select v-model.number="quicRounds" :disabled="busyActive || active">
              <option v-for="n in [1, 2, 3, 4, 5]" :key="n" :value="n">{{ n }}</option>
            </select>
          </label>
          <label class="field">
            <span>Адрес проверки</span>
            <input
              v-model="quickAddress"
              :disabled="busyActive || active"
              :placeholder="quickProfile === 5 ? 'Необязательно (видеопоток YouTube QUIC)' : 'www.youtube.com'"
            >
          </label>
        </div>

        <p v-if="showQuicOptions" class="notice-banner is-warn quic-live-warn" role="note">
          <span>
            QUIC-подбор (профиль 5) временно переключает реальный лок на живом nfqws2 и требует установленный <code>h3-curl</code> (см. карточку Профиля 5 во вкладке «Стратегии»).
          </span>
        </p>

        <div class="actions sweep-actions">
          <button
            type="button"
            class="primary"
            :disabled="busyActive || active || (quickProfile !== 5 && !quickAddress.trim())"
            :class="{ 'is-busy': busyButton === 'quick-start' }"
            @click="startQuickRun"
          >
            <Icon name="play" class="icon-sm" />
            <span>Запустить быстрый подбор</span>
          </button>
        </div>
      </template>
    </section>

    <section class="panel" aria-label="Ход и результаты прогона">
      <div class="panel-h">
        <div>
          <h2>Ход и результаты прогона</h2>
          <p v-if="data" class="panel-sub mono">
            Scope: {{ data.scope || '-' }} · Начало: {{ date(data.started) }} · Обновлено: {{ date(data.updated) }}
          </p>
        </div>
        <div class="actions">
          <span v-if="data" class="chip" :class="stateChipClass">{{ stateLabel }}</span>
          <span v-if="data" class="chip">
            {{ data.source === 'saved' ? 'Сохранённый отчёт' : data.source === 'live' ? 'Текущий отчёт' : 'Нет отчёта' }}
          </span>
          <button
            id="supersweep-refresh-btn"
            type="button"
            class="ghost compact-btn"
            :disabled="loading || busyActive"
            :aria-busy="loading"
            @click="refresh"
          >
            <Icon name="refresh" class="icon-sm" />
            <span>{{ loading ? 'Обновляем...' : 'Обновить' }}</span>
          </button>
        </div>
      </div>

      <div v-if="!data && !error" class="skeleton-list" aria-label="Загружаем данные суперсвипа">
        <div v-for="i in 3" :key="i" class="skeleton-row" />
      </div>

      <div v-else-if="data && !data.available && !active" class="empty-state">
        <strong>Прогонов пока нет</strong>
        <p>Выберите режим и параметры выше, затем нажмите кнопку запуска.</p>
      </div>

      <template v-else-if="data">
        <div class="sweep-progress-block">
          <div class="sweep-progress-head">
            <span>Фаза: <strong>{{ data.phase || '-' }}</strong></span>
            <span class="mono">{{ data.completed }} / {{ data.total }} ({{ progressPct(data.completed, data.total) }}%)</span>
          </div>
          <div
            class="progress-track"
            role="progressbar"
            aria-label="Общий прогресс суперсвипа"
            :aria-valuenow="data.completed"
            aria-valuemin="0"
            :aria-valuemax="data.total || 1"
          >
            <div
              class="progress-fill"
              :class="{ 'is-ok': data.state === 'done' }"
              :style="{ width: `${progressPct(data.completed, data.total)}%` }"
            />
          </div>
        </div>

        <div v-if="data.workers.length" class="supersweep-workers">
          <article v-for="worker in data.workers" :key="worker.name" class="list-row worker-card">
            <div class="worker-head">
              <span class="prof-id">{{ worker.profile }}</span>
              <div class="worker-title">
                <strong>{{ worker.label || worker.name }}</strong>
                <span class="mono">{{ worker.completed }} / {{ worker.total }}</span>
              </div>
            </div>

            <div
              class="progress-track"
              role="progressbar"
              :aria-label="`Прогресс: ${worker.label || worker.name}`"
              :aria-valuenow="worker.completed"
              aria-valuemin="0"
              :aria-valuemax="worker.total || 1"
            >
              <div class="progress-fill" :style="{ width: `${progressPct(worker.completed, worker.total)}%` }" />
            </div>

            <div class="worker-chips">
              <span class="chip on">Успех: {{ worker.ok }}</span>
              <span class="chip is-warn">Предупр.: {{ worker.warn }}</span>
              <span class="chip is-bad">Ошибки: {{ worker.fail }}</span>
            </div>

            <dl class="worker-dl">
              <div><dt>Стратегия</dt><dd class="mono">{{ worker.current_strategy ?? '-' }}</dd></div>
              <div><dt>Цель</dt><dd class="mono">{{ worker.current_target || '-' }}</dd></div>
              <div><dt>Зелёные</dt><dd class="mono">{{ worker.greens || '-' }}</dd></div>
              <div><dt>Жёлтые</dt><dd class="mono">{{ worker.warns || '-' }}</dd></div>
              <div><dt>Применено</dt><dd class="mono">{{ worker.applied || '-' }}</dd></div>
            </dl>
          </article>
        </div>

        <div class="sweep-subsection">
          <h3>Применённые победители</h3>
          <p class="panel-sub">Зафиксировано в этом прогоне; актуальные локи всегда видны во вкладке «Стратегии».</p>
          <div v-if="data.applied.length" class="list-stack applied-list">
            <div v-for="(row, index) in data.applied" :key="index" class="list-row applied-row">
              <span>{{ row.kind === 'profile' ? 'Профиль' : 'Домен' }} <strong class="mono">{{ row.target }}</strong></span>
              <span class="chip on">#{{ row.strategy }}</span>
            </div>
          </div>
          <p v-else class="panel-d empty-sub">В этом прогоне стратегии ещё не применялись.</p>
        </div>

        <details v-if="data.domains.length" class="domains-fold">
          <summary>Результаты доменов РКН ({{ data.domains.length }})</summary>
          <div class="list-stack domains-result-list">
            <div v-for="row in data.domains" :key="row.domain" class="list-row domain-result-row">
              <strong class="mono">{{ row.domain }}</strong>
              <div class="actions">
                <span class="chip" :class="row.verdict === 'ok' ? 'on' : row.verdict === 'warn' ? 'is-warn' : 'is-bad'">
                  {{ verdicts[row.verdict] }}
                </span>
                <span class="chip">лучшая: {{ row.best_strategy ?? '-' }}</span>
                <span class="chip" :class="{ on: row.applied != null }">применена: {{ row.applied ?? '-' }}</span>
              </div>
            </div>
          </div>
        </details>
      </template>
    </section>
  </div>
</template>

<style scoped>
.sweep-stack { display: grid; gap: 1rem; }
.sweep-form { margin-top: 0.25rem; }
.field-full { grid-column: 1 / -1; }
.sweep-form textarea { min-height: 4.5rem; }
.quic-live-warn { margin-top: 0.75rem; }
.sweep-actions { margin-top: 0.85rem; }

.sweep-progress-block {
  display: grid;
  gap: 0.45rem;
  margin-bottom: 0.9rem;
}
.sweep-progress-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
  font-size: 0.84rem;
}

.supersweep-workers {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 270px), 1fr));
  gap: 0.65rem;
  margin-bottom: 1rem;
}
.worker-card { gap: 0.55rem; }
.worker-head {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}
.worker-title {
  flex: 1;
  min-width: 0;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 0.5rem;
}
.worker-title strong {
  font-size: 0.88rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.worker-title span {
  color: var(--muted);
  font-size: 0.76rem;
  flex-shrink: 0;
}
.worker-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
}
.worker-dl {
  margin: 0;
  display: grid;
  gap: 0.2rem;
}
.worker-dl div {
  display: flex;
  justify-content: space-between;
  gap: 0.6rem;
  font-size: 0.77rem;
  padding-top: 0.22rem;
  border-top: 1px solid var(--line);
}
.worker-dl dt { color: var(--muted); }
.worker-dl dd {
  margin: 0;
  text-align: right;
  overflow-wrap: anywhere;
}

.sweep-subsection {
  display: grid;
  gap: 0.45rem;
  margin-top: 0.35rem;
}
.sweep-subsection h3 {
  margin: 0;
  font-size: 0.94rem;
  font-weight: 700;
}
.empty-sub { margin: 0.2rem 0 0; }
.applied-list { margin-top: 0.25rem; }
.applied-row,
.domain-result-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}
.domains-fold { margin-top: 0.9rem; }
.domains-fold summary { cursor: pointer; font-size: 0.84rem; color: var(--ink-2); font-weight: 500; }
.domains-result-list { margin-top: 0.55rem; }
</style>
