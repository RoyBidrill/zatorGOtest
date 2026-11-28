<script setup lang="ts">
import { computed, ref } from 'vue'
import { runCheck, serviceAction } from '../api/endpoints'
import CheckResults from '../components/ui/CheckResults.vue'
import Icon from '../components/ui/Icon.vue'
import ZapretVersionManager from '../components/ui/ZapretVersionManager.vue'
import { busyActive, busyButton, withBusy } from '../stores/busy'
import { confirmDialog } from '../stores/confirm'
import { refreshAll, scope, status, statusCheck, statusCheckRan, statusCheckAt, statusLoaded, versionInfo, versionInfoFresh } from '../stores/status'
import { showToast } from '../stores/toast'
import { loadZapretReleases, zapretBranchShort, zapretReleasesState } from '../stores/zapretReleases'

const running = computed(() => Boolean(status.value?.zapret2_running))
const health = computed(() => status.value?.health)
const overall = computed(() => health.value?.overall || 'unknown')
const overallLabel = computed(() => {
  if (running.value && overall.value === 'ok') return 'Служба запущена'
  if (running.value && overall.value !== 'ok') return 'Служба требует внимания'
  if (!running.value && overall.value === 'down') return 'Служба остановлена'
  return 'Состояние неизвестно'
})
const warnings = computed(() => status.value?.service_warnings || [])
const profiles = computed(() => status.value?.profiles || [])
const pinnedCount = computed(() => profiles.value.filter((p) => {
  const lock = String(p.current_lock || 'auto')
  return lock !== 'auto' && lock !== '0'
}).length)
const disabledProfiles = computed(() => profiles.value.filter((p) => String(p.current_lock) === '0').length)
const autoMode = computed(() => status.value?.auto_mode || '-')
const watchdog = computed(() => health.value?.watchdog ?? status.value?.nfqws_watchdog)
const configPending = computed(() => !!versionInfo.value?.config_update_pending)
const zapretVersionLabel = computed(() => {
  const v = versionInfo.value?.zapret2_version
  if (!v) return '-'
  const tag = v === 'self-built' ? v : `v${v}`
  const br = zapretBranchShort(versionInfo.value?.zapret2_source)
  return br ? `${tag} (${br})` : tag
})
const checkTime = ref<number | null>(statusCheckAt.value)

function onDiagToggle(ev: Event) {
  if ((ev.target as HTMLDetailsElement).open && zapretReleasesState.value === 'idle') {
    void loadZapretReleases(false)
  }
}

function yn(value: boolean | undefined) {
  return value === true ? 'Включён' : value === false ? 'Выключен' : 'Неизвестно'
}
function dateTime(value: number | null) {
  return value ? new Date(value).toLocaleString('ru-RU') : '-'
}

async function refresh() {
  try {
    await withBusy('refresh-status', async () => { await refreshAll() })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function check() {
  try {
    await withBusy('status-check', async () => {
      statusCheck.value = await runCheck()
      statusCheckRan.value = true
      checkTime.value = Date.now()
      statusCheckAt.value = checkTime.value
    })
    showToast('Проверка доступности завершена')
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function svc(action: 'start' | 'stop' | 'restart') {
  if (action === 'restart') {
    const ok = await confirmDialog({
      title: 'Перезапустить zapret2?',
      message: 'Служба будет остановлена и запущена заново.',
      confirmText: 'Перезапустить',
    })
    if (!ok) return
  }
  try {
    await withBusy(`svc-${action}`, async () => {
      await serviceAction(action)
      await refreshAll()
    })
    const labels = { start: 'запущена', stop: 'остановлена', restart: 'перезапущена' } as const
    showToast(`zapret2 ${labels[action]}`)
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}
</script>

<template>
  <section class="page-stack">
    <header class="page-head">
      <div>
        <span class="eyebrow">Главная панель</span>
        <h1>Обзор системы</h1>
        <p>Состояние службы, ключевые показатели и быстрый переход к настройкам трафика.</p>
      </div>
      <div class="actions">
        <button
          type="button"
          class="secondary-button"
          :disabled="busyActive"
          :class="{ 'is-busy': busyButton === 'refresh-status' }"
          @click="refresh"
        >
          <Icon name="refresh" class="icon-sm" />
          <span>Обновить</span>
        </button>
      </div>
    </header>

    <div v-if="!statusLoaded" class="skeleton-list" aria-label="Загружаем состояние устройства">
      <div class="skeleton-row is-tall" />
      <div v-for="i in 3" :key="i" class="skeleton-row" />
    </div>
    <template v-else>
      <section class="overview-top">
        <article class="panel service-card" :class="overall">
          <div class="service-card-label">
            <span class="status-dot" />
            <span>Состояние zapret2</span>
          </div>
          <h2>{{ overallLabel }}</h2>
          <p>{{ running ? 'Процесс службы запущен.' : 'Процесс службы не запущен.' }} Доступность сайтов определяется отдельной проверкой.</p>
          <div class="service-actions">
            <button
              type="button"
              class="primary"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === 'status-check' }"
              @click="check"
            >
              <Icon name="shield" class="icon-sm" />
              <span>Проверить доступность</span>
            </button>
            <button
              type="button"
              class="secondary-button"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === (running ? 'svc-stop' : 'svc-start') }"
              @click="svc(running ? 'stop' : 'start')"
            >
              {{ running ? 'Остановить службу' : 'Запустить службу' }}
            </button>
            <button
              type="button"
              class="icon-btn"
              aria-label="Перезапустить zapret2"
              title="Перезапустить zapret2"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === 'svc-restart' }"
              @click="svc('restart')"
            >
              <Icon name="refresh" class="icon-sm" />
            </button>
          </div>
        </article>

        <aside class="panel quick-card">
          <h2>Быстрые переходы</h2>
          <div class="quick-links">
            <router-link to="/sweep" class="quick-link">
              <span><strong>Подобрать стратегии</strong><small>Быстрый тест и полный прогон</small></span>
              <Icon name="arrow-right" class="icon-sm quick-arrow" />
            </router-link>
            <router-link to="/strategies" class="quick-link">
              <span><strong>Настроить профили</strong><small>Фиксации и проверки</small></span>
              <Icon name="arrow-right" class="icon-sm quick-arrow" />
            </router-link>
            <router-link to="/domains" class="quick-link">
              <span><strong>Управлять списками</strong><small>Домены, исключения, Googlevideo</small></span>
              <Icon name="arrow-right" class="icon-sm quick-arrow" />
            </router-link>
          </div>
        </aside>
      </section>

      <section class="panel" aria-labelledby="updates-title">
        <div class="panel-h">
          <div>
            <h2 id="updates-title">Конфигурация</h2>
            <p class="panel-sub">Обновление шаблонов и стратегических ресурсов</p>
          </div>
          <router-link class="text-button" to="/settings/updates">
            <span>Настроить</span>
            <Icon name="arrow-right" class="icon-sm" />
          </router-link>
        </div>
        <div class="update-row" :class="versionInfoFresh ? (configPending ? 'is-info' : 'is-neutral') : 'is-muted'">
          <span class="update-mark" aria-hidden="true">
            <Icon name="sliders" class="icon-sm" />
          </span>
          <div class="update-copy">
            <strong v-if="configPending">Обнаружен более новый шаблон конфигурации</strong>
            <strong v-else-if="versionInfoFresh">Нового шаблона конфигурации не обнаружено</strong>
            <strong v-else>Состояние шаблона не обновлено</strong>
            <small v-if="versionInfoFresh && versionInfo" class="mono">
              Активный: {{ versionInfo.config_date || '-' }} · Шаблон: {{ versionInfo.config_default_date || '-' }}
            </small>
            <small v-else>Показанные сведения могут быть устаревшими.</small>
          </div>
          <router-link class="text-button" to="/settings/config">Посмотреть</router-link>
        </div>
      </section>

      <section class="overview-metrics" aria-label="Краткие показатели">
        <article class="panel metric-card">
          <span>Сторожевой процесс</span>
          <strong :class="watchdog === true ? 'state-ok' : watchdog === false ? 'state-warn' : ''">{{ yn(watchdog) }}</strong>
          <small>Watchdog nfqws2</small>
        </article>
        <article class="panel metric-card">
          <span>Авторотация</span>
          <strong>{{ autoMode }}</strong>
          <small>TCP / HTTP</small>
        </article>
        <article class="panel metric-card">
          <span>Стратегии</span>
          <strong class="mono">{{ pinnedCount }} из {{ profiles.length }}</strong>
          <small>{{ disabledProfiles }} выключено</small>
        </article>
        <article class="panel metric-card">
          <span>Предупреждения</span>
          <strong class="mono" :class="warnings.length ? 'state-warn' : ''">{{ warnings.length }}</strong>
          <small>Состояние службы</small>
        </article>
      </section>

      <section class="panel">
        <div class="panel-h">
          <div>
            <h2>Проверка доступности</h2>
            <p class="panel-sub">Результаты появляются после запуска проверки через текущую конфигурацию.</p>
          </div>
          <span v-if="checkTime" class="chip mono">{{ dateTime(checkTime) }}</span>
        </div>
        <div v-if="!statusCheckRan" class="empty-state">
          <strong>Проверка ещё не запускалась</strong>
          <p>Нажмите «Проверить доступность» в карточке состояния zapret2 выше, чтобы проверить TLS и медиапотоки.</p>
        </div>
        <CheckResults v-else :payload="statusCheck" :empty-hidden="false" empty-message="Проверка завершилась без подробных результатов." />
      </section>

      <section class="overview-bottom">
        <article class="panel">
          <div class="panel-h">
            <div>
              <h2>Основные профили</h2>
              <p class="panel-sub">Текущие фиксации из состояния устройства</p>
            </div>
            <router-link class="text-button" to="/strategies">
              <span>Все профили</span>
              <Icon name="arrow-right" class="icon-sm" />
            </router-link>
          </div>
          <div v-if="profiles.length" class="list-stack">
            <div v-for="profile in profiles.slice(0, 4)" :key="profile.profile" class="list-row profile-summary-row">
              <div class="profile-summary-main">
                <span class="prof-id">{{ profile.profile }}</span>
                <div class="profile-summary-text">
                  <strong>{{ profile.label }}</strong>
                  <small>макс. № {{ profile.max_strategy ?? '-' }}</small>
                </div>
              </div>
              <span
                class="chip"
                :class="profile.current_lock === '0' ? 'is-bad' : profile.current_lock && profile.current_lock !== 'auto' ? 'on' : ''"
              >
                {{ profile.current_lock === '0' ? 'Выключен' : profile.current_lock && profile.current_lock !== 'auto' ? `#${profile.current_lock}` : 'auto' }}
              </span>
            </div>
          </div>
          <div v-else class="empty-state">
            <strong>Профили пока не загружены</strong>
            <p>Данные появятся после инициализации состояния службы.</p>
          </div>
        </article>

        <details class="panel diagnostics-card" @toggle="onDiagToggle">
          <summary class="diag-summary">
            <span>
              <strong>Диагностика службы</strong>
              <small>Технические детали и управление версией zapret2</small>
            </span>
            <Icon name="chevron-down" class="icon-sm diag-caret" />
          </summary>
          <dl class="diag-dl">
            <div><dt>Scope</dt><dd class="mono">{{ scope }}</dd></div>
            <div><dt>Firewall ensure</dt><dd class="mono">{{ health?.fw_ensure || '-' }}</dd></div>
            <div><dt>Аргументы nfqws2</dt><dd class="mono">{{ health?.args_present ?? status?.args_present ?? '-' }}</dd></div>
            <div><dt>Firewall hook</dt><dd class="mono">{{ health?.fw_hook_present ?? status?.fw_hook_present ?? '-' }}</dd></div>
            <div><dt>Проверка после обновления</dt><dd class="mono">{{ health?.post_update_verify || status?.post_update_verify || '-' }}</dd></div>
            <div><dt>Версия ZatorGO</dt><dd class="mono">{{ versionInfo?.zator_version || '-' }}</dd></div>
            <div><dt>Версия zapret2</dt><dd class="mono">{{ zapretVersionLabel }}</dd></div>
          </dl>
          <ZapretVersionManager compact />
          <div v-if="warnings.length" class="notice-banner is-warn diag-warnings">
            <div>
              <strong>Предупреждения</strong>
              <p v-for="(warning, index) in warnings" :key="index">{{ warning }}</p>
            </div>
          </div>
          <div class="diagnostics-links">
            <router-link class="text-button" to="/settings/zapret">
              <span>Все версии zapret2</span>
              <Icon name="arrow-right" class="icon-sm" />
            </router-link>
            <router-link class="text-button" to="/settings/errors">
              <span>Все сообщения службы</span>
              <Icon name="arrow-right" class="icon-sm" />
            </router-link>
          </div>
        </details>
      </section>
    </template>
  </section>
</template>

<style scoped>
.overview-top,
.overview-bottom {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(260px, 0.85fr);
  gap: 1rem;
  align-items: start;
}

.service-card {
  background:
    radial-gradient(ellipse at 95% 0%, var(--accent-soft), transparent 52%),
    var(--surface);
}
.service-card-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 500;
}
.service-card-label .status-dot { margin-top: 0; }
.service-card h2 {
  margin: 0.65rem 0 0.35rem;
  font-size: clamp(1.35rem, 2.4vw, 1.8rem);
  font-weight: 750;
  letter-spacing: -0.03em;
  line-height: 1.15;
}
.service-card p {
  margin: 0;
  color: var(--muted);
  font-size: 0.85rem;
  line-height: 1.48;
}
.service-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 1.1rem;
}

.quick-card h2 {
  margin: 0 0 0.7rem;
  font-size: 1rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.quick-links { display: grid; gap: 0.45rem; }
.quick-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.7rem;
  padding: 0.65rem 0.78rem;
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  background: var(--surface-2);
  transition: border-color 150ms var(--ease), background-color 150ms var(--ease);
}
.quick-link:hover {
  border-color: color-mix(in srgb, var(--accent) 42%, var(--line));
  background: var(--surface-hover);
}
.quick-link span { display: grid; gap: 0.14rem; min-width: 0; }
.quick-link strong { font-size: 0.84rem; font-weight: 600; }
.quick-link small { color: var(--muted); font-size: 0.76rem; }
.quick-arrow { color: var(--accent); }

.update-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 0.75rem;
  padding-top: 0.7rem;
  border-top: 1px solid var(--line);
}
.update-row.is-muted { opacity: 0.78; }
.update-mark {
  display: grid;
  place-items: center;
  width: 2rem;
  height: 2rem;
  border-radius: var(--radius-sm);
  color: var(--accent);
  background: var(--accent-soft);
}
.update-copy { display: grid; gap: 0.18rem; min-width: 0; }
.update-copy strong { font-size: 0.85rem; }
.update-copy small { color: var(--muted); font-size: 0.76rem; overflow-wrap: anywhere; }

.overview-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
}
.metric-card {
  display: grid;
  gap: 0.28rem;
  padding: 0.9rem 1rem;
  box-shadow: var(--shadow-sm), var(--inner-highlight);
}
.metric-card span,
.metric-card small {
  color: var(--muted);
  font-size: 0.74rem;
}
.metric-card strong {
  font-size: 1.08rem;
  font-weight: 700;
  line-height: 1.2;
}
.state-ok { color: var(--ok); }
.state-warn { color: var(--warn); }

.profile-summary-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}
.profile-summary-main {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  min-width: 0;
}
.profile-summary-text {
  display: grid;
  gap: 0.1rem;
  min-width: 0;
}
.profile-summary-text strong { font-size: 0.88rem; }
.profile-summary-text small { color: var(--muted); font-size: 0.76rem; }

.diag-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.6rem;
  cursor: pointer;
  list-style: none;
}
.diag-summary::-webkit-details-marker { display: none; }
.diag-summary span { display: grid; gap: 0.18rem; }
.diag-summary strong { font-size: 0.96rem; }
.diag-summary small { color: var(--muted); font-size: 0.78rem; }
.diag-caret {
  color: var(--muted);
  transition: transform 180ms var(--ease);
}
.diagnostics-card[open] .diag-caret {
  transform: rotate(180deg);
}
.diag-dl { margin: 0.85rem 0 0; }
.diag-dl div {
  display: flex;
  justify-content: space-between;
  gap: 0.8rem;
  padding: 0.42rem 0;
  border-top: 1px solid var(--line);
  font-size: 0.78rem;
}
.diag-dl dt { color: var(--muted); }
.diag-dl dd { margin: 0; text-align: right; overflow-wrap: anywhere; }
.diag-warnings { margin-top: 0.65rem; }
.diag-warnings p { margin: 0.2rem 0 0; font-size: 0.8rem; }
.diagnostics-links {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.45rem;
  margin-top: 0.65rem;
}

@media (max-width: 900px) {
  .overview-top,
  .overview-bottom { grid-template-columns: 1fr; }
}

@media (max-width: 600px) {
  .overview-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.55rem; }
  .metric-card { padding: 0.75rem 0.85rem; }
  .service-actions > button { flex: 1 1 auto; }
  .update-row { grid-template-columns: auto minmax(0, 1fr); }
  .update-row > a { grid-column: 2; justify-self: start; }
}
</style>
