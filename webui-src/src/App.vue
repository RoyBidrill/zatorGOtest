<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, formBody } from './api/client'
import { logout as apiLogout } from './api/endpoints'
import { clearLoginGate, forceLogin, needLogin } from './stores/auth'
import { fetchAndApplyState } from './stores/state'
import { authRequired, status, statusLoaded, versionInfo } from './stores/status'
import { applyUpdate, hydrateUpdateCheck, startUpdateScheduler, stopUpdateScheduler, updateApplying, updateCheckResult, updateCheckState } from './stores/updates'
import { showToast } from './stores/toast'
import { theme, type ThemeMode } from './stores/theme'
import Icon, { type IconName } from './components/ui/Icon.vue'
import ToastHost from './components/ui/ToastHost.vue'
import ConfirmDialog from './components/ui/ConfirmDialog.vue'

interface NavTab {
  to: string
  name: string
  label: string
  hint: string
  icon: IconName
}

const route = useRoute()
const primaryTabs: NavTab[] = [
  { to: '/', name: 'status', label: 'Обзор', hint: 'Состояние системы', icon: 'overview' },
  { to: '/strategies', name: 'strategies', label: 'Стратегии', hint: 'Профили и фиксации', icon: 'strategies' },
  { to: '/sweep', name: 'sweep', label: 'Подбор стратегий', hint: 'Supersweep', icon: 'sweep' },
  { to: '/domains', name: 'domains', label: 'Домены и списки', hint: 'Hostlist и Googlevideo', icon: 'domains' },
]
const extraTabs: NavTab[] = [
  { to: '/custom-strats', name: 'custom-strats', label: 'Свои стратегии', hint: 'Конструктор и импорт', icon: 'custom-strats' },
  { to: '/blobs-sni', name: 'blobs-sni', label: 'Блобы и SNI', hint: 'TLS/QUIC, пул SNI, файлы', icon: 'blobs' },
  { to: '/settings', name: 'settings', label: 'Настройки', hint: 'Система, сеть, диагностика', icon: 'settings' },
]
const themes: { id: ThemeMode; label: string }[] = [
  { id: 'auto', label: 'Системная' },
  { id: 'light', label: 'Светлая' },
  { id: 'dark', label: 'Тёмная' },
]
const active = computed(() => String(route.name || 'status'))
const title = computed(() => [...primaryTabs, ...extraTabs].find((tab) => tab.name === active.value)?.label || 'Обзор')
const running = computed(() => Boolean(status.value?.zapret2_running))
const releaseVersion = computed(() => {
  if (updateCheckState.value !== 'success' || !updateCheckResult.value?.update_available) return ''
  const next = updateCheckResult.value.release || versionInfo.value?.latest_release || ''
  const current = versionInfo.value?.zator_version || ''
  return next.replace(/^v/i, '').toLowerCase() !== current.replace(/^v/i, '').toLowerCase() ? next : ''
})
const healthOverall = computed(() => status.value?.health?.overall || 'unknown')
const warnCount = computed(() => status.value?.service_warnings?.length || 0)
const healthLabel = computed(() => ({
  ok: 'Норма', degraded: 'Требует внимания', down: 'Остановлена', unknown: 'Состояние неизвестно',
} as Record<string, string>)[healthOverall.value] || healthOverall.value)
const mobileMoreOpen = ref(false)

const loginPass = ref('')
const loginError = ref('')
const loginBusy = ref(false)
const logoutBusy = ref(false)

function setTheme(mode: ThemeMode) { theme.value = mode }

async function bootstrap() {
  try {
    await fetchAndApplyState()
    hydrateUpdateCheck(versionInfo.value)
    clearLoginGate()
    startUpdateScheduler()
  } catch (e) {
    const err = e as Error & { status?: number }
    if (err.status === 401) {
      forceLogin()
      return
    }
    statusLoaded.value = false
    showToast(err.message, 'error')
  }
}

async function submitLogin() {
  loginError.value = ''
  loginBusy.value = true
  try {
    await api('/api/login', formBody({ password: loginPass.value }))
    loginPass.value = ''
    clearLoginGate()
    statusLoaded.value = false
    await bootstrap()
  } catch (e) {
    loginError.value = (e as Error).message
  } finally {
    loginBusy.value = false
  }
}

async function logout() {
  if (!authRequired.value) return
  logoutBusy.value = true
  stopUpdateScheduler()
  try {
    try { await apiLogout() } catch { /* session may already have expired */ }
    forceLogin()
    loginPass.value = ''
    loginError.value = ''
  } finally {
    logoutBusy.value = false
  }
}

watch(needLogin, (required) => { if (required) stopUpdateScheduler() })
watch(() => route.name, () => { mobileMoreOpen.value = false })
onMounted(() => { void bootstrap() })
onUnmounted(stopUpdateScheduler)
</script>

<template>
  <div v-if="needLogin" class="login-screen">
    <form class="login-card" @submit.prevent="submitLogin">
      <img class="login-logo" :src="'./icon.png'" width="68" height="68" alt="ZatorGO">
      <div class="login-brand">Zator<span>GO</span></div>
      <p class="login-subtitle">Панель управления zapret2</p>
      <div v-if="loginError" class="notice-banner is-danger" role="alert">{{ loginError }}</div>
      <label class="field">
        <span>Пароль</span>
        <input v-model="loginPass" type="password" autocomplete="current-password" required autofocus :disabled="loginBusy">
      </label>
      <button type="submit" class="primary" :disabled="loginBusy || !loginPass">{{ loginBusy ? 'Входим…' : 'Войти' }}</button>
    </form>
  </div>
  <div v-else class="shell">
    <aside class="rail" aria-label="Основная навигация">
      <router-link class="brand" to="/" aria-label="ZatorGO обзор">
        <img class="brand-logo" :src="'./icon.png'" width="38" height="38" alt="">
        <span class="brand-text"><strong>Zator<span>GO</span></strong><small>Control Center</small></span>
      </router-link>
      <div class="nav-caption">Управление</div>
      <nav class="nav" aria-label="Управление">
        <router-link v-for="tab in primaryTabs" :key="tab.name" :to="tab.to" :class="{ 'is-active': active === tab.name }">
          <Icon :name="tab.icon" class="icon-md" />
          <span><strong>{{ tab.label }}</strong><small>{{ tab.hint }}</small></span>
        </router-link>
      </nav>
      <div class="nav-caption nav-caption-extra">Дополнительно</div>
      <nav class="nav" aria-label="Дополнительно">
        <router-link v-for="tab in extraTabs" :key="tab.name" :to="tab.to" :class="{ 'is-active': active === tab.name }">
          <Icon :name="tab.icon" class="icon-md" />
          <span><strong>{{ tab.label }}</strong><small>{{ tab.hint }}</small></span>
        </router-link>
      </nav>
      <div class="rail-status" :class="healthOverall">
        <span class="status-dot" />
        <div>
          <strong>{{ running ? 'Служба запущена' : statusLoaded ? 'Служба остановлена' : 'Состояние неизвестно' }}</strong>
          <small>{{ warnCount ? `${warnCount} предупреждений` : healthLabel }}</small>
        </div>
      </div>
      <div class="rail-foot">ZatorGO Control Center</div>
    </aside>

    <div class="workspace">
      <header class="topbar">
        <div class="breadcrumbs"><span>Панель управления</span><b>/</b><strong>{{ title }}</strong></div>
        <div class="top-controls">
          <div class="version-control" aria-label="Версия ZatorGO">
            <router-link to="/settings/updates" class="version-current" title="Текущая версия ZatorGO">{{ versionInfo?.zator_version || 'ZatorGO' }}</router-link>
            <span v-if="releaseVersion" class="version-arrow" aria-hidden="true"><Icon name="arrow-right" class="icon-sm" /></span>
            <button v-if="releaseVersion" type="button" class="version-new" :disabled="updateApplying" :class="{ 'is-busy': updateApplying }" :aria-label="`Обновить ZatorGO до ${releaseVersion}`" @click="applyUpdate('app')">{{ releaseVersion }}</button>
            <span v-else-if="updateCheckState === 'checking'" class="version-checking" aria-label="Проверяем обновления">...</span>
          </div>
          <div class="top-health" :class="healthOverall">
            <span class="status-dot" />
            <span>{{ running ? 'zapret2 работает' : statusLoaded ? 'zapret2 остановлен' : healthLabel }}</span>
          </div>
          <label class="theme-control">
            <span class="sr-only">Цветовая тема</span>
            <select :value="theme" @change="setTheme(($event.target as HTMLSelectElement).value as ThemeMode)">
              <option v-for="option in themes" :key="option.id" :value="option.id">{{ option.label }}</option>
            </select>
          </label>
          <button v-if="authRequired" type="button" class="logout-btn" aria-label="Выйти" title="Выйти" :disabled="logoutBusy" @click="logout">
            <Icon name="logout" />
          </button>
        </div>
      </header>
      <main class="main"><router-view /></main>
    </div>

    <nav class="tab-bar" aria-label="Мобильная навигация">
      <router-link v-for="tab in primaryTabs" :key="tab.name" :to="tab.to" :class="{ 'is-active': active === tab.name }">
        <Icon :name="tab.icon" class="icon-md" />
        <span>{{ tab.name === 'sweep' ? 'Подбор' : tab.name === 'domains' ? 'Домены' : tab.label }}</span>
      </router-link>
      <div class="mobile-more-wrap">
        <button type="button" :class="{ 'is-active': ['custom-strats', 'blobs-sni', 'settings'].includes(active) }" aria-haspopup="menu" :aria-expanded="mobileMoreOpen" @click="mobileMoreOpen = !mobileMoreOpen">
          <Icon name="more" class="icon-md" />
          <span>Ещё</span>
        </button>
        <div v-if="mobileMoreOpen" class="mobile-more-menu" role="menu">
          <router-link v-for="tab in extraTabs" :key="tab.name" :to="tab.to" role="menuitem">
            <Icon :name="tab.icon" class="icon-sm" />
            <span>{{ tab.label }}</span>
          </router-link>
          <button v-if="authRequired" type="button" role="menuitem" @click="logout">
            <Icon name="logout" class="icon-sm" />
            <span>Выйти</span>
          </button>
        </div>
      </div>
    </nav>
    <ToastHost />
    <ConfirmDialog />
  </div>
</template>
