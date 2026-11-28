<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, formBody } from '../api/client'
import {
  applySetting, backups as backupsApi, fetchClientScopes, fetchRecommendations, updateClientScope,
} from '../api/endpoints'
import { busyActive, busyButton, withBusy } from '../stores/busy'
import { confirmDialog } from '../stores/confirm'
import {
  fallbackSettings, ifacesSettings, modeSettings, ports, provider, settingsLoaded, telemetrySettings,
  tlsBlobSettings, udpGamesSettings, wgBlobSettings, wgStateSettings, wssizeRampSettings,
  refreshFallbackSettings, refreshIfacesSettings, refreshModeSetting, refreshPorts, refreshProvider,
  refreshUdpGamesSettings, refreshWgBlobSettings, refreshWgStateSettings,
  refreshWssizeRampSettings,
} from '../stores/settings'
import type { ClientScopeMapping, Recommendations, WssizeRampSettings } from '../api/types'
import { backups } from '../stores/backups'
import { fetchAndApplyState } from '../stores/state'
import { refreshAll, scopes, status } from '../stores/status'
import { announceRestart, restartSuffix, showToast } from '../stores/toast'
import { applyUpdate, refreshUpdateCheck, updateCheckError, updateCheckResult, updateCheckState, updateMode } from '../stores/updates'
import Icon from '../components/ui/Icon.vue'
import ZapretVersionManager from '../components/ui/ZapretVersionManager.vue'
import { loadZapretReleases, zapretReleasesState } from '../stores/zapretReleases'

const route = useRoute()
const router = useRouter()

const sections = [
  { id: 'sec-updates', label: 'Обновления', group: 'Система' },
  { id: 'sec-provider', label: 'Провайдер', group: 'Система' },
  { id: 'sec-telemetry', label: 'Телеметрия', group: 'Система' },
  { id: 'sec-backups', label: 'Бэкапы', group: 'Система' },
  { id: 'sec-modes', label: 'Режимы', group: 'Обход' },
  { id: 'sec-tls', label: 'TLS', group: 'Обход' },
  { id: 'sec-wg', label: 'WireGuard', group: 'Обход' },
  { id: 'sec-wssize', label: 'WSSIZE', group: 'Обход' },
  { id: 'sec-firewall', label: 'Firewall', group: 'Сеть' },
  { id: 'sec-ifaces', label: 'Интерфейсы', group: 'Сеть' },
  { id: 'sec-ports', label: 'Порты', group: 'Сеть' },
  { id: 'sec-scopes', label: 'Scopes', group: 'Сеть' },
  { id: 'sec-zapret', label: 'Версия zapret2', group: 'Сервис' },
  { id: 'sec-config', label: 'Конфиг', group: 'Сервис' },
  { id: 'sec-errors', label: 'Ошибки', group: 'Сервис' },
]

const settingGroups = [
  { id: 'grp-bypass', key: 'bypass', title: 'Обход DPI', first: 'sec-modes' },
  { id: 'grp-net', key: 'network', title: 'Сеть', first: 'sec-firewall' },
  { id: 'grp-system', key: 'system', title: 'Система', first: 'sec-updates' },
  { id: 'grp-svc', key: 'diagnostics', title: 'Диагностика', first: 'sec-zapret' },
]

const modes = [
  { key: 'auto_mode', post: 'auto_mode_state', title: 'Авторотация TCP/HTTP', field: 'enabled' as const },
  { key: 'hostlist', post: 'hostlist_state', title: 'Autohostlist', field: 'auto' as const },
  { key: 'fallback', post: 'fallback_state', title: 'Безразборный режим', field: 'enabled' as const, fromFallback: true },
  { key: 'udp-games', post: 'udp_games_state', title: 'UDP Games 1026-65531', field: 'enabled' as const, fromUdp: true },
  { key: 'dns_desync', post: 'dns_desync_state', title: 'Антиспуф DNS (весь UDP/53)', field: 'enabled' as const },
  { key: 'rst_guard', post: 'rst_guard_state', title: 'RST guard', field: 'enabled' as const },
  { key: 'reasm', post: 'reasm_state', title: 'reasm-disable', field: 'enabled' as const },
]

const fw = ref(status.value?.fwtype || 'iptables')
const offload = ref(status.value?.flowoffload || 'donttouch')
watch(status, (s) => {
  if (s?.fwtype) fw.value = s.fwtype
  if (s?.flowoffload) offload.value = s.flowoffload
}, { immediate: true })

const fwDirty = computed(() => Boolean(status.value?.fwtype && fw.value !== status.value.fwtype))
const offloadDirty = computed(() => Boolean(status.value?.flowoffload && offload.value !== status.value.flowoffload))

const ifaceWan = ref('')
const ifaceLan = ref('')
watch(ifacesSettings, (i) => {
  if (!i) return
  ifaceWan.value = i.wan || i.suggested?.wan || ''
  ifaceLan.value = i.lan || i.suggested?.lan || ''
}, { immediate: true })

const ifaceOptions = computed(() => {
  const list = ifacesSettings.value?.available || []
  const names = list.map((x) => x.name)
  for (const extra of [ifaceWan.value, ifaceLan.value, ifacesSettings.value?.suggested?.wan, ifacesSettings.value?.suggested?.lan]) {
    if (extra && !names.includes(extra)) names.push(extra)
  }
  return names
})

const wgOn = ref(false)
const wgBlob = ref('')
const wgRepeats = ref(2)
watch(wgStateSettings, (w) => { if (w) wgOn.value = !!w.enabled }, { immediate: true })
watch(wgBlobSettings, (w) => {
  if (!w) return
  wgBlob.value = w.current_blob || ''
  wgRepeats.value = Number(w.current_repeats || 2)
}, { immediate: true })

const portProto = ref<'tcp' | 'udp'>('tcp')
const portValue = ref('')
const providerName = ref('')
const providerCity = ref('')
const recommendations = ref<Recommendations | null>(null)
const recommendationsBusy = ref(false)
const providerKnown = computed(() => {
  const name = String(provider.value?.provider || '').trim()
  return !!name && name !== 'Не определён' && name !== 'Unknown'
})
const providerDraftSaved = computed(() => {
  const parts = String(provider.value?.provider || '').split(' - ')
  return providerName.value.trim() === (parts[0] || '') && providerCity.value.trim() === parts.slice(1).join(' - ')
})
const recommendationProfiles = computed(() => Object.entries(recommendations.value?.profiles || {}))
watch(provider, (p) => {
  const raw = String(p?.provider || '')
  if (raw === 'Не определён') {
    providerName.value = ''
    providerCity.value = ''
    return
  }
  const parts = raw.split(' - ')
  providerName.value = parts[0] || ''
  providerCity.value = parts.slice(1).join(' - ')
}, { immediate: true })

const scopeForm = reactive({ enable: false, mask: '0xff00', shift: '8', max: '255' })
const clientMappings = ref<ClientScopeMapping[]>([])
const clientIP = ref('')
const clientScopeID = ref('1')
watch(scopes, (s) => {
  if (!s) return
  scopeForm.enable = !!s.enabled
  if (s.mask != null && String(s.mask) !== '') scopeForm.mask = String(s.mask)
  if (s.shift != null) scopeForm.shift = String(s.shift)
  if (s.max_scope != null) scopeForm.max = String(s.max_scope)
}, { immediate: true })

const configText = ref('')
const configPath = ref('')
const configLoaded = ref(false)
const errors = ref({ available: false, content: '', path: '', lines: 0, suppressed_conntrack: 0 })
const wssizeOn = ref(false)
const wssizeMode = ref<WssizeRampSettings['mode']>('full')
const wssizeScale = ref(1)
watch(wssizeRampSettings, (w) => {
  if (!w) return
  wssizeOn.value = w.enabled
  wssizeMode.value = w.mode
  wssizeScale.value = w.scale
}, { immediate: true })

const portList = computed(() => {
  const info = ports.value?.[portProto.value]
  return info?.user || []
})

async function refresh() {
  try {
    await withBusy('refresh-settings', fetchAndApplyState)
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

function modeOn(m: typeof modes[number]) {
  if (m.fromFallback) return fallbackSettings.value?.enabled
  if (m.fromUdp) return udpGamesSettings.value?.enabled
  const d = modeSettings[m.key]
  return m.field === 'auto' ? d?.auto : d?.enabled
}

async function toggleMode(m: typeof modes[number], on: boolean) {
  try {
    await withBusy(`mode-${m.key}`, async () => {
      announceRestart()
      const res = await applySetting.mode_state(m.post, on)
      showToast(`${m.title}: ${on ? 'вкл' : 'выкл'}.${restartSuffix(res)}`)
      if (m.fromFallback) await refreshFallbackSettings()
      else if (m.fromUdp) await refreshUdpGamesSettings()
      else await refreshModeSetting(m.key)
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveSelect(setting: string, value: string, label: string) {
  try {
    await withBusy(`sel-${setting}`, async () => {
      announceRestart()
      const res = await api('/api/settings', formBody({ setting, value }))
      showToast(`${label}: ${value}.${restartSuffix(res)}`)
      await fetchAndApplyState()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveWg(restart = true) {
  try {
    const repeats = Number(wgRepeats.value)
    if (!Number.isInteger(repeats) || repeats < 2 || repeats > 99) {
      showToast('Repeats WireGuard: целое число 2-99', 'error')
      return
    }
    if (wgOn.value && !String(wgBlob.value || '').trim()) {
      showToast('Выберите WG blob перед включением', 'error')
      return
    }
    await withBusy('wg', async () => {
      if (restart) announceRestart()
      // Один рестарт в конце: иначе двойной maybeRestart.
      await applySetting.wg_state(wgOn.value, false)
      if (wgBlob.value) await applySetting.wg_blob(wgBlob.value, false)
      await applySetting.wg_repeats(repeats, restart)
      showToast('WireGuard сохранён')
      await refreshWgBlobSettings()
      await refreshWgStateSettings()
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function addPort() {
  try {
    const raw = String(portValue.value ?? '').trim()
    if (!raw) {
      showToast('Укажите порт или список портов', 'error')
      return
    }
    await withBusy('port-add', async () => {
      announceRestart()
      const res = await applySetting.ports_add(portProto.value, raw)
      portValue.value = ''
      showToast(`Порты добавлены.${restartSuffix(res)}`)
      await refreshPorts()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function removePort(v: string) {
  try {
    await withBusy('port-rm', async () => {
      announceRestart()
      await applySetting.ports_remove(portProto.value, v)
      await refreshPorts()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveProvider() {
  try {
    await withBusy('provider', async () => {
      await applySetting.provider_set(providerName.value.trim(), providerCity.value.trim())
      showToast('Провайдер сохранён')
      await refreshProvider()
      await refreshAll()
      recommendations.value = null
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function setTelemetryConsent(enabled: boolean) {
  try {
    await withBusy('telemetry', async () => {
      const result = await applySetting.telemetry_consent(enabled)
      await fetchAndApplyState()
      if (!enabled) showToast('Отправка статистики отключена')
      else if (!result.configured) showToast('Согласие сохранено. Сервер отправки не настроен, данные не отправляются.')
      else if (result.sent) showToast('Согласие сохранено, статистика отправлена')
      else showToast('Согласие сохранено, отправить статистику не удалось', 'error')
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveScope() {
  try {
    await withBusy('scope', async () => {
      announceRestart()
      const res = await api<{ ok?: boolean; enabled?: boolean; warning?: string }>('/api/settings', formBody({
        setting: 'client_scope',
        client_scope_enable: scopeForm.enable ? '1' : '0',
        client_scope_mark_mask: String(scopeForm.mask ?? '').trim(),
        client_scope_mark_shift: String(scopeForm.shift ?? '').trim(),
        client_scope_mark_max: String(scopeForm.max ?? '').trim(),
      }))
      await fetchAndApplyState()
      const enabled = res.enabled ?? !!scopes.value?.enabled
      scopeForm.enable = !!enabled
      if (res.warning) {
        showToast(res.warning, 'warning')
      } else {
        showToast(enabled ? 'Client scopes включены' : 'Client scopes выключены')
      }
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function refreshClientScopes() {
  const data = await fetchClientScopes()
  clientMappings.value = data.mappings || []
}

async function addClientScope() {
  const ip = clientIP.value.trim()
  const id = Number(clientScopeID.value)
  if (!ip || !Number.isInteger(id) || id < 1 || id > Number(scopes.value.max_scope || 255)) {
    showToast(`Укажите IP и номер scope от 1 до ${scopes.value.max_scope || 255}`, 'error')
    return
  }
  try {
    await withBusy('client-scope-add', async () => {
      announceRestart()
      const res = await updateClientScope('add', ip, `mark:${id}`)
      clientIP.value = ''
      showToast(`Клиент ${ip} добавлен в mark:${id}.${restartSuffix(res)}`)
      await refreshClientScopes()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function removeClientScope(mapping: ClientScopeMapping) {
  try {
    await withBusy(`client-scope-rm-${mapping.ip}`, async () => {
      announceRestart()
      const res = await updateClientScope('remove', mapping.ip)
      showToast(`Клиент ${mapping.ip} удалён.${restartSuffix(res)}`)
      await refreshClientScopes()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function loadConfig() {
  try {
    await withBusy('cfg-load', async () => {
      const data = await api<{ content?: string; path?: string; error?: string }>('/api/settings?setting=config_raw')
      if (data.error) throw new Error(data.error)
      configText.value = data.content || ''
      configPath.value = data.path || ''
      configLoaded.value = true
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveConfig() {
  const ok = await confirmDialog({
    title: 'Записать config?',
    message: ['Файл zapret2/config будет перезаписан.', 'zapret2 перезапустится.'],
    danger: true,
  })
  if (!ok) return
  try {
    await withBusy('cfg-save', async () => {
      announceRestart()
      await api('/api/settings', formBody({ setting: 'config_raw', value: configText.value }))
      showToast('Конфиг сохранён')
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function loadErrors() {
  try {
    await withBusy('err-load', async () => {
      const data = await api<typeof errors.value>('/api/settings?setting=nfqws2_errors')
      errors.value = {
        available: !!data.available,
        content: data.content || '',
        path: data.path || '',
        lines: data.lines || 0,
        suppressed_conntrack: data.suppressed_conntrack || 0,
      }
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function downloadBackup(name: string) {
  try {
    await withBusy('bak-dl', async () => {
      await backupsApi.download(name)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveWssize() {
  if (!wssizeRampSettings.value) return
  if (!Number.isInteger(wssizeScale.value) || wssizeScale.value < 0 || wssizeScale.value > 14) {
    showToast('Scale должен быть 0-14', 'error')
    return
  }
  try {
    await withBusy('wssize', async () => {
      announceRestart()
      const res = await applySetting.wssize_ramp({
        ...wssizeRampSettings.value!,
        enabled: wssizeOn.value,
        mode: wssizeMode.value,
        scale: wssizeScale.value,
      })
      showToast(`wssize_ramp сохранён.${restartSuffix(res)}`)
      await refreshWssizeRampSettings()
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function refreshWssizeIps() {
  try {
    await withBusy('wssize-refresh', async () => {
      const res = await applySetting.wssize_refresh_ips()
      const parts = [`Googlevideo IP: ${res.ipv4_count ?? 0}`]
      if ((res.local_ips ?? 0) > 0 || (res.sni_resolved_ips ?? 0) > 0) {
        parts.push(`локально: ${res.local_ips ?? 0}`)
      }
      if (res.ipv4_error) {
        showToast(`${parts.join(', ')} (feed: ${res.ipv4_error})`, 'warning')
      } else {
        showToast(parts.join(', '))
      }
      await refreshWssizeRampSettings()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function saveIfaces() {
  if (!ifaceWan.value.trim() || !ifaceLan.value.trim()) {
    showToast('Укажите WAN и LAN', 'error')
    return
  }
  try {
    await withBusy('ifaces', async () => {
      announceRestart()
      const res = await applySetting.ifaces({ lan: ifaceLan.value.trim(), wan: ifaceWan.value.trim() })
      showToast(`Интерфейсы: LAN=${ifaceLan.value}, WAN=${ifaceWan.value}.${restartSuffix(res)}`)
      await refreshIfacesSettings()
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function redetectIfaces() {
  try {
    await withBusy('ifaces-auto', async () => {
      announceRestart()
      const res = await applySetting.ifaces({ action: 'redetect' })
      showToast(`Автоопределение: LAN=${res.lan || '-'}, WAN=${res.wan || '-'}.${restartSuffix(res)}`)
      await refreshIfacesSettings()
      await refreshAll()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function redetectProvider() {
  try {
    await withBusy('provider-redetect', async () => {
      await applySetting.provider_redetect()
      showToast('Провайдер переопределён')
      await refreshProvider()
      await refreshAll()
      recommendations.value = null
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function loadRecommendations() {
  try {
    recommendationsBusy.value = true
    recommendations.value = await fetchRecommendations()
  } catch (e) {
    showToast((e as Error).message, 'error')
  } finally {
    recommendationsBusy.value = false
  }
}

async function uploadBackup(ev: Event) {
  const input = ev.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  try {
    await withBusy('bak-upload', async () => {
      const res = await backupsApi.upload(file)
      showToast(`Загружен: ${res.name}`)
      await fetchAndApplyState()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function createBackup() {
  try {
    await withBusy('bak-create', async () => {
      const res = await backupsApi.create()
      showToast(`Бэкап: ${res.name}`)
      await fetchAndApplyState()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function deleteBackup(name: string) {
  const ok = await confirmDialog({ title: 'Удалить бэкап?', message: name, danger: true })
  if (!ok) return
  try {
    await withBusy('bak-del', async () => {
      await backupsApi.delete(name)
      await fetchAndApplyState()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function restoreBackup(name: string) {
  const ok = await confirmDialog({
    title: 'Восстановить бэкап?',
    message: [
      `Архив: ${name}`,
      'Будут восстановлены конфиг, списки доменов и локи стратегий.',
      'zapret2 будет перезапущен.',
    ],
    danger: true,
    confirmText: 'Восстановить',
  })
  if (!ok) return
  try {
    await withBusy('bak-restore', async () => {
      announceRestart()
      const res = await backupsApi.restore(name, 'full')
      showToast(`Восстановлено файлов: ${res.files ?? 0}.${restartSuffix(res)}`)
      await fetchAndApplyState()
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

const panelAliases: Record<string, string> = {
  updates: 'sec-updates', provider: 'sec-provider', backups: 'sec-backups',
  modes: 'sec-modes', 'auto-mode': 'sec-modes', fallback: 'sec-modes', hostlist: 'sec-modes',
  'udp-games': 'sec-modes', 'dns-desync': 'sec-modes', 'rst-guard': 'sec-modes',
  reasm: 'sec-modes',
  tls: 'sec-tls', 'tls-blob': 'sec-tls',
  wg: 'sec-wg', wireguard: 'sec-wg',
  wssize: 'sec-wssize', 'wssize-ramp': 'sec-wssize',
  firewall: 'sec-firewall', fwtype: 'sec-firewall', flowoffload: 'sec-firewall',
  ifaces: 'sec-ifaces', iface: 'sec-ifaces', interfaces: 'sec-ifaces',
  ports: 'sec-ports', scopes: 'sec-scopes', 'client-scope': 'sec-scopes',
  zapret: 'sec-zapret', 'zapret-version': 'sec-zapret', config: 'sec-config', errors: 'sec-errors',
}

function panelIdFromRoute(): string {
  const raw = String(route.params.panel || (route.hash || '').replace(/^#/, '') || '')
  if (!raw) return 'sec-modes'
  return panelAliases[raw] || (raw.startsWith('sec-') ? raw : `sec-${raw}`)
}

const activeCategory = computed(() => {
  const id = panelIdFromRoute()
  const section = sections.find((item) => item.id === id)
  const group = section?.group
  return group === 'Обход' ? 'bypass' : group === 'Сеть' ? 'network' : group === 'Сервис' ? 'diagnostics' : 'system'
})

const targetSectionId = ref('')
let targetTimer: number | undefined

function scrollTargetPanel() {
  const explicitPanel = String(route.params.panel || (route.hash || '').replace(/^#/, '') || '').trim()
  if (!explicitPanel || !settingsLoaded.value) return
  const id = panelIdFromRoute()
  void nextTick(() => {
    const el = document.getElementById(id)
    if (!el) return
    el.scrollIntoView({ block: 'start', behavior: 'smooth' })
    targetSectionId.value = id
    window.clearTimeout(targetTimer)
    targetTimer = window.setTimeout(() => { targetSectionId.value = '' }, 4000)
  })
}

watch(activeCategory, (cat) => {
  if (cat === 'diagnostics' && zapretReleasesState.value === 'idle') {
    void loadZapretReleases(false)
  }
}, { immediate: true })

watch([() => route.params.panel, () => route.hash, settingsLoaded], () => {
  scrollTargetPanel()
}, { immediate: true })

function goSection(id: string) {
  const slug = id.replace(/^sec-/, '')
  void router.push(`/settings/${slug}`)
}

onMounted(async () => {
  // Последовательно: параллельный withBusy раньше сбрасывал busy чужим finally.
  await loadConfig()
  await loadErrors()
  try { await refreshClientScopes() } catch (e) { showToast((e as Error).message, 'error') }
})

onBeforeUnmount(() => {
  window.clearTimeout(targetTimer)
})
</script>

<template>
  <section class="page-stack">
    <header class="page-head">
      <div>
        <span class="eyebrow">Конфигурация системы</span>
        <h1>Настройки</h1>
        <p>Режимы обхода DPI, сетевые параметры, обновления и диагностические инструменты.</p>
      </div>
      <div class="actions">
        <button type="button" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'refresh-settings' }" @click="refresh">
          <Icon name="refresh" class="icon-sm" />
          <span>Обновить</span>
        </button>
      </div>
    </header>

    <div class="tabs-bar" role="tablist" aria-label="Категории настроек">
      <button
        v-for="group in settingGroups"
        :key="group.key"
        type="button"
        role="tab"
        :aria-selected="activeCategory === group.key"
        class="tab-pill"
        :class="{ active: activeCategory === group.key }"
        @click="goSection(group.first)"
      >
        {{ group.title }}
      </button>
    </div>

    <div v-if="!settingsLoaded" class="skeleton-list" aria-label="Загрузка настроек">
      <div class="skeleton-row is-tall" />
      <div v-for="i in 3" :key="i" class="skeleton-row" />
    </div>

    <template v-else>
      <div v-show="activeCategory === 'system'" class="settings-category">
        <section id="sec-updates" class="panel" :class="{ 'is-target': targetSectionId === 'sec-updates' }">
          <div class="panel-h"><h2>Обновления</h2></div>
          <p class="panel-d">Выберите, какие части обновить. Конфигурация включает Lua, стратегии, списки и blob-файлы.</p>
          <p class="panel-d" role="status">
            <template v-if="updateCheckState === 'checking'">Проверяем обновления...</template>
            <template v-else-if="updateCheckState === 'error'">Проверка не удалась: {{ updateCheckError }}</template>
            <template v-else-if="updateCheckState === 'success'">
              {{ updateCheckResult?.update_available ? 'Есть обновление' : 'Новых выпусков не найдено' }}
              <template v-if="updateCheckResult?.release"> · {{ updateCheckResult.release }}</template>
            </template>
            <template v-else>Версия ещё не проверена</template>
          </p>
          <div class="updates-bar">
            <label class="field">
              <span>Режим</span>
              <select v-model="updateMode" :disabled="busyActive">
                <option value="app">Только Zator</option>
                <option value="config">Только конфиги и стратегии</option>
                <option value="full">Всё</option>
              </select>
            </label>
            <button
              type="button"
              :disabled="busyActive || updateCheckState === 'checking'"
              :class="{ 'is-busy': updateCheckState === 'checking' }"
              @click="refreshUpdateCheck"
            >
              Проверить
            </button>
            <button type="button" class="primary" :disabled="busyActive" @click="applyUpdate(updateMode)">Обновить</button>
          </div>
        </section>

        <section id="sec-provider" class="panel" :class="{ 'is-target': targetSectionId === 'sec-provider' }">
          <div class="panel-h"><h2>Провайдер</h2></div>
          <p class="panel-d">Нужен для рекомендаций стратегий. Можно задать вручную или определить автоматически.</p>
          <div class="grid-2">
            <label class="field"><span>Имя</span><input v-model="providerName" :disabled="busyActive"></label>
            <label class="field"><span>Город</span><input v-model="providerCity" :disabled="busyActive"></label>
          </div>
          <div class="actions section-actions">
            <button type="button" class="primary" :disabled="busyActive || !providerName.trim()" @click="saveProvider">Сохранить</button>
            <button
              type="button"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === 'provider-redetect' }"
              @click="redetectProvider"
            >
              Определить заново
            </button>
          </div>

          <hr class="panel-divider">

          <div class="subsection">
            <h3>Рекомендации стратегий</h3>
            <p class="panel-d">В запросе передаётся название провайдера; сервер также видит IP роутера. Подсказки основаны на статистике успешных проверок и кешируются на сутки.</p>
            <div>
              <button
                type="button"
                :disabled="!providerKnown || !providerDraftSaved || recommendationsBusy || busyActive"
                @click="loadRecommendations"
              >
                {{ recommendationsBusy ? 'Загрузка...' : 'Загрузить рекомендации' }}
              </button>
            </div>
            <p v-if="!providerKnown" class="panel-d sub-note">Сначала определите или сохраните провайдера.</p>
            <p v-else-if="!providerDraftSaved" class="panel-d sub-note">Сначала сохраните изменённое название провайдера.</p>
            <template v-if="recommendations">
              <p class="panel-d sub-note">
                <template v-if="recommendations.status === 'ready'">Статистика собрана с {{ recommendations.samples }} установок.</template>
                <template v-else-if="recommendations.status === 'insufficient'">Пока мало данных: {{ recommendations.samples }} установок, требуется {{ recommendations.minimum }}.</template>
                <template v-else-if="recommendations.status === 'stale'">Сервер временно недоступен; показан сохранённый результат.</template>
                <template v-else-if="recommendations.status === 'unknown_provider'">Провайдер не определён.</template>
                <template v-else>Рекомендации пока недоступны.</template>
              </p>
              <div class="list-stack">
                <div v-for="[profileId, item] in recommendationProfiles" :key="profileId" class="list-row">
                  <div class="rec-head">
                    <strong>Профиль {{ profileId }}</strong>
                    <span v-if="item.clone_recommended" class="chip on">
                      клоны {{ item.clone_pct }}% против {{ item.classic_pct }}%
                    </span>
                  </div>
                  <p v-if="item.top.length" class="panel-sub">
                    Лучшие стратегии: {{ item.top.map((x) => `${x.strategy} (${x.success_pct}%, ${x.mode})`).join(', ') }}
                  </p>
                  <p v-else class="panel-sub">Нет достаточной статистики по стратегиям.</p>
                </div>
              </div>
            </template>
          </div>
        </section>

        <section id="sec-telemetry" class="panel" :class="{ 'is-target': targetSectionId === 'sec-telemetry' }">
          <div class="panel-h"><h2>Анонимная статистика</h2></div>
          <p class="panel-d">При согласии отправляются псевдоним установки, провайдер, номера стратегий, выбранные TLS blob и режим fake, тип устройства и наличие WebUI. Домены и содержимое трафика не отправляются.</p>
          <p class="panel-d">Отправка выключена, пока вы явно не дадите согласие.</p>
          <label class="toggle-row">
            <span>Разрешить отправку статистики</span>
            <input
              type="checkbox"
              :checked="!!telemetrySettings?.enabled"
              :disabled="busyActive"
              @change="setTelemetryConsent(($event.target as HTMLInputElement).checked)"
            >
          </label>
          <p v-if="telemetrySettings?.enabled && !telemetrySettings.configured" class="panel-d sub-note">
            Согласие сохранено, но endpoint и token отправки не настроены; статистика не отправляется.
          </p>
        </section>

        <section id="sec-backups" class="panel" :class="{ 'is-target': targetSectionId === 'sec-backups' }">
          <div class="panel-h"><h2>Бэкапы</h2></div>
          <p class="panel-d">Снимок конфига и локов. Можно скачать или восстановить из файла.</p>
          <div class="actions">
            <button
              type="button"
              class="primary"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === 'bak-create' }"
              @click="createBackup"
            >
              <Icon name="plus" class="icon-sm" />
              <span>Создать бэкап</span>
            </button>
            <div class="file-picker">
              <label class="file-picker-btn" :class="{ 'is-disabled': busyActive }">
                <Icon name="upload" class="icon-sm" />
                <span>Загрузить архив</span>
                <input
                  type="file"
                  accept=".tar,.tgz,.gz,application/x-tar"
                  class="sr-only"
                  :disabled="busyActive"
                  @change="uploadBackup"
                >
              </label>
            </div>
          </div>
          <div v-if="(backups?.items || []).length" class="list-stack list-top-gap">
            <div v-for="b in (backups?.items || [])" :key="b.name" class="list-row compact-item">
              <div class="item-meta">
                <code>{{ b.name }}</code>
                <small>{{ b.date }} · {{ b.size ?? 0 }}</small>
              </div>
              <div class="actions">
                <button
                  type="button"
                  class="ghost compact-btn"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === 'bak-dl' }"
                  @click="downloadBackup(b.name)"
                >
                  <Icon name="download" class="icon-sm" />
                  <span>Скачать</span>
                </button>
                <button
                  type="button"
                  class="compact-btn"
                  :disabled="busyActive"
                  :class="{ 'is-busy': busyButton === 'bak-restore' }"
                  @click="restoreBackup(b.name)"
                >
                  Восстановить
                </button>
                <button
                  type="button"
                  class="ghost danger icon-btn"
                  aria-label="Удалить бэкап"
                  title="Удалить бэкап"
                  :disabled="busyActive"
                  @click="deleteBackup(b.name)"
                >
                  <Icon name="trash" class="icon-sm" />
                </button>
              </div>
            </div>
          </div>
          <p v-else class="panel-d sub-note">Сохранённых бэкапов пока нет.</p>
        </section>
      </div>

      <div v-show="activeCategory === 'bypass'" class="settings-category">
        <section id="sec-modes" class="panel" :class="{ 'is-target': targetSectionId === 'sec-modes' }">
          <div class="panel-h"><h2>Режимы обхода</h2></div>
          <p class="panel-d">Авторотация, hostlist, fallback, DNS, UDP games, RST и reasm.</p>
          <div class="grid-2">
            <label v-for="m in modes" :key="m.key" class="toggle-row">
              <span>{{ m.title }}</span>
              <input
                type="checkbox"
                :checked="!!modeOn(m)"
                :disabled="busyActive"
                @change="toggleMode(m, ($event.target as HTMLInputElement).checked)"
              >
            </label>
          </div>
          <p v-if="udpGamesSettings?.ports" class="panel-d sub-note">
            UDP Games порты: <code>{{ udpGamesSettings.ports }}</code> · стратегия профиля 7 во вкладке «Стратегии».
          </p>
        </section>

        <section id="sec-tls" class="panel" :class="{ 'is-target': targetSectionId === 'sec-tls' }">
          <div class="panel-h">
            <h2>TLS / QUIC блобы и SNI</h2>
            <span class="chip">{{ tlsBlobSettings?.current_mode || '-' }}</span>
          </div>
          <p class="panel-d">
            Глобальный TLS blob: <code>{{ tlsBlobSettings?.current_blob || tlsBlobSettings?.current_mode || '-' }}</code>.
            Управление глобальным и профильными блобами (включая QUIC/5), режимами фейков, SNI-пулом и загрузкой бинарных файлов вынесено в отдельный раздел.
          </p>
          <div class="actions">
            <router-link class="btn-link" to="/blobs-sni">
              <span>Открыть «Блобы и SNI»</span>
              <Icon name="arrow-right" class="icon-sm" />
            </router-link>
          </div>
        </section>

        <section id="sec-wg" class="panel" :class="{ 'is-target': targetSectionId === 'sec-wg' }">
          <div class="panel-h">
            <h2>WireGuard fakes</h2>
            <span class="chip" :class="{ on: wgOn }">{{ wgOn ? 'вкл' : 'выкл' }}</span>
          </div>
          <div class="grid-2">
            <label class="toggle-row">
              <span>Включить WG-стратегию</span>
              <input v-model="wgOn" type="checkbox" :disabled="busyActive">
            </label>
            <label class="field">
              <span>Repeats</span>
              <input v-model.number="wgRepeats" type="number" min="2" max="99" :disabled="busyActive">
            </label>
            <label class="field field-full">
              <span>Blob</span>
              <select v-model="wgBlob" :disabled="busyActive">
                <option v-for="b in (wgBlobSettings?.available_blobs || [])" :key="b" :value="b">{{ b }}</option>
              </select>
            </label>
          </div>
          <div class="actions section-actions">
            <button type="button" class="primary" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'wg' }" @click="saveWg(true)">
              Сохранить WG
            </button>
          </div>
        </section>

        <section id="sec-wssize" class="panel" :class="{ 'is-target': targetSectionId === 'sec-wssize' }">
          <div class="panel-h">
            <h2>WSSIZE ramp</h2>
            <span v-if="wssizeRampSettings" class="chip" :class="{ on: wssizeOn }">{{ wssizeOn ? 'вкл' : 'выкл' }}</span>
          </div>
          <p v-if="!wssizeRampSettings" class="panel-d">Настройка недоступна в этой сборке или ещё не загружена.</p>
          <template v-else>
            <p class="panel-d">
              Googlevideo IP: <strong class="mono">{{ wssizeRampSettings.googlevideo_ips }}</strong>
              <template v-if="(wssizeRampSettings.googlevideo_local_ips ?? 0) > 0"> · локально: {{ wssizeRampSettings.googlevideo_local_ips }}</template>
              <template v-if="(wssizeRampSettings.googlevideo_hosts ?? 0) > 0"> · SNI-хостов: {{ wssizeRampSettings.googlevideo_hosts }}</template>
              · DNS-сбор: {{ wssizeRampSettings.googlevideo_local_collection }}
              <template v-if="wssizeRampSettings.googlevideo_generated"> · от {{ wssizeRampSettings.googlevideo_generated.slice(0, 16).replace('T', ' ') }} UTC</template>
            </p>
            <div class="grid-2">
              <label class="toggle-row field-full">
                <span>Включить wssize_ramp</span>
                <input v-model="wssizeOn" type="checkbox" :disabled="busyActive">
              </label>
              <label class="field">
                <span>Режим</span>
                <select v-model="wssizeMode" :disabled="busyActive">
                  <option value="full">full</option>
                  <option value="lite">lite</option>
                </select>
              </label>
              <label class="field">
                <span>Scale (0-14)</span>
                <input v-model.number="wssizeScale" type="number" min="0" max="14" :disabled="busyActive">
              </label>
            </div>
            <div class="actions section-actions">
              <button type="button" class="primary" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'wssize' }" @click="saveWssize">
                Сохранить
              </button>
              <button type="button" class="ghost" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'wssize-refresh' }" @click="refreshWssizeIps">
                <Icon name="refresh" class="icon-sm" />
                <span>Обновить IP</span>
              </button>
            </div>
          </template>
        </section>
      </div>

      <div v-show="activeCategory === 'network'" class="settings-category">
        <section id="sec-firewall" class="panel" :class="{ 'is-target': targetSectionId === 'sec-firewall' }">
          <div class="panel-h"><h2>Firewall / Offload</h2></div>
          <p class="panel-d">Тип межсетевого экрана и flow offload.</p>
          <div class="grid-2">
            <div class="fw-pair">
              <label class="field">
                <span>FWTYPE</span>
                <select v-model="fw" :disabled="busyActive">
                  <option value="iptables">iptables</option>
                  <option value="nftables">nftables</option>
                </select>
              </label>
              <button type="button" :class="{ primary: fwDirty }" :disabled="busyActive" @click="saveSelect('fwtype', fw, 'FWTYPE')">
                Сохранить FW
              </button>
            </div>
            <div class="fw-pair">
              <label class="field">
                <span>FLOWOFFLOAD</span>
                <select v-model="offload" :disabled="busyActive">
                  <option value="donttouch">donttouch</option>
                  <option value="none">none</option>
                  <option value="software">software</option>
                  <option value="hardware">hardware</option>
                </select>
              </label>
              <button type="button" :class="{ primary: offloadDirty }" :disabled="busyActive" @click="saveSelect('flowoffload', offload, 'Offload')">
                Сохранить Offload
              </button>
            </div>
          </div>
        </section>

        <section id="sec-ifaces" class="panel" :class="{ 'is-target': targetSectionId === 'sec-ifaces' }">
          <div class="panel-h">
            <h2>Интерфейсы WAN / LAN</h2>
            <span v-if="ifacesSettings?.needs_autodetect" class="chip is-warn">нужно задать</span>
          </div>
          <p class="panel-d">
            На Keenetic/Entware без <code>IFACE_WAN</code> / <code>IFACE_LAN</code> правила NFQUEUE не цепляют трафик.
            WAN: uplink (default route), LAN: локальный bridge (обычно <code>br0</code>).
          </p>
          <p v-if="ifacesSettings?.suggested" class="panel-d">
            Автоопределение:
            WAN=<code>{{ ifacesSettings.suggested.wan || '-' }}</code>,
            LAN=<code>{{ ifacesSettings.suggested.lan || '-' }}</code>
            <template v-if="ifacesSettings.suggested.source"> · {{ ifacesSettings.suggested.source }}</template>
          </p>
          <div class="grid-2">
            <label class="field">
              <span>IFACE_WAN (внешний)</span>
              <select v-model="ifaceWan" :disabled="busyActive">
                <option v-for="n in ifaceOptions" :key="'w-' + n" :value="n">{{ n }}</option>
              </select>
            </label>
            <label class="field">
              <span>IFACE_LAN (локальный)</span>
              <select v-model="ifaceLan" :disabled="busyActive">
                <option v-for="n in ifaceOptions" :key="'l-' + n" :value="n">{{ n }}</option>
              </select>
            </label>
          </div>
          <div class="actions section-actions">
            <button type="button" class="primary" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'ifaces' }" @click="saveIfaces">
              Сохранить
            </button>
            <button type="button" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'ifaces-auto' }" @click="redetectIfaces">
              Определить заново
            </button>
          </div>
        </section>

        <section id="sec-ports" class="panel" :class="{ 'is-target': targetSectionId === 'sec-ports' }">
          <div class="panel-h"><h2>Порты NFQWS2</h2></div>
          <p class="panel-d">Дополнительные порты, которые обрабатывает nfqws2.</p>
          <div class="port-add-form">
            <select v-model="portProto" :disabled="busyActive" aria-label="Протокол">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <input v-model="portValue" :disabled="busyActive" placeholder="443 или 1000-2000" aria-label="Порт или диапазон">
            <button type="button" class="primary" :disabled="busyActive" @click="addPort">
              <Icon name="plus" class="icon-sm" />
              <span>Добавить</span>
            </button>
          </div>
          <p v-if="ports?.[portProto]?.full" class="panel-d sub-note">Текущие: <code>{{ ports[portProto]?.full }}</code></p>
          <div v-if="portList.length" class="list-stack list-top-gap">
            <div v-for="p in portList" :key="p" class="list-row compact-item">
              <code>{{ p }}</code>
              <button
                type="button"
                class="ghost danger icon-btn"
                aria-label="Удалить порт"
                title="Удалить порт"
                :disabled="busyActive"
                @click="removePort(p)"
              >
                <Icon name="trash" class="icon-sm" />
              </button>
            </div>
          </div>
          <p v-else class="panel-d sub-note">Пользовательских портов пока нет.</p>
        </section>

        <section id="sec-scopes" class="panel" :class="{ 'is-target': targetSectionId === 'sec-scopes' }">
          <div class="panel-h">
            <h2>Client scopes</h2>
            <span class="chip" :class="{ on: scopeForm.enable }">{{ scopeForm.enable ? 'вкл' : 'выкл' }}</span>
          </div>
          <p class="panel-d">Разные стратегии для разных клиентов по mark. Локи задаются во вкладке «Стратегии».</p>
          <div class="grid-2">
            <label class="toggle-row">
              <span>Включить режим mark</span>
              <input v-model="scopeForm.enable" type="checkbox" :disabled="busyActive">
            </label>
            <label class="field"><span>mask</span><input v-model="scopeForm.mask" :disabled="busyActive"></label>
            <label class="field"><span>shift</span><input v-model="scopeForm.shift" type="number" min="0" max="31" :disabled="busyActive"></label>
            <label class="field"><span>max</span><input v-model="scopeForm.max" type="number" min="1" max="255" :disabled="busyActive"></label>
          </div>
          <div class="actions section-actions">
            <button type="button" class="primary" :disabled="busyActive" :class="{ 'is-busy': busyButton === 'scope' }" @click="saveScope">
              Сохранить scopes
            </button>
          </div>

          <hr class="panel-divider">

          <p class="panel-d">IP клиента -> mark scope. Устройства с этим IP будут использовать стратегии выбранного mark.</p>
          <div class="client-scope-form">
            <label class="field">
              <span>IP клиента</span>
              <input v-model="clientIP" :disabled="busyActive" placeholder="192.168.1.10 или IPv6">
            </label>
            <label class="field">
              <span>Mark ID</span>
              <input v-model="clientScopeID" :disabled="busyActive" type="number" min="1" :max="scopes.max_scope || 255">
            </label>
            <button type="button" class="primary" :disabled="busyActive" @click="addClientScope">
              <Icon name="plus" class="icon-sm" />
              <span>Добавить</span>
            </button>
          </div>
          <div v-if="clientMappings.length" class="list-stack list-top-gap">
            <div v-for="mapping in clientMappings" :key="mapping.ip" class="list-row compact-item">
              <div class="item-meta">
                <code>{{ mapping.ip }}</code>
                <span class="chip">{{ mapping.scope }}</span>
              </div>
              <button
                type="button"
                class="ghost danger icon-btn"
                aria-label="Удалить клиента"
                title="Удалить клиента"
                :disabled="busyActive"
                @click="removeClientScope(mapping)"
              >
                <Icon name="trash" class="icon-sm" />
              </button>
            </div>
          </div>
          <p v-else class="panel-d sub-note">IP-маппинги ещё не добавлены.</p>
        </section>
      </div>

      <div v-show="activeCategory === 'diagnostics'" class="settings-category">
        <section id="sec-zapret" class="panel" :class="{ 'is-target': targetSectionId === 'sec-zapret' }">
          <ZapretVersionManager />
        </section>

        <section id="sec-config" class="panel" :class="{ 'is-target': targetSectionId === 'sec-config' }">
          <div class="panel-h">
            <h2>Конфиг zapret2</h2>
            <button type="button" class="ghost compact-btn" :disabled="busyActive" @click="loadConfig">
              <Icon name="refresh" class="icon-sm" />
              <span>Перечитать</span>
            </button>
          </div>
          <p class="panel-d">Сырой файл · <code>{{ configPath || '/opt/zapret2/config' }}</code></p>
          <textarea v-if="configLoaded" v-model="configText" class="config-editor" :disabled="busyActive" spellcheck="false" />
          <div v-else class="skeleton-row is-tall" aria-label="Загрузка конфига" />
          <div class="actions section-actions">
            <button
              type="button"
              class="primary"
              :disabled="busyActive || !configLoaded"
              :class="{ 'is-busy': busyButton === 'cfg-save' }"
              @click="saveConfig"
            >
              Сохранить и перезапустить
            </button>
          </div>
        </section>

        <section id="sec-errors" class="panel" :class="{ 'is-target': targetSectionId === 'sec-errors' }">
          <div class="panel-h">
            <h2>Ошибки nfqws2</h2>
            <button type="button" class="ghost compact-btn" :disabled="busyActive" @click="loadErrors">
              <Icon name="refresh" class="icon-sm" />
              <span>Обновить</span>
            </button>
          </div>
          <p class="panel-d">Последние сообщения демона nfqws2.</p>
          <p v-if="!errors.available" class="panel-d">Журнал пуст или не найден.</p>
          <template v-else>
            <div class="error-meta">
              <code>{{ errors.path }}</code>
              <span class="chip">строк: {{ errors.lines }}</span>
              <span v-if="errors.suppressed_conntrack > 0" class="chip is-warn">
                скрыто conntrack: {{ errors.suppressed_conntrack }}
              </span>
            </div>
            <pre class="error-log">{{ errors.content || '(пусто)' }}</pre>
          </template>
        </section>
      </div>
    </template>
  </section>
</template>

<style scoped>
.settings-category {
  display: grid;
  gap: 0.9rem;
  min-width: 0;
}
.panel { scroll-margin-top: calc(var(--topbar-h) + 1rem); }
.field-full { grid-column: 1 / -1; }
.section-actions { margin-top: 0.85rem; }
.sub-note { margin: 0.7rem 0 0; }
.list-top-gap { margin-top: 0.8rem; }

.updates-bar {
  display: grid;
  grid-template-columns: minmax(12rem, 1fr) auto auto;
  gap: 0.5rem;
  align-items: end;
}

.subsection {
  display: grid;
  gap: 0.55rem;
}
.subsection h3 {
  margin: 0;
  font-size: 0.94rem;
  font-weight: 700;
}
.rec-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.fw-pair {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.5rem;
  align-items: end;
}

.port-add-form {
  display: grid;
  grid-template-columns: 7rem minmax(10rem, 1fr) auto;
  gap: 0.5rem;
  align-items: center;
}

.client-scope-form {
  display: grid;
  grid-template-columns: minmax(12rem, 1fr) 8.5rem auto;
  gap: 0.55rem;
  align-items: end;
}

.compact-item {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem 0.75rem;
}
.item-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.45rem;
  min-width: 0;
}
.item-meta small { color: var(--muted); font-size: 0.78rem; }
.item-meta code { overflow-wrap: anywhere; }

.error-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.45rem;
  margin-bottom: 0.65rem;
}

@media (max-width: 720px) {
  .updates-bar,
  .fw-pair,
  .port-add-form,
  .client-scope-form {
    grid-template-columns: 1fr;
  }
}
</style>
