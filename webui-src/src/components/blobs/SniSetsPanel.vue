<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { sni } from '../../api/endpoints'
import type { SniSetInfo } from '../../api/types'
import { busyActive, busyButton, withBusy } from '../../stores/busy'
import { confirmDialog } from '../../stores/confirm'
import { refreshSniState, sniSets, sniUnavailable } from '../../stores/sni'
import { showToast } from '../../stores/toast'
import Icon from '../ui/Icon.vue'

const userSets = computed(() => sniSets.value.filter((s: SniSetInfo) => s.origin === 'user'))
const zatorSets = computed(() => sniSets.value.filter((s: SniSetInfo) => s.origin !== 'user'))

const mode = ref<'create' | 'edit' | 'view'>('create')
const selectedKey = ref('')
const draftName = ref('')
const draftList = ref('')
const userSelectedMode = ref(false)

const domainLines = computed(() =>
  draftList.value.split(/\s+/).map((s) => s.trim()).filter(Boolean))

const selectedProjectSet = computed(() =>
  mode.value === 'view' ? zatorSets.value.find((s) => s.name === selectedKey.value) || null : null)

function selectNew(explicit = false) {
  if (explicit) userSelectedMode.value = true
  mode.value = 'create'
  selectedKey.value = ''
  draftName.value = ''
  draftList.value = ''
}

function selectUser(s: SniSetInfo) {
  userSelectedMode.value = true
  mode.value = 'edit'
  selectedKey.value = s.name
  draftName.value = s.name
  draftList.value = (s.domains || []).join('\n')
}

function selectProject(s: SniSetInfo) {
  userSelectedMode.value = true
  mode.value = 'view'
  selectedKey.value = s.name
}

function cloneProjectToUser(s: SniSetInfo) {
  userSelectedMode.value = true
  mode.value = 'create'
  selectedKey.value = ''
  draftName.value = `${s.name}_custom`.slice(0, 32)
  draftList.value = (s.domains || []).join('\n')
}

watch(sniSets, (list) => {
  if (!list.length) return
  if (mode.value === 'edit' && !list.some((s) => s.origin === 'user' && s.name === selectedKey.value)) {
    selectNew(false)
  }
  if (!userSelectedMode.value && !selectedKey.value) {
    if (userSets.value.length) selectUser(userSets.value[0])
    else if (zatorSets.value.length) selectProject(zatorSets.value[0])
  }
}, { deep: true, immediate: true })

async function saveSet() {
  const name = draftName.value.trim().toLowerCase()
  if (!name) {
    showToast('Введите имя набора (латиница, цифры, _)', 'error')
    return
  }
  if (!domainLines.value.length) {
    showToast('Добавьте хотя бы один домен', 'error')
    return
  }
  try {
    await withBusy('sni-set-save', async () => {
      await sni.writeSet(name, draftList.value)
      await refreshSniState()
      userSelectedMode.value = true
      mode.value = 'edit'
      selectedKey.value = name
      draftName.value = name
      showToast(`Набор «${name}» сохранён. Пул обновится на лету.`)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

async function removeSet(name: string) {
  const ok = await confirmDialog({
    title: `Удалить набор «${name}»?`,
    message: 'Набор будет удалён из sni_user.txt. Если он назначен профилю, сначала смените пул профиля.',
    confirmText: 'Удалить',
    danger: true,
  })
  if (!ok) return
  try {
    await withBusy(`sni-set-del-${name}`, async () => {
      await sni.deleteSet(name)
      await refreshSniState()
      showToast(`Набор «${name}» удалён.`)
      selectNew(true)
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}
</script>

<template>
  <section class="panel" aria-label="Наборы SNI">
    <p v-if="sniUnavailable" class="panel-d">Хранилище наборов SNI недоступно.</p>
    <div v-else class="sets-layout">
      <aside class="sets-sidebar">
        <div class="sidebar-top">
          <strong>Наборы</strong>
          <button
            type="button"
            class="ghost compact-btn"
            :class="{ 'new-active': mode === 'create' }"
            :disabled="busyActive"
            @click="selectNew(true)"
          >
            <Icon name="plus" class="icon-sm" />
            <span>Новый</span>
          </button>
        </div>

        <div class="group-label">Ваши ({{ userSets.length }})</div>
        <p v-if="!userSets.length" class="empty-hint">Пока нет своих наборов.</p>
        <button
          v-for="s in userSets"
          :key="'u-' + s.name"
          type="button"
          class="set-nav-item"
          :class="{ active: mode === 'edit' && selectedKey === s.name }"
          @click="selectUser(s)"
        >
          <span>{{ s.name }}</span>
          <span class="chip">{{ s.domains.length }}</span>
        </button>

        <div class="group-label group-label-extra">Проектные zator ({{ zatorSets.length }})</div>
        <button
          v-for="s in zatorSets"
          :key="'z-' + s.name"
          type="button"
          class="set-nav-item"
          :class="{ active: mode === 'view' && selectedKey === s.name }"
          @click="selectProject(s)"
        >
          <span>{{ s.name }}</span>
          <span class="chip">{{ s.domains.length }}</span>
        </button>
      </aside>

      <div class="sets-detail">
        <template v-if="selectedProjectSet">
          <div class="panel-h">
            <h2>{{ selectedProjectSet.name }}</h2>
            <span class="chip">zator · только чтение</span>
          </div>
          <p class="panel-d">
            Поставляется с Zator (<code>sni_zator.txt</code>). Одноимённый набор в <code>sni_user.txt</code> автоматически перекрывает проектный.
          </p>
          <div class="domain-chips">
            <span v-for="d in selectedProjectSet.domains" :key="d" class="chip">{{ d }}</span>
          </div>
          <div class="actions detail-actions">
            <button type="button" class="primary" :disabled="busyActive" @click="cloneProjectToUser(selectedProjectSet)">
              Клонировать в свой набор
            </button>
          </div>
        </template>

        <template v-else>
          <div class="panel-h">
            <h2>{{ mode === 'edit' ? `Редактирование: ${selectedKey}` : 'Новый свой набор' }}</h2>
            <span class="chip">sni_user.txt</span>
          </div>
          <p class="panel-d">Используется в SNI-пулах профилей и сохраняется в резервных копиях.</p>
          <div class="detail-fields">
            <label class="field">
              <span>Имя набора (латиница, цифры, <code>_</code>)</span>
              <input
                id="sni-set-name"
                v-model="draftName"
                type="text"
                placeholder="my_cdn"
                autocomplete="off"
                :disabled="busyActive"
              >
            </label>
            <label class="field">
              <span>Домены ({{ domainLines.length }} / 32, по одному в строке)</span>
              <textarea
                id="sni-set-list"
                v-model="draftList"
                rows="7"
                :disabled="busyActive"
                placeholder="www.google.com&#10;mail.ru"
              />
            </label>
          </div>
          <div class="actions detail-actions">
            <button
              id="sni-set-save"
              type="button"
              class="primary"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === 'sni-set-save' }"
              @click="saveSet"
            >
              Сохранить набор
            </button>
            <button
              v-if="mode === 'edit'"
              :id="`sni-set-del-${selectedKey}`"
              type="button"
              class="ghost danger"
              :disabled="busyActive"
              :class="{ 'is-busy': busyButton === `sni-set-del-${selectedKey}` }"
              @click="removeSet(selectedKey)"
            >
              Удалить набор
            </button>
          </div>
        </template>
      </div>
    </div>
  </section>
</template>

<style scoped>
.sets-layout {
  display: grid;
  grid-template-columns: minmax(215px, 260px) minmax(0, 1fr);
  gap: 1.15rem;
  align-items: start;
}
.sets-sidebar {
  display: grid;
  gap: 0.32rem;
  padding-right: 0.85rem;
  border-right: 1px solid var(--line);
}
.sidebar-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.35rem;
}
.new-active {
  border-color: color-mix(in srgb, var(--accent) 45%, var(--line));
  background: var(--accent-soft);
  color: var(--accent);
}
.group-label {
  color: var(--muted);
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.group-label-extra { margin-top: 0.7rem; }
.empty-hint { margin: 0.15rem 0; color: var(--muted); font-size: 0.8rem; }
.set-nav-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.4rem;
  width: 100%;
  min-height: 2rem;
  padding: 0.42rem 0.6rem;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  text-align: left;
  font-size: 0.84rem;
  font-weight: 500;
}
.set-nav-item:hover:not(:disabled) {
  background: var(--surface-hover);
  border-color: transparent;
}
.set-nav-item.active {
  border-color: color-mix(in srgb, var(--accent) 42%, transparent);
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}
.sets-detail { min-width: 0; }
.detail-fields { display: grid; gap: 0.75rem; }
.domain-chips { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.detail-actions { margin-top: 0.9rem; }

@media (max-width: 780px) {
  .sets-layout { grid-template-columns: 1fr; }
  .sets-sidebar {
    padding-right: 0;
    padding-bottom: 0.85rem;
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
}
</style>
