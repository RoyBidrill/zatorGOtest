<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { customBlobs, customBlobsUpload } from '../../api/endpoints'
import type { CustomBlobInfo } from '../../api/types'
import { busyActive, busyButton, withBusy } from '../../stores/busy'
import { confirmDialog } from '../../stores/confirm'
import { customBlobsPayload } from '../../stores/sni'
import { showToast } from '../../stores/toast'
import Icon from '../ui/Icon.vue'

const emit = defineEmits<{ dirty: []; reload: [] }>()

const dir = computed(() => customBlobsPayload.value?.dir || '/opt/zator/files/fake/custom_blob')
const blobs = computed(() => customBlobsPayload.value?.blobs || [])
const files = computed(() => customBlobsPayload.value?.files || [])
const stock = computed(() => customBlobsPayload.value?.stock || [])
const configDirty = computed(() => !!customBlobsPayload.value?.config_dirty)
const refsTotal = computed(() => blobs.value.reduce((acc, b) => acc + (b.refs || 0), 0))

const uploadFile = ref<File | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  uploadFile.value = input.files?.[0] || null
}

function formatSize(bytes: number): string {
  return bytes < 1024 ? `${bytes} Б` : `${(bytes / 1024).toFixed(1)} КиБ`
}

async function upload() {
  const file = uploadFile.value
  if (!file) {
    showToast('Выберите файл блоба.', 'warning')
    return
  }
  if (file.size < 1 || file.size > 262144) {
    showToast('Размер файла должен быть от 1 Б до 256 КиБ.', 'warning')
    return
  }
  try {
    await withBusy('custom-blob-upload', async () => {
      const buffer = await file.arrayBuffer()
      const payload = await customBlobsUpload(file.name, buffer)
      uploadFile.value = null
      if (fileInput.value) fileInput.value.value = ''
      if (payload?.created != null) {
        emit('dirty')
        showToast(`Файл ${payload.file || file.name} загружен и добавлен (запись #${payload.created}). Примените к конфигу.`)
      } else {
        showToast(`Файл ${payload?.file || file.name} загружен в ${dir.value}.`)
      }
      emit('reload')
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}

const formOpen = ref(false)
const modalVisible = ref(false)
const editId = ref<number | null>(null)
const formName = ref('')
const formFile = ref('')
const formComment = ref('')
const formError = ref('')
const nameField = ref<HTMLInputElement | null>(null)
const original = ref({ name: '', file: '', comment: '' })

const nameTakenHint = computed(() => {
  const name = formName.value.trim().toLowerCase()
  if (!name) return ''
  if (stock.value.some((s) => s.toLowerCase() === name)) {
    return `Имя «${name}» уже занято штатным блобом конфига.`
  }
  const dup = blobs.value.find((b) => b.name.toLowerCase() === name && b.id !== editId.value)
  if (dup) return `Имя «${name}» уже используется в записи #${dup.id}.`
  return ''
})

const saveDisabled = computed(() => {
  if (busyActive.value || !formName.value.trim() || !formFile.value) return true
  if (editId.value === null) return false
  return formName.value.trim() === original.value.name
    && formFile.value === original.value.file
    && formComment.value.trim() === original.value.comment
})

function highlightRow(id: number) {
  nextTick(() => {
    const el = document.getElementById(`custom-blob-row-${id}`)
    if (!el) return
    el.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    el.classList.add('is-target')
    window.setTimeout(() => el.classList.remove('is-target'), 4500)
  })
}

function openAdd() {
  editId.value = null
  formName.value = ''
  formFile.value = files.value[0] || ''
  formComment.value = ''
  formError.value = ''
  original.value = { name: '', file: formFile.value, comment: '' }
  formOpen.value = true
}

function openEdit(item: CustomBlobInfo) {
  editId.value = item.id
  formName.value = item.name
  formFile.value = item.file
  formComment.value = item.comment
  formError.value = ''
  original.value = { name: item.name, file: item.file, comment: item.comment }
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
    nextTick(() => nameField.value?.focus())
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
  const name = formName.value.trim()
  if (!name || !formFile.value) {
    formError.value = 'Укажите имя блоба и выберите файл.'
    return
  }
  formError.value = ''
  const wasEdit = editId.value !== null
  const targetId = editId.value
  try {
    await withBusy(wasEdit ? `custom-blob-edit-${targetId}` : 'custom-blob-add', async () => {
      if (wasEdit) {
        const res = await customBlobs.edit(String(targetId), name, formFile.value, formComment.value.trim())
        formOpen.value = false
        emit('dirty')
        showToast(res.renamed
          ? 'Сохранено, ссылки в «Своих стратегиях» обновлены.'
          : 'Сохранено.')
        emit('reload')
        highlightRow(targetId as number)
      } else {
        const res = await customBlobs.add(name, formFile.value, formComment.value.trim())
        formOpen.value = false
        emit('dirty')
        showToast('Блоб добавлен.')
        emit('reload')
        if (typeof res.id === 'number') highlightRow(res.id)
      }
    })
  } catch (e) {
    formError.value = (e as Error).message
  }
}

async function removeItem(item: CustomBlobInfo) {
  const ok = await confirmDialog({
    title: `Удалить блоб «${item.name}»?`,
    message: item.refs > 0
      ? `Блоб используется в ${item.refs} пользовательских стратегиях: удаление будет отклонено, пока ссылки не убраны.`
      : 'Декларация и файл будут удалены (если на файл нет других ссылок).',
    confirmText: 'Удалить',
    danger: true,
  })
  if (!ok) return
  try {
    await withBusy(`custom-blob-delete-${item.id}`, async () => {
      await customBlobs.remove(String(item.id))
      emit('dirty')
      showToast('Блоб удалён.')
      emit('reload')
    })
  } catch (e) {
    showToast((e as Error).message, 'error')
  }
}
</script>

<template>
  <section id="custom-blobs-panel" class="panel" aria-label="Пользовательские блобы">
    <div class="panel-h">
      <div>
        <h2>Пользовательские блобы</h2>
        <p class="panel-sub">Декларации <code>--blob=ИМЯ:@файл</code> для использования в «Своих стратегиях»</p>
      </div>
      <div class="actions">
        <span v-if="blobs.length && !configDirty" class="chip on">Синхронизировано с конфигом</span>
        <button id="custom-blob-add" type="button" class="primary" :disabled="busyActive || !files.length" @click="openAdd">
          <Icon name="plus" class="icon-sm" />
          <span>Добавить блоб</span>
        </button>
      </div>
    </div>

    <div class="upload-strip">
      <div class="field">
        <span class="field-caption">Загрузить бинарный файл (1 Б - 256 КиБ, в <code>{{ dir }}</code>)</span>
        <div class="file-picker">
          <label class="file-picker-btn" :class="{ 'is-disabled': busyActive }" for="custom-blob-file">
            <Icon name="upload" class="icon-sm" />
            <span>Выбрать файл</span>
          </label>
          <input id="custom-blob-file" ref="fileInput" class="sr-only" type="file" :disabled="busyActive" @change="onFileChange">
          <span class="file-picker-name">{{ uploadFile ? uploadFile.name : 'Файл не выбран' }}</span>
          <span v-if="uploadFile" class="chip">{{ formatSize(uploadFile.size) }}</span>
        </div>
      </div>
      <div class="actions">
        <button
          id="custom-blob-upload-btn"
          type="button"
          :class="{ 'is-busy': busyButton === 'custom-blob-upload' }"
          :disabled="busyActive || !uploadFile"
          @click="upload"
        >
          Загрузить файл
        </button>
      </div>
    </div>

    <div v-if="!blobs.length" class="empty-state">
      <strong>Своих блобов пока нет</strong>
      <p>{{ files.length ? 'Нажмите «Добавить блоб» выше.' : 'Загрузите .bin файл выше, декларация создастся автоматически.' }}</p>
    </div>

    <div v-else class="list-stack">
      <article v-for="item in blobs" :id="`custom-blob-row-${item.id}`" :key="item.id" class="list-row blob-row">
        <div class="blob-top">
          <div class="blob-meta">
            <strong class="mono">{{ item.name }}</strong>
            <span class="chip">{{ item.file }}</span>
            <span class="chip" :class="{ on: item.refs > 0 }">
              {{ item.refs ? `стратегий: ${item.refs}` : 'не используется' }}
            </span>
            <span v-if="item.comment" class="blob-comment">{{ item.comment }}</span>
          </div>
          <div class="actions">
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
              :class="{ 'is-busy': busyButton === `custom-blob-delete-${item.id}` }"
              @click="removeItem(item)"
            >
              <Icon name="trash" class="icon-sm" />
            </button>
          </div>
        </div>
        <code class="mono blob-spec">--blob={{ item.name }}:@{{ dir }}/{{ item.file }}</code>
      </article>
    </div>

    <details id="custom-blob-stock-names" class="stock-fold">
      <summary>Занятые штатные имена ({{ stock.length }})</summary>
      <div class="stock-list">
        <code v-for="s in stock" :key="s" class="chip">{{ s }}</code>
      </div>
    </details>

    <div
      v-if="formOpen"
      :class="['modal-overlay', { 'is-visible': modalVisible }]"
      role="dialog"
      aria-modal="true"
      @click.self="cancelForm"
    >
      <form id="custom-blob-form" class="modal-card modal-wide" @submit.prevent="saveForm">
        <h3 class="modal-title">{{ editId === null ? 'Новый блоб' : `Блоб #${editId}` }}</h3>
        <div class="modal-fields">
          <label class="field">
            <span>Имя блоба (--blob=ИМЯ:@...)</span>
            <input
              id="custom-blob-name"
              ref="nameField"
              v-model="formName"
              type="text"
              maxlength="32"
              placeholder="my_fake_tls"
              :disabled="busyActive"
            >
          </label>
          <p v-if="nameTakenHint" class="warn-hint">{{ nameTakenHint }}</p>
          <label class="field">
            <span>Файл (из custom_blob/)</span>
            <select id="custom-blob-file-select" v-model="formFile" :disabled="busyActive">
              <option v-for="f in files" :key="f" :value="f">{{ f }}</option>
            </select>
          </label>
          <label class="field">
            <span>Комментарий (необязательно)</span>
            <input id="custom-blob-comment" v-model="formComment" type="text" maxlength="64" :disabled="busyActive">
          </label>
          <p class="modal-note">
            При переименовании ссылки в «Своих стратегиях» обновятся автоматически (всего ссылок: {{ refsTotal }}).
          </p>
          <p v-if="formError" id="custom-blob-error" class="err-hint" role="alert">{{ formError }}</p>
        </div>
        <div class="modal-actions">
          <button id="custom-blob-cancel" type="button" class="ghost" :disabled="busyActive" @click="cancelForm">Отмена</button>
          <button
            id="custom-blob-save"
            type="submit"
            class="primary"
            :class="{ 'is-busy': busyButton === (editId === null ? 'custom-blob-add' : `custom-blob-edit-${editId}`) }"
            :disabled="saveDisabled"
          >
            {{ editId === null ? 'Добавить' : 'Сохранить' }}
          </button>
        </div>
      </form>
    </div>
  </section>
</template>

<style scoped>
.upload-strip {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.75rem;
  align-items: end;
  margin: 0.75rem 0 0.9rem;
  padding: 0.8rem 0.85rem;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius-md);
  background: var(--surface-2);
}
.blob-top { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 0.5rem; }
.blob-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; min-width: 0; }
.blob-comment { color: var(--muted); font-size: 0.82rem; }
.blob-spec {
  background: transparent;
  padding: 0;
  color: var(--muted);
  font-size: 0.76rem;
  overflow-wrap: anywhere;
}
.stock-fold { margin-top: 0.9rem; }
.stock-fold summary { cursor: pointer; color: var(--muted); font-size: 0.8rem; }
.stock-list { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.5rem; }
.modal-note {
  margin: 0;
  color: var(--muted);
  font-size: 0.82rem;
}

@media (max-width: 680px) {
  .upload-strip { grid-template-columns: 1fr; }
}
</style>
