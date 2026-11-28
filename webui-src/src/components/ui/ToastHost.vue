<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { toast, type ToastState } from '../../stores/toast'
import Icon from './Icon.vue'

const current = ref<ToastState | null>(null)
const visible = ref(false)
let hideTimer = 0
let removeTimer = 0

function dismiss() {
  if (!current.value) return
  window.clearTimeout(hideTimer)
  window.clearTimeout(removeTimer)
  visible.value = false
  removeTimer = window.setTimeout(() => { current.value = null }, 260)
}

watch(toast, (value) => {
  if (!value) return
  window.clearTimeout(removeTimer)
  current.value = value
  visible.value = false
  requestAnimationFrame(() => { visible.value = true })
  window.clearTimeout(hideTimer)
  hideTimer = window.setTimeout(dismiss, value.type === 'error' || value.type === 'warning' ? 8000 : 3500)
})

onBeforeUnmount(() => {
  window.clearTimeout(hideTimer)
  window.clearTimeout(removeTimer)
})
</script>

<template>
  <div v-if="current" class="toast-region" role="status" aria-live="polite" aria-atomic="true">
    <div :class="['toast', current.type, { 'is-visible': visible }]" :role="current.type === 'error' ? 'alert' : undefined">
      <div class="toast-message">{{ current.message }}</div>
      <button type="button" class="toast-close" aria-label="Закрыть уведомление" title="Закрыть" @click="dismiss">
        <Icon name="cross" class="icon-sm" />
      </button>
    </div>
  </div>
</template>
