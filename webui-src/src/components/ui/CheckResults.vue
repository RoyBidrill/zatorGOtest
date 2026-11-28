<script setup lang="ts">
import { computed } from 'vue'
import type { CheckItem, CheckPayload } from '../../api/types'

const props = withDefaults(defineProps<{
  payload: CheckPayload | null
  emptyMessage: string
  emptyHidden?: boolean
}>(), { emptyHidden: true })

const results = computed(() => {
  const list = props.payload?.results
  return Array.isArray(list) ? list : []
})

const isEmpty = computed(() =>
  props.emptyHidden && !props.payload?.message)

const metaLine = computed(() => {
  const p = props.payload
  if (!p) return ''
  const bits: string[] = []
  if (p.lock) bits.push(`лок ${p.lock}`)
  if (p.scope) bits.push(`scope ${p.scope}`)
  if (p.zapret2_running === false) bits.push('zapret2 выключен')
  if (p.zapret2_running === true) bits.push('zapret2 online')
  if (p.waited_apply) bits.push('после apply')
  if (p.applied === true) bits.push('лок подтверждён')
  if (p.applied === false) bits.push('лок не совпал')
  if (p.retried) bits.push('retry')
  return bits.join(' · ')
})

function verdictChipClass(verdict: string | undefined) {
  if (verdict === 'ok') return 'on'
  if (verdict === 'warn') return 'is-warn'
  if (verdict === 'unknown') return ''
  return 'is-bad'
}

function lineClass(state: string | undefined) {
  if (state === 'ok' || state === 'http') return 'ok'
  if (state === 'aborted') return ''
  return 'bad'
}

function downloadClass(state: string | undefined) {
  return state === 'ok' ? 'ok' : 'bad'
}

function hasVerdict(item: CheckItem) {
  return Boolean(item.verdict)
}
</script>

<template>
  <div v-if="!isEmpty || results.length">
    <p v-if="metaLine" class="check-meta">{{ metaLine }}</p>
    <p v-if="payload?.message" class="panel-d">{{ payload.message }}</p>
    <p v-if="!results.length && !payload?.message" class="panel-d">{{ emptyMessage }}</p>
    <div v-else-if="results.length" class="check-list">
      <article v-for="(item, index) in results" :key="index" class="check-item">
        <div class="check-head">
          <div class="check-head-main">
            <strong>{{ item.label || 'Цель' }}</strong>
            <span v-if="item.target" class="check-target">{{ item.target }}</span>
          </div>
          <span v-if="hasVerdict(item)" class="chip" :class="verdictChipClass(item.verdict)">
            {{ item.text || item.verdict }}
          </span>
        </div>

        <div class="check-metrics">
          <template v-if="hasVerdict(item)">
            <span v-if="item.tls12_detail" class="check-badge" :class="lineClass(item.tls12_detail.state)">
              {{ item.tls12_detail.text || 'TLS 1.2' }}
            </span>
            <span v-if="item.tls13_detail" class="check-badge" :class="lineClass(item.tls13_detail.state)">
              {{ item.tls13_detail.text || 'TLS 1.3' }}
            </span>
            <span v-if="item.download" class="check-badge" :class="downloadClass(item.download.state)">
              {{ item.download.text || 'Данные' }}
            </span>
            <span v-if="item.quic" class="check-badge" :class="item.verdict === 'ok' ? 'ok' : item.verdict === 'warn' ? 'warn' : 'bad'">
              HTTP/3: {{ item.quic.ok_count }}/{{ item.quic.total_probes }} (раундов: {{ item.quic.rounds }}){{ item.quic.reason ? ` · ${item.quic.reason}` : '' }}
            </span>
          </template>
          <template v-else>
            <span class="check-badge" :class="item.tls12 ? 'ok' : 'bad'">TLS 1.2: {{ item.tls12 ? 'OK' : 'FAIL' }}</span>
            <span class="check-badge" :class="item.tls13 ? 'ok' : 'bad'">TLS 1.3: {{ item.tls13 ? 'OK' : 'FAIL' }}</span>
          </template>
        </div>
      </article>
    </div>
  </div>
</template>
