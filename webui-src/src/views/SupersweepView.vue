<script setup lang="ts">
import { computed } from 'vue'
import SupersweepPanel from '../components/strategies/SupersweepPanel.vue'
import { scopes, scope, refreshAll } from '../stores/status'

const scopeOptions = computed(() => scopes.value.scopes || ['default'])
</script>

<template>
  <section class="page-stack">
    <header class="page-head">
      <div>
        <span class="eyebrow">Автоматический подбор</span>
        <h1>Подбор стратегий</h1>
        <p>Запустите быстрый тест для одного профиля или полный прогон. Найденные и применённые результаты показаны отдельно.</p>
      </div>
    </header>
    <SupersweepPanel :scope="scope" :scopes="scopeOptions" @started="refreshAll" @cancelled="refreshAll" />
  </section>
</template>
