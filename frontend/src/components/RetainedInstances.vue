<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { computed } from 'vue'
import { retainedInstanceRows, retainedMonthlyTotal, shortId } from '../utils/deployments.js'

const props = defineProps({ deployments: { type: Array, required: true } })
const rows = computed(() => retainedInstanceRows(props.deployments))
const total = computed(() => retainedMonthlyTotal(rows.value))
const usd = (value) => `$${value.toFixed(2)}`
</script>

<template>
  <section class="retained-instances" aria-labelledby="retained-title">
    <h4 id="retained-title" class="app-detail-subsection-title">Retained instances</h4>
    <p class="app-detail-helper-text">Every retained deployment runs its own instance and is billed until destroyed, including cleanup pending. Estimates are infrastructure costs, separate from your subscription.</p>
    <table class="apps-table" aria-label="Retained instances">
      <thead><tr><th scope="col">Deployment</th><th scope="col">EC2 type</th><th scope="col">Enclave</th><th scope="col">State</th><th scope="col">Est. monthly</th></tr></thead>
      <tbody>
        <tr v-for="row in rows" :key="row.id">
          <td><code>{{ shortId(row.id) }}</code> · {{ row.role }}</td>
          <td>{{ row.instanceType }}</td>
          <td>{{ row.cpus ?? '—' }} vCPU · {{ row.memoryMb ? `${row.memoryMb / 1024} GB` : '—' }}</td>
          <td>{{ row.state }}</td>
          <td>{{ row.estimate === null ? 'Unavailable' : usd(row.estimate) }}</td>
        </tr>
      </tbody>
      <tfoot><tr><th scope="row" colspan="4">Total</th><td>{{ usd(total.total) }}<span v-if="!total.complete"> + unavailable estimates</span></td></tr></tfoot>
    </table>
  </section>
</template>
