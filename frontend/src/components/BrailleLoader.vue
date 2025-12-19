<template>
  <span class="braille-loader">{{ currentFrame }}</span>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue'

export default {
  name: 'BrailleLoader',
  props: {
    speed: { type: Number, default: 80 }
  },
  setup(props) {
    const frames = ['⣼', '⣹', '⢻', '⠿', '⡟', '⣏', '⣧', '⣶']
    const currentFrame = ref(frames[0])
    let frameIndex = 0
    let intervalId = null

    onMounted(() => {
      intervalId = setInterval(() => {
        frameIndex = (frameIndex + 1) % frames.length
        currentFrame.value = frames[frameIndex]
      }, props.speed)
    })

    onUnmounted(() => {
      if (intervalId) clearInterval(intervalId)
    })

    return { currentFrame }
  }
}
</script>

<style scoped>
.braille-loader {
  font-size: 1.2em;
  display: inline-block;
}
</style>
