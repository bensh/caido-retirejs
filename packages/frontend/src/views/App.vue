<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import { ref } from "vue";

const myVar = ref(
  "Use the RetireJS Scanner page from the sidebar to run manual or live scans.",
);

const onGenerateClick = () => {
  myVar.value =
    "Open the RetireJS Scanner page via the sidebar item to review findings.";
};
</script>

<template>
  <div class="h-full flex justify-center items-center">
    <div class="flex flex-col gap-1">
      <Button label="Generate random string" @click="onGenerateClick" />
      <InputText :model-value="myVar" readonly />
    </div>
  </div>
</template>
