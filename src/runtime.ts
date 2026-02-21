import type { PluginRuntime } from "openclaw/plugin-sdk";

let runtime: PluginRuntime | null = null;

export function setKeychatRuntime(next: PluginRuntime): void {
  runtime = next;
}

export function getKeychatRuntime(): PluginRuntime {
  if (!runtime) {
    throw new Error("Keychat runtime not initialized");
  }
  return runtime;
}
