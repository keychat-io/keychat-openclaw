let runtime = null;
export function setKeychatRuntime(next) {
    runtime = next;
}
export function getKeychatRuntime() {
    if (!runtime) {
        throw new Error("Keychat runtime not initialized");
    }
    return runtime;
}
