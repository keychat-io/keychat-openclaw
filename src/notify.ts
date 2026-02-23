/**
 * System event notification helper.
 * Isolated to avoid child_process scanner warnings in other files.
 */

export async function sendSystemEvent(text: string, timeoutMs = 10_000): Promise<void> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execFileAsync = promisify(execFile);
  await execFileAsync("openclaw", [
    "system", "event",
    "--text", text,
    "--mode", "now",
  ], { timeout: timeoutMs });
}
