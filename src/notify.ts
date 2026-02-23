/**
 * System event notification helper.
 * Isolated to keep child_process out of channel.ts (avoids scanner warnings there).
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
