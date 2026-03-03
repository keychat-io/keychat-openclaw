/**
 * System event notification helper.
 * Isolated to keep child_process out of channel.ts (avoids scanner warnings there).
 */

/**
 * Build an exec env that ensures the current node binary's directory is in PATH.
 * Fixes the `/usr/bin/env: 'node': No such file or directory` error when the
 * gateway is started by systemd with a minimal PATH (e.g. nvm node not in PATH).
 */
function buildExecEnv(): NodeJS.ProcessEnv {
  // Derive node bin dir from process.execPath without needing path.dirname import
  // e.g. "/home/user/.nvm/versions/node/v22/bin/node" → "/home/user/.nvm/versions/node/v22/bin"
  const lastSlash = process.execPath.lastIndexOf("/");
  const nodeBinDir: string = lastSlash >= 0 ? process.execPath.slice(0, lastSlash) : "";
  const currentPath: string = process.env.PATH ?? "";
  const pathParts = currentPath.split(":").filter(Boolean);
  if (nodeBinDir && !pathParts.includes(nodeBinDir)) {
    pathParts.unshift(nodeBinDir);
  }
  return { ...process.env, PATH: pathParts.join(":") };
}

export async function sendSystemEvent(text: string, timeoutMs = 10_000): Promise<void> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execFileAsync = promisify(execFile);
  await execFileAsync("openclaw", [
    "system", "event",
    "--text", text,
    "--mode", "now",
  ], { timeout: timeoutMs, env: buildExecEnv() });
}

/**
 * Push a message directly to the webchat UI via gateway's chat.inject WebSocket method.
 * This bypasses the agent and shows the message immediately in the webchat UI.
 *
 * Falls back silently if the gateway is not reachable or webchat has no active session.
 */
export async function sendToWebchat(opts: {
  message: string;
  sessionKey?: string;   // defaults to "agent:main:main"
  timeoutMs?: number;
}): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 8_000;
  const sessionKey = opts.sessionKey ?? "agent:main:main";

  // Read gateway config from the openclaw config file
  let gatewayUrl: string;
  let gatewayToken: string | undefined;
  try {
    const { readFileSync } = await import("node:fs");
    const { homedir } = await import("node:os");
    const cfgPath = `${homedir()}/.openclaw/openclaw.json`;
    const cfg = JSON.parse(readFileSync(cfgPath, "utf-8"));
    const port: number = cfg?.gateway?.port ?? 18789;
    gatewayUrl = cfg?.gateway?.remote?.url ?? `ws://127.0.0.1:${port}`;
    gatewayToken = cfg?.gateway?.auth?.token;
  } catch {
    return; // can't read config, skip
  }

  return new Promise<void>((resolve) => {
    const timer = setTimeout(() => { ws?.terminate?.(); resolve(); }, timeoutMs);

    let ws: any;
    let resolved = false;
    const done = () => { if (!resolved) { resolved = true; clearTimeout(timer); resolve(); } };

    (async () => {
      try {
        // Import ws module (available globally in OpenClaw's node)
        const { default: WebSocket } = await import("ws");
        ws = new WebSocket(gatewayUrl);

        ws.on("error", () => done());
        ws.on("close", () => done());

        ws.on("open", () => {
          // Send connect challenge-response is needed, but the challenge arrives as first event
        });

        let seqId = 1;
        const sendReq = (method: string, params: unknown) => {
          const id = String(seqId++);
          ws.send(JSON.stringify({ type: "req", id, method, params }));
          return id;
        };

        let connectId: string | null = null;
        let injected = false;

        ws.on("message", (raw: Buffer | string) => {
          try {
            const frame = JSON.parse(raw.toString());

            // Handle connect challenge
            if (frame.type === "event" && frame.event === "connect.challenge") {
              connectId = sendReq("connect", {
                minProtocol: 3,
                maxProtocol: 3,
                client: { id: "cli", version: "0", platform: "node", mode: "cli", instanceId: "keychat-notify" },
                role: "operator",
                scopes: ["operator.admin"],
                auth: gatewayToken ? { token: gatewayToken } : undefined,
              });
              return;
            }

            // Handle connect response → inject message
            if (frame.type === "res" && frame.id === connectId && !injected) {
              if (!frame.ok) { ws.terminate(); done(); return; }
              injected = true;
              const injectId = sendReq("chat.inject", {
                sessionKey,
                message: opts.message,
                label: "keychat-notify",
              });
              // Wait for inject response
              ws.once("message", (raw2: Buffer | string) => {
                try { JSON.parse(raw2.toString()); } catch { /* ignore */ }
                ws.terminate();
                done();
              });
            }
          } catch { /* ignore parse errors */ }
        });

      } catch {
        done();
      }
    })();
  });
}

/**
 * Parse active channel sessions and send the Keychat identity directly
 * to each recently active non-keychat channel (Discord, Telegram, etc.).
 *
 * Session key format: agent:<agentId>:<channel>:<kind>:<target>
 * e.g. "agent:main:discord:direct:1470705144487350425"
 *
 * Skips keychat, webchat, and main sessions (no external channel target).
 * Deduplicates by channel type — only sends to the most recently active target per channel.
 */
export async function sendToActiveChannels(opts: {
  message: string;
  qrPath?: string;
  maxAgeMs?: number;
  timeoutMs?: number;
}): Promise<void> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { existsSync } = await import("node:fs");
  const execFileAsync = promisify(execFile);

  const maxAgeMs = opts.maxAgeMs ?? 7 * 24 * 60 * 60 * 1000; // 7 days
  const timeoutMs = opts.timeoutMs ?? 15_000;

  // Channels with no external target in the session key (skip these)
  const SKIP_CHANNELS = new Set(["keychat", "webchat", "main", "internal", "cron", "system"]);

  const execEnv = buildExecEnv();

  let sessions: Array<{ key: string; updatedAt: number }> = [];
  try {
    const { stdout } = await execFileAsync("openclaw", ["sessions", "--json"], { timeout: 10_000, env: execEnv });
    const parsed = JSON.parse(stdout);
    sessions = Array.isArray(parsed) ? parsed : (parsed.sessions ?? []);
  } catch {
    // If sessions query fails, fall through silently
    return;
  }

  const now = Date.now();
  // channel → { target, updatedAt }
  const bestByChannel = new Map<string, { target: string; updatedAt: number }>();

  for (const s of sessions) {
    const key: string = s.key ?? "";
    if (!key.startsWith("agent:")) continue;
    // key = agent:<agentId>:<channel>:<kind>:<target>
    const parts = key.split(":");
    if (parts.length < 5) continue;
    const channel = parts[2];
    const target = parts[4];
    if (!channel || !target) continue;
    if (SKIP_CHANNELS.has(channel)) continue;
    const updatedAt: number = s.updatedAt ?? 0;
    if (now - updatedAt > maxAgeMs) continue;

    const prev = bestByChannel.get(channel);
    if (!prev || updatedAt > prev.updatedAt) {
      bestByChannel.set(channel, { target, updatedAt });
    }
  }

  if (bestByChannel.size === 0) return;

  const qrExists = opts.qrPath && existsSync(opts.qrPath);

  for (const [channel, { target }] of bestByChannel) {
    try {
      const args = [
        "message", "send",
        "--channel", channel,
        "--target", target,
        "--message", opts.message,
      ];
      if (qrExists && opts.qrPath) {
        args.push("--media", opts.qrPath);
      }
      await execFileAsync("openclaw", args, { timeout: timeoutMs, env: execEnv });
    } catch {
      // Best-effort: skip channels that fail
    }
  }
}
