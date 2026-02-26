import { existsSync, mkdirSync, chmodSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
import https from "node:https";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Auto-install dependencies if missing (e.g. after git clone without npm install)
if (!existsSync(join(__dirname, "node_modules", "zod"))) {
  console.log("[keychat] Dependencies missing, running npm install...");
  try {
    execSync("npm install --omit=dev --ignore-scripts", { cwd: __dirname, stdio: "inherit", timeout: 60_000 });
    console.log("[keychat] Dependencies installed successfully");
  } catch (e) {
    throw new Error("[keychat] Failed to install dependencies. Run manually: cd " + __dirname + " && npm install");
  }
}

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { keychatPlugin, getAgentKeychatId, getAgentKeychatUrl, getAllAgentContacts } from "./src/channel.js";
import { setKeychatRuntime } from "./src/runtime.js";

/** Download a URL following redirects, return a Buffer. */
function downloadBinary(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadBinary(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

/** Ensure bridge binary exists, download if missing. */
async function ensureBinary(): Promise<void> {
  const binaryDir = join(__dirname, "bridge", "target", "release");
  const binaryPath = join(binaryDir, "keychat-openclaw");

  if (existsSync(binaryPath)) return;

  const platform = process.platform;
  const arch = process.arch;
  const artifacts: Record<string, string> = {
    "darwin-arm64": "keychat-openclaw-darwin-arm64",
    "darwin-x64": "keychat-openclaw-darwin-x64",
    "linux-x64": "keychat-openclaw-linux-x64",
    "linux-arm64": "keychat-openclaw-linux-arm64",
  };

  const artifact = artifacts[`${platform}-${arch}`];
  if (!artifact) {
    console.warn(`[keychat] No pre-compiled binary for ${platform}-${arch}. Build from source: cd bridge && cargo build --release`);
    return;
  }

  const url = `https://github.com/keychat-io/keychat-openclaw/releases/latest/download/${artifact}`;
  console.log(`[keychat] Bridge binary not found, downloading ${artifact}...`);

  try {
    mkdirSync(binaryDir, { recursive: true });
    const buffer = await downloadBinary(url);
    writeFileSync(binaryPath, buffer);
    chmodSync(binaryPath, 0o755);
    console.log("[keychat] ✅ Bridge binary installed");
  } catch (err: any) {
    console.warn(`[keychat] Binary download failed: ${err.message}`);
    console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  }
}

/** Ensure channels.keychat exists in openclaw.json config. */
function ensureConfig(): void {
  const configPath = join(homedir(), ".openclaw", "openclaw.json");
  try {
    let config: any = {};
    if (existsSync(configPath)) {
      config = JSON.parse(readFileSync(configPath, "utf-8"));
    }
    if (config.channels?.keychat) return;

    if (!config.channels) config.channels = {};
    config.channels.keychat = { enabled: true, dmPolicy: "open" };
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
    console.log("[keychat] ✅ Config initialized (channels.keychat.enabled = true)");
  } catch (err: any) {
    console.warn(`[keychat] Could not auto-configure: ${err.message}`);
  }
}

const plugin = {
  id: "keychat",
  name: "Keychat",
  description:
    "Keychat channel plugin — sovereign identity + E2E encrypted chat. " +
    "Agent generates its own Public Key ID, just like a human Keychat user.",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    console.log("[keychat] register() called");
    try {
      // Auto-setup: download binary + init config on first load
      ensureConfig();
      ensureBinary().catch((err) => console.warn("[keychat] ensureBinary error:", err));
      setKeychatRuntime(api.runtime);
      console.log("[keychat] runtime set, registering channel...");
      api.registerChannel({ plugin: keychatPlugin });
      console.log("[keychat] channel registered successfully");

      // Register keychat_identity agent tool so the agent can fetch ID info
      // and send it to the user on whatever channel they're on
      api.registerTool({
        name: "keychat_identity",
        label: "Keychat Identity",
        description:
          "Get the Keychat identity (npub, contact link, QR code path) for all active agent accounts. " +
          "Call this after Keychat setup/install to retrieve the agent's Keychat ID and share it with the user.",
        parameters: { type: "object", properties: {}, required: [] },
        async execute(_toolCallId: string, _params: any) {
          const contacts = getAllAgentContacts();
          if (contacts.length === 0) {
            return {
              details: null,
              content: [
                {
                  type: "text" as const,
                  text: "No Keychat accounts are active yet. The bridge may still be starting — try again in a few seconds.",
                },
              ],
            };
          }
          const { generateQRDataUrl } = await import("./src/qrcode.js");
          const results = [];
          const contentParts: Array<{ type: "text"; text: string } | { type: "image"; data: string; mimeType: string }> = [];

          for (const c of contacts) {
            const qrDataUrl = await generateQRDataUrl(c.npub);
            results.push({
              accountId: c.accountId,
              npub: c.npub,
              contactUrl: c.contactUrl,
            });
            contentParts.push({
              type: "text" as const,
              text: `Account: ${c.accountId}\nnpub: ${c.npub}\nContact: ${c.contactUrl}`,
            });
            if (qrDataUrl) {
              // Extract base64 from data URL: "data:image/png;base64,..."
              const base64 = qrDataUrl.replace(/^data:image\/png;base64,/, "");
              contentParts.push({
                type: "image" as const,
                data: base64,
                mimeType: "image/png",
              });
            }
          }

          return {
            details: null,
            content: contentParts,
          };
        },
      });

      // Register /keychat-id command to show agent Keychat ID, link, and QR
      api.registerCommand({
        name: "keychat-id",
        description: "Show Keychat agent ID(s), contact link(s), and QR code path(s)",
        handler: () => {
          const contacts = getAllAgentContacts();
          if (contacts.length === 0) {
            return { text: "⚠️ No Keychat accounts are active yet. Wait for the bridge to start." };
          }
          const lines = contacts.map((c) => {
            const qrExists = existsSync(c.qrCodePath);
            return [
              `🔑 **${c.accountId}**`,
              `  npub: \`${c.npub}\``,
              `  📱 Link: ${c.contactUrl}`,
              qrExists
                ? `  🖼️ QR: ${c.qrCodePath}`
                : `  (QR image not found)`,
            ].join("\n");
          });
          return { text: lines.join("\n\n") };
        },
      });
    } catch (err) {
      console.error("[keychat] register failed:", err);
    }
  },
};

export default plugin;
export { getAgentKeychatId, getAgentKeychatUrl, getAllAgentContacts, resetPeerSession } from "./src/channel.js";
export { generateQRDataUrl } from "./src/qrcode.js";
export {
  requestInvoice,
  fetchLnurlPayMetadata,
  verifyPayment,
  formatSats,
  lightningAddressToLnurlp,
} from "./src/lightning.js";
export {
  NwcClient,
  parseNwcUri,
  initNwc,
  getNwcClient,
  disconnectNwc,
} from "./src/nwc.js";
