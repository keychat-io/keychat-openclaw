import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { keychatPlugin, getAgentKeychatId, getAgentKeychatUrl, getAllAgentContacts } from "./src/channel.js";
import { setKeychatRuntime } from "./src/runtime.js";
import { existsSync } from "node:fs";

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
