import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { keychatPlugin, getAgentKeychatId, getAgentKeychatUrl } from "./src/channel.js";
import { setKeychatRuntime } from "./src/runtime.js";

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
