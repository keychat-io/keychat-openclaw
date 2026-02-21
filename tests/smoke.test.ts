import { test, describe } from "node:test";
import assert from "node:assert";

describe("config-schema", () => {
  test("validates correct config", async () => {
    const { KeychatConfigSchema } = await import("../src/config-schema.ts");
    const result = KeychatConfigSchema.safeParse({
      enabled: true,
      name: "test-agent",
      relays: ["wss://relay.keychat.io"],
      dmPolicy: "open",
      allowFrom: ["npub1abc"],
      lightningAddress: "user@walletofsatoshi.com",
    });
    assert.ok(result.success, `Validation failed: ${JSON.stringify(result.error?.issues)}`);
  });

  test("rejects invalid dmPolicy", async () => {
    const { KeychatConfigSchema } = await import("../src/config-schema.ts");
    const result = KeychatConfigSchema.safeParse({
      dmPolicy: "yolo",
    });
    assert.ok(!result.success, "Should reject invalid dmPolicy");
  });

  test("accepts empty config", async () => {
    const { KeychatConfigSchema } = await import("../src/config-schema.ts");
    const result = KeychatConfigSchema.safeParse({});
    assert.ok(result.success, "Empty config should be valid (all fields optional)");
  });
});

describe("keychain", () => {
  test("exports expected functions", async () => {
    const keychain = await import("../src/keychain.ts");
    assert.strictEqual(typeof keychain.storeMnemonic, "function");
    assert.strictEqual(typeof keychain.retrieveMnemonic, "function");
    assert.strictEqual(typeof keychain.deleteMnemonic, "function");
  });
});

describe("qrcode", () => {
  test("generateQRDataUrl returns string", async () => {
    const { generateQRDataUrl } = await import("../src/qrcode.ts");
    const result = await generateQRDataUrl("npub1test");
    // Returns data URL or empty string if qrcode not installed
    assert.strictEqual(typeof result, "string");
  });
});
