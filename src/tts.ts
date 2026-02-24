import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

export interface TtsConfig {
  provider: "say" | "piper" | "openai";
  /** macOS 'say' voice name (e.g. "Tingting" for Chinese, "Samantha" for English) */
  voice?: string;
  /** Path to piper binary */
  piperPath?: string;
  /** Path to piper voice model */
  piperModel?: string;
  /** OpenAI API key */
  openaiApiKey?: string;
  /** OpenAI TTS voice */
  openaiVoice?: string;
}

/**
 * Generate speech from text using macOS 'say' command.
 * Outputs AIFF, then converts to OGG via ffmpeg if available.
 */
async function ttsSay(text: string, config: TtsConfig): Promise<string> {
  const outPath = join(tmpdir(), `tts_${Date.now()}.aiff`);
  const args = ["-o", outPath];

  if (config.voice) {
    args.push("-v", config.voice);
  }
  args.push(text);

  await execFileAsync("say", args, { timeout: 30000 });

  // Try to convert to OGG with ffmpeg
  const oggPath = outPath.replace(".aiff", ".ogg");
  try {
    await execFileAsync("ffmpeg", [
      "-i", outPath,
      "-c:a", "libopus",
      "-b:a", "24k",
      "-ar", "48000",
      "-ac", "1",
      "-y", oggPath,
    ], { timeout: 30000 });
    return oggPath;
  } catch {
    // ffmpeg not available, return AIFF
    return outPath;
  }
}

/**
 * Generate speech using OpenAI TTS API.
 */
async function ttsOpenAI(text: string, config: TtsConfig): Promise<string> {
  if (!config.openaiApiKey) throw new Error("OpenAI API key required");

  const response = await fetch("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.openaiApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "tts-1",
      input: text,
      voice: config.openaiVoice || "alloy",
      response_format: "opus",
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`OpenAI TTS failed (${response.status}): ${body}`);
  }

  const { writeFile } = await import("node:fs/promises");
  const audioData = Buffer.from(await response.arrayBuffer());
  const outPath = join(tmpdir(), `tts_${Date.now()}.ogg`);
  await writeFile(outPath, audioData);
  return outPath;
}

/**
 * Main TTS function — generate audio file from text.
 * Returns path to audio file (OGG preferred).
 */
export async function synthesize(text: string, config: TtsConfig = { provider: "say" }): Promise<string> {
  switch (config.provider) {
    case "say":
      return ttsSay(text, config);
    case "openai":
      return ttsOpenAI(text, config);
    case "piper":
      throw new Error("Piper TTS not yet implemented");
    default:
      throw new Error(`Unknown TTS provider: ${config.provider}`);
  }
}
