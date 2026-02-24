import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

export interface SttConfig {
  provider: "whisper-cpp" | "openai";
  /** Path to whisper-cpp binary (default: auto-detect via which) */
  whisperPath?: string;
  /** Path to whisper model file */
  modelPath?: string;
  /** Model size for auto-download: tiny, base, small, medium */
  modelSize?: string;
  /** OpenAI API key (for openai provider) */
  openaiApiKey?: string;
  /** Language hint (e.g. "zh", "en", "auto") */
  language?: string;
}

const DEFAULT_MODEL_SIZE = "small";

/** Find whisper-cpp binary */
async function findWhisperBinary(configPath?: string): Promise<string> {
  if (configPath && existsSync(configPath)) return configPath;

  // Try common locations
  const candidates = [
    "/opt/homebrew/bin/whisper-cpp",
    "/usr/local/bin/whisper-cpp",
    "/usr/bin/whisper-cpp",
  ];

  for (const c of candidates) {
    if (existsSync(c)) return c;
  }

  // Try which
  try {
    const { stdout } = await execFileAsync("which", ["whisper-cpp"]);
    const path = stdout.trim();
    if (path && existsSync(path)) return path;
  } catch {}

  throw new Error("whisper-cpp not found. Install with: brew install whisper-cpp");
}

/** Find or download whisper model */
async function findModel(configPath?: string, modelSize?: string): Promise<string> {
  if (configPath && existsSync(configPath)) return configPath;

  const size = modelSize || DEFAULT_MODEL_SIZE;

  // Check common model locations
  const candidates = [
    join(process.env.HOME || "", `.cache/whisper/ggml-${size}.bin`),
    `/opt/homebrew/share/whisper-cpp/models/ggml-${size}.bin`,
    `/usr/local/share/whisper-cpp/models/ggml-${size}.bin`,
    join(process.env.HOME || "", `whisper-models/ggml-${size}.bin`),
  ];

  for (const c of candidates) {
    if (existsSync(c)) return c;
  }

  throw new Error(
    `Whisper model ggml-${size}.bin not found. Download it:\n` +
    `  mkdir -p ~/.cache/whisper && cd ~/.cache/whisper\n` +
    `  curl -LO https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-${size}.bin`
  );
}

/**
 * Transcribe an audio file to text using whisper-cpp.
 */
export async function transcribeLocal(
  audioPath: string,
  config: SttConfig = { provider: "whisper-cpp" },
): Promise<string> {
  const binary = await findWhisperBinary(config.whisperPath);
  const model = await findModel(config.modelPath, config.modelSize);

  const args = [
    "-m", model,
    "-f", audioPath,
    "--no-timestamps",
    "--print-special", "false",
    "-t", "4",  // threads
  ];

  if (config.language && config.language !== "auto") {
    args.push("-l", config.language);
  }

  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      timeout: 60000, // 60s timeout
      maxBuffer: 10 * 1024 * 1024,
    });

    // whisper-cpp outputs text to stdout, strip whitespace
    const text = stdout.trim();
    if (!text) {
      console.warn(`[stt] whisper-cpp produced no output. stderr: ${stderr}`);
      return "[voice message - transcription empty]";
    }
    return text;
  } catch (err: any) {
    console.error(`[stt] whisper-cpp failed: ${err.message}`);
    throw new Error(`Speech-to-text failed: ${err.message}`);
  }
}

/**
 * Transcribe using OpenAI Whisper API (fallback).
 */
export async function transcribeOpenAI(
  audioPath: string,
  apiKey: string,
  language?: string,
): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const audioData = await readFile(audioPath);
  const blob = new Blob([audioData], { type: "audio/ogg" });

  const form = new FormData();
  form.append("file", blob, "voice.ogg");
  form.append("model", "whisper-1");
  if (language && language !== "auto") form.append("language", language);

  const response = await fetch("https://api.openai.com/v1/audio/transcriptions", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}` },
    body: form,
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`OpenAI Whisper API failed (${response.status}): ${body}`);
  }

  const result = await response.json() as { text: string };
  return result.text || "[voice message - transcription empty]";
}

/**
 * Main transcribe function — picks provider from config.
 */
export async function transcribe(
  audioPath: string,
  config: SttConfig = { provider: "whisper-cpp" },
): Promise<string> {
  if (config.provider === "openai") {
    if (!config.openaiApiKey) throw new Error("OpenAI API key required for openai STT provider");
    return transcribeOpenAI(audioPath, config.openaiApiKey, config.language);
  }
  return transcribeLocal(audioPath, config);
}
