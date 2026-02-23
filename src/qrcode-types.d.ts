declare module "qrcode" {
  export function toDataURL(text: string, options?: Record<string, unknown>): Promise<string>;
  export function toFile(path: string, text: string, options?: Record<string, unknown>): Promise<void>;
  export function toString(text: string, options?: Record<string, unknown>): Promise<string>;
}
