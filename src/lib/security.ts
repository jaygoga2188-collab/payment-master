import "server-only";

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as nodeScrypt,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(nodeScrypt);

function required(name: string) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Server configuration missing: ${name}`);
  return value;
}

function encryptionKey() {
  const key = Buffer.from(required("CREDENTIAL_ENCRYPTION_KEY"), "base64");
  if (key.length !== 32) throw new Error("CREDENTIAL_ENCRYPTION_KEY must decode to 32 bytes.");
  return key;
}

export function encryptSecret(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
}

export function decryptSecret(value: string) {
  const [version, ivValue, tagValue, payload] = value.split(".");
  if (version !== "v1" || !ivValue || !tagValue || !payload) throw new Error("Encrypted secret format is invalid.");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(ivValue, "base64url"));
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(payload, "base64url")), decipher.final()]).toString("utf8");
}

export function hashToken(value: string) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function newToken() {
  return randomBytes(32).toString("base64url");
}

export async function hashPassword(password: string) {
  const salt = randomBytes(16).toString("base64url");
  const hash = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt$${salt}$${hash.toString("base64url")}`;
}

export async function verifyPassword(password: string, stored: string) {
  const [algorithm, salt, expected] = stored.split("$");
  if (algorithm !== "scrypt" || !salt || !expected) return false;
  const actual = (await scrypt(password, salt, 64)) as Buffer;
  const expectedBuffer = Buffer.from(expected, "base64url");
  return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
}

export function hmac(secret: string, value: string) {
  return createHmac("sha256", secret).update(value, "utf8").digest("hex");
}

export function safeEqual(left: string, right: string) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function assertAdminSetupToken(token: unknown) {
  const expected = required("ADMIN_SETUP_TOKEN");
  return typeof token === "string" && safeEqual(token, expected);
}
