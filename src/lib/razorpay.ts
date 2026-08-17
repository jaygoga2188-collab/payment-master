import "server-only";

import { createHmac } from "node:crypto";
import { safeEqual } from "@/lib/security";

export type RazorpayCredentials = { keyId: string; keySecret: string };

type RazorpayError = { error?: { description?: string; reason?: string } };

export async function razorpayRequest<T>(credentials: RazorpayCredentials, path: string, init: RequestInit = {}) {
  const authorization = Buffer.from(`${credentials.keyId}:${credentials.keySecret}`, "utf8").toString("base64");
  const response = await fetch(`https://api.razorpay.com/v1${path}`, {
    ...init,
    headers: { Authorization: `Basic ${authorization}`, "Content-Type": "application/json", ...(init.headers || {}) },
    cache: "no-store",
  });
  const payload = (await response.json().catch(() => ({}))) as T & RazorpayError;
  if (!response.ok) throw new Error(payload.error?.description || payload.error?.reason || "Razorpay request failed.");
  return payload;
}

export async function testRazorpayCredentials(credentials: RazorpayCredentials) {
  await razorpayRequest(credentials, "/payments?count=1");
  return true;
}

export function verifyRazorpaySignature(secret: string, payload: string, signature: string) {
  const expected = createHmac("sha256", secret).update(payload, "utf8").digest("hex");
  return safeEqual(expected, signature);
}
