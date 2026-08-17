import "server-only";

import { createHmac } from "node:crypto";
import { safeEqual } from "@/lib/security";

export type CashfreeCredentials = {
  appId: string;
  secretKey: string;
  mode: "sandbox" | "production";
  apiVersion: string;
};

function baseUrl(mode: CashfreeCredentials["mode"]) {
  return mode === "production" ? "https://api.cashfree.com/pg" : "https://sandbox.cashfree.com/pg";
}

export async function cashfreeRequest<T>(credentials: CashfreeCredentials, path: string, init: RequestInit = {}) {
  const response = await fetch(`${baseUrl(credentials.mode)}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "x-api-version": credentials.apiVersion,
      "x-client-id": credentials.appId,
      "x-client-secret": credentials.secretKey,
      ...(init.headers || {}),
    },
    cache: "no-store",
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    // Log only provider-safe diagnostics. Never log request headers because
    // they contain the Cashfree secret key.
    const details = payload && typeof payload === "object" ? payload as Record<string, unknown> : {};
    console.error("Cashfree API request rejected", {
      status: response.status,
      code: String(details.code || details.type || "").slice(0, 120),
      message: String(details.message || details.error || "").slice(0, 300),
    });
    throw new Error(`CASHFREE_PROVIDER_${response.status}`);
  }
  return payload as T;
}

export function verifyCashfreeWebhook(secret: string, timestamp: string, rawBody: string, signature: string) {
  if (!timestamp || !signature) return false;
  const expected = createHmac("sha256", secret).update(`${timestamp}${rawBody}`).digest("base64");
  return safeEqual(expected, signature);
}
