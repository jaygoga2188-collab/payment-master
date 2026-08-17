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
  if (!response.ok) throw new Error("CASHFREE_PROVIDER_ERROR");
  return payload as T;
}

export function verifyCashfreeWebhook(secret: string, timestamp: string, rawBody: string, signature: string) {
  if (!timestamp || !signature) return false;
  const expected = createHmac("sha256", secret).update(`${timestamp}${rawBody}`).digest("base64");
  return safeEqual(expected, signature);
}
