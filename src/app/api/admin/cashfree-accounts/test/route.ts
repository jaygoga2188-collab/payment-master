import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin } from "@/lib/admin";
import { cashfreeRequest } from "@/lib/cashfree";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request); await requireAdmin(request);
    const body = await request.json() as Record<string, unknown>;
    const appId = String(body.app_id || "").trim(); const secretKey = String(body.secret_key || "").trim();
    const mode = body.mode === "sandbox" ? "sandbox" : "production";
    const apiVersion = String(body.api_version || "2025-01-01").trim();
    if (!appId || !secretKey || !/^20\d{2}-\d{2}-\d{2}$/.test(apiVersion)) throw new Error("Enter Cashfree App ID, Secret Key and API version.");
    await cashfreeRequest({ appId, secretKey, mode, apiVersion }, "/orders?limit=1");
    return NextResponse.json({ success: true, message: "Cashfree credentials connected successfully." });
  } catch (error) { return adminError(error); }
}
