import { NextRequest, NextResponse } from "next/server";
import { applyCashfreeWebhook } from "@/lib/payment-api";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const signature = request.headers.get("x-webhook-signature") || "";
    const timestamp = request.headers.get("x-webhook-timestamp") || "";
    await applyCashfreeWebhook(rawBody, timestamp, signature);
    return NextResponse.json({ success: true });
  } catch { return NextResponse.json({ success: false }, { status: 401 }); }
}
