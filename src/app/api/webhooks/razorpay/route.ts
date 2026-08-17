import { NextRequest, NextResponse } from "next/server";
import { applyWebhook } from "@/lib/payment-api";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const signature = request.headers.get("x-razorpay-signature") || "";
    if (!signature) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    await applyWebhook(await request.text(), signature);
    return NextResponse.json({ accepted: true });
  } catch { return NextResponse.json({ error: "Unauthorized" }, { status: 401 }); }
}
