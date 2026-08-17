import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin } from "@/lib/admin";
import { testRazorpayCredentials } from "@/lib/razorpay";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request); await requireAdmin(request);
    const body = await request.json() as Record<string, unknown>;
    const keyId = String(body.key_id || "").trim(); const keySecret = String(body.key_secret || "").trim();
    if (!/^rzp_(test|live)_[A-Za-z0-9]+$/.test(keyId) || !keySecret) return NextResponse.json({ error: "Enter a valid Key ID and Secret Key." }, { status: 400 });
    await testRazorpayCredentials({ keyId, keySecret });
    return NextResponse.json({ success: true, message: "Credentials valid." });
  } catch { return NextResponse.json({ success: false, error: "Credentials could not be validated." }, { status: 400 }); }
}
