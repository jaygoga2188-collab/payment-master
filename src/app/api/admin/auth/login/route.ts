import { NextRequest, NextResponse } from "next/server";
import { assertSameOrigin, attachSession, checkRateLimit, clientIp, createSession, loginAdmin } from "@/lib/admin";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request);
    if (!(await checkRateLimit(`login:${clientIp(request)}`, 5, 600))) return NextResponse.json({ error: "Too many sign-in attempts. Try again later." }, { status: 429 });
    const body = await request.json() as Record<string, unknown>;
    const user = await loginAdmin(String(body.email || "").trim().toLowerCase(), String(body.password || ""));
    if (!user) return NextResponse.json({ error: "Invalid email or password." }, { status: 401 });
    return attachSession(NextResponse.json({ success: true }), await createSession(user));
  } catch { return NextResponse.json({ error: "Sign-in could not be completed." }, { status: 400 }); }
}
