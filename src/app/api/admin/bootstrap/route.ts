import { NextRequest, NextResponse } from "next/server";
import { adminCount, assertSameOrigin, attachSession, checkRateLimit, clientIp, createBootstrapAdmin, createSession } from "@/lib/admin";
import { assertAdminSetupToken } from "@/lib/security";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request);
    if (!(await checkRateLimit(`bootstrap:${clientIp(request)}`, 5, 600))) return NextResponse.json({ error: "Too many attempts. Try again later." }, { status: 429 });
    if ((await adminCount()) > 0) return NextResponse.json({ error: "Admin setup has already been completed." }, { status: 409 });
    const body = await request.json() as Record<string, unknown>;
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const name = String(body.name || "").trim().slice(0, 80);
    if (!assertAdminSetupToken(body.setup_token) || !name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) return NextResponse.json({ error: "Use a valid email and a password of at least 12 characters." }, { status: 400 });
    const user = await createBootstrapAdmin({ name, email, password });
    const response = NextResponse.json({ success: true });
    return attachSession(response, await createSession(user));
  } catch { return NextResponse.json({ error: "Setup could not be completed." }, { status: 400 }); }
}
