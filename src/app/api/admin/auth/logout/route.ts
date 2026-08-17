import { NextRequest, NextResponse } from "next/server";
import { assertSameOrigin, clearSession } from "@/lib/admin";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); return clearSession(request, NextResponse.json({ success: true })); }
  catch { return NextResponse.json({ error: "Request rejected." }, { status: 403 }); }
}
