import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { rotateWebsiteSecret } from "@/lib/manager";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const secret = await rotateWebsiteSecret(body.id); await writeAudit(user, "website.secret_rotated", "website", String(body.id || ""), "Rotated the website authentication secret."); return NextResponse.json({ success: true, site_auth_secret: secret }); }
  catch (error) { return adminError(error); }
}
