import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { createWebsite, deleteWebsite, rotateWebsiteSecret, updateWebsite } from "@/lib/manager";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json(); const result = await createWebsite(body); await writeAudit(user, "website.created", "website", result.id, "Created a website and one-time authentication secret."); return NextResponse.json({ success: true, id: result.id, site_auth_secret: result.secret }, { status: 201 }); }
  catch (error) { return adminError(error); }
}
export async function PATCH(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const id = await updateWebsite(body.id, body); await writeAudit(user, "website.updated", "website", id, "Updated website status or Razorpay assignment."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
export async function DELETE(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const id = new URL(request.url).searchParams.get("id"); await deleteWebsite(id); await writeAudit(user, "website.archived", "website", id, "Removed a website from active operations while preserving its history."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
