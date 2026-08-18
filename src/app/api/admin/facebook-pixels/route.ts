import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { archiveFacebookPixel, createFacebookPixel, updateFacebookPixel } from "@/lib/manager";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const id = await createFacebookPixel(await request.json()); await writeAudit(user, "facebook_pixel.created", "facebook_pixel", id, "Created a Facebook Pixel for later site assignment."); return NextResponse.json({ success: true, id }, { status: 201 }); }
  catch (error) { return adminError(error); }
}
export async function PATCH(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const id = await updateFacebookPixel(body.id, body); await writeAudit(user, "facebook_pixel.updated", "facebook_pixel", id, "Updated Facebook Pixel settings."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
export async function DELETE(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const id = new URL(request.url).searchParams.get("id"); await archiveFacebookPixel(id); await writeAudit(user, "facebook_pixel.archived", "facebook_pixel", id, "Archived a Facebook Pixel while keeping the assignment history."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
