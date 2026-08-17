import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { createAccount, deleteAccount, updateAccount } from "@/lib/manager";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json(); const id = await createAccount(body); await writeAudit(user, "account.created", "razorpay_account", id, "Created a Razorpay account."); return NextResponse.json({ success: true, id }, { status: 201 }); }
  catch (error) { return adminError(error); }
}
export async function PATCH(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const id = await updateAccount(body.id, body); await writeAudit(user, "account.updated", "razorpay_account", id, "Updated Razorpay account settings or credentials."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
export async function DELETE(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const id = new URL(request.url).searchParams.get("id"); await deleteAccount(id); await writeAudit(user, "account.deleted", "razorpay_account", id, "Deleted an unused Razorpay account."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
