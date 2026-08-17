import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { createCashfreeAccount, deleteCashfreeAccount, updateCashfreeAccount } from "@/lib/manager";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json(); const id = await createCashfreeAccount(body); await writeAudit(user, "cashfree_account.created", "cashfree_account", id, "Created a Cashfree account."); return NextResponse.json({ success: true, id }, { status: 201 }); }
  catch (error) { return adminError(error); }
}
export async function PATCH(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const id = await updateCashfreeAccount(body.id, body); await writeAudit(user, "cashfree_account.updated", "cashfree_account", id, "Updated Cashfree account settings or credentials."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
export async function DELETE(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const id = new URL(request.url).searchParams.get("id"); await deleteCashfreeAccount(id); await writeAudit(user, "cashfree_account.deleted", "cashfree_account", id, "Deleted an unused Cashfree account."); return NextResponse.json({ success: true }); }
  catch (error) { return adminError(error); }
}
