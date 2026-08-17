import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { bulkAssignWebsiteIds } from "@/lib/manager";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const paymentProvider = String(body.payment_provider || "razorpay"); const ids = await bulkAssignWebsiteIds(body.website_ids, body.account_id, paymentProvider); await writeAudit(user, "website.bulk_assigned", "website", null, `Updated ${paymentProvider} assignment for ${ids.length} website(s).`, { websiteCount: ids.length, paymentProvider }); return NextResponse.json({ success: true, count: ids.length }); }
  catch (error) { return adminError(error); }
}
