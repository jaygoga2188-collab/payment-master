import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { bulkAssignWebsiteIds } from "@/lib/manager";

export async function POST(request: NextRequest) {
  try { assertSameOrigin(request); const user = await requireAdmin(request); const body = await request.json() as Record<string, unknown>; const ids = await bulkAssignWebsiteIds(body.website_ids, body.razorpay_account_id); await writeAudit(user, "website.bulk_assigned", "website", null, `Updated Razorpay assignment for ${ids.length} website(s).`, { websiteCount: ids.length }); return NextResponse.json({ success: true, count: ids.length }); }
  catch (error) { return adminError(error); }
}
