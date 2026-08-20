import { NextRequest, NextResponse } from "next/server";
import { adminError, assertSameOrigin, requireAdmin, writeAudit } from "@/lib/admin";
import { bulkAttachFacebookPixel } from "@/lib/manager";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request);
    const user = await requireAdmin(request);
    const body = await request.json() as Record<string, unknown>;
    const ids = await bulkAttachFacebookPixel(body.website_ids, body.facebook_pixel_id);
    await writeAudit(user, "website.bulk_pixel_assigned", "website", null, `Assigned a Facebook Pixel to ${ids.length} website(s).`, { websiteCount: ids.length });
    return NextResponse.json({ success: true, count: ids.length });
  } catch (error) {
    return adminError(error);
  }
}
