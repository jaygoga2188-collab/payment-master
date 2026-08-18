import { NextRequest, NextResponse } from "next/server";
import { authenticateSite } from "@/lib/manager";
import { sql } from "@/lib/db";

export const runtime = "nodejs";

// Pixel IDs are public browser configuration, but the assignment itself is
// resolved only after the calling website authenticates with Payment Master.
export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const website = await authenticateSite(request, rawBody, "/api/tracking/pixels");
    const rows = await sql`SELECT p.pixel_id FROM website_facebook_pixels wfp JOIN facebook_pixels p ON p.id = wfp.facebook_pixel_id WHERE wfp.website_id = ${website.id} AND p.status = 'active' AND p.archived_at IS NULL ORDER BY p.created_at ASC`;
    return NextResponse.json({ success: true, pixels: rows.map((row) => String(row.pixel_id)) }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ success: false, pixels: [] }, { status: 403, headers: { "Cache-Control": "no-store" } });
  }
}
