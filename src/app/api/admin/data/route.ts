import { NextRequest, NextResponse } from "next/server";
import { adminError, requireAdmin } from "@/lib/admin";
import { managerData } from "@/lib/manager";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try { await requireAdmin(request); return NextResponse.json(await managerData(new URL(request.url).searchParams.get("date")), { headers: { "Cache-Control": "no-store" } }); }
  catch (error) { return adminError(error); }
}
