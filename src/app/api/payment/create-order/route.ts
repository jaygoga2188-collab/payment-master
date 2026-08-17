import { NextRequest, NextResponse } from "next/server";
import { createCentralPayment, paymentError } from "@/lib/payment-api";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try { return NextResponse.json(await createCentralPayment(request, await request.text()), { status: 201, headers: { "Cache-Control": "no-store" } }); }
  catch (error) { const result = paymentError(error); return NextResponse.json(result.body, { status: result.status, headers: { "Cache-Control": "no-store" } }); }
}
