import { NextRequest, NextResponse } from "next/server";
import { paymentError, verifyCentralPayment } from "@/lib/payment-api";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try { return NextResponse.json(await verifyCentralPayment(request, await request.text()), { headers: { "Cache-Control": "no-store" } }); }
  catch (error) {
    const result = paymentError(error);
    console.warn("Payment verification rejected", { code: result.body.code, status: result.status });
    return NextResponse.json(result.body, { status: result.status, headers: { "Cache-Control": "no-store" } });
  }
}
