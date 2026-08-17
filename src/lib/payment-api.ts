import "server-only";

import { randomUUID } from "node:crypto";
import { ensureSchema, sql } from "@/lib/db";
import { authenticateSite, credentialForAccount } from "@/lib/manager";
import { razorpayRequest, verifyRazorpaySignature } from "@/lib/razorpay";
import type { NextRequest } from "next/server";

type Transaction = {
  id: string; website_id: string; razorpay_account_id: string; razorpay_credential_version_id: string; internal_order_id: string;
  resource_type: "order" | "payment_link"; razorpay_order_id: string | null; razorpay_payment_link_id: string | null; razorpay_payment_id: string | null;
  checkout_url: string | null; amount_paise: number; currency: string; status: string;
};

function text(value: unknown, max = 255) { return String(value || "").trim().slice(0, max); }
function amount(value: unknown) { const number = Number(value); if (!Number.isSafeInteger(number) || number < 100) throw new Error("INVALID_PAYMENT_REQUEST"); return number; }
function currency(value: unknown) { const result = text(value || "INR", 3).toUpperCase(); if (result !== "INR") throw new Error("INVALID_PAYMENT_REQUEST"); return result; }
function orderId(value: unknown) { const result = text(value, 128); if (!/^[A-Za-z0-9_-]{6,128}$/.test(result)) throw new Error("INVALID_PAYMENT_REQUEST"); return result; }
function domainFromUrl(value: string) { try { const url = new URL(value); return url.protocol === "https:" ? url.host.toLowerCase() : ""; } catch { return ""; } }
function allowedCallback(value: unknown, domain: string) { const url = text(value, 1024); if (!url || domainFromUrl(url) !== domain.toLowerCase()) throw new Error("INVALID_CALLBACK_URL"); return url; }
function publicTransaction(row: Transaction, keyId: string) {
  return {
    success: true,
    internal_order_id: row.internal_order_id,
    order_id: row.razorpay_order_id || undefined,
    payment_link_id: row.razorpay_payment_link_id || undefined,
    payment_link: row.checkout_url || undefined,
    key_id: keyId,
    amount: Number(row.amount_paise),
    currency: row.currency,
    status: row.status,
  };
}

export async function createCentralPayment(request: NextRequest, rawBody: string) {
  const website = await authenticateSite(request, rawBody, "/api/payment/create-order");
  const body = JSON.parse(rawBody) as Record<string, unknown>;
  if (text(body.site_code, 64).toUpperCase() !== website.site_code) throw new Error("SITE_AUTH_FAILED");
  if (!website.razorpay_account_id) throw new Error("PAYMENT_UNAVAILABLE");
  const accounts = await sql`SELECT id, status FROM razorpay_accounts WHERE id = ${website.razorpay_account_id}`;
  if (!accounts[0] || accounts[0].status !== "active") throw new Error("PAYMENT_UNAVAILABLE");
  const internalOrderId = orderId(body.internal_order_id);
  const amountPaise = amount(body.amount);
  const paymentCurrency = currency(body.currency);
  const existingRows = await sql`SELECT * FROM payment_transactions WHERE website_id = ${website.id} AND internal_order_id = ${internalOrderId}`;
  if (existingRows[0]) {
    const existing = existingRows[0] as Transaction;
    const credentials = await credentialForAccount(existing.razorpay_account_id, existing.razorpay_credential_version_id);
    return publicTransaction(existing, credentials.keyId);
  }
  const credentials = await credentialForAccount(website.razorpay_account_id);
  const kind = text(body.kind || "order", 20) === "payment_link" ? "payment_link" : "order";
  const transactionId = randomUUID();
  if (kind === "payment_link") {
    const customerInput = (body.customer && typeof body.customer === "object" ? body.customer : {}) as Record<string, unknown>;
    const callbackUrl = allowedCallback(body.callback_url, website.domain);
    const customer: Record<string, string> = {};
    const name = text(customerInput.name, 80); if (name) customer.name = name;
    const contact = text(customerInput.contact, 15).replace(/\D/g, ""); if (/^\d{10}$/.test(contact)) customer.contact = `+91${contact}`;
    const email = text(customerInput.email, 160); if (email.includes("@")) customer.email = email;
    const link = await razorpayRequest<{ id: string; short_url: string; status: string }>(credentials, "/payment_links/", {
      method: "POST",
      body: JSON.stringify({ amount: amountPaise, currency: paymentCurrency, accept_partial: false, reference_id: internalOrderId, description: text(body.description, 255) || "Order payment", customer, notify: { sms: false, email: false }, reminder_enable: false, callback_url: callbackUrl, callback_method: "get", notes: { website: website.site_code, internal_order_id: internalOrderId } }),
    });
    const hosted = new URL(link.short_url);
    if (hosted.protocol !== "https:" || hosted.hostname !== "rzp.io") throw new Error("PAYMENT_PROVIDER_ERROR");
    await sql`INSERT INTO payment_transactions (id, website_id, razorpay_account_id, razorpay_credential_version_id, internal_order_id, resource_type, razorpay_payment_link_id, checkout_url, amount_paise, currency, status) VALUES (${transactionId}, ${website.id}, ${website.razorpay_account_id}, ${credentials.version.id}, ${internalOrderId}, 'payment_link', ${link.id}, ${hosted.toString()}, ${amountPaise}, ${paymentCurrency}, 'pending')`;
    const row: Transaction = { id: transactionId, website_id: website.id, razorpay_account_id: website.razorpay_account_id, razorpay_credential_version_id: credentials.version.id, internal_order_id: internalOrderId, resource_type: "payment_link", razorpay_order_id: null, razorpay_payment_link_id: link.id, razorpay_payment_id: null, checkout_url: hosted.toString(), amount_paise: amountPaise, currency: paymentCurrency, status: "pending" };
    return publicTransaction(row, credentials.keyId);
  }
  const order = await razorpayRequest<{ id: string; amount: number; currency: string; status: string }>(credentials, "/orders", { method: "POST", body: JSON.stringify({ amount: amountPaise, currency: paymentCurrency, receipt: internalOrderId, notes: { website: website.site_code, internal_order_id: internalOrderId } }) });
  if (order.amount !== amountPaise || order.currency !== paymentCurrency) throw new Error("PAYMENT_PROVIDER_ERROR");
  await sql`INSERT INTO payment_transactions (id, website_id, razorpay_account_id, razorpay_credential_version_id, internal_order_id, resource_type, razorpay_order_id, amount_paise, currency, status) VALUES (${transactionId}, ${website.id}, ${website.razorpay_account_id}, ${credentials.version.id}, ${internalOrderId}, 'order', ${order.id}, ${amountPaise}, ${paymentCurrency}, 'created')`;
  const row: Transaction = { id: transactionId, website_id: website.id, razorpay_account_id: website.razorpay_account_id, razorpay_credential_version_id: credentials.version.id, internal_order_id: internalOrderId, resource_type: "order", razorpay_order_id: order.id, razorpay_payment_link_id: null, razorpay_payment_id: null, checkout_url: null, amount_paise: amountPaise, currency: paymentCurrency, status: "created" };
  return publicTransaction(row, credentials.keyId);
}

export async function verifyCentralPayment(request: NextRequest, rawBody: string) {
  const website = await authenticateSite(request, rawBody, "/api/payment/verify");
  const body = JSON.parse(rawBody) as Record<string, unknown>;
  if (text(body.site_code, 64).toUpperCase() !== website.site_code) throw new Error("SITE_AUTH_FAILED");
  const internalOrderId = orderId(body.internal_order_id);
  const rows = await sql`SELECT * FROM payment_transactions WHERE website_id = ${website.id} AND internal_order_id = ${internalOrderId}`;
  const transaction = rows[0] as Transaction | undefined;
  if (!transaction) throw new Error("PAYMENT_NOT_FOUND");
  const paymentId = text(body.razorpay_payment_id, 100);
  const signature = text(body.razorpay_signature, 200);
  if (!/^pay_[A-Za-z0-9]+$/.test(paymentId) || !/^[a-f0-9]{64}$/i.test(signature)) throw new Error("PAYMENT_VERIFICATION_FAILED");
  const credentials = await credentialForAccount(transaction.razorpay_account_id, transaction.razorpay_credential_version_id);
  if (transaction.resource_type === "payment_link") {
    const linkId = text(body.razorpay_payment_link_id, 100);
    const reference = text(body.razorpay_payment_link_reference_id, 128);
    const linkStatus = text(body.razorpay_payment_link_status, 30).toLowerCase();
    if (linkId !== transaction.razorpay_payment_link_id || reference !== transaction.internal_order_id || linkStatus !== "paid" || !verifyRazorpaySignature(credentials.keySecret, `${linkId}|${reference}|${linkStatus}|${paymentId}`, signature)) throw new Error("PAYMENT_VERIFICATION_FAILED");
    const link = await razorpayRequest<{ id: string; status: string; amount: number; amount_paid: number; currency: string; payments?: { payment_id?: string; status?: string; amount?: number }[] }>(credentials, `/payment_links/${encodeURIComponent(linkId)}`);
    const captured = (link.payments || []).some((item) => item.payment_id === paymentId && item.status === "captured" && item.amount === transaction.amount_paise);
    if (link.status !== "paid" || link.amount !== transaction.amount_paise || link.amount_paid !== transaction.amount_paise || link.currency !== transaction.currency || !captured) throw new Error("PAYMENT_NOT_CAPTURED");
  } else {
    const orderIdValue = text(body.razorpay_order_id, 100);
    if (orderIdValue !== transaction.razorpay_order_id || !verifyRazorpaySignature(credentials.keySecret, `${orderIdValue}|${paymentId}`, signature)) throw new Error("PAYMENT_VERIFICATION_FAILED");
    const payment = await razorpayRequest<{ id: string; order_id: string; amount: number; currency: string; status: string; captured: boolean }>(credentials, `/payments/${encodeURIComponent(paymentId)}`);
    if (payment.order_id !== transaction.razorpay_order_id || payment.amount !== transaction.amount_paise || payment.currency !== transaction.currency || payment.status !== "captured" || !payment.captured) throw new Error("PAYMENT_NOT_CAPTURED");
  }
  await sql`UPDATE payment_transactions SET razorpay_payment_id = ${paymentId}, status = 'paid', updated_at = now() WHERE id = ${transaction.id}`;
  return { success: true, status: "paid", internal_order_id: transaction.internal_order_id, razorpay_payment_id: paymentId, amount: transaction.amount_paise, currency: transaction.currency };
}

export async function applyWebhook(rawBody: string, signature: string) {
  await ensureSchema();
  const rows = await sql`SELECT v.id AS version_id, v.razorpay_account_id, v.encrypted_webhook_secret FROM razorpay_credential_versions v WHERE v.encrypted_webhook_secret IS NOT NULL`;
  let accountId: string | null = null;
  for (const item of rows as { version_id: string; razorpay_account_id: string; encrypted_webhook_secret: string }[]) {
    const credentials = await credentialForAccount(item.razorpay_account_id, item.version_id);
    if (credentials.webhookSecret && verifyRazorpaySignature(credentials.webhookSecret, rawBody, signature)) { accountId = item.razorpay_account_id; break; }
  }
  if (!accountId) throw new Error("WEBHOOK_AUTH_FAILED");
  const payload = JSON.parse(rawBody) as { event?: string; payload?: { payment?: { entity?: { id?: string; order_id?: string; status?: string } }; payment_link?: { entity?: { id?: string; status?: string } } } };
  const payment = payload.payload?.payment?.entity;
  const link = payload.payload?.payment_link?.entity;
  const matches = await sql`SELECT * FROM payment_transactions WHERE razorpay_account_id = ${accountId} AND (razorpay_order_id = ${payment?.order_id || ""} OR razorpay_payment_link_id = ${link?.id || ""})`;
  const status = payload.event === "payment.captured" || payload.event === "payment_link.paid" ? "paid" : payload.event === "payment.failed" ? "failed" : null;
  if (status) await Promise.all((matches as Transaction[]).map((transaction) => sql`UPDATE payment_transactions SET razorpay_payment_id = ${payment?.id || transaction.razorpay_payment_id}, status = ${status}, updated_at = now() WHERE id = ${transaction.id}`));
  return { accepted: true };
}

export function paymentError(error: unknown) {
  const message = error instanceof Error ? error.message : "PAYMENT_UNAVAILABLE";
  if (message === "SITE_AUTH_FAILED") return { status: 401, body: { success: false, error: "Unauthorized payment request." } };
  if (["INVALID_PAYMENT_REQUEST", "INVALID_CALLBACK_URL"].includes(message)) return { status: 400, body: { success: false, error: "Invalid payment request." } };
  if (["PAYMENT_NOT_FOUND", "PAYMENT_VERIFICATION_FAILED", "PAYMENT_NOT_CAPTURED"].includes(message)) return { status: 400, body: { success: false, error: "Payment could not be verified." } };
  return { status: 503, body: { success: false, error: "Payment service temporarily unavailable." } };
}
