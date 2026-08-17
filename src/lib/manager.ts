import "server-only";

import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { ensureSchema, sql } from "@/lib/db";
import { decryptSecret, encryptSecret, hmac, newToken, safeEqual } from "@/lib/security";

type AccountRow = {
  id: string; account_name: string; key_id: string; mode: "test" | "live"; status: "active" | "inactive";
  current_credential_version_id: string | null; created_at: string; updated_at: string;
};

type CredentialRow = { id: string; razorpay_account_id: string; key_id: string; encrypted_key_secret: string; encrypted_webhook_secret: string | null; version_number: number; status: string };
type WebsiteRow = { id: string; name: string; domain: string; site_code: string; encrypted_auth_secret: string; status: "active" | "inactive"; razorpay_account_id: string | null; created_at: string; updated_at: string };

function cleanText(value: unknown, max: number) { return String(value || "").trim().slice(0, max); }
function assertDomain(value: unknown) {
  const domain = cleanText(value, 255).replace(/^https?:\/\//, "").replace(/\/$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+(?::\d+)?$/i.test(domain)) throw new Error("A valid domain is required.");
  return domain;
}
function assertSiteCode(value: unknown) {
  const code = cleanText(value, 64).toUpperCase();
  if (!/^[A-Z0-9_-]{3,64}$/.test(code)) throw new Error("Site code must use 3–64 letters, numbers, _ or -.");
  return code;
}
function assertId(value: unknown) {
  const id = cleanText(value, 80);
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error("Invalid record.");
  return id;
}
function mode(value: unknown) { const item = cleanText(value, 8); if (item !== "test" && item !== "live") throw new Error("Mode must be test or live."); return item; }
function status(value: unknown) { const item = cleanText(value, 10); if (item !== "active" && item !== "inactive") throw new Error("Status must be active or inactive."); return item; }

export async function createAccount(input: Record<string, unknown>) {
  await ensureSchema();
  const accountName = cleanText(input.account_name, 100);
  const keyId = cleanText(input.key_id, 160);
  const secret = cleanText(input.key_secret, 300);
  const webhookSecret = cleanText(input.webhook_secret, 300) || null;
  if (!accountName || !/^rzp_(test|live)_[A-Za-z0-9]+$/.test(keyId) || !secret) throw new Error("Account name, valid Razorpay Key ID and Secret Key are required.");
  const accountId = randomUUID();
  const versionId = randomUUID();
  await sql`INSERT INTO razorpay_accounts (id, account_name, key_id, mode, status, current_credential_version_id) VALUES (${accountId}, ${accountName}, ${keyId}, ${mode(input.mode)}, ${status(input.status)}, ${versionId})`;
  await sql`INSERT INTO razorpay_credential_versions (id, razorpay_account_id, key_id, encrypted_key_secret, encrypted_webhook_secret, version_number, status) VALUES (${versionId}, ${accountId}, ${keyId}, ${encryptSecret(secret)}, ${webhookSecret ? encryptSecret(webhookSecret) : null}, 1, 'current')`;
  return accountId;
}

export async function updateAccount(accountIdValue: unknown, input: Record<string, unknown>) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const accounts = await sql`SELECT * FROM razorpay_accounts WHERE id = ${accountId}`;
  const account = accounts[0] as AccountRow | undefined;
  if (!account) throw new Error("Razorpay account not found.");
  const accountName = cleanText(input.account_name, 100) || account.account_name;
  const keyId = cleanText(input.key_id, 160) || account.key_id;
  if (!/^rzp_(test|live)_[A-Za-z0-9]+$/.test(keyId)) throw new Error("Valid Razorpay Key ID is required.");
  const nextMode = input.mode ? mode(input.mode) : account.mode;
  const nextStatus = input.status ? status(input.status) : account.status;
  const nextSecret = cleanText(input.key_secret, 300);
  const updateWebhook = Object.hasOwn(input, "webhook_secret");
  const webhookSecret = cleanText(input.webhook_secret, 300);
  if (nextSecret || updateWebhook || keyId !== account.key_id) {
    const versions = await sql`SELECT * FROM razorpay_credential_versions WHERE id = ${account.current_credential_version_id}`;
    const current = versions[0] as CredentialRow | undefined;
    if (!current) throw new Error("Credential version is unavailable.");
    const versionRows = await sql`SELECT coalesce(max(version_number), 0)::int AS max FROM razorpay_credential_versions WHERE razorpay_account_id = ${accountId}`;
    const versionId = randomUUID();
    await sql`UPDATE razorpay_credential_versions SET status = 'retired' WHERE id = ${current.id}`;
    await sql`INSERT INTO razorpay_credential_versions (id, razorpay_account_id, key_id, encrypted_key_secret, encrypted_webhook_secret, version_number, status) VALUES (${versionId}, ${accountId}, ${keyId}, ${encryptSecret(nextSecret || decryptSecret(current.encrypted_key_secret))}, ${updateWebhook ? (webhookSecret ? encryptSecret(webhookSecret) : null) : current.encrypted_webhook_secret}, ${Number(versionRows[0]?.max || 0) + 1}, 'current')`;
    await sql`UPDATE razorpay_accounts SET account_name = ${accountName}, key_id = ${keyId}, mode = ${nextMode}, status = ${nextStatus}, current_credential_version_id = ${versionId}, updated_at = now() WHERE id = ${accountId}`;
  } else {
    await sql`UPDATE razorpay_accounts SET account_name = ${accountName}, key_id = ${keyId}, mode = ${nextMode}, status = ${nextStatus}, updated_at = now() WHERE id = ${accountId}`;
  }
  return accountId;
}

export async function deleteAccount(accountIdValue: unknown) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const assigned = await sql`SELECT count(*)::int AS count FROM websites WHERE razorpay_account_id = ${accountId}`;
  const transactions = await sql`SELECT count(*)::int AS count FROM payment_transactions WHERE razorpay_account_id = ${accountId}`;
  if (Number(assigned[0]?.count || 0) || Number(transactions[0]?.count || 0)) throw new Error("Unassign websites and retain transaction history before deleting this account.");
  await sql`DELETE FROM razorpay_credential_versions WHERE razorpay_account_id = ${accountId}`;
  await sql`DELETE FROM razorpay_accounts WHERE id = ${accountId}`;
}

export async function credentialForAccount(accountIdValue: unknown, versionId?: string | null) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const rows = versionId
    ? await sql`SELECT * FROM razorpay_credential_versions WHERE id = ${versionId} AND razorpay_account_id = ${accountId}`
    : await sql`SELECT v.* FROM razorpay_accounts a JOIN razorpay_credential_versions v ON v.id = a.current_credential_version_id WHERE a.id = ${accountId}`;
  const version = rows[0] as CredentialRow | undefined;
  if (!version) throw new Error("Credentials are unavailable.");
  return { version, keyId: version.key_id, keySecret: decryptSecret(version.encrypted_key_secret), webhookSecret: version.encrypted_webhook_secret ? decryptSecret(version.encrypted_webhook_secret) : null };
}

export async function createWebsite(input: Record<string, unknown>) {
  await ensureSchema();
  const name = cleanText(input.name, 120);
  if (!name) throw new Error("Website name is required.");
  const id = randomUUID();
  const secret = newToken();
  const assignment = cleanText(input.razorpay_account_id, 80) || null;
  if (assignment) assertId(assignment);
  await sql`INSERT INTO websites (id, name, domain, site_code, encrypted_auth_secret, status, razorpay_account_id) VALUES (${id}, ${name}, ${assertDomain(input.domain)}, ${assertSiteCode(input.site_code)}, ${encryptSecret(secret)}, ${status(input.status || 'active')}, ${assignment})`;
  return { id, secret };
}

export async function updateWebsite(websiteIdValue: unknown, input: Record<string, unknown>) {
  await ensureSchema();
  const id = assertId(websiteIdValue);
  const rows = await sql`SELECT * FROM websites WHERE id = ${id}`;
  const website = rows[0] as WebsiteRow | undefined;
  if (!website) throw new Error("Website not found.");
  const assignmentInput = Object.hasOwn(input, "razorpay_account_id") ? cleanText(input.razorpay_account_id, 80) || null : website.razorpay_account_id;
  if (assignmentInput) assertId(assignmentInput);
  await sql`UPDATE websites SET name = ${cleanText(input.name, 120) || website.name}, domain = ${input.domain ? assertDomain(input.domain) : website.domain}, site_code = ${input.site_code ? assertSiteCode(input.site_code) : website.site_code}, status = ${input.status ? status(input.status) : website.status}, razorpay_account_id = ${assignmentInput}, updated_at = now() WHERE id = ${id}`;
  return id;
}

export async function rotateWebsiteSecret(websiteIdValue: unknown) {
  await ensureSchema();
  const id = assertId(websiteIdValue);
  const secret = newToken();
  await sql`UPDATE websites SET encrypted_auth_secret = ${encryptSecret(secret)}, updated_at = now() WHERE id = ${id}`;
  return secret;
}

export async function deleteWebsite(websiteIdValue: unknown) {
  await ensureSchema();
  const id = assertId(websiteIdValue);
  const transactions = await sql`SELECT count(*)::int AS count FROM payment_transactions WHERE website_id = ${id}`;
  if (Number(transactions[0]?.count || 0)) throw new Error("This website has transaction history. Set it inactive instead.");
  await sql`DELETE FROM websites WHERE id = ${id}`;
}

export async function bulkAssignWebsiteIds(value: unknown, accountIdValue: unknown) {
  await ensureSchema();
  const ids = Array.isArray(value) ? value.map(assertId) : [];
  if (!ids.length || ids.length > 100) throw new Error("Select between 1 and 100 websites.");
  const accountId = cleanText(accountIdValue, 80) || null;
  if (accountId) assertId(accountId);
  await Promise.all(ids.map((id) => sql`UPDATE websites SET razorpay_account_id = ${accountId}, updated_at = now() WHERE id = ${id}`));
  return ids;
}

export async function managerData() {
  await ensureSchema();
  const [accounts, websites, transactions, logs, metrics] = await Promise.all([
    sql`SELECT a.id, a.account_name, a.key_id, a.mode, a.status, a.created_at, a.updated_at, count(w.id)::int AS website_count FROM razorpay_accounts a LEFT JOIN websites w ON w.razorpay_account_id = a.id GROUP BY a.id ORDER BY a.created_at DESC`,
    sql`SELECT w.id, w.name, w.domain, w.site_code, w.status, w.razorpay_account_id, w.created_at, w.updated_at, a.account_name AS razorpay_account_name FROM websites w LEFT JOIN razorpay_accounts a ON a.id = w.razorpay_account_id ORDER BY w.created_at DESC`,
    sql`SELECT t.id, t.internal_order_id, t.razorpay_order_id, t.razorpay_payment_link_id, t.razorpay_payment_id, t.amount_paise, t.currency, t.status, t.created_at, t.updated_at, w.name AS website_name, a.account_name FROM payment_transactions t JOIN websites w ON w.id = t.website_id JOIN razorpay_accounts a ON a.id = t.razorpay_account_id ORDER BY t.created_at DESC LIMIT 100`,
    sql`SELECT l.id, l.action, l.entity_type, l.entity_id, l.message, l.created_at, u.email AS admin_email FROM audit_logs l LEFT JOIN admin_users u ON u.id = l.admin_user_id ORDER BY l.created_at DESC LIMIT 100`,
    sql`SELECT (SELECT count(*)::int FROM websites) AS websites, (SELECT count(*)::int FROM websites WHERE status = 'active') AS active_websites, (SELECT count(*)::int FROM razorpay_accounts) AS accounts, (SELECT count(*)::int FROM razorpay_accounts WHERE status = 'active') AS active_accounts, (SELECT count(*)::int FROM payment_transactions WHERE created_at >= date_trunc('day', now())) AS today_payments, (SELECT count(*)::int FROM payment_transactions WHERE status = 'paid' AND created_at >= date_trunc('day', now())) AS successful_payments, (SELECT count(*)::int FROM payment_transactions WHERE status = 'failed' AND created_at >= date_trunc('day', now())) AS failed_payments`,
  ]);
  return { accounts, websites, transactions, logs, metrics: metrics[0] || {} };
}

export async function authenticateSite(request: NextRequest, rawBody: string, expectedPath: string) {
  await ensureSchema();
  const siteCode = request.headers.get("x-payment-site")?.trim().toUpperCase() || "";
  const timestamp = request.headers.get("x-payment-timestamp")?.trim() || "";
  const signature = request.headers.get("x-payment-signature")?.trim() || "";
  if (!siteCode || !timestamp || !signature || !/^\d{13}$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp)) > 5 * 60_000) throw new Error("SITE_AUTH_FAILED");
  const rows = await sql`SELECT * FROM websites WHERE site_code = ${siteCode}`;
  const website = rows[0] as WebsiteRow | undefined;
  if (!website || website.status !== "active") throw new Error("SITE_AUTH_FAILED");
  const bodyHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody));
  const hash = Buffer.from(bodyHash).toString("hex");
  const canonical = `${timestamp}.${request.method.toUpperCase()}.${expectedPath}.${hash}`;
  if (!safeEqual(hmac(decryptSecret(website.encrypted_auth_secret), canonical), signature)) throw new Error("SITE_AUTH_FAILED");
  return website;
}

export function publicWebsite(website: WebsiteRow) {
  return { id: website.id, name: website.name, domain: website.domain, siteCode: website.site_code, status: website.status, razorpayAccountId: website.razorpay_account_id };
}
