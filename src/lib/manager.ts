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
type CashfreeAccountRow = { id: string; account_name: string; app_id: string; mode: "sandbox" | "production"; api_version: string; status: "active" | "inactive"; current_credential_version_id: string | null; created_at: string; updated_at: string };
type CashfreeCredentialRow = { id: string; cashfree_account_id: string; app_id: string; encrypted_secret_key: string; encrypted_webhook_secret: string | null; version_number: number; status: string };
type WebsiteRow = { id: string; name: string; domain: string; site_code: string; encrypted_auth_secret: string; status: "active" | "inactive"; payment_provider: "razorpay" | "cashfree"; razorpay_account_id: string | null; cashfree_account_id: string | null; created_at: string; updated_at: string };

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
function cashfreeMode(value: unknown) { const item = cleanText(value, 12); if (item !== "sandbox" && item !== "production") throw new Error("Cashfree mode must be sandbox or production."); return item; }
function provider(value: unknown) { const item = cleanText(value, 16) || "razorpay"; if (item !== "razorpay" && item !== "cashfree") throw new Error("Select Razorpay or Cashfree."); return item as "razorpay" | "cashfree"; }
function assertPixelId(value: unknown) { const pixelId = cleanText(value, 32); if (!/^\d{5,25}$/.test(pixelId)) throw new Error("Facebook Pixel ID must contain only digits."); return pixelId; }
function pixelIds(value: unknown) { if (!Array.isArray(value)) return []; return [...new Set(value.map((item) => assertId(item)))] .slice(0, 25); }
// Keep the Cashfree integration aligned with the established hosted-link flow.
// Individual accounts can still retain another version when that is explicitly
// configured in the admin panel.
function apiVersion(value: unknown) { const item = cleanText(value, 20) || "2022-01-01"; if (!/^20\d{2}-\d{2}-\d{2}$/.test(item)) throw new Error("Cashfree API version is invalid."); return item; }
function reportDate(value?: string | null) {
  const today = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  const selected = cleanText(value, 10) || today;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(selected) || Number.isNaN(Date.parse(`${selected}T00:00:00Z`))) throw new Error("Invalid report date.");
  return selected;
}

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
  const assigned = await sql`SELECT count(*)::int AS count FROM websites WHERE razorpay_account_id = ${accountId} AND archived_at IS NULL`;
  if (Number(assigned[0]?.count || 0)) throw new Error("Move assigned websites to another gateway before archiving this account.");
  // Archive instead of deleting: transaction/account links and historic credentials
  // remain usable for audit and delayed webhook verification.
  await sql`UPDATE razorpay_accounts SET status = 'inactive', archived_at = now(), updated_at = now() WHERE id = ${accountId} AND archived_at IS NULL`;
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

export async function createCashfreeAccount(input: Record<string, unknown>) {
  await ensureSchema();
  const accountName = cleanText(input.account_name, 100);
  const appId = cleanText(input.app_id, 200);
  const secret = cleanText(input.secret_key, 500);
  const webhookSecret = cleanText(input.webhook_secret, 500) || null;
  if (!accountName || !appId || !secret) throw new Error("Account name, Cashfree App ID and Secret Key are required.");
  const accountId = randomUUID(); const versionId = randomUUID();
  await sql`INSERT INTO cashfree_accounts (id, account_name, app_id, mode, api_version, status, current_credential_version_id) VALUES (${accountId}, ${accountName}, ${appId}, ${cashfreeMode(input.mode)}, ${apiVersion(input.api_version)}, ${status(input.status)}, ${versionId})`;
  await sql`INSERT INTO cashfree_credential_versions (id, cashfree_account_id, app_id, encrypted_secret_key, encrypted_webhook_secret, version_number, status) VALUES (${versionId}, ${accountId}, ${appId}, ${encryptSecret(secret)}, ${webhookSecret ? encryptSecret(webhookSecret) : null}, 1, 'current')`;
  return accountId;
}

export async function updateCashfreeAccount(accountIdValue: unknown, input: Record<string, unknown>) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const rows = await sql`SELECT * FROM cashfree_accounts WHERE id = ${accountId}`;
  const account = rows[0] as CashfreeAccountRow | undefined;
  if (!account) throw new Error("Cashfree account not found.");
  const accountName = cleanText(input.account_name, 100) || account.account_name;
  const appId = cleanText(input.app_id, 200) || account.app_id;
  const nextMode = input.mode ? cashfreeMode(input.mode) : account.mode;
  const nextVersion = input.api_version ? apiVersion(input.api_version) : account.api_version;
  const nextStatus = input.status ? status(input.status) : account.status;
  const nextSecret = cleanText(input.secret_key, 500);
  const updateWebhook = Object.hasOwn(input, "webhook_secret");
  const webhookSecret = cleanText(input.webhook_secret, 500);
  if (nextSecret || updateWebhook || appId !== account.app_id) {
    const currentRows = await sql`SELECT * FROM cashfree_credential_versions WHERE id = ${account.current_credential_version_id}`;
    const current = currentRows[0] as CashfreeCredentialRow | undefined;
    if (!current) throw new Error("Credential version is unavailable.");
    const versionRows = await sql`SELECT coalesce(max(version_number), 0)::int AS max FROM cashfree_credential_versions WHERE cashfree_account_id = ${accountId}`;
    const versionId = randomUUID();
    await sql`UPDATE cashfree_credential_versions SET status = 'retired' WHERE id = ${current.id}`;
    await sql`INSERT INTO cashfree_credential_versions (id, cashfree_account_id, app_id, encrypted_secret_key, encrypted_webhook_secret, version_number, status) VALUES (${versionId}, ${accountId}, ${appId}, ${encryptSecret(nextSecret || decryptSecret(current.encrypted_secret_key))}, ${updateWebhook ? (webhookSecret ? encryptSecret(webhookSecret) : null) : current.encrypted_webhook_secret}, ${Number(versionRows[0]?.max || 0) + 1}, 'current')`;
    await sql`UPDATE cashfree_accounts SET account_name = ${accountName}, app_id = ${appId}, mode = ${nextMode}, api_version = ${nextVersion}, status = ${nextStatus}, current_credential_version_id = ${versionId}, updated_at = now() WHERE id = ${accountId}`;
  } else {
    await sql`UPDATE cashfree_accounts SET account_name = ${accountName}, app_id = ${appId}, mode = ${nextMode}, api_version = ${nextVersion}, status = ${nextStatus}, updated_at = now() WHERE id = ${accountId}`;
  }
  return accountId;
}

export async function deleteCashfreeAccount(accountIdValue: unknown) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const [assigned] = await Promise.all([
    sql`SELECT count(*)::int AS count FROM websites WHERE cashfree_account_id = ${accountId} AND archived_at IS NULL`,
  ]);
  if (Number(assigned[0]?.count || 0)) throw new Error("Move assigned websites to another gateway before archiving this account.");
  // Archive rather than delete so lifetime collections and verification history stay intact.
  await sql`UPDATE cashfree_accounts SET status = 'inactive', archived_at = now(), updated_at = now() WHERE id = ${accountId} AND archived_at IS NULL`;
}

async function replaceWebsitePixels(websiteId: string, value: unknown) {
  const ids = pixelIds(value);
  for (const id of ids) {
    const rows = await sql`SELECT id FROM facebook_pixels WHERE id = ${id} AND status = 'active' AND archived_at IS NULL`;
    if (!rows[0]) throw new Error("Choose active Facebook Pixels only.");
  }
  await sql`DELETE FROM website_facebook_pixels WHERE website_id = ${websiteId}`;
  await Promise.all(ids.map((pixelId) => sql`INSERT INTO website_facebook_pixels (website_id, facebook_pixel_id) VALUES (${websiteId}, ${pixelId})`));
}

export async function createFacebookPixel(input: Record<string, unknown>) {
  await ensureSchema();
  const pixelName = cleanText(input.pixel_name, 100);
  if (!pixelName) throw new Error("Facebook Pixel name is required.");
  const id = randomUUID();
  await sql`INSERT INTO facebook_pixels (id, pixel_name, pixel_id, status) VALUES (${id}, ${pixelName}, ${assertPixelId(input.pixel_id)}, ${status(input.status || 'active')})`;
  return id;
}

export async function updateFacebookPixel(pixelIdValue: unknown, input: Record<string, unknown>) {
  await ensureSchema();
  const id = assertId(pixelIdValue);
  const rows = await sql`SELECT * FROM facebook_pixels WHERE id = ${id} AND archived_at IS NULL`;
  const current = rows[0] as { pixel_name: string; pixel_id: string; status: "active" | "inactive" } | undefined;
  if (!current) throw new Error("Facebook Pixel not found.");
  await sql`UPDATE facebook_pixels SET pixel_name = ${cleanText(input.pixel_name, 100) || current.pixel_name}, pixel_id = ${input.pixel_id ? assertPixelId(input.pixel_id) : current.pixel_id}, status = ${input.status ? status(input.status) : current.status}, updated_at = now() WHERE id = ${id}`;
  return id;
}

export async function archiveFacebookPixel(pixelIdValue: unknown) {
  await ensureSchema();
  const id = assertId(pixelIdValue);
  await sql`UPDATE facebook_pixels SET status = 'inactive', archived_at = now(), updated_at = now() WHERE id = ${id} AND archived_at IS NULL`;
}

export async function cashfreeCredentialForAccount(accountIdValue: unknown, versionId?: string | null) {
  await ensureSchema();
  const accountId = assertId(accountIdValue);
  const versionRows = versionId
    ? await sql`SELECT * FROM cashfree_credential_versions WHERE id = ${versionId} AND cashfree_account_id = ${accountId}`
    : await sql`SELECT v.* FROM cashfree_accounts a JOIN cashfree_credential_versions v ON v.id = a.current_credential_version_id WHERE a.id = ${accountId}`;
  const version = versionRows[0] as CashfreeCredentialRow | undefined;
  const accountRows = await sql`SELECT * FROM cashfree_accounts WHERE id = ${accountId}`;
  const account = accountRows[0] as CashfreeAccountRow | undefined;
  if (!version || !account) throw new Error("Credentials are unavailable.");
  return { version, appId: version.app_id, secretKey: decryptSecret(version.encrypted_secret_key), webhookSecret: version.encrypted_webhook_secret ? decryptSecret(version.encrypted_webhook_secret) : null, mode: account.mode, apiVersion: account.api_version };
}

export async function createWebsite(input: Record<string, unknown>) {
  await ensureSchema();
  const name = cleanText(input.name, 120);
  if (!name) throw new Error("Website name is required.");
  const id = randomUUID();
  const secret = newToken();
  const paymentProvider = provider(input.payment_provider);
  const razorpayAssignment = cleanText(input.razorpay_account_id, 80) || null;
  const cashfreeAssignment = cleanText(input.cashfree_account_id, 80) || null;
  if (razorpayAssignment) assertId(razorpayAssignment);
  if (cashfreeAssignment) assertId(cashfreeAssignment);
  if (paymentProvider === "razorpay" && !razorpayAssignment) throw new Error("Assign an active Razorpay account.");
  if (paymentProvider === "cashfree" && !cashfreeAssignment) throw new Error("Assign an active Cashfree account.");
  await sql`INSERT INTO websites (id, name, domain, site_code, encrypted_auth_secret, status, payment_provider, razorpay_account_id, cashfree_account_id) VALUES (${id}, ${name}, ${assertDomain(input.domain)}, ${assertSiteCode(input.site_code)}, ${encryptSecret(secret)}, ${status(input.status || 'active')}, ${paymentProvider}, ${razorpayAssignment}, ${cashfreeAssignment})`;
  await replaceWebsitePixels(id, input.facebook_pixel_ids);
  return { id, secret };
}

export async function updateWebsite(websiteIdValue: unknown, input: Record<string, unknown>) {
  await ensureSchema();
  const id = assertId(websiteIdValue);
  const rows = await sql`SELECT * FROM websites WHERE id = ${id} AND archived_at IS NULL`;
  const website = rows[0] as WebsiteRow | undefined;
  if (!website) throw new Error("Website not found.");
  const paymentProvider = input.payment_provider ? provider(input.payment_provider) : website.payment_provider;
  const razorpayAssignment = Object.hasOwn(input, "razorpay_account_id") ? cleanText(input.razorpay_account_id, 80) || null : website.razorpay_account_id;
  const cashfreeAssignment = Object.hasOwn(input, "cashfree_account_id") ? cleanText(input.cashfree_account_id, 80) || null : website.cashfree_account_id;
  if (razorpayAssignment) assertId(razorpayAssignment);
  if (cashfreeAssignment) assertId(cashfreeAssignment);
  if (paymentProvider === "razorpay" && !razorpayAssignment) throw new Error("Assign a Razorpay account before saving.");
  if (paymentProvider === "cashfree" && !cashfreeAssignment) throw new Error("Assign a Cashfree account before saving.");
  await sql`UPDATE websites SET name = ${cleanText(input.name, 120) || website.name}, domain = ${input.domain ? assertDomain(input.domain) : website.domain}, site_code = ${input.site_code ? assertSiteCode(input.site_code) : website.site_code}, status = ${input.status ? status(input.status) : website.status}, payment_provider = ${paymentProvider}, razorpay_account_id = ${razorpayAssignment}, cashfree_account_id = ${cashfreeAssignment}, updated_at = now() WHERE id = ${id}`;
  if (Object.hasOwn(input, "facebook_pixel_ids")) await replaceWebsitePixels(id, input.facebook_pixel_ids);
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
  const rows = await sql`SELECT domain, site_code FROM websites WHERE id = ${id} AND archived_at IS NULL`;
  const website = rows[0] as { domain: string; site_code: string } | undefined;
  if (!website) throw new Error("Website not found.");
  // Remove it from operations while preserving payment/audit foreign keys. The
  // original identifiers are retained, and live unique identifiers are freed
  // so the same site can be added again later if required.
  await sql`UPDATE websites SET status = 'inactive', archived_at = now(), archived_domain = ${website.domain}, archived_site_code = ${website.site_code}, domain = ${`archived-${id}.invalid`}, site_code = ${`ARCHIVED_${id.replaceAll("-", "")}`}, razorpay_account_id = NULL, cashfree_account_id = NULL, updated_at = now() WHERE id = ${id}`;
}

export async function bulkAssignWebsiteIds(value: unknown, accountIdValue: unknown, providerValue: unknown = "razorpay") {
  await ensureSchema();
  const ids = Array.isArray(value) ? value.map(assertId) : [];
  if (!ids.length || ids.length > 1000) throw new Error("Select between 1 and 1000 websites.");
  const paymentProvider = provider(providerValue);
  const accountId = cleanText(accountIdValue, 80) || null;
  if (accountId) assertId(accountId);
  if (!accountId) throw new Error("Choose a payment account.");
  if (paymentProvider === "razorpay") await Promise.all(ids.map((id) => sql`UPDATE websites SET payment_provider = 'razorpay', razorpay_account_id = ${accountId}, updated_at = now() WHERE id = ${id} AND archived_at IS NULL`));
  else await Promise.all(ids.map((id) => sql`UPDATE websites SET payment_provider = 'cashfree', cashfree_account_id = ${accountId}, updated_at = now() WHERE id = ${id} AND archived_at IS NULL`));
  return ids;
}

export async function managerData(selectedDate?: string | null) {
  await ensureSchema();
  const selectedReportDate = reportDate(selectedDate);
  const [accounts, cashfreeAccounts, websites, pixels, transactions, logs, metrics, collectionSummary, collectionBySite, collectionByAccount, gatewayLedger] = await Promise.all([
    sql`SELECT a.id, a.account_name, a.key_id, a.mode, a.status, a.created_at, a.updated_at, count(w.id)::int AS website_count FROM razorpay_accounts a LEFT JOIN websites w ON w.razorpay_account_id = a.id AND w.archived_at IS NULL WHERE a.archived_at IS NULL GROUP BY a.id ORDER BY a.created_at DESC`,
    sql`SELECT a.id, a.account_name, a.app_id, a.mode, a.api_version, a.status, a.created_at, a.updated_at, count(w.id)::int AS website_count FROM cashfree_accounts a LEFT JOIN websites w ON w.cashfree_account_id = a.id AND w.archived_at IS NULL WHERE a.archived_at IS NULL GROUP BY a.id ORDER BY a.created_at DESC`,
    sql`SELECT w.id, w.name, w.domain, w.site_code, w.status, w.payment_provider, w.razorpay_account_id, w.cashfree_account_id, w.created_at, w.updated_at, r.account_name AS razorpay_account_name, c.account_name AS cashfree_account_name, coalesce(array_agg(wfp.facebook_pixel_id) FILTER (WHERE wfp.facebook_pixel_id IS NOT NULL), '{}'::uuid[]) AS facebook_pixel_ids FROM websites w LEFT JOIN razorpay_accounts r ON r.id = w.razorpay_account_id LEFT JOIN cashfree_accounts c ON c.id = w.cashfree_account_id LEFT JOIN website_facebook_pixels wfp ON wfp.website_id = w.id WHERE w.archived_at IS NULL GROUP BY w.id, r.account_name, c.account_name ORDER BY w.created_at DESC`,
    sql`SELECT p.id, p.pixel_name, p.pixel_id, p.status, p.archived_at, p.created_at, p.updated_at, count(wfp.website_id)::int AS website_count, coalesce(string_agg(w.name, ', ' ORDER BY w.name), '') AS assigned_websites FROM facebook_pixels p LEFT JOIN website_facebook_pixels wfp ON wfp.facebook_pixel_id = p.id LEFT JOIN websites w ON w.id = wfp.website_id GROUP BY p.id ORDER BY p.archived_at NULLS FIRST, p.created_at DESC`,
    sql`SELECT * FROM (SELECT t.id, t.internal_order_id, t.razorpay_order_id AS provider_order_id, t.razorpay_payment_link_id AS provider_link_id, t.razorpay_payment_id AS provider_payment_id, t.amount_paise, t.currency, t.status, t.created_at, t.updated_at, w.name AS website_name, a.account_name, 'razorpay'::text AS provider FROM payment_transactions t JOIN websites w ON w.id = t.website_id JOIN razorpay_accounts a ON a.id = t.razorpay_account_id WHERE t.status = 'paid' UNION ALL SELECT t.id, t.internal_order_id, t.cashfree_order_id AS provider_order_id, NULL::text AS provider_link_id, NULL::text AS provider_payment_id, t.amount_paise, t.currency, t.status, t.created_at, t.updated_at, w.name AS website_name, a.account_name, 'cashfree'::text AS provider FROM cashfree_transactions t JOIN websites w ON w.id = t.website_id JOIN cashfree_accounts a ON a.id = t.cashfree_account_id WHERE t.status = 'paid') tx ORDER BY updated_at DESC LIMIT 100`,
    sql`SELECT l.id, l.action, l.entity_type, l.entity_id, l.message, l.created_at, u.email AS admin_email FROM audit_logs l LEFT JOIN admin_users u ON u.id = l.admin_user_id ORDER BY l.created_at DESC LIMIT 100`,
    sql`SELECT (SELECT count(*)::int FROM websites WHERE archived_at IS NULL) AS websites, (SELECT count(*)::int FROM websites WHERE status = 'active' AND archived_at IS NULL) AS active_websites, ((SELECT count(*)::int FROM razorpay_accounts WHERE archived_at IS NULL) + (SELECT count(*)::int FROM cashfree_accounts WHERE archived_at IS NULL)) AS accounts, ((SELECT count(*)::int FROM razorpay_accounts WHERE status = 'active' AND archived_at IS NULL) + (SELECT count(*)::int FROM cashfree_accounts WHERE status = 'active' AND archived_at IS NULL)) AS active_accounts, ((SELECT count(*)::int FROM payment_transactions WHERE created_at >= date_trunc('day', now())) + (SELECT count(*)::int FROM cashfree_transactions WHERE created_at >= date_trunc('day', now()))) AS today_payments, ((SELECT count(*)::int FROM payment_transactions WHERE status = 'paid' AND created_at >= date_trunc('day', now())) + (SELECT count(*)::int FROM cashfree_transactions WHERE status = 'paid' AND created_at >= date_trunc('day', now()))) AS successful_payments, ((SELECT count(*)::int FROM payment_transactions WHERE status = 'failed' AND created_at >= date_trunc('day', now())) + (SELECT count(*)::int FROM cashfree_transactions WHERE status = 'failed' AND created_at >= date_trunc('day', now()))) AS failed_payments`,
    sql`SELECT provider, count(*)::int AS payment_count, coalesce(sum(amount_paise), 0)::bigint AS amount_paise FROM (SELECT 'razorpay'::text AS provider, amount_paise, updated_at FROM payment_transactions WHERE status = 'paid' UNION ALL SELECT 'cashfree'::text AS provider, amount_paise, updated_at FROM cashfree_transactions WHERE status = 'paid') paid WHERE (paid.updated_at AT TIME ZONE 'Asia/Kolkata')::date = ${selectedReportDate}::date GROUP BY provider`,
    sql`SELECT website_name, provider, count(*)::int AS payment_count, coalesce(sum(amount_paise), 0)::bigint AS amount_paise FROM (SELECT w.name AS website_name, 'razorpay'::text AS provider, t.amount_paise, t.updated_at FROM payment_transactions t JOIN websites w ON w.id = t.website_id WHERE t.status = 'paid' UNION ALL SELECT w.name AS website_name, 'cashfree'::text AS provider, t.amount_paise, t.updated_at FROM cashfree_transactions t JOIN websites w ON w.id = t.website_id WHERE t.status = 'paid') paid WHERE (paid.updated_at AT TIME ZONE 'Asia/Kolkata')::date = ${selectedReportDate}::date GROUP BY website_name, provider ORDER BY amount_paise DESC, website_name ASC`,
    sql`SELECT account_name, provider, count(*)::int AS payment_count, coalesce(sum(amount_paise), 0)::bigint AS amount_paise FROM (SELECT a.account_name, 'razorpay'::text AS provider, t.amount_paise, t.updated_at FROM payment_transactions t JOIN razorpay_accounts a ON a.id = t.razorpay_account_id WHERE t.status = 'paid' UNION ALL SELECT a.account_name, 'cashfree'::text AS provider, t.amount_paise, t.updated_at FROM cashfree_transactions t JOIN cashfree_accounts a ON a.id = t.cashfree_account_id WHERE t.status = 'paid') paid WHERE (paid.updated_at AT TIME ZONE 'Asia/Kolkata')::date = ${selectedReportDate}::date GROUP BY account_name, provider ORDER BY amount_paise DESC, account_name ASC`,
    sql`SELECT provider, account_name, account_status, archived_at, count(transaction_id)::int AS payment_count, coalesce(sum(amount_paise), 0)::bigint AS amount_paise, max(updated_at) AS last_payment_at FROM (SELECT 'razorpay'::text AS provider, a.account_name, CASE WHEN a.archived_at IS NULL THEN a.status ELSE 'archived' END AS account_status, a.archived_at, t.id AS transaction_id, t.amount_paise, t.updated_at FROM razorpay_accounts a LEFT JOIN payment_transactions t ON t.razorpay_account_id = a.id AND t.status = 'paid' UNION ALL SELECT 'cashfree'::text AS provider, a.account_name, CASE WHEN a.archived_at IS NULL THEN a.status ELSE 'archived' END AS account_status, a.archived_at, t.id AS transaction_id, t.amount_paise, t.updated_at FROM cashfree_accounts a LEFT JOIN cashfree_transactions t ON t.cashfree_account_id = a.id AND t.status = 'paid') ledger GROUP BY provider, account_name, account_status, archived_at ORDER BY archived_at NULLS FIRST, amount_paise DESC, account_name ASC`,
  ]);
  const summary = { razorpay_amount_paise: 0, razorpay_payments: 0, cashfree_amount_paise: 0, cashfree_payments: 0 };
  for (const row of collectionSummary as { provider: string; amount_paise: number; payment_count: number }[]) {
    if (row.provider === "razorpay") { summary.razorpay_amount_paise = Number(row.amount_paise || 0); summary.razorpay_payments = Number(row.payment_count || 0); }
    if (row.provider === "cashfree") { summary.cashfree_amount_paise = Number(row.amount_paise || 0); summary.cashfree_payments = Number(row.payment_count || 0); }
  }
  return { accounts, cashfreeAccounts, websites, pixels, transactions, logs, metrics: metrics[0] || {}, collection: { date: selectedReportDate, ...summary, total_amount_paise: summary.razorpay_amount_paise + summary.cashfree_amount_paise, total_payments: summary.razorpay_payments + summary.cashfree_payments }, collectionBySite, collectionByAccount, gatewayLedger };
}

export async function authenticateSite(request: NextRequest, rawBody: string, expectedPath: string) {
  await ensureSchema();
  const siteCode = request.headers.get("x-payment-site")?.trim().toUpperCase() || "";
  const timestamp = request.headers.get("x-payment-timestamp")?.trim() || "";
  const signature = request.headers.get("x-payment-signature")?.trim() || "";
  if (!siteCode || !timestamp || !signature || !/^\d{13}$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp)) > 5 * 60_000) throw new Error("SITE_AUTH_FAILED");
  const rows = await sql`SELECT * FROM websites WHERE site_code = ${siteCode} AND archived_at IS NULL`;
  const website = rows[0] as WebsiteRow | undefined;
  if (!website || website.status !== "active") throw new Error("SITE_AUTH_FAILED");
  const bodyHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody));
  const hash = Buffer.from(bodyHash).toString("hex");
  const canonical = `${timestamp}.${request.method.toUpperCase()}.${expectedPath}.${hash}`;
  if (!safeEqual(hmac(decryptSecret(website.encrypted_auth_secret), canonical), signature)) throw new Error("SITE_AUTH_FAILED");
  return website;
}

export function publicWebsite(website: WebsiteRow) {
  return { id: website.id, name: website.name, domain: website.domain, siteCode: website.site_code, status: website.status, provider: website.payment_provider, razorpayAccountId: website.razorpay_account_id, cashfreeAccountId: website.cashfree_account_id };
}
