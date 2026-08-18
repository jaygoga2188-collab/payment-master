import "server-only";

import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required.");

export const sql = neon(databaseUrl);

let schemaPromise: Promise<void> | undefined;

export function ensureSchema() {
  if (!schemaPromise) schemaPromise = createSchema();
  return schemaPromise;
}

async function createSchema() {
  await sql`CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY,
    admin_user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS razorpay_accounts (
    id UUID PRIMARY KEY,
    account_name TEXT NOT NULL UNIQUE,
    key_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('test','live')),
    status TEXT NOT NULL CHECK (status IN ('active','inactive')) DEFAULT 'active',
    current_credential_version_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS razorpay_credential_versions (
    id UUID PRIMARY KEY,
    razorpay_account_id UUID NOT NULL REFERENCES razorpay_accounts(id) ON DELETE RESTRICT,
    key_id TEXT NOT NULL,
    encrypted_key_secret TEXT NOT NULL,
    encrypted_webhook_secret TEXT,
    version_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('current','retired')) DEFAULT 'current',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(razorpay_account_id, version_number)
  )`;
  await sql`CREATE TABLE IF NOT EXISTS websites (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    site_code TEXT NOT NULL UNIQUE,
    encrypted_auth_secret TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','inactive')) DEFAULT 'active',
    razorpay_account_id UUID REFERENCES razorpay_accounts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS cashfree_accounts (
    id UUID PRIMARY KEY,
    account_name TEXT NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('sandbox','production')),
    api_version TEXT NOT NULL DEFAULT '2025-01-01',
    status TEXT NOT NULL CHECK (status IN ('active','inactive')) DEFAULT 'active',
    current_credential_version_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS cashfree_credential_versions (
    id UUID PRIMARY KEY,
    cashfree_account_id UUID NOT NULL REFERENCES cashfree_accounts(id) ON DELETE RESTRICT,
    app_id TEXT NOT NULL,
    encrypted_secret_key TEXT NOT NULL,
    encrypted_webhook_secret TEXT,
    version_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('current','retired')) DEFAULT 'current',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(cashfree_account_id, version_number)
  )`;
  await sql`ALTER TABLE websites ADD COLUMN IF NOT EXISTS payment_provider TEXT NOT NULL DEFAULT 'razorpay'`;
  await sql`ALTER TABLE websites ADD COLUMN IF NOT EXISTS cashfree_account_id UUID REFERENCES cashfree_accounts(id) ON DELETE SET NULL`;
  await sql`ALTER TABLE razorpay_accounts ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`;
  await sql`ALTER TABLE cashfree_accounts ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`;
  await sql`CREATE TABLE IF NOT EXISTS facebook_pixels (
    id UUID PRIMARY KEY,
    pixel_name TEXT NOT NULL UNIQUE,
    pixel_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('active','inactive')) DEFAULT 'active',
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS website_facebook_pixels (
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    facebook_pixel_id UUID NOT NULL REFERENCES facebook_pixels(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (website_id, facebook_pixel_id)
  )`;
  await sql`CREATE INDEX IF NOT EXISTS website_facebook_pixels_pixel_idx ON website_facebook_pixels(facebook_pixel_id)`;
  await sql`CREATE TABLE IF NOT EXISTS cashfree_transactions (
    id UUID PRIMARY KEY,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE RESTRICT,
    cashfree_account_id UUID NOT NULL REFERENCES cashfree_accounts(id) ON DELETE RESTRICT,
    cashfree_credential_version_id UUID NOT NULL REFERENCES cashfree_credential_versions(id) ON DELETE RESTRICT,
    internal_order_id TEXT NOT NULL,
    cashfree_order_id TEXT NOT NULL,
    payment_session_id TEXT,
    checkout_url TEXT,
    amount_paise BIGINT NOT NULL CHECK (amount_paise > 0),
    currency TEXT NOT NULL DEFAULT 'INR',
    status TEXT NOT NULL CHECK (status IN ('created','pending','paid','failed','refunded','cancelled','expired')) DEFAULT 'created',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(website_id, internal_order_id),
    UNIQUE(cashfree_order_id)
  )`;
  await sql`CREATE INDEX IF NOT EXISTS cashfree_transactions_lookup_idx ON cashfree_transactions(cashfree_account_id, cashfree_order_id)`;
  await sql`CREATE TABLE IF NOT EXISTS payment_transactions (
    id UUID PRIMARY KEY,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE RESTRICT,
    razorpay_account_id UUID NOT NULL REFERENCES razorpay_accounts(id) ON DELETE RESTRICT,
    razorpay_credential_version_id UUID NOT NULL REFERENCES razorpay_credential_versions(id) ON DELETE RESTRICT,
    internal_order_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('order','payment_link')),
    razorpay_order_id TEXT,
    razorpay_payment_link_id TEXT,
    razorpay_payment_id TEXT,
    checkout_url TEXT,
    amount_paise BIGINT NOT NULL CHECK (amount_paise > 0),
    currency TEXT NOT NULL DEFAULT 'INR',
    status TEXT NOT NULL CHECK (status IN ('created','pending','paid','failed','refunded','cancelled','expired')) DEFAULT 'created',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(website_id, internal_order_id)
  )`;
  await sql`CREATE INDEX IF NOT EXISTS payment_transactions_lookup_idx ON payment_transactions(razorpay_account_id, razorpay_order_id, razorpay_payment_link_id)`;
  await sql`CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    admin_user_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS rate_limit_events (
    id UUID PRIMARY KEY,
    bucket TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS rate_limit_events_bucket_idx ON rate_limit_events(bucket, created_at)`;
}
