import "server-only";

import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { ensureSchema, sql } from "@/lib/db";
import { hashPassword, hashToken, newToken, verifyPassword } from "@/lib/security";

const COOKIE_NAME = "payment_master_session";
const SESSION_DAYS = 7;

export type AdminUser = { id: string; name: string; email: string; role: string };

function sessionOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: SESSION_DAYS * 24 * 60 * 60,
  };
}

export async function adminCount() {
  await ensureSchema();
  const rows = await sql`SELECT count(*)::int AS count FROM admin_users`;
  return Number(rows[0]?.count || 0);
}

export async function createBootstrapAdmin(input: { name: string; email: string; password: string }) {
  await ensureSchema();
  const id = randomUUID();
  const passwordHash = await hashPassword(input.password);
  await sql`INSERT INTO admin_users (id, name, email, password_hash) VALUES (${id}, ${input.name}, ${input.email}, ${passwordHash})`;
  return { id, name: input.name, email: input.email, role: "owner" } satisfies AdminUser;
}

export async function loginAdmin(email: string, password: string) {
  await ensureSchema();
  const rows = await sql`SELECT id, name, email, password_hash, role FROM admin_users WHERE email = ${email}`;
  const user = rows[0] as { id: string; name: string; email: string; password_hash: string; role: string } | undefined;
  if (!user || !(await verifyPassword(password, user.password_hash))) return null;
  return { id: user.id, name: user.name, email: user.email, role: user.role } satisfies AdminUser;
}

export async function createSession(user: AdminUser) {
  await ensureSchema();
  const token = newToken();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await sql`INSERT INTO admin_sessions (id, admin_user_id, token_hash, expires_at) VALUES (${randomUUID()}, ${user.id}, ${hashToken(token)}, ${expiresAt})`;
  return token;
}

export function attachSession(response: NextResponse, token: string) {
  response.cookies.set(COOKIE_NAME, token, sessionOptions());
  return response;
}

export async function clearSession(request: NextRequest, response: NextResponse) {
  await ensureSchema();
  const token = request.cookies.get(COOKIE_NAME)?.value;
  if (token) await sql`DELETE FROM admin_sessions WHERE token_hash = ${hashToken(token)}`;
  response.cookies.set(COOKIE_NAME, "", { ...sessionOptions(), maxAge: 0 });
  return response;
}

async function resolveSession(token?: string) {
  if (!token) return null;
  await ensureSchema();
  const rows = await sql`SELECT u.id, u.name, u.email, u.role FROM admin_sessions s JOIN admin_users u ON u.id = s.admin_user_id WHERE s.token_hash = ${hashToken(token)} AND s.expires_at > now()`;
  return (rows[0] as AdminUser | undefined) || null;
}

export async function currentAdmin() {
  const store = await cookies();
  return resolveSession(store.get(COOKIE_NAME)?.value);
}

export async function requireAdmin(request: NextRequest) {
  const user = await resolveSession(request.cookies.get(COOKIE_NAME)?.value);
  if (!user) throw new Error("UNAUTHORIZED");
  return user;
}

export function assertSameOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (!origin) return;
  try {
    if (new URL(origin).host !== request.nextUrl.host) throw new Error("CSRF blocked");
  } catch {
    throw new Error("CSRF blocked");
  }
}

export async function checkRateLimit(bucket: string, limit: number, windowSeconds: number) {
  await ensureSchema();
  const cutoff = new Date(Date.now() - windowSeconds * 1000).toISOString();
  await sql`DELETE FROM rate_limit_events WHERE created_at < ${cutoff}`;
  const rows = await sql`SELECT count(*)::int AS count FROM rate_limit_events WHERE bucket = ${bucket} AND created_at >= ${cutoff}`;
  if (Number(rows[0]?.count || 0) >= limit) return false;
  await sql`INSERT INTO rate_limit_events (id, bucket) VALUES (${randomUUID()}, ${bucket})`;
  return true;
}

export async function writeAudit(user: AdminUser | null, action: string, entityType: string, entityId: string | null, message: string, metadata: Record<string, unknown> = {}) {
  await ensureSchema();
  await sql`INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id, message, metadata) VALUES (${randomUUID()}, ${user?.id || null}, ${action}, ${entityType}, ${entityId}, ${message}, ${JSON.stringify(metadata)}::jsonb)`;
}

export function clientIp(request: NextRequest) {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
}

export function adminError(error: unknown) {
  const message = error instanceof Error ? error.message : "Request failed.";
  if (message === "UNAUTHORIZED") return NextResponse.json({ error: "Please sign in again." }, { status: 401 });
  if (message === "CSRF blocked") return NextResponse.json({ error: "Request origin was rejected." }, { status: 403 });
  return NextResponse.json({ error: "Request could not be completed." }, { status: 400 });
}
