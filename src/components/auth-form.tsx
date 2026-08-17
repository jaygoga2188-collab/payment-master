"use client";

import { FormEvent, useState } from "react";

export function AuthForm({ mode }: { mode: "login" | "setup" }) {
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const response = await fetch(mode === "setup" ? "/api/admin/bootstrap" : "/api/admin/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
    const result = await response.json().catch(() => ({})); setBusy(false);
    if (!response.ok) return setError(result.error || "Request failed.");
    location.assign("/dashboard");
  }
  return <main className="auth-shell"><section className="auth-card"><p className="eyebrow">CENTRAL PAYMENT MANAGER</p><h1>{mode === "setup" ? "Create owner account" : "Welcome back"}</h1><p className="muted">{mode === "setup" ? "Use the one-time setup token to create the first secure admin account." : "Sign in to manage websites, Razorpay and Cashfree accounts."}</p><form onSubmit={submit} className="stack">{mode === "setup" && <><label>Setup token<input name="setup_token" type="password" required autoComplete="off" /></label><label>Your name<input name="name" required maxLength={80} autoComplete="name" /></label></>}<label>Email<input name="email" type="email" required autoComplete="email" /></label><label>Password<input name="password" type="password" minLength={12} required autoComplete={mode === "setup" ? "new-password" : "current-password"} /></label>{error && <p className="error">{error}</p>}<button className="primary" disabled={busy}>{busy ? "Please wait…" : mode === "setup" ? "Create secure admin" : "Sign in"}</button></form>{mode === "login" && <a className="subtle-link" href="/setup">First-time setup</a>}</section></main>;
}
